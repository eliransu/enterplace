//! SCIM 2.0 provisioning (license feature `scim`, on top of `members`), ported from the Cloudflare app
//! (cloud/control-plane/src/app/members.ts, its SCIM section, SCIM tokens and password links). An identity provider
//! such as Okta or Microsoft Entra ID creates, updates and removes people, and pushes groups, which become teams.
//!
//! The API is at `/console/scim/v2` (Users, Groups, ServiceProviderConfig, ResourceTypes, Schemas), so its changes
//! are admin records in the console's audit chain. It takes a SCIM token an owner makes on the SCIM page; Gantry
//! keeps only the token's SHA-256. Deactivating (`active: false`) or deleting a person removes them and revokes every
//! key named with their email, as removing a member in the console does.
//!
//! A person SCIM makes has no password ("!" never matches a hash). An owner or admin gives them a one-time link to
//! set one, or they sign in with single sign-on.
//!
//! Groups map to teams by name: "Platform Eng" is team `platform-eng`. A person in groups takes the team of the first
//! by name, and is an admin when any of their groups is marked as an admin group on the SCIM page, else a viewer.
//! Owners keep their role. A person who leaves their last group returns to team `default` as a viewer.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::{
    Extension as Ext,
    extract::{ConnectInfo, Path, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{any, get, post},
};
use gantry_console::{
    Admin, Console, Form, Tls, Via, bare_page, foreign,
    html::{self, esc},
    redirect, same_origin,
};
use gantry_server::store::tokio_postgres::{Row, Transaction};
use serde_json::{Map, Value, json};

use super::Db;
use super::members::{self, Members, Role};
use crate::license::Status;

pub const FEATURE: &str = "scim";

pub const MIGRATION: &str = "
ALTER TABLE enterprise_people ADD COLUMN scim_external_id text;
CREATE TABLE enterprise_scim_tokens (
    token_sha256 text PRIMARY KEY,
    name text NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used timestamptz
);
CREATE TABLE enterprise_password_links (
    token_sha256 text PRIMARY KEY,
    person_id text NOT NULL REFERENCES enterprise_people (id) ON DELETE CASCADE,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at timestamptz
);
CREATE TABLE enterprise_scim_groups (
    id text PRIMARY KEY,
    display_name text NOT NULL UNIQUE,
    external_id text,
    team text NOT NULL,
    grants text NOT NULL DEFAULT 'viewer' CHECK (grants IN ('admin', 'viewer')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE enterprise_scim_group_members (
    group_id text NOT NULL REFERENCES enterprise_scim_groups (id) ON DELETE CASCADE,
    person_id text NOT NULL REFERENCES enterprise_people (id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, person_id)
);
";

pub(super) const USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub(super) const ENTERPRISE: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
pub(super) const GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub(super) const ERROR: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const LIST: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const PATH: &str = "/console/scim/v2";
const NAV: &str = "SCIM";
const LINK_DAYS: i32 = 3;
const MAX_RESULTS: i64 = 200;
const MAX_BODY: usize = 1 << 20;
/// Per client address and minute. Entra ID and Okta stay well under it; a loop or a flood does not.
const REQUESTS_PER_MINUTE: u32 = 1200;
/// Wrong tokens per client address and minute before the address waits out the minute.
pub(super) const BAD_TOKENS_PER_MINUTE: u32 = 10;
const MINUTE: Duration = Duration::from_secs(60);

#[derive(Clone)]
struct Scim {
    members: Members,
    limits: Arc<Mutex<HashMap<String, Window>>>,
}

struct Window {
    start: Instant,
    requests: u32,
    bad: u32,
}

/// Adds the SCIM page, the API under it, and the password links for people SCIM makes. Needs `members`' tables.
pub fn register(extension: &mut gantry_server::Extension, db: Arc<Db>, keys: PathBuf) {
    let scim = Scim {
        members: Members { db, keys },
        limits: Arc::default(),
    };
    let console = &mut extension.console;
    console.nav.push(("/console/scim".into(), NAV.into()));
    console.routes = std::mem::take(&mut console.routes)
        .route("/scim", get(scim_page))
        .route("/scim/tokens", post(create_token))
        .route("/scim/tokens/revoke", post(revoke_token))
        .route("/scim/groups/role", post(group_role))
        .route("/scim/password-link", post(password_link))
        .route(
            "/set-password/{token}",
            get(set_password_page).post(set_password),
        )
        .route("/scim/v2/{*rest}", any(api))
        .layer(Ext(scim));
}

/// Without the feature (or without `members`, whose tables it writes), its addresses say why: the page as a page,
/// the API in SCIM's error shape, so the identity provider shows the reason. No nav entry.
pub fn locked(extension: &mut gantry_server::Extension, status: &Status) {
    let Err(refused) = status
        .require(FEATURE)
        .and_then(|()| status.require(members::FEATURE))
    else {
        return;
    };
    let (code, message) = (refused.code, refused.message);
    let detail = format!("{message} (code {code})");
    let page = move || {
        let message = message.clone();
        async move {
            bare_page(
                StatusCode::FORBIDDEN,
                "SCIM needs a license",
                &format!(
                    r#"<h1 class="t-lg" style="margin: 0">SCIM needs a license</h1><p class="t-lead g-muted" style="margin: 0">{}</p><p class="t-small g-muted" style="margin: 0">Code: {}</p>"#,
                    esc(&message),
                    code
                ),
            )
        }
    };
    let console = &mut extension.console;
    console.routes = std::mem::take(&mut console.routes)
        .route("/scim", get(page.clone()))
        .route("/scim/tokens", post(page.clone()))
        .route("/set-password/{token}", get(page))
        .route(
            "/scim/v2/{*rest}",
            any(move || {
                let detail = detail.clone();
                async move { error(StatusCode::FORBIDDEN, &detail, None) }
            }),
        );
}

// ---------------------------------------------------------------- rate limits

impl Scim {
    /// Counts a request from `client`; `Err` holds the seconds until it may send again.
    fn admit(&self, client: &str) -> Result<(), u64> {
        let mut limits = self.limits.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        if limits.len() > 10_000 {
            limits.retain(|_, w| now.duration_since(w.start) < MINUTE);
        }
        let window = limits.entry(client.to_string()).or_insert(Window {
            start: now,
            requests: 0,
            bad: 0,
        });
        if now.duration_since(window.start) >= MINUTE {
            *window = Window {
                start: now,
                requests: 0,
                bad: 0,
            };
        }
        if window.requests >= REQUESTS_PER_MINUTE || window.bad >= BAD_TOKENS_PER_MINUTE {
            return Err(MINUTE
                .saturating_sub(now.duration_since(window.start))
                .as_secs()
                .max(1));
        }
        window.requests += 1;
        Ok(())
    }

    fn bad_token(&self, client: &str) {
        let mut limits = self.limits.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(window) = limits.get_mut(client) {
            window.bad += 1;
        }
    }
}

// ---------------------------------------------------------------- SCIM answers

fn reply(status: StatusCode, body: &Value) -> Response {
    let mut response = (status, body.to_string()).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/scim+json"),
    );
    response
}

fn error(status: StatusCode, detail: &str, scim_type: Option<&str>) -> Response {
    let mut body =
        json!({ "schemas": [ERROR], "status": status.as_u16().to_string(), "detail": detail });
    if let Some(kind) = scim_type {
        body["scimType"] = kind.into();
    }
    reply(status, &body)
}

fn unavailable(err: impl std::fmt::Display) -> Response {
    error(StatusCode::SERVICE_UNAVAILABLE, &err.to_string(), None)
}

fn list(resources: Vec<Value>, total: i64, start: i64) -> Response {
    reply(
        StatusCode::OK,
        &json!({
            "schemas": [LIST],
            "totalResults": total,
            "startIndex": start,
            "itemsPerPage": resources.len(),
            "Resources": resources,
        }),
    )
}

/// `attribute eq "value"`, the one filter form Okta and Entra ID send, as (attribute in lower case, value).
pub(super) fn filter(text: &str) -> Option<(String, String)> {
    let text = text.trim();
    let (attribute, rest) = text.split_once(char::is_whitespace)?;
    let rest = rest.trim_start();
    let op = rest.get(..2)?;
    if !op.eq_ignore_ascii_case("eq") {
        return None;
    }
    let value = rest.get(2..)?.trim();
    let value = value.strip_prefix('"')?.strip_suffix('"')?;
    Some((attribute.to_lowercase(), value.replace("\\\"", "\"")))
}

/// The team a group's display name maps to: lower case, anything but letters, digits, `.` and `_` becomes `-`.
pub(super) fn team_of(name: &str) -> Option<String> {
    let mut team = String::new();
    for c in name.trim().chars().flat_map(char::to_lowercase) {
        if c.is_ascii_alphanumeric() || c == '.' || c == '_' {
            team.push(c);
        } else if !team.ends_with('-') {
            team.push('-');
        }
    }
    let team: String = team.trim_matches('-').chars().take(64).collect();
    let team = team.trim_end_matches('-').to_string();
    members::valid_team(&team).then_some(team)
}

fn bool_of(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(b) => Some(*b),
        Value::String(s) if s.eq_ignore_ascii_case("true") => Some(true),
        Value::String(s) if s.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

fn text_of(value: &Value) -> Option<String> {
    value.as_str().map(|s| s.trim().to_string())
}

/// A person's name from a SCIM user: given and family names, else formatted, else displayName.
fn name_of(user: &Value) -> String {
    let name = &user["name"];
    let parts: Vec<&str> = [&name["givenName"], &name["familyName"]]
        .iter()
        .filter_map(|v| v.as_str().map(str::trim))
        .filter(|s| !s.is_empty())
        .collect();
    let joined = parts.join(" ");
    let name = [
        joined.as_str(),
        name["formatted"].as_str().unwrap_or(""),
        user["displayName"].as_str().unwrap_or(""),
    ]
    .into_iter()
    .map(str::trim)
    .find(|s| !s.is_empty())
    .unwrap_or("");
    name.chars().take(128).collect()
}

fn email_of(user: &Value) -> String {
    let emails = user["emails"].as_array();
    let primary = emails.and_then(|e| e.iter().find(|m| m["primary"] == true));
    let first = emails.and_then(|e| e.first());
    [
        Some(&user["userName"]),
        primary.map(|m| &m["value"]),
        first.map(|m| &m["value"]),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_str)
    .map(|s| s.trim().to_lowercase())
    .find(|s| !s.is_empty())
    .unwrap_or_default()
}

// ---------------------------------------------------------------- rows

struct Person {
    id: String,
    email: String,
    name: String,
    role: String,
    team: String,
    created: String,
    external: Option<String>,
    groups: Value,
}

const PERSON: &str = r#"SELECT p.id, p.email, p.name, p.role, p.team,
    to_char(p.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created, p.scim_external_id,
    COALESCE((SELECT json_agg(json_build_object('value', g.id, 'display', g.display_name) ORDER BY g.display_name)
        FROM enterprise_scim_group_members m JOIN enterprise_scim_groups g ON g.id = m.group_id
        WHERE m.person_id = p.id), '[]')::text AS groups
    FROM enterprise_people p"#;

fn person(row: &Row) -> Result<Person, String> {
    let groups: String = row.try_get("groups").map_err(members::db_error)?;
    Ok(Person {
        id: row.try_get("id").map_err(members::db_error)?,
        email: row.try_get("email").map_err(members::db_error)?,
        name: row.try_get("name").map_err(members::db_error)?,
        role: row.try_get("role").map_err(members::db_error)?,
        team: row.try_get("team").map_err(members::db_error)?,
        created: row.try_get("created").map_err(members::db_error)?,
        external: row.try_get("scim_external_id").map_err(members::db_error)?,
        groups: serde_json::from_str(&groups).map_err(members::db_error)?,
    })
}

struct Group {
    id: String,
    name: String,
    external: Option<String>,
    created: String,
    updated: String,
    members: Vec<(String, String)>,
}

const GROUP_ROW: &str = r#"SELECT g.id, g.display_name, g.external_id,
    to_char(g.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created,
    to_char(g.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS updated,
    COALESCE((SELECT json_agg(json_build_array(p.id, p.email) ORDER BY p.email)
        FROM enterprise_scim_group_members m JOIN enterprise_people p ON p.id = m.person_id
        WHERE m.group_id = g.id), '[]')::text AS members
    FROM enterprise_scim_groups g"#;

fn group(row: &Row) -> Result<Group, String> {
    let members: String = row.try_get("members").map_err(members::db_error)?;
    Ok(Group {
        id: row.try_get("id").map_err(members::db_error)?,
        name: row.try_get("display_name").map_err(members::db_error)?,
        external: row.try_get("external_id").map_err(members::db_error)?,
        created: row.try_get("created").map_err(members::db_error)?,
        updated: row.try_get("updated").map_err(members::db_error)?,
        members: serde_json::from_str(&members).map_err(members::db_error)?,
    })
}

/// Sets the team and role of these people from their groups, in `tx`. Owners keep their role.
async fn follow_groups(tx: &Transaction<'_>, people: &[String]) -> Result<(), String> {
    for id in people {
        let rows = tx
            .query(
                "SELECT g.team, g.grants FROM enterprise_scim_group_members m JOIN enterprise_scim_groups g \
                 ON g.id = m.group_id WHERE m.person_id = $1 ORDER BY g.display_name",
                &[id],
            )
            .await
            .map_err(members::db_error)?;
        let team = rows
            .first()
            .map(|r| r.try_get::<_, String>(0))
            .transpose()
            .map_err(members::db_error)?
            .unwrap_or_else(|| "default".into());
        let admin = rows
            .iter()
            .any(|r| r.try_get::<_, &str>(1).is_ok_and(|g| g == "admin"));
        tx.execute(
            "UPDATE enterprise_people SET team = $2, \
             role = CASE WHEN role = 'owner' THEN role WHEN $3 THEN 'admin' ELSE 'viewer' END WHERE id = $1",
            &[id, &team, &admin],
        )
        .await
        .map_err(members::db_error)?;
    }
    Ok(())
}

// ---------------------------------------------------------------- the API

/// One authenticated SCIM request.
struct Call<'a> {
    console: &'a Console,
    scim: &'a Scim,
    actor: Admin,
    /// The API's address as the identity provider reached it, for `meta.location`.
    base: String,
}

type Answer = Result<Response, Response>;

impl Call<'_> {
    /// Writes an admin record, before the change. `code` marks a refusal. `Err` is the answer: nothing is done.
    async fn audit(
        &self,
        action: &'static str,
        target: Value,
        code: Option<&str>,
    ) -> Result<(), Response> {
        self.console
            .audit(Some(&self.actor), action, target, code)
            .await
            .map_err(|err| error(StatusCode::SERVICE_UNAVAILABLE, err, None))
    }

    /// Records a refused change and answers it.
    async fn refuse(
        &self,
        action: &'static str,
        target: Value,
        code: &str,
        status: StatusCode,
        detail: &str,
        scim_type: &str,
    ) -> Response {
        if let Err(answer) = self.audit(action, target, Some(code)).await {
            return answer;
        }
        error(status, detail, Some(scim_type))
    }

    fn db(&self) -> &Db {
        &self.scim.members.db
    }

    fn user_json(&self, p: &Person, active: bool) -> Value {
        let (given, family) = p.name.split_once(' ').unwrap_or((&p.name, ""));
        let groups: Vec<Value> = p
            .groups
            .as_array()
            .map(|g| {
                g.iter()
                    .map(|g| {
                        json!({
                            "value": g["value"],
                            "display": g["display"],
                            "$ref": format!("{}/Groups/{}", self.base, g["value"].as_str().unwrap_or("")),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut user = json!({
            "schemas": [USER, ENTERPRISE],
            "id": p.id,
            "userName": p.email,
            "name": { "givenName": given, "familyName": family, "formatted": p.name },
            "displayName": p.name,
            "emails": [{ "value": p.email, "type": "work", "primary": true }],
            "active": active,
            "groups": groups,
            ENTERPRISE: { "department": p.team },
            "meta": {
                "resourceType": "User",
                "created": p.created,
                "lastModified": p.created,
                "location": format!("{}/Users/{}", self.base, p.id),
            },
        });
        if let Some(external) = &p.external {
            user["externalId"] = external.as_str().into();
        }
        user
    }

    fn group_json(&self, g: &Group, with_members: bool) -> Value {
        let mut body = json!({
            "schemas": [GROUP],
            "id": g.id,
            "displayName": g.name,
            "meta": {
                "resourceType": "Group",
                "created": g.created,
                "lastModified": g.updated,
                "location": format!("{}/Groups/{}", self.base, g.id),
            },
        });
        if with_members {
            body["members"] = g
                .members
                .iter()
                .map(|(id, email)| {
                    json!({ "value": id, "display": email, "$ref": format!("{}/Users/{id}", self.base) })
                })
                .collect();
        }
        if let Some(external) = &g.external {
            body["externalId"] = external.as_str().into();
        }
        body
    }

    async fn person(&self, id: &str) -> Result<Option<Person>, Response> {
        let client = self.db().client().await.map_err(unavailable)?;
        let row = client
            .query_opt(&format!("{PERSON} WHERE p.id = $1"), &[&id])
            .await
            .map_err(|e| unavailable(members::db_error(e)))?;
        row.as_ref().map(person).transpose().map_err(unavailable)
    }

    async fn group(&self, id: &str) -> Result<Option<Group>, Response> {
        let client = self.db().client().await.map_err(unavailable)?;
        let row = client
            .query_opt(&format!("{GROUP_ROW} WHERE g.id = $1"), &[&id])
            .await
            .map_err(|e| unavailable(members::db_error(e)))?;
        row.as_ref().map(group).transpose().map_err(unavailable)
    }

    async fn found_person(&self, id: &str) -> Result<Person, Response> {
        self.person(id).await?.ok_or_else(|| {
            error(
                StatusCode::NOT_FOUND,
                &format!(
                    "No person has the id {id}. They may have been removed; provision them again."
                ),
                None,
            )
        })
    }

    async fn found_group(&self, id: &str) -> Result<Group, Response> {
        self.group(id).await?.ok_or_else(|| {
            error(
                StatusCode::NOT_FOUND,
                &format!("No group has the id {id}. Push the group again."),
                None,
            )
        })
    }

    /// A page of `select` (PERSON or GROUP_ROW) filtered as the query asks.
    async fn page(
        &self,
        uri: &Uri,
        select: &str,
        columns: &[(&str, &str)],
        order: &str,
    ) -> Result<(Vec<Row>, i64, i64), Response> {
        let query = Form::of(uri);
        let mut condition = String::new();
        let mut value = String::new();
        let text = query.get("filter");
        if !text.trim().is_empty() {
            let known: Vec<&str> = columns.iter().map(|(a, _)| *a).collect();
            let parsed = filter(text).and_then(|(attribute, v)| {
                columns
                    .iter()
                    .find(|(a, _)| a.eq_ignore_ascii_case(&attribute))
                    .map(|(_, column)| (column.to_string(), v))
            });
            let Some((column, v)) = parsed else {
                return Err(error(
                    StatusCode::BAD_REQUEST,
                    &format!(
                        "The filters supported are {} eq \"value\".",
                        known.join(", ")
                    ),
                    Some("invalidFilter"),
                ));
            };
            condition = format!(" WHERE {column}");
            value = v;
        }
        let start = query.get("startIndex").parse::<i64>().unwrap_or(1).max(1);
        let count = query
            .get("count")
            .parse::<i64>()
            .unwrap_or(MAX_RESULTS)
            .clamp(0, MAX_RESULTS);
        let client = self.db().client().await.map_err(unavailable)?;
        let params: Vec<&(dyn gantry_server::store::tokio_postgres::types::ToSql + Sync)> =
            if condition.is_empty() {
                vec![]
            } else {
                vec![&value]
            };
        let rows = client
            .query(
                &format!(
                    "{select}{condition} ORDER BY {order} OFFSET {} LIMIT {count}",
                    start - 1
                ),
                &params,
            )
            .await
            .map_err(|e| unavailable(members::db_error(e)))?;
        let total: i64 = client
            .query_one(
                &format!("SELECT count(*) FROM ({select}{condition}) AS matched"),
                &params,
            )
            .await
            .and_then(|r| r.try_get(0))
            .map_err(|e| unavailable(members::db_error(e)))?;
        Ok((rows, total, start))
    }

    // ------------------------------------------------ Users

    async fn list_users(&self, uri: &Uri) -> Answer {
        let (rows, total, start) = self
            .page(
                uri,
                PERSON,
                &[
                    ("userName", "lower(p.email) = lower($1)"),
                    ("externalId", "p.scim_external_id = $1"),
                    ("id", "p.id = $1"),
                ],
                "email",
            )
            .await?;
        let people = rows
            .iter()
            .map(person)
            .collect::<Result<Vec<_>, _>>()
            .map_err(unavailable)?;
        Ok(list(
            people.iter().map(|p| self.user_json(p, true)).collect(),
            total,
            start,
        ))
    }

    async fn create_user(&self, body: &Value) -> Answer {
        let email = email_of(body);
        if !members::valid_email(&email) {
            return Err(error(
                StatusCode::BAD_REQUEST,
                "userName must be the person's email address. Map userName to the email attribute in the identity provider.",
                Some("invalidValue"),
            ));
        }
        if body.get("active").and_then(bool_of) == Some(false) {
            return Err(error(
                StatusCode::BAD_REQUEST,
                "Gantry provisions active people only. Assign the person once they are active in the identity provider.",
                Some("invalidValue"),
            ));
        }
        let department = body[ENTERPRISE]["department"].as_str().unwrap_or("").trim();
        let team = if members::valid_team(department) {
            department
        } else {
            "default"
        };
        let name = match name_of(body) {
            name if name.is_empty() => email.clone(),
            name => name,
        };
        let external = text_of(&body["externalId"]).filter(|e| !e.is_empty());
        let target = json!({ "email": email, "role": "viewer", "team": team, "via": "scim" });
        let exists = {
            let client = self.db().client().await.map_err(unavailable)?;
            client
                .query_opt(
                    "SELECT 1 FROM enterprise_people WHERE email = $1",
                    &[&email],
                )
                .await
                .map_err(|e| unavailable(members::db_error(e)))?
                .is_some()
        };
        if exists {
            return Err(self
                .refuse(
                    "member_added",
                    target,
                    "uniqueness",
                    StatusCode::CONFLICT,
                    &format!("{email} is already a member. Match them by userName instead of creating them."),
                    "uniqueness",
                )
                .await);
        }
        let id = format!("usr_{}", members::random_hex(16).map_err(unavailable)?);
        let salt = members::random_hex(16).map_err(unavailable)?;
        self.audit("member_added", target, None).await?;
        let made = {
            let client = self.db().client().await.map_err(unavailable)?;
            // No one knows a password for this person: "!" never equals a PBKDF2 hash. They set one by a link.
            client
                .execute(
                    "INSERT INTO enterprise_people (id, email, name, password_salt, password_hash, role, team, scim_external_id) \
                     VALUES ($1, $2, $3, $4, '!', 'viewer', $5, $6) ON CONFLICT (email) DO NOTHING",
                    &[&id, &email, &name, &salt, &team, &external],
                )
                .await
                .map_err(|e| unavailable(members::db_error(e)))?
        };
        if made != 1 {
            return Err(error(
                StatusCode::CONFLICT,
                &format!("{email} is already a member."),
                Some("uniqueness"),
            ));
        }
        let p = self.found_person(&id).await?;
        let mut response = reply(StatusCode::CREATED, &self.user_json(&p, true));
        if let Ok(location) = HeaderValue::from_str(&format!("{}/Users/{id}", self.base)) {
            response.headers_mut().insert(header::LOCATION, location);
        }
        Ok(response)
    }

    /// Removes the person and revokes every key named with their email. The last owner stays.
    async fn deactivate(&self, p: &Person, why: &str) -> Result<(), Response> {
        let members = &self.scim.members;
        let target = |keys: &[String]| {
            let prefixes: Vec<&str> = keys.iter().filter_map(|k| k.get(..8)).collect();
            json!({ "email": p.email, "role": p.role, "via": "scim", "why": why, "keys_revoked": prefixes })
        };
        if p.role == "owner" {
            let owners: i64 = {
                let client = self.db().client().await.map_err(unavailable)?;
                client
                    .query_one(
                        "SELECT count(*) FROM enterprise_people WHERE role = 'owner'",
                        &[],
                    )
                    .await
                    .and_then(|r| r.try_get(0))
                    .map_err(|e| unavailable(members::db_error(e)))?
            };
            if owners <= 1 {
                return Err(self.last_owner(target(&[])).await);
            }
        }
        let keys = members
            .keys_of(&p.email)
            .map_err(|e| unavailable(members::db_error(e)))?;
        self.audit("member_removed", target(&keys), None).await?;
        match members.change(&p.id, None).await {
            Err(err) => return Err(unavailable(err)),
            Ok(Err(_)) => return Err(self.last_owner(target(&[])).await),
            Ok(Ok(())) => {}
        }
        members.revoke(keys).await.map_err(|err| {
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "{} was removed, and their keys could not all be revoked: {err}. Revoke the keys named {} under People and workloads in the console.",
                    p.email, p.email
                ),
                None,
            )
        })
    }

    async fn last_owner(&self, target: Value) -> Response {
        self.refuse(
            "member_removed",
            target,
            "last_owner",
            StatusCode::CONFLICT,
            "This is the last owner. Make another member an owner in the console first.",
            "mutability",
        )
        .await
    }

    /// Applies a name, externalId and department to a person, and records what changed.
    async fn update_user(
        &self,
        p: &Person,
        user_name: Option<String>,
        name: Option<String>,
        external: Option<Option<String>>,
        department: Option<String>,
    ) -> Answer {
        if let Some(user_name) = user_name
            .map(|u| u.to_lowercase())
            .filter(|u| !u.is_empty())
            && user_name != p.email
        {
            return Err(self
                .refuse(
                    "member_changed",
                    json!({ "email": p.email, "userName": user_name, "via": "scim" }),
                    "mutability",
                    StatusCode::BAD_REQUEST,
                    &format!(
                        "userName is the person's email, {}, and their keys are named with it, so it does not change. Deprovision the person and provision {user_name} instead.",
                        p.email
                    ),
                    "mutability",
                )
                .await);
        }
        let name = name.filter(|n| !n.is_empty() && *n != p.name);
        let external = external.filter(|e| *e != p.external);
        // A person in groups takes their team from the groups.
        let in_groups = p.groups.as_array().is_some_and(|g| !g.is_empty());
        let team = department.filter(|d| !in_groups && members::valid_team(d) && *d != p.team);
        if name.is_none() && external.is_none() && team.is_none() {
            return Ok(reply(StatusCode::OK, &self.user_json(p, true)));
        }
        let target = json!({ "email": p.email, "name": name, "team": team.as_ref().map(|t| [&p.team, t]), "via": "scim" });
        self.audit("member_changed", target, None).await?;
        {
            let client = self.db().client().await.map_err(unavailable)?;
            client
                .execute(
                    "UPDATE enterprise_people SET name = COALESCE($2, name), team = COALESCE($3, team), \
                     scim_external_id = CASE WHEN $4 THEN $5 ELSE scim_external_id END WHERE id = $1",
                    &[&p.id, &name, &team, &external.is_some(), &external.clone().flatten()],
                )
                .await
                .map_err(|e| unavailable(members::db_error(e)))?;
        }
        let p = self.found_person(&p.id).await?;
        Ok(reply(StatusCode::OK, &self.user_json(&p, true)))
    }

    async fn replace_user(&self, p: &Person, body: &Value) -> Answer {
        if body.get("active").and_then(bool_of) == Some(false) {
            self.deactivate(p, "deactivated by SCIM").await?;
            return Ok(reply(StatusCode::OK, &self.user_json(p, false)));
        }
        let user_name = (!email_of(body).is_empty()).then(|| email_of(body));
        let external = Some(text_of(&body["externalId"]).filter(|e| !e.is_empty()));
        let department = text_of(&body[ENTERPRISE]["department"]);
        self.update_user(p, user_name, Some(name_of(body)), external, department)
            .await
    }

    async fn patch_user(&self, p: &Person, body: &Value) -> Answer {
        let Some(ops) = body["Operations"].as_array() else {
            return Err(error(
                StatusCode::BAD_REQUEST,
                r#"A PATCH needs Operations, such as {"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}."#,
                Some("invalidSyntax"),
            ));
        };
        let mut set: Map<String, Value> = Map::new();
        let mut external_removed = false;
        for op in ops {
            let kind = op["op"].as_str().unwrap_or("").to_lowercase();
            let path = op["path"].as_str().unwrap_or("").trim();
            match kind.as_str() {
                "add" | "replace" if path.is_empty() => match op["value"].as_object() {
                    Some(value) => {
                        set.extend(value.iter().map(|(k, v)| (k.to_lowercase(), v.clone())))
                    }
                    None => {
                        return Err(error(
                            StatusCode::BAD_REQUEST,
                            "An operation without a path needs an object as its value.",
                            Some("invalidValue"),
                        ));
                    }
                },
                "add" | "replace" => {
                    set.insert(path.to_lowercase(), op["value"].clone());
                }
                "remove" if path.eq_ignore_ascii_case("externalId") => external_removed = true,
                "remove" => {}
                _ => {
                    return Err(error(
                        StatusCode::BAD_REQUEST,
                        &format!(
                            "Unknown PATCH op {:?}. Use add, replace or remove.",
                            op["op"]
                        ),
                        Some("invalidSyntax"),
                    ));
                }
            }
        }
        // Attributes by their full names, as Entra ID sends the enterprise extension's.
        let core = format!("{}:", USER.to_lowercase());
        let enterprise = format!("{}:", ENTERPRISE.to_lowercase());
        let mut attributes: Map<String, Value> = Map::new();
        for (key, value) in set {
            let key = key.strip_prefix(&core).map(str::to_string).unwrap_or(key);
            if key == ENTERPRISE.to_lowercase() {
                if let Some(d) = value.get("department") {
                    attributes.insert("department".into(), d.clone());
                }
            } else if let Some(rest) = key.strip_prefix(&enterprise) {
                attributes.insert(rest.into(), value);
            } else if key == "name" {
                for part in ["givenName", "familyName", "formatted"] {
                    if let Some(v) = value.get(part) {
                        attributes.insert(format!("name.{}", part.to_lowercase()), v.clone());
                    }
                }
            } else {
                attributes.insert(key, value);
            }
        }
        if attributes.get("active").and_then(bool_of) == Some(false) {
            self.deactivate(p, "deactivated by SCIM").await?;
            // Okta reads the user back from the answer; Entra ID takes 200 or 204.
            return Ok(reply(StatusCode::OK, &self.user_json(p, false)));
        }
        let text = |key: &str| attributes.get(key).and_then(text_of);
        let (given, family) = p.name.split_once(' ').unwrap_or((&p.name, ""));
        let name = if text("name.givenname").is_some() || text("name.familyname").is_some() {
            let given = text("name.givenname").unwrap_or_else(|| given.to_string());
            let family = text("name.familyname").unwrap_or_else(|| family.to_string());
            Some(
                format!("{given} {family}")
                    .trim()
                    .chars()
                    .take(128)
                    .collect(),
            )
        } else {
            text("name.formatted").or_else(|| text("displayname"))
        };
        let external = if external_removed {
            Some(None)
        } else {
            text("externalid").map(|e| Some(e).filter(|e| !e.is_empty()))
        };
        self.update_user(p, text("username"), name, external, text("department"))
            .await
    }

    async fn users(&self, method: &Method, id: Option<&str>, uri: &Uri, body: &Value) -> Answer {
        let Some(id) = id else {
            return match *method {
                Method::GET => self.list_users(uri).await,
                Method::POST => self.create_user(body).await,
                _ => Err(not_allowed(method, "Users")),
            };
        };
        let p = self.found_person(id).await?;
        match *method {
            Method::GET => Ok(reply(StatusCode::OK, &self.user_json(&p, true))),
            Method::PUT => self.replace_user(&p, body).await,
            Method::PATCH => self.patch_user(&p, body).await,
            Method::DELETE => {
                self.deactivate(&p, "deleted by SCIM").await?;
                Ok(StatusCode::NO_CONTENT.into_response())
            }
            _ => Err(not_allowed(method, "a User")),
        }
    }

    // ------------------------------------------------ Groups

    /// The person IDs in a members value (`[{"value": id}]`), each checked to be a person.
    async fn member_ids(&self, value: &Value) -> Result<Vec<String>, Response> {
        let Some(items) = value.as_array() else {
            return Err(error(
                StatusCode::BAD_REQUEST,
                r#"members is a list, such as [{"value":"usr_..."}]."#,
                Some("invalidValue"),
            ));
        };
        let ids: Vec<String> = items
            .iter()
            .filter_map(|m| m["value"].as_str().map(str::to_string))
            .collect();
        let client = self.db().client().await.map_err(unavailable)?;
        let known: Vec<String> = client
            .query(
                "SELECT id FROM enterprise_people WHERE id = ANY($1)",
                &[&ids],
            )
            .await
            .map_err(|e| unavailable(members::db_error(e)))?
            .iter()
            .filter_map(|r| r.try_get(0).ok())
            .collect();
        if let Some(missing) = ids.iter().find(|id| !known.contains(id)) {
            return Err(error(
                StatusCode::BAD_REQUEST,
                &format!(
                    "No person has the id {missing}. Provision the person before adding them to a group."
                ),
                Some("invalidValue"),
            ));
        }
        Ok(ids)
    }

    async fn name_taken(&self, name: &str, other_than: &str) -> Result<bool, Response> {
        let client = self.db().client().await.map_err(unavailable)?;
        Ok(client
            .query_opt(
                "SELECT 1 FROM enterprise_scim_groups WHERE display_name = $1 AND id <> $2",
                &[&name, &other_than],
            )
            .await
            .map_err(|e| unavailable(members::db_error(e)))?
            .is_some())
    }

    /// Writes a group's name, externalId and members, and moves everyone whose groups changed to their new team.
    async fn write_group(
        &self,
        id: &str,
        name: &str,
        external: Option<String>,
        members: &[String],
        before: &[String],
    ) -> Result<(), Response> {
        let team = team_of(name).ok_or_else(|| bad_group_name(name))?;
        let mut client = self.db().client().await.map_err(unavailable)?;
        let written = async {
            let tx = client.transaction().await.map_err(members::db_error)?;
            tx.execute(
                "INSERT INTO enterprise_scim_groups (id, display_name, external_id, team) VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (id) DO UPDATE SET display_name = $2, external_id = $3, team = $4, updated_at = now()",
                &[&id, &name, &external, &team],
            )
            .await
            .map_err(members::db_error)?;
            tx.execute(
                "DELETE FROM enterprise_scim_group_members WHERE group_id = $1",
                &[&id],
            )
            .await
            .map_err(members::db_error)?;
            tx.execute(
                "INSERT INTO enterprise_scim_group_members (group_id, person_id) SELECT $1, unnest($2::text[]) ON CONFLICT DO NOTHING",
                &[&id, &members],
            )
            .await
            .map_err(members::db_error)?;
            let mut affected: Vec<String> = before.iter().chain(members).cloned().collect();
            affected.sort();
            affected.dedup();
            follow_groups(&tx, &affected).await?;
            tx.commit().await.map_err(members::db_error)
        };
        written.await.map_err(unavailable)
    }

    async fn list_groups(&self, uri: &Uri) -> Answer {
        let (rows, total, start) = self
            .page(
                uri,
                GROUP_ROW,
                &[
                    ("displayName", "g.display_name = $1"),
                    ("externalId", "g.external_id = $1"),
                    ("id", "g.id = $1"),
                ],
                "display_name",
            )
            .await?;
        let groups = rows
            .iter()
            .map(group)
            .collect::<Result<Vec<_>, _>>()
            .map_err(unavailable)?;
        let with_members = !excludes_members(uri);
        Ok(list(
            groups
                .iter()
                .map(|g| self.group_json(g, with_members))
                .collect(),
            total,
            start,
        ))
    }

    async fn create_group(&self, body: &Value) -> Answer {
        let name = text_of(&body["displayName"]).unwrap_or_default();
        let team = team_of(&name).ok_or_else(|| bad_group_name(&name))?;
        let members = match body.get("members") {
            Some(m) if !m.is_null() => self.member_ids(m).await?,
            _ => vec![],
        };
        let target =
            json!({ "group": name, "team": team, "members": members.len(), "via": "scim" });
        if self.name_taken(&name, "").await? {
            return Err(self
                .refuse("group_created", target, "uniqueness", StatusCode::CONFLICT, &format!("A group is named {name} already. Match it by displayName instead of creating it."), "uniqueness")
                .await);
        }
        let id = format!("grp_{}", members::random_hex(16).map_err(unavailable)?);
        self.audit("group_created", target, None).await?;
        let external = text_of(&body["externalId"]).filter(|e| !e.is_empty());
        self.write_group(&id, &name, external, &members, &[])
            .await?;
        let g = self.found_group(&id).await?;
        let mut response = reply(StatusCode::CREATED, &self.group_json(&g, true));
        if let Ok(location) = HeaderValue::from_str(&format!("{}/Groups/{id}", self.base)) {
            response.headers_mut().insert(header::LOCATION, location);
        }
        Ok(response)
    }

    /// Records and writes a group's new state.
    async fn change_group(
        &self,
        g: &Group,
        name: String,
        external: Option<String>,
        members: Vec<String>,
    ) -> Result<(), Response> {
        let before: Vec<String> = g.members.iter().map(|(id, _)| id.clone()).collect();
        let added: Vec<&String> = members.iter().filter(|m| !before.contains(m)).collect();
        let removed: Vec<&String> = before.iter().filter(|m| !members.contains(m)).collect();
        let target = json!({
            "group": g.name,
            "name": (name != g.name).then_some(&name),
            "added": added,
            "removed": removed,
            "via": "scim",
        });
        if name != g.name && self.name_taken(&name, &g.id).await? {
            return Err(self
                .refuse(
                    "group_changed",
                    target,
                    "uniqueness",
                    StatusCode::CONFLICT,
                    &format!("A group is named {name} already."),
                    "uniqueness",
                )
                .await);
        }
        team_of(&name).ok_or_else(|| bad_group_name(&name))?;
        self.audit("group_changed", target, None).await?;
        self.write_group(&g.id, &name, external, &members, &before)
            .await
    }

    async fn patch_group(&self, g: &Group, body: &Value) -> Result<(), Response> {
        let Some(ops) = body["Operations"].as_array() else {
            return Err(error(
                StatusCode::BAD_REQUEST,
                r#"A PATCH needs Operations, such as {"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"members","value":[{"value":"usr_..."}]}]}."#,
                Some("invalidSyntax"),
            ));
        };
        let mut name = g.name.clone();
        let mut external = g.external.clone();
        let mut members: Vec<String> = g.members.iter().map(|(id, _)| id.clone()).collect();
        for op in ops {
            let kind = op["op"].as_str().unwrap_or("").to_lowercase();
            let path = op["path"].as_str().unwrap_or("").trim();
            let value = &op["value"];
            let lower = path.to_lowercase();
            match (kind.as_str(), lower.as_str()) {
                ("add" | "replace", "") => {
                    if let Some(n) = text_of(&value["displayName"]) {
                        name = n;
                    }
                    if let Some(e) = text_of(&value["externalId"]) {
                        external = Some(e);
                    }
                    if let Some(m) = value.get("members") {
                        members = self.member_ids(m).await?;
                    }
                }
                ("add" | "replace", "displayname") => name = text_of(value).unwrap_or_default(),
                ("add" | "replace", "externalid") => external = text_of(value),
                ("add", "members") => {
                    for id in self.member_ids(value).await? {
                        if !members.contains(&id) {
                            members.push(id);
                        }
                    }
                }
                ("replace", "members") => members = self.member_ids(value).await?,
                ("remove", "members") if value.is_null() => members.clear(),
                ("remove", "members") => {
                    let gone: Vec<String> = value
                        .as_array()
                        .map(|v| {
                            v.iter()
                                .filter_map(|m| m["value"].as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default();
                    members.retain(|m| !gone.contains(m));
                }
                ("remove", "externalid") => external = None,
                ("remove", _) if lower.starts_with("members[") => {
                    // Okta: members[value eq "usr_..."]
                    let inner = path
                        .get(8..)
                        .and_then(|p| p.strip_suffix(']'))
                        .and_then(filter)
                        .filter(|(attribute, _)| attribute == "value");
                    let Some((_, id)) = inner else {
                        return Err(error(
                            StatusCode::BAD_REQUEST,
                            r#"Name the member to remove as members[value eq "usr_..."]."#,
                            Some("invalidPath"),
                        ));
                    };
                    members.retain(|m| *m != id);
                }
                ("add" | "replace" | "remove", _) => {}
                _ => {
                    return Err(error(
                        StatusCode::BAD_REQUEST,
                        &format!(
                            "Unknown PATCH op {:?}. Use add, replace or remove.",
                            op["op"]
                        ),
                        Some("invalidSyntax"),
                    ));
                }
            }
        }
        self.change_group(g, name, external, members).await
    }

    async fn groups(&self, method: &Method, id: Option<&str>, uri: &Uri, body: &Value) -> Answer {
        let Some(id) = id else {
            return match *method {
                Method::GET => self.list_groups(uri).await,
                Method::POST => self.create_group(body).await,
                _ => Err(not_allowed(method, "Groups")),
            };
        };
        let g = self.found_group(id).await?;
        match *method {
            Method::GET => Ok(reply(
                StatusCode::OK,
                &self.group_json(&g, !excludes_members(uri)),
            )),
            Method::PUT => {
                let name = text_of(&body["displayName"]).unwrap_or_else(|| g.name.clone());
                let members = match body.get("members") {
                    Some(m) if !m.is_null() => self.member_ids(m).await?,
                    _ => vec![],
                };
                let external = text_of(&body["externalId"])
                    .filter(|e| !e.is_empty())
                    .or(g.external.clone());
                self.change_group(&g, name, external, members).await?;
                let g = self.found_group(id).await?;
                Ok(reply(StatusCode::OK, &self.group_json(&g, true)))
            }
            Method::PATCH => {
                self.patch_group(&g, body).await?;
                Ok(StatusCode::NO_CONTENT.into_response())
            }
            Method::DELETE => {
                let before: Vec<String> = g.members.iter().map(|(id, _)| id.clone()).collect();
                self.audit(
                    "group_deleted",
                    json!({ "group": g.name, "members": before.len(), "via": "scim" }),
                    None,
                )
                .await?;
                let mut client = self.db().client().await.map_err(unavailable)?;
                let deleted = async {
                    let tx = client.transaction().await.map_err(members::db_error)?;
                    tx.execute("DELETE FROM enterprise_scim_groups WHERE id = $1", &[&g.id])
                        .await
                        .map_err(members::db_error)?;
                    follow_groups(&tx, &before).await?;
                    tx.commit().await.map_err(members::db_error)
                };
                deleted.await.map_err(unavailable)?;
                Ok(StatusCode::NO_CONTENT.into_response())
            }
            _ => Err(not_allowed(method, "a Group")),
        }
    }
}

fn excludes_members(uri: &Uri) -> bool {
    Form::of(uri)
        .get("excludedAttributes")
        .split(',')
        .any(|a| a.trim().eq_ignore_ascii_case("members"))
}

fn bad_group_name(name: &str) -> Response {
    error(
        StatusCode::BAD_REQUEST,
        &format!(
            "The group name {name:?} has no letters or digits, and it becomes the team's name. Rename the group in the identity provider."
        ),
        Some("invalidValue"),
    )
}

fn not_allowed(method: &Method, what: &str) -> Response {
    error(
        StatusCode::METHOD_NOT_ALLOWED,
        &format!("{method} is not supported on {what}."),
        None,
    )
}

// ---------------------------------------------------------------- discovery

fn service_provider_config(base: &str) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": { "supported": true },
        "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
        "filter": { "supported": true, "maxResults": MAX_RESULTS },
        "changePassword": { "supported": false },
        "sort": { "supported": false },
        "etag": { "supported": false },
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "Bearer token",
            "description": "A SCIM token an owner makes on the console's SCIM page.",
            "primary": true
        }],
        "meta": { "resourceType": "ServiceProviderConfig", "location": format!("{base}/ServiceProviderConfig") }
    })
}

fn resource_types(base: &str) -> Vec<Value> {
    let kind = |id: &str, endpoint: &str, description: &str, schema: &str, extensions: Value| {
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": id,
            "name": id,
            "endpoint": endpoint,
            "description": description,
            "schema": schema,
            "schemaExtensions": extensions,
            "meta": { "resourceType": "ResourceType", "location": format!("{base}/ResourceTypes/{id}") }
        })
    };
    vec![
        kind(
            "User",
            "/Users",
            "A person who signs in to the console and holds keys",
            USER,
            json!([{ "schema": ENTERPRISE, "required": false }]),
        ),
        kind(
            "Group",
            "/Groups",
            "A group of people; it becomes a team",
            GROUP,
            json!([]),
        ),
    ]
}

fn attribute(
    name: &str,
    kind: &str,
    required: bool,
    mutability: &str,
    unique: bool,
    multi: bool,
    sub: Vec<Value>,
) -> Value {
    let mut a = json!({
        "name": name,
        "type": kind,
        "multiValued": multi,
        "required": required,
        "caseExact": false,
        "mutability": mutability,
        "returned": "default",
        "uniqueness": if unique { "server" } else { "none" },
    });
    if !sub.is_empty() {
        a["subAttributes"] = sub.into();
    }
    a
}

fn schemas(base: &str) -> Vec<Value> {
    let s = |n: &str| attribute(n, "string", false, "readWrite", false, false, vec![]);
    let reference = |n: &str, m: &str| attribute(n, "reference", false, m, false, false, vec![]);
    let schema = |id: &str, name: &str, description: &str, attributes: Vec<Value>| {
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
            "id": id,
            "name": name,
            "description": description,
            "attributes": attributes,
            "meta": { "resourceType": "Schema", "location": format!("{base}/Schemas/{id}") }
        })
    };
    vec![
        schema(
            USER,
            "User",
            "A person",
            vec![
                attribute("userName", "string", true, "readWrite", true, false, vec![]),
                attribute(
                    "name",
                    "complex",
                    false,
                    "readWrite",
                    false,
                    false,
                    vec![s("formatted"), s("givenName"), s("familyName")],
                ),
                s("displayName"),
                attribute(
                    "emails",
                    "complex",
                    false,
                    "readWrite",
                    false,
                    true,
                    vec![
                        s("value"),
                        s("type"),
                        attribute(
                            "primary",
                            "boolean",
                            false,
                            "readWrite",
                            false,
                            false,
                            vec![],
                        ),
                    ],
                ),
                attribute(
                    "active",
                    "boolean",
                    false,
                    "readWrite",
                    false,
                    false,
                    vec![],
                ),
                attribute(
                    "groups",
                    "complex",
                    false,
                    "readOnly",
                    false,
                    true,
                    vec![s("value"), s("display"), reference("$ref", "readOnly")],
                ),
            ],
        ),
        schema(
            ENTERPRISE,
            "EnterpriseUser",
            "The person's department, which becomes their team",
            vec![s("department")],
        ),
        schema(
            GROUP,
            "Group",
            "A group; it becomes a team",
            vec![
                attribute(
                    "displayName",
                    "string",
                    true,
                    "readWrite",
                    true,
                    false,
                    vec![],
                ),
                attribute(
                    "members",
                    "complex",
                    false,
                    "readWrite",
                    false,
                    true,
                    vec![s("value"), s("display"), reference("$ref", "immutable")],
                ),
            ],
        ),
    ]
}

fn discovery(base: &str, resource: &str, id: Option<&str>) -> Response {
    let (all, what) = match resource {
        "ResourceTypes" => (resource_types(base), "resource type"),
        _ => (schemas(base), "schema"),
    };
    match id {
        None => {
            let total = i64::try_from(all.len()).unwrap_or(0);
            list(all, total, 1)
        }
        Some(id) => match all.iter().find(|v| v["id"] == id) {
            Some(found) => reply(StatusCode::OK, found),
            None => error(StatusCode::NOT_FOUND, &format!("No {what} {id}."), None),
        },
    }
}

/// The SCIM API: the rate limit, the token, then the resource.
async fn api(
    State(console): State<Console>,
    Ext(scim): Ext<Scim>,
    tls: Tls,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();
    let client = parts
        .extensions
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map_or_else(|| "unknown".to_string(), |c| c.0.ip().to_string());
    if let Err(wait) = scim.admit(&client) {
        let mut response = error(
            StatusCode::TOO_MANY_REQUESTS,
            &format!("Too many SCIM requests from this address. Try again in {wait} seconds."),
            None,
        );
        if let Ok(value) = HeaderValue::from_str(&wait.to_string()) {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        return response;
    }
    let token = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.get(..7)
                .filter(|b| b.eq_ignore_ascii_case("bearer "))
                .and(v.get(7..))
        })
        .unwrap_or("")
        .trim()
        .to_string();
    let named = async {
        let client = scim.members.db.client().await?;
        client
            .query_opt(
                "UPDATE enterprise_scim_tokens SET last_used = now() WHERE token_sha256 = $1 RETURNING name",
                &[&gantry_core::id::sha256_hex(token.as_bytes())],
            )
            .await
            .map_err(members::db_error)?
            .map(|r| r.try_get::<_, String>(0).map_err(members::db_error))
            .transpose()
    };
    let name = match named.await {
        Err(err) => return unavailable(err),
        Ok(Some(name)) => name,
        Ok(None) => {
            scim.bad_token(&client);
            let _ = console
                .audit(
                    None,
                    "scim_request",
                    json!({ "path": parts.uri.path() }),
                    Some("bad_token"),
                )
                .await;
            return error(
                StatusCode::UNAUTHORIZED,
                "This needs a SCIM token of this install, as Authorization: Bearer gscim_... An owner makes one on the console's SCIM page.",
                None,
            );
        }
    };
    let call = Call {
        console: &console,
        scim: &scim,
        actor: Admin {
            role: "scim".into(),
            ..Admin::of_role(&format!("scim:{name}"), "", false, Via::Key)
        },
        base: format!("{}{PATH}", members::origin(&parts.headers, &tls)),
    };
    let path = parts.uri.path();
    let rest = path.split_once("/scim/v2/").map_or("", |(_, rest)| rest);
    let segments: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    let bytes = match axum::body::to_bytes(body, MAX_BODY).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "The body is over 1 MB. Send one resource at a time.",
                None,
            );
        }
    };
    let body: Value = if bytes.iter().all(u8::is_ascii_whitespace) {
        Value::Null
    } else {
        match serde_json::from_slice(&bytes) {
            Ok(body) => body,
            Err(err) => {
                return error(
                    StatusCode::BAD_REQUEST,
                    &format!(
                        "The body is not JSON: {err}. Send a SCIM resource as application/scim+json."
                    ),
                    Some("invalidSyntax"),
                );
            }
        }
    };
    let method = &parts.method;
    let answer = match (segments.as_slice(), method) {
        (["ServiceProviderConfig"], &Method::GET) => {
            Ok(reply(StatusCode::OK, &service_provider_config(&call.base)))
        }
        ([resource @ ("ResourceTypes" | "Schemas")], &Method::GET) => {
            Ok(discovery(&call.base, resource, None))
        }
        ([resource @ ("ResourceTypes" | "Schemas"), id], &Method::GET) => {
            Ok(discovery(&call.base, resource, Some(id)))
        }
        (["Users"], _) => call.users(method, None, &parts.uri, &body).await,
        (["Users", id], _) => call.users(method, Some(id), &parts.uri, &body).await,
        (["Groups"], _) => call.groups(method, None, &parts.uri, &body).await,
        (["Groups", id], _) => call.groups(method, Some(id), &parts.uri, &body).await,
        _ => Err(error(
            StatusCode::NOT_FOUND,
            &format!(
                "No SCIM resource {method} {path}. The resources are Users, Groups, ServiceProviderConfig, ResourceTypes and Schemas."
            ),
            None,
        )),
    };
    answer.unwrap_or_else(|refused| refused)
}

// ---------------------------------------------------------------- console pages

fn back(
    console: &Console,
    admin: &Admin,
    uri: &Uri,
    status: StatusCode,
    title: &str,
    text: &str,
) -> Response {
    let main = format!(
        "{}{}{}",
        html::head(&esc(title), "", ""),
        members::banner(&esc(text), true),
        html::link("Back to SCIM", "", "/console/scim", false)
    );
    console.page(status, admin, NAV, uri, &main)
}

fn shown_once(
    console: &Console,
    admin: &Admin,
    uri: &Uri,
    title: &str,
    lead: &str,
    value: &str,
) -> Response {
    let main = format!(
        r#"{}<span class="g-command g-command--value"><span class="g-command__text t-mono" id="shown-once">{}</span><button class="g-btn g-btn--quiet g-btn--sm t-small" type="button" data-copy="shown-once">{}Copy</button></span><div class="g-head__actions">{}</div>"#,
        html::head(&esc(title), lead, ""),
        esc(value),
        html::icon("copy"),
        html::link("Done", "", "/console/scim", false)
    );
    console.page(StatusCode::OK, admin, NAV, uri, &main)
}

async fn scim_page(
    State(console): State<Console>,
    Ext(scim): Ext<Scim>,
    headers: HeaderMap,
    uri: Uri,
    tls: Tls,
) -> Response {
    let Some(admin) = console.signed_in(&headers).await else {
        return redirect("/console/sign-in");
    };
    match scim_main(&scim, &admin, &members::origin(&headers, &tls)).await {
        Ok(main) => console.page(StatusCode::OK, &admin, NAV, &uri, &main),
        Err(err) => back(
            &console,
            &admin,
            &uri,
            StatusCode::SERVICE_UNAVAILABLE,
            "SCIM",
            &err,
        ),
    }
}

async fn scim_main(scim: &Scim, admin: &Admin, origin: &str) -> Result<String, String> {
    let me = Role::of(admin);
    let (owner, edit) = (me == Role::Owner, me != Role::Viewer);
    let client = scim.members.db.client().await?;
    let field = |row: &Row, i| row.try_get::<_, String>(i).map_err(members::db_error);
    let tokens = client
        .query(
            "SELECT token_sha256, name, created_by, to_char(created_at, 'YYYY-MM-DD'), \
             COALESCE(to_char(last_used, 'YYYY-MM-DD HH24:MI'), 'never') FROM enterprise_scim_tokens ORDER BY created_at",
            &[],
        )
        .await
        .map_err(members::db_error)?;
    let mut token_rows = String::new();
    for row in &tokens {
        let end = if owner {
            format!(
                r#"<form method="post" action="/console/scim/tokens/revoke">{}{}</form>"#,
                members::hidden("prefix", field(row, 0)?.get(..16).unwrap_or("")),
                members::small_button("Revoke token")
            )
        } else {
            String::new()
        };
        token_rows += &html::row(
            &esc(&field(row, 1)?),
            &format!(
                "made by {} on {}, last used {}",
                esc(&field(row, 2)?),
                esc(&field(row, 3)?),
                esc(&field(row, 4)?)
            ),
            &end,
            false,
        );
    }
    if tokens.is_empty() {
        token_rows = r#"<p class="t-body g-muted">No SCIM tokens.</p>"#.into();
    }
    let create = if owner {
        format!(
            r#"<form method="post" action="/console/scim/tokens" class="g-toolbar">{}{}</form>"#,
            members::text_field(
                "token-name",
                "name",
                "Name",
                "identity provider",
                " required",
                ""
            ),
            html::button("Create SCIM token", "", "submit", "")
        )
    } else {
        r#"<p class="t-small g-muted" style="margin: 0">Only an owner makes and revokes SCIM tokens.</p>"#.into()
    };
    let groups = client
        .query(
            "SELECT g.id, g.display_name, g.team, g.grants, (SELECT count(*) FROM enterprise_scim_group_members m WHERE m.group_id = g.id) \
             FROM enterprise_scim_groups g ORDER BY g.display_name",
            &[],
        )
        .await
        .map_err(members::db_error)?;
    let mut group_rows = String::new();
    for row in &groups {
        let grants = field(row, 3)?;
        let count: i64 = row.try_get(4).map_err(members::db_error)?;
        let end = if edit {
            let chosen = if grants == "admin" {
                Role::Admin
            } else {
                Role::Viewer
            };
            format!(
                r#"<form method="post" action="/console/scim/groups/role" class="g-toolbar">{}{}{}</form>"#,
                members::hidden("group_id", &field(row, 0)?),
                members::select("role", "Members are", &[Role::Viewer, Role::Admin], chosen),
                members::small_button("Save")
            )
        } else {
            String::new()
        };
        group_rows += &html::row(
            &esc(&field(row, 1)?),
            &format!(
                "team {}, {count} members, members are {}",
                esc(&field(row, 2)?),
                esc(&grants)
            ),
            &end,
            false,
        );
    }
    if groups.is_empty() {
        group_rows = r#"<p class="t-body g-muted">No groups pushed yet.</p>"#.into();
    }
    let waiting = client
        .query(
            "SELECT id, email, name FROM enterprise_people WHERE password_hash = '!' ORDER BY email",
            &[],
        )
        .await
        .map_err(members::db_error)?;
    drop(client);
    let mut waiting_rows = String::new();
    for row in &waiting {
        let end = if edit {
            format!(
                r#"<form method="post" action="/console/scim/password-link">{}{}</form>"#,
                members::hidden("user_id", &field(row, 0)?),
                members::small_button("Create password link")
            )
        } else {
            String::new()
        };
        waiting_rows += &html::row(&esc(&field(row, 2)?), &esc(&field(row, 1)?), &end, false);
    }
    if waiting.is_empty() {
        waiting_rows = r#"<p class="t-body g-muted">Everyone has a password or signs in with single sign-on.</p>"#.into();
    }
    Ok(format!(
        r#"{}<section class="g-section g-stack"><h2 class="t-md" style="margin: 0">Connect your identity provider</h2><p class="t-body" style="margin: 0">SCIM base URL:</p><span class="g-command g-command--value"><span class="g-command__text t-mono" id="scim-base">{}</span><button class="g-btn g-btn--quiet g-btn--sm t-small" type="button" data-copy="scim-base">{}Copy</button></span></section><section class="g-section g-stack"><h2 class="t-md" style="margin: 0">SCIM tokens</h2><section class="g-list">{token_rows}</section>{create}</section><section class="g-section g-stack"><h2 class="t-md" style="margin: 0">Groups</h2><p class="t-small g-muted" style="margin: 0">Each group is a team. Members of an admin group are admins; others are viewers. Owners keep their role.</p><section class="g-list">{group_rows}</section></section><section class="g-section g-stack"><h2 class="t-md" style="margin: 0">Waiting for a password</h2><p class="t-small g-muted" style="margin: 0">People SCIM made have no password. Send them a one-time link, valid for {LINK_DAYS} days, or let them use single sign-on.</p><section class="g-list">{waiting_rows}</section></section>"#,
        html::head(
            "SCIM provisioning",
            "Your identity provider adds, changes and removes people here, and its groups become teams. Deactivating someone there removes them here and revokes their keys at once.",
            ""
        ),
        esc(&format!("{origin}{PATH}")),
        html::icon("copy"),
    ))
}

async fn create_token(
    State(console): State<Console>,
    Ext(scim): Ext<Scim>,
    headers: HeaderMap,
    uri: Uri,
    tls: Tls,
    body: String,
) -> Response {
    let (admin, me) = match members::editor(&console, &headers, &uri, "scim_token_created").await {
        Ok(who) => who,
        Err(answer) => return answer,
    };
    let refuse = |status, text: &str| back(&console, &admin, &uri, status, "SCIM token", text);
    if me != Role::Owner {
        let _ = console
            .audit(
                Some(&admin),
                "scim_token_created",
                json!({}),
                Some("owner_only"),
            )
            .await;
        return refuse(
            StatusCode::FORBIDDEN,
            "Only an owner can create a SCIM token.",
        );
    }
    let form = Form::parse(&body);
    let name: String = match form.get("name").trim() {
        "" => "identity provider".into(),
        name => name.chars().take(64).collect(),
    };
    let token = match members::random_hex(32) {
        Ok(hex) => format!("gscim_{hex}"),
        Err(err) => return refuse(StatusCode::SERVICE_UNAVAILABLE, &err),
    };
    if let Err(err) = console
        .audit(
            Some(&admin),
            "scim_token_created",
            json!({ "name": name }),
            None,
        )
        .await
    {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, err);
    }
    let made = async {
        let client = scim.members.db.client().await?;
        client
            .execute(
                "INSERT INTO enterprise_scim_tokens (token_sha256, name, created_by) VALUES ($1, $2, $3)",
                &[&gantry_core::id::sha256_hex(token.as_bytes()), &name, &admin.name],
            )
            .await
            .map_err(members::db_error)
    };
    if let Err(err) = made.await {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, &err);
    }
    shown_once(
        &console,
        &admin,
        &uri,
        "SCIM token created",
        &format!(
            "Paste it into your identity provider now, with the base URL {}. Gantry keeps only its hash and cannot show it again.",
            esc(&format!("{}{PATH}", members::origin(&headers, &tls)))
        ),
        &token,
    )
}

async fn revoke_token(
    State(console): State<Console>,
    Ext(scim): Ext<Scim>,
    headers: HeaderMap,
    uri: Uri,
    body: String,
) -> Response {
    let (admin, me) = match members::editor(&console, &headers, &uri, "scim_token_revoked").await {
        Ok(who) => who,
        Err(answer) => return answer,
    };
    let refuse = |status, text: &str| back(&console, &admin, &uri, status, "SCIM token", text);
    if me != Role::Owner {
        let _ = console
            .audit(
                Some(&admin),
                "scim_token_revoked",
                json!({}),
                Some("owner_only"),
            )
            .await;
        return refuse(
            StatusCode::FORBIDDEN,
            "Only an owner can revoke a SCIM token.",
        );
    }
    let prefix = Form::parse(&body).get("prefix").trim().to_string();
    if prefix.len() != 16
        || !prefix
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return refuse(StatusCode::OK, "That SCIM token is not known.");
    }
    if let Err(err) = console
        .audit(
            Some(&admin),
            "scim_token_revoked",
            json!({ "prefix": prefix.get(..8) }),
            None,
        )
        .await
    {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, err);
    }
    let gone = async {
        let client = scim.members.db.client().await?;
        client
            .execute(
                "DELETE FROM enterprise_scim_tokens WHERE left(token_sha256, 16) = $1",
                &[&prefix],
            )
            .await
            .map_err(members::db_error)
    };
    match gone.await {
        Err(err) => refuse(StatusCode::SERVICE_UNAVAILABLE, &err),
        Ok(_) => redirect("/console/scim"),
    }
}

async fn group_role(
    State(console): State<Console>,
    Ext(scim): Ext<Scim>,
    headers: HeaderMap,
    uri: Uri,
    body: String,
) -> Response {
    let (admin, _) =
        match members::editor(&console, &headers, &uri, "scim_group_role_changed").await {
            Ok(who) => who,
            Err(answer) => return answer,
        };
    let refuse = |status, text: &str| back(&console, &admin, &uri, status, "Group role", text);
    let form = Form::parse(&body);
    let (id, role) = (form.get("group_id").to_string(), form.get("role"));
    if !matches!(role, "admin" | "viewer") {
        return refuse(StatusCode::OK, "Members of a group are admins or viewers.");
    }
    let name = async {
        let client = scim.members.db.client().await?;
        client
            .query_opt(
                "SELECT display_name FROM enterprise_scim_groups WHERE id = $1",
                &[&id],
            )
            .await
            .map_err(members::db_error)?
            .map(|r| r.try_get::<_, String>(0).map_err(members::db_error))
            .transpose()
    };
    let name = match name.await {
        Err(err) => return refuse(StatusCode::SERVICE_UNAVAILABLE, &err),
        Ok(None) => {
            return refuse(
                StatusCode::OK,
                "That group is not known. It may have been deleted.",
            );
        }
        Ok(Some(name)) => name,
    };
    if let Err(err) = console
        .audit(
            Some(&admin),
            "scim_group_role_changed",
            json!({ "group": name, "role": role }),
            None,
        )
        .await
    {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, err);
    }
    let changed = async {
        let mut client = scim.members.db.client().await?;
        let tx = client.transaction().await.map_err(members::db_error)?;
        tx.execute(
            "UPDATE enterprise_scim_groups SET grants = $2, updated_at = now() WHERE id = $1",
            &[&id, &role],
        )
        .await
        .map_err(members::db_error)?;
        let people: Vec<String> = tx
            .query(
                "SELECT person_id FROM enterprise_scim_group_members WHERE group_id = $1",
                &[&id],
            )
            .await
            .map_err(members::db_error)?
            .iter()
            .filter_map(|r| r.try_get(0).ok())
            .collect();
        follow_groups(&tx, &people).await?;
        tx.commit().await.map_err(members::db_error)
    };
    match changed.await {
        Err(err) => refuse(StatusCode::SERVICE_UNAVAILABLE, &err),
        Ok(()) => redirect("/console/scim"),
    }
}

async fn password_link(
    State(console): State<Console>,
    Ext(scim): Ext<Scim>,
    headers: HeaderMap,
    uri: Uri,
    tls: Tls,
    body: String,
) -> Response {
    let (admin, me) = match members::editor(&console, &headers, &uri, "password_link_created").await
    {
        Ok(who) => who,
        Err(answer) => return answer,
    };
    let refuse = |status, text: &str| back(&console, &admin, &uri, status, "No link created", text);
    let id = Form::parse(&body).get("user_id").to_string();
    let found = async {
        let client = scim.members.db.client().await?;
        let row = client
            .query_opt(
                "SELECT email, role, password_hash = '!' FROM enterprise_people WHERE id = $1",
                &[&id],
            )
            .await
            .map_err(members::db_error)?;
        row.map(|r| {
            Ok::<_, String>((
                r.try_get::<_, String>(0).map_err(members::db_error)?,
                r.try_get::<_, String>(1).map_err(members::db_error)?,
                r.try_get::<_, bool>(2).map_err(members::db_error)?,
            ))
        })
        .transpose()
    };
    let (email, role, no_password) = match found.await {
        Err(err) => return refuse(StatusCode::SERVICE_UNAVAILABLE, &err),
        Ok(None) => return refuse(StatusCode::OK, "That person is not a member."),
        Ok(Some(found)) => found,
    };
    if !no_password {
        return refuse(
            StatusCode::OK,
            "This person already has a password. They sign in with it, or an owner removes and provisions them again.",
        );
    }
    if role == "owner" && me != Role::Owner {
        return refuse(StatusCode::OK, "Only an owner can do this for an owner.");
    }
    let token = match members::random_hex(32) {
        Ok(token) => token,
        Err(err) => return refuse(StatusCode::SERVICE_UNAVAILABLE, &err),
    };
    if let Err(err) = console
        .audit(
            Some(&admin),
            "password_link_created",
            json!({ "for": email }),
            None,
        )
        .await
    {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, err);
    }
    let made = async {
        let client = scim.members.db.client().await?;
        client
            .execute(
                "INSERT INTO enterprise_password_links (token_sha256, person_id, created_by, expires_at) \
                 VALUES ($1, $2, $3, now() + make_interval(days => $4))",
                &[&gantry_core::id::sha256_hex(token.as_bytes()), &id, &admin.name, &LINK_DAYS],
            )
            .await
            .map_err(members::db_error)
    };
    if let Err(err) = made.await {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, &err);
    }
    shown_once(
        &console,
        &admin,
        &uri,
        "Password link created",
        &format!(
            "Send this link to {} yourself. It works once, for {LINK_DAYS} days.",
            esc(&email)
        ),
        &format!(
            "{}/console/set-password/{token}",
            members::origin(&headers, &tls)
        ),
    )
}

fn link_gone() -> Response {
    bare_page(
        StatusCode::GONE,
        "Link not valid",
        r#"<h1 class="t-lg" style="margin: 0">Link not valid</h1><p class="t-lead g-muted" style="margin: 0">This link was used, has expired or is not known. Ask your admin for a new one.</p>"#,
    )
}

/// The person a password link is for, while it can still be used: unused, not expired, and no password set yet.
async fn link_person(scim: &Scim, token: &str) -> Result<Option<(String, String)>, String> {
    let client = scim.members.db.client().await?;
    let row = client
        .query_opt(
            "SELECT p.id, p.email FROM enterprise_password_links l JOIN enterprise_people p ON p.id = l.person_id \
             WHERE l.token_sha256 = $1 AND l.used_at IS NULL AND l.expires_at > now() AND p.password_hash = '!'",
            &[&gantry_core::id::sha256_hex(token.as_bytes())],
        )
        .await
        .map_err(members::db_error)?;
    row.map(|r| {
        Ok((
            r.try_get(0).map_err(members::db_error)?,
            r.try_get(1).map_err(members::db_error)?,
        ))
    })
    .transpose()
}

fn set_password_form(token: &str, email: &str, error: &str) -> Response {
    let banner = if error.is_empty() {
        String::new()
    } else {
        members::banner(&esc(error), true)
    };
    bare_page(
        if error.is_empty() {
            StatusCode::OK
        } else {
            StatusCode::BAD_REQUEST
        },
        "Set your password",
        &format!(
            r#"{}{banner}<form method="post" action="/console/set-password/{}" class="g-stack">{}<div class="g-head__actions">{}</div></form>"#,
            html::head("Set your password", &format!("For {}.", esc(email)), ""),
            esc(token),
            members::text_field(
                "password",
                "password",
                "New password",
                "",
                r#" type="password" required autocomplete="new-password""#,
                "At least 12 characters."
            ),
            html::button("Set password", "", "submit", "")
        ),
    )
}

async fn set_password_page(Ext(scim): Ext<Scim>, Path(token): Path<String>) -> Response {
    match link_person(&scim, &token).await {
        Ok(Some((_, email))) => set_password_form(&token, &email, ""),
        Ok(None) => link_gone(),
        Err(err) => bare_page(
            StatusCode::SERVICE_UNAVAILABLE,
            "Link not checked",
            &esc(&err),
        ),
    }
}

async fn set_password(
    State(console): State<Console>,
    Ext(scim): Ext<Scim>,
    Path(token): Path<String>,
    headers: HeaderMap,
    uri: Uri,
    tls: Tls,
    body: String,
) -> Response {
    if !same_origin(&headers) {
        return foreign();
    }
    let (id, email) = match link_person(&scim, &token).await {
        Ok(Some(found)) => found,
        Ok(None) => return link_gone(),
        Err(err) => {
            return bare_page(
                StatusCode::SERVICE_UNAVAILABLE,
                "Link not checked",
                &esc(&err),
            );
        }
    };
    let password = Form::parse(&body).get("password").to_string();
    if password.chars().count() < members::MIN_PASSWORD {
        return set_password_form(&token, &email, "The password needs at least 12 characters.");
    }
    let hashed = tokio::task::spawn_blocking(move || members::hash_password(&password))
        .await
        .unwrap_or_else(|err| Err(err.to_string()));
    let (salt, hash) = match hashed {
        Ok(hashed) => hashed,
        Err(err) => return set_password_form(&token, &email, &err),
    };
    let Some(who) = scim.members.account(&id).await else {
        return link_gone();
    };
    if let Err(err) = console
        .audit(
            Some(&who),
            "password_set_by_link",
            json!({ "email": email }),
            None,
        )
        .await
    {
        return set_password_form(&token, &email, err);
    }
    // The link is marked used and the password set together: of two submissions at once only one passes, and only
    // while the person still has no password.
    let set = async {
        let mut client = scim.members.db.client().await?;
        let tx = client.transaction().await.map_err(members::db_error)?;
        let used = tx
            .execute(
                "UPDATE enterprise_password_links SET used_at = now() WHERE token_sha256 = $1 AND used_at IS NULL AND expires_at > now()",
                &[&gantry_core::id::sha256_hex(token.as_bytes())],
            )
            .await
            .map_err(members::db_error)?;
        let changed = tx
            .execute(
                "UPDATE enterprise_people SET password_salt = $2, password_hash = $3 WHERE id = $1 AND password_hash = '!'",
                &[&id, &salt, &hash],
            )
            .await
            .map_err(members::db_error)?;
        if used != 1 || changed != 1 {
            return Ok(false);
        }
        tx.commit().await.map_err(members::db_error)?;
        Ok::<_, String>(true)
    };
    match set.await {
        Err(err) => set_password_form(&token, &email, &err),
        Ok(false) => link_gone(),
        Ok(true) => {
            console
                .sign_in_account(&id, &who, &headers, &uri, &tls)
                .await
        }
    }
}

#[cfg(test)]
mod tests;
