//! People with roles in the console (license feature `members`), ported from the Cloudflare app
//! (cloud/control-plane/src/app/members.ts, account.ts). An owner or admin invites a person by a one-time link; the
//! person sets a name and password there and is signed in. People sign in with email and password beside admin keys
//! and single sign-on. Removing a person revokes every key named with their email, at once.
//!
//! Roles: an owner may do everything; an admin everything but make, change or remove an owner; a viewer looks.
//! An admin key is the install's root credential, so its sessions act as an owner; single sign-on acts as admin, or
//! viewer when read only. The last owner can be neither removed nor demoted.
//!
//! SCIM provisioning and the password links for people SCIM makes are in `scim.rs`, on these tables.

use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    Extension as Ext,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, Uri, header},
    response::Response,
    routing::{get, post},
};
use gantry_console::{
    Admin, Console, Form, Tls, Via, bare_page, foreign,
    html::{self, Field, esc},
    redirect, same_origin,
};
use gantry_server::store::tokio_postgres::{self, Row};
use serde_json::json;

use super::Db;
use crate::license::Status;

pub const FEATURE: &str = "members";

pub const MIGRATION: &str = "
CREATE TABLE enterprise_people (
    id text PRIMARY KEY,
    email text NOT NULL UNIQUE,
    name text NOT NULL,
    password_salt text NOT NULL,
    password_hash text NOT NULL,
    role text NOT NULL CHECK (role IN ('owner', 'admin', 'viewer')),
    team text NOT NULL DEFAULT 'default',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE enterprise_invites (
    token_sha256 text PRIMARY KEY,
    email text NOT NULL,
    role text NOT NULL CHECK (role IN ('admin', 'viewer')),
    team text NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    accepted_at timestamptz
);
";

const NAV: &str = "Members";
const INVITE_DAYS: i32 = 7;
pub(super) const MIN_PASSWORD: usize = 12;
/// PBKDF2-SHA256 at 100,000 iterations with a 16-byte salt per person, as the Cloudflare app hashes, so its
/// accounts carry over with their passwords.
const ITERATIONS: u32 = 100_000;
const LAST_OWNER: &str = "This is the last owner. Make another member an owner first.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Role {
    Owner,
    Admin,
    Viewer,
}

impl Role {
    pub(super) fn parse(word: &str) -> Option<Self> {
        match word {
            "owner" => Some(Self::Owner),
            "admin" => Some(Self::Admin),
            "viewer" => Some(Self::Viewer),
            _ => None,
        }
    }

    pub(super) fn word(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Viewer => "viewer",
        }
    }

    /// The role of whoever is signed in, however they signed in.
    pub(super) fn of(admin: &Admin) -> Self {
        match &admin.via {
            Via::Key => Self::Owner,
            Via::Sso if admin.read_only => Self::Viewer,
            Via::Sso => Self::Admin,
            Via::Account(_) => Self::parse(&admin.role).unwrap_or(Self::Viewer),
        }
    }
}

#[derive(Clone)]
pub(super) struct Members {
    pub(super) db: Arc<Db>,
    /// The keys file's path: keys are read and revoked through it, from the store.
    pub(super) keys: PathBuf,
}

/// Adds the members pages, the invite links, password sign-in and the accounts it opens to the console.
pub fn register(extension: &mut gantry_server::Extension, db: Arc<Db>, keys: PathBuf) {
    let members = Members { db, keys };
    let check = members.clone();
    let console = &mut extension.console;
    console.nav.push(("/console/members".into(), NAV.into()));
    console.sign_in = Some((
        "/console/sign-in/password".into(),
        "Sign in with email and password".into(),
    ));
    console.accounts = Some(Arc::new(move |id: String| {
        let members = check.clone();
        Box::pin(async move { members.account(&id).await })
    }));
    console.routes = std::mem::take(&mut console.routes)
        .route("/members", get(members_page))
        .route("/members/invite", post(invite))
        .route("/members/invite/revoke", post(revoke_invite))
        .route("/members/role", post(change_role))
        .route("/members/remove", post(remove))
        .route("/invite/{token}", get(invite_page).post(accept))
        .route("/sign-in/password", get(sign_in_page).post(sign_in))
        .layer(Ext(members));
}

/// Without the feature, its addresses say why instead of not existing: a bookmark or an old invite link explains
/// itself. There is no nav entry and no password sign-in.
pub fn locked(extension: &mut gantry_server::Extension, status: &Status) {
    let Err(refused) = status.require(FEATURE) else {
        return;
    };
    let (code, message) = (refused.code, refused.message);
    let answer = move || {
        let message = message.clone();
        async move {
            bare_page(
                StatusCode::FORBIDDEN,
                "Members need a license",
                &format!(
                    r#"<h1 class="t-lg" style="margin: 0">Members need a license</h1><p class="t-lead g-muted" style="margin: 0">{}</p><p class="t-small g-muted" style="margin: 0">Code: {}</p>"#,
                    esc(&message),
                    code
                ),
            )
        }
    };
    let console = &mut extension.console;
    console.routes = std::mem::take(&mut console.routes)
        .route("/members", get(answer.clone()))
        .route("/invite/{token}", get(answer.clone()))
        .route("/sign-in/password", get(answer));
}

// ---------------------------------------------------------------- passwords

pub(super) fn random_hex(bytes: usize) -> Result<String, String> {
    use ring::rand::SecureRandom;
    let mut out = vec![0u8; bytes];
    ring::rand::SystemRandom::new()
        .fill(&mut out)
        .map_err(|_| "The system gave no randomness. Try again in a moment.".to_string())?;
    Ok(gantry_core::id::hex(&out))
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

fn derive(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::MIN.saturating_add(ITERATIONS - 1),
        salt,
        password.as_bytes(),
        &mut out,
    );
    out
}

/// A new salt and the hash of `password` under it, both hex, as the Cloudflare app keeps them.
pub(super) fn hash_password(password: &str) -> Result<(String, String), String> {
    let salt = random_hex(16)?;
    let bytes = unhex(&salt).ok_or("the salt did not read back")?;
    Ok((salt, gantry_core::id::hex(&derive(password, &bytes))))
}

/// Whether `password` hashes to `hash` under `salt`, in constant time. A hash that is not hex (`!`: no password
/// set) matches nothing, after the same work.
fn password_matches(password: &str, salt: &str, hash: &str) -> bool {
    let salt = unhex(salt).unwrap_or_else(|| vec![0; 16]);
    let wanted = unhex(hash).unwrap_or_default();
    ring::pbkdf2::verify(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::MIN.saturating_add(ITERATIONS - 1),
        &salt,
        password.as_bytes(),
        &wanted,
    )
    .is_ok()
}

pub(super) fn valid_email(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.contains('@')
        && domain
            .split_once('.')
            .is_some_and(|(a, b)| !a.is_empty() && !b.is_empty())
        && !email.chars().any(char::is_whitespace)
}

pub(super) fn valid_team(team: &str) -> bool {
    (1..=64).contains(&team.len())
        && team
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

// ---------------------------------------------------------------- the tables

struct Person {
    id: String,
    email: String,
    name: String,
    role: Role,
    team: String,
    joined: String,
}

fn person(row: &Row) -> Result<Person, tokio_postgres::Error> {
    let role: String = row.try_get("role")?;
    Ok(Person {
        id: row.try_get("id")?,
        email: row.try_get("email")?,
        name: row.try_get("name")?,
        role: Role::parse(&role).unwrap_or(Role::Viewer),
        team: row.try_get("team")?,
        joined: row.try_get("joined")?,
    })
}

const PERSON: &str = "SELECT id, email, name, role, team, to_char(created_at, 'YYYY-MM-DD') AS joined FROM enterprise_people";

pub(super) fn db_error(err: impl std::fmt::Display) -> String {
    format!(
        "The members tables could not be read or written: {err}. Check that Postgres is up and the store's connection string is right, then try again. Nothing was changed."
    )
}

impl Members {
    /// Who the account `id` is now, for its console session. `None` when removed, or when the database cannot say:
    /// a session the database cannot vouch for ends.
    pub(super) async fn account(&self, id: &str) -> Option<Admin> {
        let client = self.db.client().await.ok()?;
        let row = client
            .query_opt(&format!("{PERSON} WHERE id = $1"), &[&id])
            .await
            .ok()??;
        let p = person(&row).ok()?;
        // A viewer has the open source read_only role's permissions, an owner or admin every one.
        Some(Admin {
            role: p.role.word().into(),
            ..Admin::of_role(
                &p.email,
                &p.team,
                p.role == Role::Viewer,
                Via::Account(p.id),
            )
        })
    }

    async fn people(&self) -> Result<Vec<Person>, String> {
        let client = self.db.client().await?;
        let rows = client
            .query(&format!("{PERSON} ORDER BY name, email"), &[])
            .await
            .map_err(db_error)?;
        rows.iter()
            .map(person)
            .collect::<Result<_, _>>()
            .map_err(db_error)
    }

    async fn member(&self, id: &str) -> Result<Option<Person>, String> {
        let client = self.db.client().await?;
        let row = client
            .query_opt(&format!("{PERSON} WHERE id = $1"), &[&id])
            .await
            .map_err(db_error)?;
        row.as_ref().map(person).transpose().map_err(db_error)
    }

    /// Changes a role and team, or removes the person (`to` is `None`), unless that leaves no owner. The owners are
    /// locked for the check, so two changes at once cannot both take the last one away.
    pub(super) async fn change(
        &self,
        id: &str,
        to: Option<(Role, &str)>,
    ) -> Result<Result<(), &'static str>, String> {
        let mut client = self.db.client().await?;
        let tx = client.transaction().await.map_err(db_error)?;
        let owners = tx
            .query(
                "SELECT id FROM enterprise_people WHERE role = 'owner' FOR UPDATE",
                &[],
            )
            .await
            .map_err(db_error)?;
        let is_owner = owners
            .iter()
            .any(|r| r.try_get::<_, &str>(0).is_ok_and(|o| o == id));
        let stays_owner = matches!(to, Some((Role::Owner, _)));
        if is_owner && !stays_owner && owners.len() <= 1 {
            return Ok(Err(LAST_OWNER));
        }
        match to {
            Some((role, team)) => tx
                .execute(
                    "UPDATE enterprise_people SET role = $2, team = $3 WHERE id = $1",
                    &[&id, &role.word(), &team],
                )
                .await
                .map_err(db_error)?,
            None => tx
                .execute("DELETE FROM enterprise_people WHERE id = $1", &[&id])
                .await
                .map_err(db_error)?,
        };
        tx.commit().await.map_err(db_error)?;
        Ok(Ok(()))
    }

    /// Hashes of the keys named with `email`, in any case: the person's keys.
    pub(super) fn keys_of(&self, email: &str) -> Result<Vec<String>, String> {
        let text = gantry_core::config::read_keys(&self.keys)?.unwrap_or_default();
        let entries = gantry_core::config::key_entries(&self.keys, &text)
            .map_err(|errors| errors.join("; "))?;
        Ok(entries
            .into_iter()
            .filter(|e| e.name.eq_ignore_ascii_case(email))
            .map(|e| e.sha256)
            .collect())
    }

    /// Revokes the keys with these hashes through the store, which every gateway reads within a second.
    pub(super) async fn revoke(&self, keys: Vec<String>) -> Result<(), String> {
        let path = self.keys.clone();
        tokio::task::spawn_blocking(move || {
            keys.iter()
                .try_for_each(|sha| gantry_core::keyfile::revoke(&path, sha).map(|_| ()))
        })
        .await
        .unwrap_or_else(|err| Err(err.to_string()))
    }
}

// ---------------------------------------------------------------- pages

/// A Banner, read out when the page opens. `text` is markup.
pub(super) fn banner(text: &str, error: bool) -> String {
    let edge = if error {
        r#" style="border-color: var(--flame)""#
    } else {
        ""
    };
    format!(r#"<div class="g-banner" role="alert"{edge}><span class="t-body">{text}</span></div>"#)
}

pub(super) fn select(name: &str, label: &str, options: &[Role], chosen: Role) -> String {
    let options: String = options
        .iter()
        .map(|r| {
            format!(
                r#"<option value="{0}"{1}>{0}</option>"#,
                r.word(),
                if *r == chosen { " selected" } else { "" }
            )
        })
        .collect();
    format!(
        r#"<div class="g-select-wrap"><select class="g-input g-select t-body" name="{name}" aria-label="{label}">{options}</select>{}</div>"#,
        html::icon("down")
    )
}

pub(super) fn hidden(name: &str, value: &str) -> String {
    format!(
        r#"<input type="hidden" name="{name}" value="{}">"#,
        esc(value)
    )
}

pub(super) fn small_button(label: &str) -> String {
    format!(
        r#"<button class="g-btn g-btn--quiet g-btn--sm t-small" type="submit">{label}</button>"#
    )
}

pub(super) fn text_field(
    id: &str,
    name: &str,
    label: &str,
    value: &str,
    extra: &str,
    hint: &str,
) -> String {
    html::field(&Field {
        id,
        name,
        label,
        value,
        mono: false,
        extra,
        hint,
        error: "",
    })
}

/// A short page under the console's nav: a title, an error, and the way back to the members list.
fn back(
    console: &Console,
    admin: &Admin,
    uri: &Uri,
    status: StatusCode,
    title: &str,
    error: &str,
) -> Response {
    let main = format!(
        "{}{}{}",
        html::head(&esc(title), "", ""),
        banner(&esc(error), true),
        html::link("Back to members", "", "/console/members", false)
    );
    console.page(status, admin, NAV, uri, &main)
}

fn unavailable(console: &Console, admin: &Admin, uri: &Uri, err: &str) -> Response {
    back(
        console,
        admin,
        uri,
        StatusCode::SERVICE_UNAVAILABLE,
        "Members",
        err,
    )
}

/// Who may change things, signed in, or the answer to give instead.
pub(super) async fn editor(
    console: &Console,
    headers: &HeaderMap,
    uri: &Uri,
    action: &'static str,
) -> Result<(Admin, Role), Response> {
    if !same_origin(headers) {
        return Err(foreign());
    }
    let Some(admin) = console.signed_in(headers).await else {
        return Err(redirect("/console/sign-in"));
    };
    let role = Role::of(&admin);
    if role == Role::Viewer {
        let _ = console
            .audit(
                Some(&admin),
                action,
                json!({ "reason": "viewer" }),
                Some("read_only"),
            )
            .await;
        return Err(back(
            console,
            &admin,
            uri,
            StatusCode::FORBIDDEN,
            "Read only",
            "Your role is viewer. An owner or admin can make this change.",
        ));
    }
    Ok((admin, role))
}

async fn members_page(
    State(console): State<Console>,
    Ext(members): Ext<Members>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let Some(admin) = console.signed_in(&headers).await else {
        return redirect("/console/sign-in");
    };
    match members_main(&members, &admin, "").await {
        Ok(main) => console.page(StatusCode::OK, &admin, NAV, &uri, &main),
        Err(err) => unavailable(&console, &admin, &uri, &err),
    }
}

async fn members_main(members: &Members, admin: &Admin, notice: &str) -> Result<String, String> {
    let me = Role::of(admin);
    let edit = me != Role::Viewer;
    let options: &[Role] = if me == Role::Owner {
        &[Role::Owner, Role::Admin, Role::Viewer]
    } else {
        &[Role::Admin, Role::Viewer]
    };
    let people = members.people().await?;
    let mut list = String::new();
    for p in &people {
        let touch = edit && (me == Role::Owner || p.role != Role::Owner);
        let meta = format!(
            "{}, {}, team {}, joined {}",
            esc(&p.email),
            p.role.word(),
            esc(&p.team),
            esc(&p.joined)
        );
        let end = if touch {
            format!(
                r#"<form method="post" action="/console/members/role" class="g-toolbar">{}{}{}{}</form><form method="post" action="/console/members/remove">{}{}</form>"#,
                hidden("user_id", &p.id),
                select("role", "Role", options, p.role),
                text_field(
                    &format!("team-{}", p.id),
                    "team",
                    "Team",
                    &p.team,
                    " required",
                    ""
                ),
                small_button("Save role"),
                hidden("user_id", &p.id),
                small_button("Remove member")
            )
        } else {
            String::new()
        };
        list += &html::row(&esc(&p.name), &meta, &end, false);
    }
    if people.is_empty() {
        list = html::empty(
            "",
            "No members yet",
            "Invite someone below. Admin keys and single sign-on still sign in as before.",
            "",
        );
    }
    let client = members.db.client().await?;
    let invites = client
        .query(
            "SELECT token_sha256, email, role, team, to_char(expires_at, 'YYYY-MM-DD') FROM enterprise_invites \
             WHERE accepted_at IS NULL AND expires_at > now() ORDER BY created_at DESC",
            &[],
        )
        .await
        .map_err(db_error)?;
    drop(client);
    let mut pending = String::new();
    for row in &invites {
        let field = |i| row.try_get::<_, String>(i).map_err(db_error);
        let (hash, email, role, team, expires) =
            (field(0)?, field(1)?, field(2)?, field(3)?, field(4)?);
        let end = if edit {
            format!(
                r#"<form method="post" action="/console/members/invite/revoke">{}{}</form>"#,
                hidden("prefix", hash.get(..16).unwrap_or("")),
                small_button("Revoke invite")
            )
        } else {
            String::new()
        };
        pending += &html::row(
            &esc(&email),
            &format!(
                "{}, team {}, expires {}",
                esc(&role),
                esc(&team),
                esc(&expires)
            ),
            &end,
            true,
        );
    }
    if invites.is_empty() {
        pending = r#"<p class="t-body g-muted">No pending invites.</p>"#.into();
    }
    let invite = if edit {
        format!(
            r#"<section class="g-section g-stack"><h2 class="t-md" style="margin: 0">Invite a member</h2><form method="post" action="/console/members/invite" class="g-stack"><div class="g-toolbar">{}{}{}</div><div class="g-head__actions">{}</div><p class="t-small g-muted" style="margin: 0">Gantry does not send email. You get a link valid for {INVITE_DAYS} days to send them yourself.</p></form></section>"#,
            text_field(
                "invite-email",
                "email",
                "Email",
                "",
                r#" type="email" required"#,
                ""
            ),
            select("role", "Role", &[Role::Viewer, Role::Admin], Role::Viewer),
            text_field("invite-team", "team", "Team", "default", " required", ""),
            html::button("Create invite", "", "submit", "")
        )
    } else {
        String::new()
    };
    Ok(format!(
        r#"{}{notice}<section class="g-list">{list}</section>{invite}<section class="g-section g-stack"><h2 class="t-md" style="margin: 0">Pending invites</h2>{pending}</section>"#,
        html::head(
            "Members",
            "People who sign in to this console and what they may change. Removing someone revokes their keys at once.",
            ""
        )
    ))
}

/// The address the browser reached the console at, for a link to send to someone.
pub(super) fn origin(headers: &HeaderMap, tls: &Tls) -> String {
    let https = tls.is_some()
        || headers
            .get("x-forwarded-proto")
            .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"https"));
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    format!("{}://{host}", if https { "https" } else { "http" })
}

async fn invite(
    State(console): State<Console>,
    Ext(members): Ext<Members>,
    headers: HeaderMap,
    uri: Uri,
    tls: Tls,
    body: String,
) -> Response {
    let (admin, _) = match editor(&console, &headers, &uri, "invite_created").await {
        Ok(who) => who,
        Err(answer) => return answer,
    };
    let form = Form::parse(&body);
    let email = form.get("email").trim().to_lowercase();
    let team = match form.get("team").trim() {
        "" => "default".to_string(),
        team => team.to_string(),
    };
    let role = match form.get("role") {
        "admin" => Role::Admin,
        "viewer" => Role::Viewer,
        _ => {
            return back(
                &console,
                &admin,
                &uri,
                StatusCode::OK,
                "Invite a member",
                "An invite is for the admin or viewer role. Make someone an owner after they join.",
            );
        }
    };
    let refuse = |error: &str| {
        back(
            &console,
            &admin,
            &uri,
            StatusCode::OK,
            "Invite a member",
            error,
        )
    };
    if !valid_email(&email) {
        return refuse("Enter a valid email address.");
    }
    if !valid_team(&team) {
        return refuse("A team is letters, digits, dots, _ or -.");
    }
    let token = match random_hex(24) {
        Ok(token) => token,
        Err(err) => return refuse(&err),
    };
    let created = async {
        let client = members.db.client().await?;
        let exists = client
            .query_opt(
                "SELECT 1 FROM enterprise_people WHERE email = $1",
                &[&email],
            )
            .await
            .map_err(db_error)?;
        if exists.is_some() {
            return Ok(false);
        }
        client
            .execute(
                "INSERT INTO enterprise_invites (token_sha256, email, role, team, created_by, expires_at) \
                 VALUES ($1, $2, $3, $4, $5, now() + make_interval(days => $6))",
                &[
                    &gantry_core::id::sha256_hex(token.as_bytes()),
                    &email,
                    &role.word(),
                    &team,
                    &admin.name,
                    &INVITE_DAYS,
                ],
            )
            .await
            .map_err(db_error)?;
        Ok::<_, String>(true)
    };
    // Recorded before the invite exists: the console does not act on what it cannot record.
    if let Err(err) = console
        .audit(
            Some(&admin),
            "invite_created",
            json!({ "email": email, "role": role.word(), "team": team }),
            None,
        )
        .await
    {
        return refuse(err);
    }
    match created.await {
        Err(err) => unavailable(&console, &admin, &uri, &err),
        Ok(false) => refuse(&format!(
            "{email} is already a member. Change their role in the list instead."
        )),
        Ok(true) => {
            let link = format!("{}/console/invite/{token}", origin(&headers, &tls));
            let main = format!(
                r#"{}<span class="g-command g-command--value"><span class="g-command__text t-mono" id="invite-link">{}</span><button class="g-btn g-btn--quiet g-btn--sm t-small" type="button" data-copy="invite-link">{}Copy</button></span><div class="g-head__actions">{}</div>"#,
                html::head(
                    "Invite created",
                    &format!(
                        "For {} as {}, team {}. Send them this link yourself. It is shown once and works for {INVITE_DAYS} days.",
                        esc(&email),
                        role.word(),
                        esc(&team)
                    ),
                    ""
                ),
                esc(&link),
                html::icon("copy"),
                html::link("Done", "", "/console/members", false)
            );
            console.page(StatusCode::OK, &admin, NAV, &uri, &main)
        }
    }
}

async fn revoke_invite(
    State(console): State<Console>,
    Ext(members): Ext<Members>,
    headers: HeaderMap,
    uri: Uri,
    body: String,
) -> Response {
    let (admin, _) = match editor(&console, &headers, &uri, "invite_revoked").await {
        Ok(who) => who,
        Err(answer) => return answer,
    };
    let form = Form::parse(&body);
    let prefix = form.get("prefix").trim().to_string();
    if prefix.len() != 16
        || !prefix
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return back(
            &console,
            &admin,
            &uri,
            StatusCode::OK,
            "Invite not revoked",
            "That invite is not known.",
        );
    }
    if let Err(err) = console
        .audit(
            Some(&admin),
            "invite_revoked",
            json!({ "prefix": prefix.get(..8) }),
            None,
        )
        .await
    {
        return back(
            &console,
            &admin,
            &uri,
            StatusCode::SERVICE_UNAVAILABLE,
            "Invite not revoked",
            err,
        );
    }
    let gone = async {
        let client = members.db.client().await?;
        client
            .execute(
                "DELETE FROM enterprise_invites WHERE accepted_at IS NULL AND left(token_sha256, 16) = $1",
                &[&prefix],
            )
            .await
            .map_err(db_error)
    };
    let notice = match gone.await {
        Err(err) => return unavailable(&console, &admin, &uri, &err),
        Ok(0) => banner("That invite was already used or revoked.", false),
        Ok(_) => banner("Invite revoked. Its link no longer works.", false),
    };
    match members_main(&members, &admin, &notice).await {
        Ok(main) => console.page(StatusCode::OK, &admin, NAV, &uri, &main),
        Err(err) => unavailable(&console, &admin, &uri, &err),
    }
}

async fn change_role(
    State(console): State<Console>,
    Ext(members): Ext<Members>,
    headers: HeaderMap,
    uri: Uri,
    body: String,
) -> Response {
    let (admin, me) = match editor(&console, &headers, &uri, "member_changed").await {
        Ok(who) => who,
        Err(answer) => return answer,
    };
    let form = Form::parse(&body);
    let team = form.get("team").trim().to_string();
    let refuse = |error: &str| back(&console, &admin, &uri, StatusCode::OK, "Change role", error);
    let m = match members.member(form.get("user_id")).await {
        Err(err) => return unavailable(&console, &admin, &uri, &err),
        Ok(None) => return refuse("That person is not a member."),
        Ok(Some(m)) => m,
    };
    let Some(role) = Role::parse(form.get("role")) else {
        return refuse("A role is owner, admin or viewer.");
    };
    if !valid_team(&team) {
        return refuse("A team is letters, digits, dots, _ or -.");
    }
    if (role == Role::Owner || m.role == Role::Owner) && me != Role::Owner {
        return refuse("Only an owner can make, change or remove an owner.");
    }
    let target =
        json!({ "email": m.email, "role": [m.role.word(), role.word()], "team": [m.team, team] });
    if let Err(err) = console
        .audit(Some(&admin), "member_changed", target, None)
        .await
    {
        return refuse(err);
    }
    match members.change(&m.id, Some((role, &team))).await {
        Err(err) => unavailable(&console, &admin, &uri, &err),
        Ok(Err(why)) => refuse(why),
        Ok(Ok(())) => redirect("/console/members"),
    }
}

async fn remove(
    State(console): State<Console>,
    Ext(members): Ext<Members>,
    headers: HeaderMap,
    uri: Uri,
    body: String,
) -> Response {
    let (admin, me) = match editor(&console, &headers, &uri, "member_removed").await {
        Ok(who) => who,
        Err(answer) => return answer,
    };
    let form = Form::parse(&body);
    let refuse = |status, error: &str| back(&console, &admin, &uri, status, "Remove member", error);
    let m = match members.member(form.get("user_id")).await {
        Err(err) => return unavailable(&console, &admin, &uri, &err),
        Ok(None) => return refuse(StatusCode::OK, "That person is not a member."),
        Ok(Some(m)) => m,
    };
    if m.role == Role::Owner && me != Role::Owner {
        return refuse(StatusCode::OK, "Only an owner can remove an owner.");
    }
    let keys = match members.keys_of(&m.email) {
        Ok(keys) => keys,
        Err(err) => return unavailable(&console, &admin, &uri, &db_error(err)),
    };
    let prefixes: Vec<&str> = keys.iter().filter_map(|k| k.get(..8)).collect();
    let target = json!({ "email": m.email, "role": m.role.word(), "keys_revoked": prefixes });
    if let Err(err) = console
        .audit(Some(&admin), "member_removed", target, None)
        .await
    {
        return refuse(StatusCode::SERVICE_UNAVAILABLE, err);
    }
    match members.change(&m.id, None).await {
        Err(err) => return unavailable(&console, &admin, &uri, &err),
        Ok(Err(why)) => return refuse(StatusCode::CONFLICT, why),
        Ok(Ok(())) => {}
    }
    // The person is gone, so they cannot sign in again; their keys go too, through the store, which every gateway
    // reads within a second.
    match members.revoke(keys).await {
        Ok(()) => redirect("/console/members"),
        Err(err) => refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            &format!(
                "{} was removed, and their keys could not all be revoked: {err}. Revoke the keys named {} under People and workloads.",
                m.email, m.email
            ),
        ),
    }
}

// ---------------------------------------------------------------- invite links and password sign-in

struct Invite {
    hash: String,
    email: String,
    role: String,
    team: String,
}

/// The invite behind a link, or the page that says why it does not work.
async fn find_invite(members: &Members, token: &str) -> Result<Invite, Response> {
    let notice = |status, title: &str, text: &str| {
        bare_page(
            status,
            title,
            &format!(
                r#"<h1 class="t-lg" style="margin: 0">{}</h1><p class="t-lead g-muted" style="margin: 0">{}</p>"#,
                esc(title),
                esc(text)
            ),
        )
    };
    let hash = gantry_core::id::sha256_hex(token.as_bytes());
    let row = async {
        let client = members.db.client().await?;
        client
            .query_opt(
                "SELECT email, role, team, accepted_at IS NOT NULL, expires_at <= now() FROM enterprise_invites WHERE token_sha256 = $1",
                &[&hash],
            )
            .await
            .map_err(db_error)
    };
    let row = match row.await {
        Err(err) => {
            return Err(notice(
                StatusCode::SERVICE_UNAVAILABLE,
                "Invite not checked",
                &err,
            ));
        }
        Ok(None) => {
            return Err(notice(
                StatusCode::NOT_FOUND,
                "Invite not found",
                "This invite link is not valid. Ask an owner or admin for a new one.",
            ));
        }
        Ok(Some(row)) => row,
    };
    let read = |i| row.try_get::<_, String>(i).unwrap_or_default();
    if row.try_get::<_, bool>(3).unwrap_or(true) {
        return Err(notice(
            StatusCode::GONE,
            "Invite already used",
            "This invite was accepted already. Sign in to reach the console, or ask for a new invite.",
        ));
    }
    if row.try_get::<_, bool>(4).unwrap_or(true) {
        return Err(notice(
            StatusCode::GONE,
            "Invite expired",
            &format!(
                "Invites are valid for {INVITE_DAYS} days. Ask an owner or admin for a new one."
            ),
        ));
    }
    Ok(Invite {
        hash,
        email: read(0),
        role: read(1),
        team: read(2),
    })
}

fn sign_up_form(inv: &Invite, token: &str, error: &str, name: &str) -> Response {
    let error_banner = if error.is_empty() {
        String::new()
    } else {
        banner(&esc(error), true)
    };
    bare_page(
        if error.is_empty() {
            StatusCode::OK
        } else {
            StatusCode::BAD_REQUEST
        },
        "Join the console",
        &format!(
            r#"{}{error_banner}<form method="post" action="/console/invite/{}" class="g-stack">{}{}<div class="g-head__actions">{}</div></form>"#,
            html::head(
                "Join the console",
                &format!(
                    "You are invited as {} in team {}. Set your name and a password for {}.",
                    esc(&inv.role),
                    esc(&inv.team),
                    esc(&inv.email)
                ),
                ""
            ),
            esc(token),
            text_field(
                "name",
                "name",
                "Your name",
                name,
                r#" required autocomplete="name""#,
                ""
            ),
            text_field(
                "password",
                "password",
                "Password",
                "",
                r#" type="password" required autocomplete="new-password""#,
                "At least 12 characters."
            ),
            html::button("Create account and join", "", "submit", "")
        ),
    )
}

async fn invite_page(Ext(members): Ext<Members>, Path(token): Path<String>) -> Response {
    match find_invite(&members, &token).await {
        Ok(inv) => sign_up_form(&inv, &token, "", ""),
        Err(answer) => answer,
    }
}

async fn accept(
    State(console): State<Console>,
    Ext(members): Ext<Members>,
    Path(token): Path<String>,
    headers: HeaderMap,
    uri: Uri,
    tls: Tls,
    body: String,
) -> Response {
    if !same_origin(&headers) {
        return foreign();
    }
    let inv = match find_invite(&members, &token).await {
        Ok(inv) => inv,
        Err(answer) => return answer,
    };
    let form = Form::parse(&body);
    let name: String = form.get("name").trim().chars().take(128).collect();
    let password = form.get("password").to_string();
    if name.is_empty() {
        return sign_up_form(&inv, &token, "Enter your name.", "");
    }
    if password.chars().count() < MIN_PASSWORD {
        return sign_up_form(
            &inv,
            &token,
            "The password needs at least 12 characters.",
            &name,
        );
    }
    let hashed = tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .unwrap_or_else(|err| Err(err.to_string()));
    let (salt, hash) = match hashed {
        Ok(hashed) => hashed,
        Err(err) => return sign_up_form(&inv, &token, &err, &name),
    };
    let id = match random_hex(16) {
        Ok(hex) => format!("usr_{hex}"),
        Err(err) => return sign_up_form(&inv, &token, &err, &name),
    };
    let target = json!({ "email": inv.email, "role": inv.role, "team": inv.team });
    let who = Admin {
        role: inv.role.clone(),
        ..Admin::of_role(
            &inv.email,
            &inv.team,
            inv.role == "viewer",
            Via::Account(id.clone()),
        )
    };
    if let Err(err) = console
        .audit(Some(&who), "invite_accepted", target, None)
        .await
    {
        return sign_up_form(&inv, &token, err, &name);
    }
    // One transaction: the invite is marked used and the person made together, so two clicks cannot both accept it.
    let accepted = async {
        let mut client = members.db.client().await?;
        let tx = client.transaction().await.map_err(db_error)?;
        let used = tx
            .execute(
                "UPDATE enterprise_invites SET accepted_at = now() WHERE token_sha256 = $1 AND accepted_at IS NULL AND expires_at > now()",
                &[&inv.hash],
            )
            .await
            .map_err(db_error)?;
        let made = tx
            .execute(
                "INSERT INTO enterprise_people (id, email, name, password_salt, password_hash, role, team) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (email) DO NOTHING",
                &[&id, &inv.email, &name, &salt, &hash, &inv.role, &inv.team],
            )
            .await
            .map_err(db_error)?;
        if used != 1 || made != 1 {
            return Ok(false);
        }
        tx.commit().await.map_err(db_error)?;
        Ok::<_, String>(true)
    };
    match accepted.await {
        Err(err) => sign_up_form(&inv, &token, &err, &name),
        Ok(false) => bare_page(
            StatusCode::GONE,
            "Invite already used",
            r#"<h1 class="t-lg" style="margin: 0">Invite already used</h1><p class="t-lead g-muted" style="margin: 0">This invite was accepted already, or this email is a member already. Sign in instead.</p>"#,
        ),
        Ok(true) => {
            console
                .sign_in_account(&id, &who, &headers, &uri, &tls)
                .await
        }
    }
}

fn sign_in_form(status: StatusCode, error: &str, email: &str) -> Response {
    let error_banner = if error.is_empty() {
        String::new()
    } else {
        banner(&esc(error), true)
    };
    bare_page(
        status,
        "Sign in",
        &format!(
            r#"{}{error_banner}<form method="post" action="/console/sign-in/password" class="g-stack">{}{}<div class="g-head__actions">{}{}</div></form>"#,
            html::head(
                "Sign in to the console",
                "With the email and password you set when you accepted your invite.",
                ""
            ),
            text_field(
                "email",
                "email",
                "Email",
                email,
                r#" type="email" required autocomplete="email" autofocus"#,
                ""
            ),
            text_field(
                "password",
                "password",
                "Password",
                "",
                r#" type="password" required autocomplete="current-password""#,
                ""
            ),
            html::button("Sign in", "", "submit", ""),
            html::link("Other ways to sign in", "quiet", "/console/sign-in", false)
        ),
    )
}

async fn sign_in_page(State(console): State<Console>, headers: HeaderMap) -> Response {
    if console.signed_in(&headers).await.is_some() {
        return redirect(gantry_console::HOME);
    }
    sign_in_form(StatusCode::OK, "", "")
}

async fn sign_in(
    State(console): State<Console>,
    Ext(members): Ext<Members>,
    headers: HeaderMap,
    uri: Uri,
    tls: Tls,
    body: String,
) -> Response {
    if !same_origin(&headers) {
        return foreign();
    }
    let form = Form::parse(&body);
    let email = form.get("email").trim().to_lowercase();
    let password = form.get("password").to_string();
    let found = async {
        let client = members.db.client().await?;
        let row = client
            .query_opt(
                "SELECT id, password_salt, password_hash FROM enterprise_people WHERE email = $1",
                &[&email],
            )
            .await
            .map_err(db_error)?;
        row.map(|r| {
            Ok::<_, tokio_postgres::Error>((
                r.try_get::<_, String>(0)?,
                r.try_get::<_, String>(1)?,
                r.try_get::<_, String>(2)?,
            ))
        })
        .transpose()
        .map_err(db_error)
    };
    let found = match found.await {
        Ok(found) => found,
        Err(err) => return sign_in_form(StatusCode::SERVICE_UNAVAILABLE, &err, &email),
    };
    // The same work and the same answer whether or not the email has an account.
    let (id, salt, hash) = found.unwrap_or_default();
    let matched = tokio::task::spawn_blocking(move || password_matches(&password, &salt, &hash))
        .await
        .unwrap_or(false);
    let who = if matched && !id.is_empty() {
        members.account(&id).await
    } else {
        None
    };
    let Some(who) = who else {
        let _ = console
            .audit(
                None,
                "console_sign_in",
                json!({ "via": "password" }),
                Some("bad_password"),
            )
            .await;
        return sign_in_form(
            StatusCode::UNAUTHORIZED,
            "That email and password do not match an account.",
            &email,
        );
    };
    console
        .sign_in_account(&id, &who, &headers, &uri, &tls)
        .await
}

#[cfg(test)]
mod tests;
