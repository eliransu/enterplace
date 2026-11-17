//! The admin API for teams: the policy's `teams:` (owner, members by email, the identity provider groups that put
//! people in a team) beside the teams keys name.
//!
//! - `GET /admin/teams`, `GET /admin/teams/<name>`: every team, with its keys. A role kept to some teams sees those.
//! - `POST /admin/teams` with a team as JSON, `PUT /admin/teams/<name>`, `DELETE /admin/teams/<name>`: a new policy
//!   version, as `PUT /admin/policy` saves one, so it needs `store.policy_from: store`, the edit_policy permission in
//!   a role kept to no part of the install, and is checked, recorded and approved as any version is.

use std::collections::BTreeMap;

use axum::{
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode},
    response::Response,
};
use enterplace_core::{
    config, id,
    policy::{Permission, Policy, Team},
    versions,
};
use serde_json::{Value, json};

use crate::{
    AppState, ClientAddr, DECISION, Refusal,
    admin::{Call, blocking, json_response, record, refused},
    caller_key,
    policy_api::{changed, refusal},
    read_body,
};

const ROUTES: &str = "GET and POST /admin/teams, and GET, PUT and DELETE /admin/teams/<name>";

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TeamBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    members: Vec<String>,
    #[serde(default)]
    sso_values: Vec<String>,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
}

enum Plan {
    List(Option<Vec<String>>),
    Show(String, Option<Vec<String>>),
    /// The team's new fields, or None to remove it; and whether it must not exist yet.
    Save {
        name: String,
        team: Option<Value>,
        create: bool,
        note: String,
    },
}

pub(crate) async fn handle(State(state): State<AppState>, request: Request) -> Response {
    let decision = id::decision_id();
    let mut response = match run(&state, request, &decision).await {
        Ok(response) => response,
        Err(refusal) => refusal.respond(&decision, false),
    };
    if let Ok(value) = HeaderValue::from_str(&decision) {
        response.headers_mut().insert(DECISION, value);
    }
    response
}

async fn run(state: &AppState, request: Request, decision: &str) -> Result<Response, Refusal> {
    let version = state.version();
    let client = request
        .extensions()
        .get::<ClientAddr>()
        .map(|addr| addr.0.ip().to_string());
    let mut call = Call::default();
    let outcome = allow(state, request, &mut call).await;
    let code = outcome.as_ref().err().map(|r| r.code);
    record(
        state,
        decision,
        &version,
        &call,
        client.as_deref(),
        code,
        None,
    )
    .await?;
    let plan = outcome?;
    let by = call
        .person
        .as_ref()
        .map(|p| p.name.clone())
        .unwrap_or_default();
    let done = act(state, plan, &by).await;
    if let Err(refusal) = &done {
        record(
            state,
            decision,
            &version,
            &call,
            client.as_deref(),
            Some(refusal.code),
            Some(&refusal.message),
        )
        .await?;
    }
    done
}

async fn allow(state: &AppState, request: Request, call: &mut Call) -> Result<Plan, Refusal> {
    let (parts, body) = request.into_parts();
    let name = parts
        .uri
        .path()
        .strip_prefix("/admin/teams")
        .unwrap_or_default()
        .trim_matches('/')
        .to_string();
    call.action = match (&parts.method, name.is_empty()) {
        (&Method::GET, true) => Some("list_teams"),
        (&Method::GET, false) => Some("show_team"),
        (&Method::POST, true) => Some("create_team"),
        (&Method::PUT, false) => Some("update_team"),
        (&Method::DELETE, false) => Some("delete_team"),
        _ => None,
    };
    let version = state.version();
    let Some(policy) = &version.policy else {
        return Err(refused(
            StatusCode::NOT_FOUND,
            "unknown_route",
            "Refused: this Enterplace serves no policy file, so it has no admin API.",
        ));
    };
    let key = caller_key(&parts.headers)?;
    let Some(person) = policy.identify(key) else {
        call.key = Some(id::sha256_hex(key.as_bytes())[..8].to_string());
        return Err(refused(
            StatusCode::UNAUTHORIZED,
            "unknown_key",
            "Refused: Enterplace does not know this key. It was never issued or it has been removed. Ask a Enterplace admin.",
        ));
    };
    call.person = Some(person.clone());
    call.key = Some(person.key.clone());
    let Some(role) = policy.role_of(person) else {
        return Err(refused(
            StatusCode::FORBIDDEN,
            "not_admin",
            format!(
                "Refused: the admin API is for keys marked `admin: true` or given a role: in the keys file, and the key of \"{}\" is neither. Ask a Enterplace admin.",
                person.name
            ),
        ));
    };
    let Some(action) = call.action else {
        return Err(refused(
            StatusCode::NOT_FOUND,
            "unknown_route",
            format!("Refused: the teams API serves {ROUTES}. Check the method and the path."),
        ));
    };
    if !name.is_empty() {
        call.target = Some(json!({ "team": name }));
    }
    let reading = matches!(action, "list_teams" | "show_team");
    let needs = if reading {
        Permission::SeeKeys
    } else {
        Permission::EditPolicy
    };
    if !role.may(needs) || (!reading && role.confined()) {
        return Err(refused(
            StatusCode::FORBIDDEN,
            "not_permitted",
            format!(
                "Refused: {action} needs the {} permission{}, and role \"{}\" of \"{}\" {}. Ask a Enterplace admin.",
                needs.word(),
                if reading {
                    ""
                } else {
                    " in a role not kept to an organization, teams or customers, since teams are part of the policy"
                },
                role.name,
                person.name,
                if role.may(needs) {
                    "is kept to part of the install"
                } else {
                    "does not have it"
                }
            ),
        ));
    }
    // A role kept to teams sees those teams only; one kept to an organization or customers sees the teams of the
    // keys within its reach.
    let reach = role.confined().then(|| {
        if !role.teams.is_empty() {
            role.teams.clone()
        } else {
            policy
                .entries()
                .map(|(_, p)| p)
                .filter(|p| role.covers(&p.org, &p.team, p.customer.as_deref()))
                .map(|p| p.team.clone())
                .collect()
        }
    });
    if reading {
        return Ok(if name.is_empty() {
            Plan::List(reach)
        } else {
            Plan::Show(name, reach)
        });
    }
    let note = parts
        .headers
        .get("x-enterplace-note")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .chars()
        .take(500)
        .collect::<String>();
    if action == "delete_team" {
        return Ok(Plan::Save {
            name,
            team: None,
            create: false,
            note,
        });
    }
    let (bytes, _held) = read_body(Some(&person.name), state, &parts.headers, body).await?;
    let sent: TeamBody = serde_json::from_slice(&bytes).map_err(|err| {
        refused(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            format!(
                "Refused: send a team as JSON, such as {{\"name\": \"payments\", \"owner\": \"maya@example.com\", \"members\": [\"omer@example.com\"], \"sso_values\": [\"payments-eng\"]}} ({err})."
            ),
        )
    })?;
    let name = match (action, sent.name.clone()) {
        ("create_team", Some(n)) => n,
        ("create_team", None) => {
            return Err(refused(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Refused: a new team needs a \"name\", such as {\"name\": \"payments\"}.",
            ));
        }
        (_, Some(n)) if n != name => {
            return Err(refused(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                format!(
                    "Refused: the body names team \"{n}\" and the path team \"{name}\". A team keeps its name: remove it and make a new one to rename it."
                ),
            ));
        }
        _ => name,
    };
    if !config::valid_name(&name) {
        return Err(refused(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Refused: a team name uses letters, digits, dots, dashes, underscores and @ only, at most 100 characters, for example payments.",
        ));
    }
    let mut team = serde_json::Map::new();
    team.insert("name".into(), name.clone().into());
    if let Some(owner) = &sent.owner {
        team.insert("owner".into(), owner.trim().to_ascii_lowercase().into());
    }
    let list = |v: &[String]| Value::from(v.to_vec());
    if !sent.members.is_empty() {
        let members: Vec<String> = sent
            .members
            .iter()
            .map(|m| m.trim().to_ascii_lowercase())
            .collect();
        team.insert("members".into(), list(&members));
    }
    if !sent.sso_values.is_empty() {
        team.insert("sso_values".into(), list(&sent.sso_values));
    }
    if !sent.metadata.is_empty() {
        team.insert("metadata".into(), json!(sent.metadata));
    }
    let team = Value::Object(team);
    call.target = Some(json!({ "team": name, "set": team, "note": note }));
    Ok(Plan::Save {
        name,
        team: Some(team),
        create: action == "create_team",
        note,
    })
}

/// A team as the API shows it: its fields from `teams:` and the keys in it.
fn shown(name: &str, team: Option<&Team>, policy: &Policy) -> Value {
    let keys: Vec<Value> = policy
        .entries()
        .filter(|(_, p)| p.team == name)
        .map(|(hash, p)| json!({ "name": p.name, "sha256_prefix": id::hex(&hash[..4]), "admin": p.admin }))
        .collect();
    json!({
        "name": name,
        "owner": team.and_then(|t| t.owner.clone()),
        "members": team.map(|t| t.members.clone()).unwrap_or_default(),
        "sso_values": team.map(|t| t.sso_values.clone()).unwrap_or_default(),
        "metadata": team.map(|t| t.metadata.clone()).unwrap_or_default(),
        "in_policy": team.is_some(),
        "keys": keys,
    })
}

fn names(policy: &Policy) -> Vec<String> {
    let mut all: Vec<String> = policy
        .teams()
        .iter()
        .map(|t| t.name.clone())
        .chain(policy.entries().map(|(_, p)| p.team.clone()))
        .collect();
    all.sort();
    all.dedup();
    all
}

async fn act(state: &AppState, plan: Plan, by: &str) -> Result<Response, Refusal> {
    let version = state.version();
    let policy = version.policy.clone().unwrap_or_default();
    let visible = |reach: &Option<Vec<String>>, name: &str| {
        reach.as_ref().is_none_or(|r| r.iter().any(|t| t == name))
    };
    match plan {
        Plan::List(reach) => {
            let teams: Vec<Value> = names(&policy)
                .iter()
                .filter(|n| visible(&reach, n))
                .map(|n| shown(n, policy.teams().iter().find(|t| t.name == *n), &policy))
                .collect();
            Ok(json_response(StatusCode::OK, &json!({ "teams": teams })))
        }
        Plan::Show(name, reach) => {
            if !visible(&reach, &name) || !names(&policy).contains(&name) {
                return Err(no_such(&name));
            }
            let team = policy.teams().iter().find(|t| t.name == name);
            Ok(json_response(StatusCode::OK, &shown(&name, team, &policy)))
        }
        Plan::Save {
            name,
            team,
            create,
            note,
        } => {
            let Some(reloader) = state.reloader.clone() else {
                return Err(refused(
                    StatusCode::NOT_FOUND,
                    "unknown_route",
                    "Refused: this Enterplace serves no policy file, so it has no teams API.",
                ));
            };
            let exists = policy.teams().iter().any(|t| t.name == name);
            if create && exists {
                return Err(refused(
                    StatusCode::CONFLICT,
                    "team_exists",
                    format!(
                        "Refused: team \"{name}\" is already under teams in the policy. Change it with PUT /admin/teams/{name}."
                    ),
                ));
            }
            if !create && !exists {
                return Err(no_such(&name));
            }
            let (policy_path, keys_path) = (
                reloader.policy_path().to_path_buf(),
                reloader.keys_path().to_path_buf(),
            );
            let by = by.to_string();
            let done = blocking(move || {
                let store = versions::store_for(&policy_path)?;
                let live = store.live_policy();
                let text = match &live {
                    Some(v) => v.text.clone(),
                    None => config::policy_text(&policy_path).map_err(versions::Refused::Store)?,
                };
                let new = versions::set_team(&text, &name, team)
                    .map_err(|err| versions::Refused::Invalid(vec![err]))?;
                let note = if note.is_empty() {
                    format!("teams API: team {name}")
                } else {
                    note
                };
                versions::propose(
                    &policy_path,
                    &keys_path,
                    &new,
                    live.map(|v| v.id),
                    &note,
                    &by,
                )
            })
            .await?;
            if let Err(err) = &done {
                return Err(refusal(err));
            }
            changed(
                state,
                done,
                if create {
                    StatusCode::CREATED
                } else {
                    StatusCode::OK
                },
            )
            .await
        }
    }
}

fn no_such(name: &str) -> Refusal {
    refused(
        StatusCode::NOT_FOUND,
        "no_such_team",
        format!("Refused: there is no team \"{name}\" you may see. GET /admin/teams lists them."),
    )
}
