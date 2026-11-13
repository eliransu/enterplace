//! The admin API for keys: issue, list and revoke keys while Gantry runs, without editing the keys file by hand.
//!
//! Only a key whose entry says `admin: true` may call it, wherever Gantry listens, so it is never open. Every call
//! is recorded before anything is done, as a request is. The keys file stays the one source of truth: a key is
//! added by appending its entry, removed by a replace that only happens while the file is as it was read, and the
//! reload that follows is the same one a hand edit gets.

use axum::{
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use gantry_core::{
    audit,
    config::{self, valid_name},
    id, keyfile, kill,
    policy::{Policy, Principal},
};
use serde_json::{Map, Value, json};

use crate::{
    AppState, ClientAddr, DECISION, Refusal, Reload, Snapshot, Trigger, caller_key, read_body,
};

const ROUTES: &str = "GET /admin/keys, POST /admin/keys, DELETE /admin/keys/<first 8 hex characters of the hash>, DELETE /admin/keys/self, and GET, POST and DELETE /admin/kills";

/// What an admin call asks for, once it is allowed.
enum Plan {
    List,
    Issue {
        name: String,
        team: String,
        key: String,
        attributes: keyfile::Attributes,
    },
    Revoke {
        prefix: String,
    },
    Kills,
    Kill(kill::Kill),
    Unkill {
        scope: String,
        value: String,
    },
}

/// A kill switch to set (`reason` required) or clear.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Switch {
    scope: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    reason: String,
    /// Sets the switch even when it matches no key, team or served model.
    #[serde(default)]
    force: bool,
}

/// Why a switch would stop nothing, with the names it may have meant. UX12-1: `gantry login` names keys by email,
/// so `--person maya.cohen` looks right, is reported on, and stops nothing.
fn matches_nothing(
    version: &Snapshot,
    policy: &Policy,
    scope: &str,
    value: &str,
) -> Option<String> {
    let close = |names: Vec<String>, what: &str| {
        let mut near: Vec<String> = names
            .iter()
            .filter(|n| n.contains(value) || value.contains(n.split('@').next().unwrap_or(n)))
            .cloned()
            .collect();
        near.sort();
        near.dedup();
        near.truncate(5);
        let hint = if near.is_empty() {
            String::new()
        } else {
            format!(" {what} like it: {}.", near.join(", "))
        };
        Some(hint)
    };
    let hint = match scope {
        "person" | "team" => {
            let names: Vec<String> = policy
                .entries()
                .map(|(_, who)| {
                    if scope == "person" {
                        who.name.clone()
                    } else {
                        who.team.clone()
                    }
                })
                .collect();
            if names.iter().any(|n| n == value) {
                return None;
            }
            close(
                names,
                if scope == "person" {
                    "Keys named"
                } else {
                    "Teams"
                },
            )?
        }
        "key_prefix" => {
            if policy
                .entries()
                .any(|(hash, _)| id::hex(hash).starts_with(value))
            {
                return None;
            }
            String::new()
        }
        "model" => {
            let names: Vec<String> = version
                .providers
                .iter()
                .flat_map(|p| p.models.iter().cloned())
                .chain(version.aliases.iter().map(|a| a.name.clone()))
                .chain(
                    version
                        .aliases
                        .iter()
                        .flat_map(|a| a.deployments.iter().map(|d| d.model.clone())),
                )
                .collect();
            if names.iter().any(|n| n == value) {
                return None;
            }
            close(names, "Models")?
        }
        _ => return None,
    };
    let what = if scope == "key_prefix" { "key" } else { scope };
    Some(format!(
        "Refused: no {what} \"{value}\" is served or holds a key here, so this switch would stop nothing.{hint} Name one that exists, or send \"force\": true (gantry kill --force) to set it anyway."
    ))
}

/// What is known about a call, for its record.
#[derive(Default)]
struct Call {
    action: Option<&'static str>,
    person: Option<Principal>,
    key: Option<String>,
    target: Option<Value>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NewKey {
    name: String,
    team: String,
    /// `2026-12-31` or `2026-12-31T18:00:00Z`, UTC.
    #[serde(default)]
    expires: Option<String>,
    #[serde(default)]
    budget: Option<NewBudget>,
    /// The models this key may use, within its rule's.
    #[serde(default)]
    models: Option<Vec<String>>,
    #[serde(default)]
    tpm: Option<u32>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NewBudget {
    usd: f64,
    per: String,
}

pub(crate) async fn handle(State(state): State<AppState>, request: Request) -> Response {
    let decision = id::decision_id();
    let mut response = match admin(&state, request, &decision).await {
        Ok(response) => response,
        Err(refusal) => refusal.respond(&decision, false),
    };
    if let Ok(value) = HeaderValue::from_str(&decision) {
        response.headers_mut().insert(DECISION, value);
    }
    response
}

fn refused(status: StatusCode, code: &'static str, message: impl Into<String>) -> Refusal {
    Refusal::new(status, code, message)
}

async fn admin(state: &AppState, request: Request, decision: &str) -> Result<Response, Refusal> {
    let version = state.version();
    let client = request
        .extensions()
        .get::<ClientAddr>()
        .map(|addr| addr.0.ip().to_string());
    let mut call = Call::default();
    let outcome = allow(state, &version, request, &mut call).await;
    record(
        state,
        decision,
        &version,
        &call,
        client.as_deref(),
        outcome.as_ref().err().map(|r| r.code),
        None,
    )
    .await?;
    let plan = outcome?;
    let done = act(state, &version, plan).await;
    if let Err(refusal) = &done {
        // The call was recorded as allowed before it was tried. This says it did not happen.
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

/// Who is calling, whether they may, and what they ask for. Nothing is changed here.
async fn allow(
    state: &AppState,
    version: &Snapshot,
    request: Request,
    call: &mut Call,
) -> Result<Plan, Refusal> {
    let (parts, body) = request.into_parts();
    let prefix = parts
        .uri
        .path()
        .strip_prefix("/admin/keys/")
        .map(str::to_string);
    let kills = parts.uri.path() == "/admin/kills";
    call.action = match (&parts.method, prefix.as_deref(), kills) {
        (&Method::GET, None, false) => Some("list_keys"),
        (&Method::POST, None, false) => Some("issue_key"),
        (&Method::DELETE, Some("self"), _) => Some("revoke_own_key"),
        (&Method::DELETE, Some(_), _) => Some("revoke_key"),
        (&Method::GET, None, true) => Some("list_kills"),
        (&Method::POST, None, true) => Some("set_kill"),
        (&Method::DELETE, None, true) => Some("clear_kill"),
        _ => None,
    };
    let Some(policy) = &version.policy else {
        return Err(refused(
            StatusCode::NOT_FOUND,
            "unknown_route",
            "Refused: this Gantry serves no keys file, so it has no admin API.",
        ));
    };
    let key = caller_key(&parts.headers)?;
    let Some(person) = policy.identify(key) else {
        call.key = Some(id::sha256_hex(key.as_bytes())[..8].to_string());
        return Err(refused(
            StatusCode::UNAUTHORIZED,
            "unknown_key",
            "Refused: Gantry does not know this key. It was never issued or it has been removed. Ask a Gantry admin.",
        ));
    };
    call.person = Some(person.clone());
    // Every admin record names the caller's key by its hash prefix, as request records do.
    call.key = Some(person.key.clone());
    // `gantry logout` revokes the key it sends, whoever's it is: no one needs to be an admin to give up their own key.
    if call.action == Some("revoke_own_key") {
        let hash = id::sha256_hex(key.as_bytes());
        call.target =
            Some(json!({ "name": person.name, "team": person.team, "sha256_prefix": &hash[..8] }));
        return Ok(Plan::Revoke { prefix: hash });
    }
    if !person.admin {
        return Err(refused(
            StatusCode::FORBIDDEN,
            "not_admin",
            format!(
                "Refused: the admin API is for keys marked `admin: true` in the keys file, and the key of \"{}\" is not. Ask a Gantry admin.",
                person.name
            ),
        ));
    }
    let not_here = || {
        refused(
            StatusCode::NOT_FOUND,
            "unknown_route",
            format!("Refused: the admin API serves {ROUTES}. Check the method and the path."),
        )
    };
    match call.action.ok_or_else(not_here)? {
        "list_keys" => Ok(Plan::List),
        "list_kills" => Ok(Plan::Kills),
        action @ ("set_kill" | "clear_kill") => {
            let (bytes, _held) = read_body(Some(&person.name), state, &parts.headers, body).await?;
            let switch: Switch = serde_json::from_slice(&bytes).map_err(|err| {
                refused(StatusCode::BAD_REQUEST, "invalid_request", format!("Refused: send a JSON object with \"scope\" (person, team, key_prefix, model or all), \"value\" and, to set a switch, \"reason\" ({err})."))
            })?;
            // Clearing needs no reason, so a placeholder passes the check of scope and value.
            let reason = if action == "set_kill" {
                switch.reason.as_str()
            } else {
                "-"
            };
            let value = kill::checked(&switch.scope, &switch.value, reason).map_err(|err| {
                refused(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    format!("Refused: {err}"),
                )
            })?;
            let mut target = json!({ "scope": switch.scope, "value": value });
            if action == "set_kill" {
                target["reason"] = switch.reason.trim().into();
            }
            call.target = Some(target);
            if action == "set_kill"
                && !switch.force
                && let Some(problem) = matches_nothing(version, policy, &switch.scope, &value)
            {
                return Err(refused(
                    StatusCode::BAD_REQUEST,
                    "kill_matches_nothing",
                    problem,
                ));
            }
            if action == "clear_kill" {
                return Ok(Plan::Unkill {
                    scope: switch.scope,
                    value,
                });
            }
            Ok(Plan::Kill(kill::Kill {
                scope: switch.scope,
                value,
                reason: switch.reason.trim().to_string(),
                by: person.name.clone(),
                at: audit::timestamp(),
            }))
        }
        "issue_key" => {
            let (bytes, _held) = read_body(Some(&person.name), state, &parts.headers, body).await?;
            let new: NewKey = serde_json::from_slice(&bytes).map_err(|err| {
                refused(StatusCode::BAD_REQUEST, "invalid_request", format!("Refused: send a JSON object with \"name\" and \"team\", and optionally \"expires\", \"budget\", \"models\" and \"tpm\" ({err})."))
            })?;
            if !valid_name(&new.name) || !valid_name(&new.team) {
                return Err(refused(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Refused: a name and a team use letters, digits, dots, dashes, underscores and @ only, at most 100 characters, for example maya.cohen and payments.",
                ));
            }
            if let Some(Err(problem)) = new.expires.as_deref().map(config::issuable_expiry) {
                return Err(refused(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    format!("Refused: {problem}."),
                ));
            }
            let budget = match &new.budget {
                None => None,
                Some(b) => {
                    let per = match b.per.as_str() {
                        "day" => Some(gantry_core::policy::Period::Day),
                        "month" => Some(gantry_core::policy::Period::Month),
                        _ => None,
                    };
                    match per {
                        Some(per) if b.usd.is_finite() && b.usd > 0.0 => {
                            Some(gantry_core::policy::Budget { usd: b.usd, per })
                        }
                        _ => {
                            return Err(refused(
                                StatusCode::BAD_REQUEST,
                                "invalid_request",
                                "Refused: budget takes US dollars above 0 and a period, for example {\"usd\": 20, \"per\": \"month\"}.",
                            ));
                        }
                    }
                }
            };
            if let Some(models) = &new.models {
                let served: Vec<&String> = version
                    .providers
                    .iter()
                    .flat_map(|p| p.models.iter())
                    .chain(version.aliases.iter().map(|a| &a.name))
                    .collect();
                if let Some(unknown) = models.iter().find(|m| *m != "*" && !served.contains(m)) {
                    return Err(refused(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        format!(
                            "Refused: model \"{unknown}\" is not served here, so the key could never use it. List models or aliases of the policy, as GET /v1/models lists them."
                        ),
                    ));
                }
            }
            if new.models.as_ref().is_some_and(Vec::is_empty)
                || new.tpm.is_some_and(|t| !(1..=1_000_000_000).contains(&t))
            {
                return Err(refused(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Refused: models lists at least one model the key may use, and tpm is the tokens it may use per minute, 1 to 1000000000, for example {\"models\": [\"gpt-4o-mini\"], \"tpm\": 200000}.",
                ));
            }
            let key = id::new_key().map_err(|err| {
                refused(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "no_randomness",
                    format!("Refused: {err}. Try again."),
                )
            })?;
            call.target = Some(
                json!({ "name": new.name, "team": new.team, "sha256_prefix": &id::sha256_hex(key.as_bytes())[..8] }),
            );
            Ok(Plan::Issue {
                name: new.name,
                team: new.team,
                key,
                attributes: keyfile::Attributes {
                    admin: false,
                    expires: new.expires,
                    budget,
                    models: new.models,
                    tpm: new.tpm,
                },
            })
        }
        _ => {
            let prefix = prefix.unwrap_or_default().to_ascii_lowercase();
            if prefix.len() < 8
                || prefix.len() > 64
                || !prefix.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(refused(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Refused: name the key by the first 8 hex characters of its hash, as GET /admin/keys lists it.",
                ));
            }
            let keys_path = state
                .reloader
                .as_ref()
                .map(|r| r.keys_path().to_path_buf())
                .unwrap_or_default();
            // Looked up in the file, which may hold an entry the version in use does not have yet.
            let entries = config::read_keys(&keys_path)
                .map_err(|err| {
                    refused(StatusCode::CONFLICT, "keys_file", format!("Refused: {err}"))
                })?
                .map(|text| config::key_entries(&keys_path, &text).unwrap_or_default())
                .unwrap_or_default();
            let matching: Vec<_> = entries
                .iter()
                .filter(|e| e.sha256.starts_with(&prefix))
                .collect();
            match matching.as_slice() {
                [] => Err(refused(
                    StatusCode::NOT_FOUND,
                    "no_such_key",
                    format!(
                        "Refused: no key in the keys file has a hash that starts with {prefix}. GET /admin/keys lists them."
                    ),
                )),
                [found] => {
                    call.target = Some(
                        json!({ "name": found.name, "team": found.team, "sha256_prefix": &found.sha256[..8] }),
                    );
                    Ok(Plan::Revoke { prefix })
                }
                _ => Err(refused(
                    StatusCode::BAD_REQUEST,
                    "ambiguous_key",
                    format!(
                        "Refused: more than one key hash starts with {prefix}. Send more of the hash."
                    ),
                )),
            }
        }
    }
}

/// Writes the record of an admin call and waits for it. A call that cannot be recorded does not happen.
async fn record(
    state: &AppState,
    decision: &str,
    version: &Snapshot,
    call: &Call,
    client: Option<&str>,
    code: Option<&str>,
    error: Option<&str>,
) -> Result<(), Refusal> {
    let Some(audit) = &state.audit else {
        return Ok(());
    };
    let verdict = match (code, error) {
        (None, _) => "allow",
        (Some(_), None) => "refused",
        (Some(_), Some(_)) => "failed",
    };
    let mut record = Map::new();
    record.insert("event".into(), "admin".into());
    record.insert("id".into(), decision.into());
    record.insert("time".into(), audit::timestamp().into());
    record.insert(
        "person".into(),
        call.person
            .as_ref()
            .map_or("unknown", |p| p.name.as_str())
            .into(),
    );
    record.insert(
        "team".into(),
        call.person.as_ref().map(|p| p.team.clone()).into(),
    );
    record.insert("client".into(), client.into());
    record.insert("key".into(), call.key.clone().into());
    record.insert("action".into(), call.action.into());
    record.insert("target".into(), call.target.clone().unwrap_or(Value::Null));
    record.insert("verdict".into(), verdict.into());
    record.insert("code".into(), code.into());
    if let Some(error) = error {
        record.insert("error".into(), error.into());
    }
    record.insert("policy_sha256".into(), version.policy_sha256.clone().into());
    record.insert("keys_sha256".into(), version.keys_sha256.clone().into());
    let (tell, written) = tokio::sync::oneshot::channel();
    audit.log.append_record_then(&record, move |result| {
        let _ = tell.send(result);
    });
    if matches!(written.await, Ok(Ok(()))) {
        return Ok(());
    }
    eprintln!("gantry: the audit log could not be written, so admin call {decision} was refused");
    Err(refused(
        StatusCode::SERVICE_UNAVAILABLE,
        "audit_unavailable",
        "Refused: Gantry could not write this call to its audit log, and it does not act on what it cannot record. Tell your Gantry admin.",
    ))
}

fn json_response(status: StatusCode, body: &Value) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Refusal> {
    tokio::task::spawn_blocking(work).await.map_err(|_| {
        refused(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "Refused: the change stopped before it finished. Check the keys file and try again.",
        )
    })
}

/// Puts the change in effect at once, so the answer can say whether it is.
async fn reload(state: &AppState) -> Result<Value, Refusal> {
    let Some(reloader) = state.reloader.clone() else {
        return Ok(json!({ "in_effect": false }));
    };
    Ok(
        match blocking(move || reloader.check(Trigger::FileChange)).await? {
            Reload::Loaded | Reload::Unchanged => json!({ "in_effect": true }),
            Reload::Rejected(problems) => json!({
                "in_effect": false,
                "problems": problems,
                "message": "The keys file changed, but the files on disk do not pass the check, so Gantry keeps the version it has. Fix the problems listed and the change applies within 2 seconds.",
            }),
        },
    )
}

async fn act(state: &AppState, version: &Snapshot, plan: Plan) -> Result<Response, Refusal> {
    let switches = state.kills.clone();
    let switches = || {
        switches.clone().ok_or_else(|| {
            refused(
                StatusCode::NOT_FOUND,
                "unknown_route",
                "Refused: this Gantry serves no keys file, so it has no kill switches.",
            )
        })
    };
    let kills_error = |err: String| {
        refused(
            StatusCode::CONFLICT,
            "kills_file",
            format!("Refused: {err}"),
        )
    };
    let keys_path = state
        .reloader
        .as_ref()
        .map(|r| r.keys_path().to_path_buf())
        .unwrap_or_default();
    let file_error =
        |err: String| refused(StatusCode::CONFLICT, "keys_file", format!("Refused: {err}"));
    match plan {
        Plan::List => {
            let mut keys: Vec<Value> = version
                .policy
                .iter()
                .flat_map(|policy| policy.entries())
                .map(|(hash, who)| {
                    json!({
                        "name": who.name,
                        "team": who.team,
                        "sha256_prefix": id::hex(&hash[..4]),
                        "admin": who.admin,
                        "expires": who.expires,
                        "budget": who.budget.map(|b| json!({ "usd": b.usd, "per": b.per.word() })),
                        "models": who.models,
                        "tpm": who.tpm,
                    })
                })
                .collect();
            keys.sort_by_key(|k| (k["name"].to_string(), k["sha256_prefix"].to_string()));
            Ok(json_response(StatusCode::OK, &json!({ "keys": keys })))
        }
        Plan::Issue {
            name,
            team,
            key,
            attributes,
        } => {
            let (n, t, k) = (name.clone(), team.clone(), key.clone());
            let rotated = blocking(move || keyfile::add_with(&n, &t, &k, &attributes, &keys_path))
                .await?
                .map_err(file_error)?;
            let status = reload(state).await?;
            Ok(json_response(
                StatusCode::CREATED,
                &json!({
                    "key": key,
                    "name": name,
                    "team": team,
                    "sha256_prefix": &id::sha256_hex(key.as_bytes())[..8],
                    "rotated": rotated,
                    "status": status,
                    "message": "This key is shown once and is not stored anywhere. Only its hash is in the keys file.",
                }),
            ))
        }
        Plan::Kills => {
            let kills = switches()?.current().map_err(kills_error)?;
            Ok(json_response(StatusCode::OK, &json!({ "kills": *kills })))
        }
        Plan::Kill(kill) => {
            let s = switches()?;
            let k = kill.clone();
            let replaced = blocking(move || s.set(k)).await?.map_err(kills_error)?;
            Ok(json_response(
                StatusCode::CREATED,
                &json!({ "kill": kill, "replaced": replaced, "in_effect": true }),
            ))
        }
        Plan::Unkill { scope, value } => {
            let s = switches()?;
            let (sc, v) = (scope.clone(), value.clone());
            match blocking(move || s.clear(&sc, &v))
                .await?
                .map_err(kills_error)?
            {
                Some(cleared) => Ok(json_response(
                    StatusCode::OK,
                    &json!({ "cleared": cleared, "in_effect": true }),
                )),
                None => Err(refused(
                    StatusCode::NOT_FOUND,
                    "no_such_switch",
                    format!(
                        "Refused: no kill switch is on for {scope} {value}. GET /admin/kills lists the ones that are."
                    ),
                )),
            }
        }
        Plan::Revoke { prefix } => {
            let gone = blocking(move || keyfile::revoke(&keys_path, &prefix))
                .await?
                .map_err(file_error)?;
            let Some(gone) = gone else {
                return Err(refused(
                    StatusCode::NOT_FOUND,
                    "no_such_key",
                    "Refused: the key was removed from the keys file by someone else meanwhile.",
                ));
            };
            let status = reload(state).await?;
            Ok(json_response(
                StatusCode::OK,
                &json!({
                    "revoked": { "name": gone.name, "team": gone.team, "sha256_prefix": &gone.sha256[..8] },
                    "status": status,
                }),
            ))
        }
    }
}
