//! New and pending (`/console/app/#/apps/new`): the callers no admin has reviewed and the models no provider serves,
//! found in the request log, with what `new_callers:` in the policy does to them. Allow and Block put a caller's name
//! on the policy's `allowed:` or `blocked:` list, a policy change like any other: recorded, checked and in force on
//! every gateway within 2 seconds.

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::{get, put},
};
use enterplace_core::{
    config,
    insights::{MAX_ROWS, Query, Row},
    policy::{NEW_CALLERS_PAGE, NewMode, Permission},
    versions,
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

use crate::{
    Console,
    api::{Fail, answer, bad, body_of, commit, ok, sentence, signed_in, text},
    figures::time_list,
    insights::scoped,
};

/// How far back the request log is read for callers and models.
const DAYS: u64 = 30;

/// The refusals an admin fixes by serving the model from a provider the caller can use.
const MODEL_CODES: [&str; 3] = ["unknown_model", "wrong_route", "login_needed"];

pub(crate) fn routes() -> Router<Console> {
    Router::new()
        .route("/api/callers", get(list).post(decide))
        .route("/api/callers/mode", put(mode_set))
}

#[derive(Default)]
struct Caller {
    team: String,
    first: String,
    last: String,
    requests: u64,
    refused: u64,
    /// The newest refusal: its code and model.
    code: String,
    model: String,
}

#[derive(Default)]
struct Model {
    first: String,
    last: String,
    requests: u64,
    callers: Vec<String>,
    code: String,
    /// The newest request for it was let through: whatever refused it before is fixed.
    fixed: bool,
}

/// What a caller is, by its key: the Coding agents page shows people, Apps and agents shows service keys.
fn kind_of(entries: &[config::KeyEntry], name: &str) -> &'static str {
    let mine: Vec<&config::KeyEntry> = entries.iter().filter(|e| e.name == name).collect();
    if mine.iter().any(|e| e.admin) {
        return "admin";
    }
    let kind = |k: &str| {
        mine.iter()
            .any(|e| e.options.metadata.get("kind").map(String::as_str) == Some(k))
    };
    if mine.is_empty() {
        // Named by a JWT, single sign-on or an authenticating proxy, with no Enterplace key.
        "signed in"
    } else if kind("workload") {
        "service key"
    } else if kind(enterplace_core::keyfile::PERSON_TOKEN_KIND) {
        "person token"
    } else {
        "person key"
    }
}

/// What to tell the admin about a refusal: in words, and the step that fixes it.
fn refusal(code: &str, model: &str) -> Value {
    let (words, fix) = match code {
        "" => return Value::Null,
        "awaiting_approval" => ("Held until an admin allows it", "allow"),
        "caller_blocked" => ("Blocked", "allow"),
        "unknown_model" => ("No provider serves this model", "provider"),
        "wrong_route" => ("Its provider does not take this route", "provider"),
        "login_needed" => (
            "Its provider takes only a person's own Claude or ChatGPT login",
            "provider",
        ),
        _ => ("Refused", "requests"),
    };
    json!({ "code": code, "words": words, "fix": fix, "model": model })
}

async fn list(State(console): State<Console>, headers: HeaderMap) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, false).await?;
            if !admin.may(Permission::SeeRecords) {
                return Err(Fail(
                    StatusCode::FORBIDDEN,
                    format!(
                        "Your role, {}, does not have the see_records permission this page needs. Ask an Enterplace admin to add it to the role under roles: in the policy.",
                        admin.role
                    ),
                ));
            }
            let c = console.config();
            let loaded = config::load(&c.policy, Some(&c.keys)).map_err(|problems| {
                Fail(
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!(
                        "The policy does not load, so new callers cannot be told apart: {} Fix it under Policy file, then reload this page.",
                        problems.join(" ")
                    ),
                )
            })?;
            let entries = config::read_keys(&c.keys)
                .ok()
                .flatten()
                .and_then(|text| config::key_entries(&c.keys, &text).ok())
                .unwrap_or_default();
            let mut query = Query {
                from: versions::hours_ago(DAYS * 24),
                limit: MAX_ROWS,
                ..Query::default()
            };
            scoped(&admin, &mut query);
            let rows = crate::insights::rows(&console, &query).await.map_err(|problem| {
                Fail(
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!(
                        "{} Check that this gateway can reach its store or its audit log file, then reload the page.",
                        sentence(&problem)
                    ),
                )
            })?;
            let setting = loaded.policy.new_callers();
            let (callers, models) = fold(&rows);
            let served = |model: &str| {
                loaded
                    .providers
                    .iter()
                    .any(|p| p.models.iter().any(|m| config::model_matches(m, model)))
                    || loaded.aliases.iter().any(|a| a.name == model)
            };
            let mut listed = Vec::new();
            if let Some(setting) = setting {
                for (name, caller) in &callers {
                    let kind = kind_of(&entries, name);
                    if kind == "admin" || setting.allowed.contains(name) {
                        continue;
                    }
                    let state = if setting.blocked.contains(name) {
                        "blocked"
                    } else {
                        match setting.mode {
                            NewMode::Allow => "new",
                            NewMode::Hold => "pending",
                            NewMode::Block => "blocked by default",
                        }
                    };
                    listed.push(json!({
                        "name": name,
                        "team": caller.team,
                        "kind": kind,
                        "state": state,
                        "first_seen": time_list(&caller.first),
                        "last_seen": time_list(&caller.last),
                        "first_at": caller.first,
                        "requests": caller.requests,
                        "refused": caller.refused,
                        "refusal": refusal(&caller.code, &caller.model),
                    }));
                }
                // A name blocked before it sent anything in the window is still listed, so it can be allowed.
                for name in setting.blocked.iter().filter(|n| !callers.contains_key(*n)) {
                    listed.push(json!({
                        "name": name,
                        "team": "",
                        "kind": kind_of(&entries, name),
                        "state": "blocked",
                        "first_seen": "",
                        "last_seen": "",
                        "first_at": "",
                        "requests": 0,
                        "refused": 0,
                        "refusal": Value::Null,
                    }));
                }
            }
            // Newest first: what just arrived is what the admin is looking for.
            listed.sort_by(|a, b| b["first_at"].as_str().cmp(&a["first_at"].as_str()));
            let models: Vec<Value> = models
                .into_iter()
                .filter(|(model, m)| !(m.fixed || (m.code == "unknown_model" && served(model))))
                .map(|(model, m)| {
                    json!({
                        "model": model,
                        "first_seen": time_list(&m.first),
                        "last_seen": time_list(&m.last),
                        "requests": m.requests,
                        "callers": m.callers,
                        "refusal": refusal(&m.code, &model),
                    })
                })
                .collect();
            let waiting = listed
                .iter()
                .filter(|c| matches!(c["state"].as_str(), Some("new" | "pending")))
                .count()
                + models.len();
            Ok(ok(json!({
                "set": setting.is_some(),
                "mode": setting.map(|s| s.mode.word()),
                "allowed": setting.map(|s| s.allowed.iter().collect::<Vec<_>>()).unwrap_or_default(),
                "may": crate::edit::edits_policy(&admin),
                "page": NEW_CALLERS_PAGE,
                "days": DAYS,
                "waiting": waiting,
                "callers": listed,
                "models": models,
            })))
        }
        .await,
    )
}

/// Each named caller and each model refused for want of a provider, from rows newest first.
fn fold(rows: &[Row]) -> (BTreeMap<String, Caller>, BTreeMap<String, Model>) {
    let mut callers: BTreeMap<String, Caller> = BTreeMap::new();
    let mut models: BTreeMap<String, Model> = BTreeMap::new();
    for row in rows {
        let (person, model) = (row.label("person"), row.label("model"));
        let refused = row.verdict != "allow";
        // A caller with no name (an unknown key, a login that named nobody) is no one to allow or block.
        if !person.is_empty() && person != "unknown" {
            let c = callers.entry(person.to_string()).or_default();
            if c.requests == 0 {
                c.last = row.time.clone();
                c.team = row.label("team").to_string();
            }
            c.first = row.time.clone();
            c.requests += 1;
            if refused {
                c.refused += 1;
                if c.code.is_empty() {
                    c.code = row.code.clone();
                    c.model = model.to_string();
                }
            }
        }
        if model.is_empty() {
            continue;
        }
        let first_for_model = !models.contains_key(model);
        if !refused && first_for_model {
            // The newest request for it went through: nothing to fix.
            models.insert(
                model.to_string(),
                Model {
                    fixed: true,
                    ..Model::default()
                },
            );
            continue;
        }
        if refused && !MODEL_CODES.contains(&row.code.as_str()) && first_for_model {
            continue;
        }
        let m = models.entry(model.to_string()).or_default();
        if m.fixed {
            continue;
        }
        if m.requests == 0 {
            m.last = row.time.clone();
            m.code = row.code.clone();
        }
        m.first = row.time.clone();
        m.requests += 1;
        if !person.is_empty() && !m.callers.iter().any(|c| c == person) {
            m.callers.push(person.to_string());
        }
    }
    (callers, models)
}

/// The `new_callers:` map of the policy, made when it has none.
fn setting(tree: &mut Map<String, Value>) -> Result<&mut Map<String, Value>, String> {
    tree.entry("new_callers")
        .or_insert_with(|| json!({ "mode": "allow" }))
        .as_object_mut()
        .ok_or_else(|| {
            "new_callers in the policy is not a map. Fix it under Policy file, Edit the file, then try again.".to_string()
        })
}

/// Takes `name` off both lists, then puts it on `list` (`None`: neither).
fn place(setting: &mut Map<String, Value>, name: &str, list: Option<&str>) {
    for which in ["allowed", "blocked"] {
        if let Some(Value::Array(names)) = setting.get_mut(which) {
            names.retain(|n| n.as_str() != Some(name));
            if names.is_empty() {
                setting.remove(which);
            }
        }
    }
    if let Some(list) = list {
        let names = setting.entry(list).or_insert_with(|| json!([]));
        if let Value::Array(names) = names {
            names.push(name.into());
        }
    }
}

/// `{"mode": "hold", "allow": ["billing-bot"]}`: what happens to new callers from now on, and the callers to allow
/// with it, so the ones already working keep working.
async fn mode_set(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            let body = body_of(&bytes)?;
            let mode = text(&body, "mode").to_string();
            if NewMode::parse(&mode).is_none() {
                return Err(bad(
                    "Send mode allow (let new callers through and list them here), hold (refuse them until an admin allows them) or block (refuse them; an admin can still allow them).",
                ));
            }
            let allow: Vec<String> = body
                .get("allow")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect();
            let note = if allow.is_empty() {
                format!("New callers: {mode}")
            } else {
                format!("New callers: {mode}, allowing {}", allow.join(", "))
            };
            let target = json!({ "mode": mode, "allow": allow });
            commit(&console, &admin, "set_new_callers", note, target, |tree| {
                let setting = setting(tree)?;
                setting.insert("mode".into(), mode.clone().into());
                for name in &allow {
                    place(setting, name, Some("allowed"));
                }
                Ok(())
            })
            .await
        }
        .await,
    )
}

/// `{"name": "billing-bot", "decision": "allow"}`: allow or block one caller by name, in force within 2 seconds.
async fn decide(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            let body = body_of(&bytes)?;
            let name = text(&body, "name").to_string();
            let decision = text(&body, "decision").to_string();
            let list = match decision.as_str() {
                "allow" => "allowed",
                "block" => "blocked",
                _ => {
                    return Err(bad(
                        "Send {\"name\": \"<caller>\", \"decision\": \"allow\"} to let a caller in, or \"block\" to refuse it.",
                    ));
                }
            };
            if name.is_empty() {
                return Err(bad(
                    "Name the caller to allow or block, as its key, person token or JWT names it, such as billing-bot.",
                ));
            }
            let note = format!("{} {name}", if list == "allowed" { "Allow" } else { "Block" });
            let target = json!({ "name": name, "decision": decision });
            commit(&console, &admin, "decide_new_caller", note, target, |tree| {
                place(setting(tree)?, &name, Some(list));
                Ok(())
            })
            .await
        }
        .await,
    )
}
