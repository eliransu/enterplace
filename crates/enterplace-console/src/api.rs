//! The JSON the console app (`console-ui/`, served at `/console/app/`) reads and writes: providers and their models,
//! MCP servers and which of their tools each rule allows, and the policy's basics (mode, rules, budgets, guardrails,
//! aliases). The app signs in with the console's own session cookie, so every call is checked as a page is.
//!
//! Every change goes through [`commit`]: the role must hold `edit_policy`, the change is recorded in the audit chain
//! with who made it before it is made, the new text is checked as `enterplace check` checks a file, and it is then
//! saved as a new version (policy kept in the store) or written over the file in one rename (policy kept in the
//! file). The answer says on how many gateways it is in force, or which refused it and why. A form edit writes the
//! policy without its comments.

use axum::{
    Router,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use enterplace_core::{
    catalog, config,
    policy::Permission,
    store,
    versions::{self, Refused},
};
use serde_json::{Map, Value, json};

use crate::{
    Act, Admin, Console, NOT_RECORDED, edit, guarded, read_only, record, redirect, same_origin,
};

pub(crate) fn routes() -> Router<Console> {
    Router::new()
        .route("/app", get(|| async { redirect("/console/app/") }))
        .route("/app/", get(app_index))
        .route("/app/{file}", get(app_file))
        .route("/api/me", get(me))
        .route("/api/providers", get(providers).post(provider_add))
        .route(
            "/api/providers/{name}",
            put(provider_edit).delete(provider_remove),
        )
        .route("/api/mcp", get(mcp_list).post(mcp_add))
        .route("/api/mcp/{name}", put(mcp_edit).delete(mcp_remove))
        .route("/api/mcp/{name}/tools", put(mcp_tools))
        .route("/api/policy", get(policy_get))
        .route("/api/policy/mode", put(mode_set))
        .route("/api/policy/identity", put(identity_set))
        .route("/api/policy/rules", post(rule_add))
        .route(
            "/api/policy/rules/{name}",
            put(rule_edit).delete(rule_remove),
        )
        .route("/api/policy/limits", post(limit_add))
        .route(
            "/api/policy/limits/{index}",
            put(limit_edit).delete(limit_remove),
        )
        .route("/api/policy/guardrails", post(guard_add))
        .route(
            "/api/policy/guardrails/{name}",
            put(guard_edit).delete(guard_remove),
        )
        .route("/api/policy/guardrails/{name}/on", put(guardrail_set))
        .route("/api/policy/guardrails/{name}/test", post(guardrail_test))
        .route("/api/policy/aliases", post(alias_add))
        .route(
            "/api/policy/aliases/{name}",
            put(alias_edit).delete(alias_remove),
        )
}

// ---------------------------------------------------------------- the app

const APP_HTML: &str = include_str!("../app/index.html");
const APP_JS: &str = include_str!("../app/app.js");
const APP_CSS: &str = include_str!("../app/app.css");

async fn app_index(State(console): State<Console>, headers: HeaderMap) -> Response {
    if console.admin(&headers).await.is_none() {
        return redirect("/console/sign-in");
    }
    guarded(
        (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            APP_HTML,
        )
            .into_response(),
    )
}

async fn app_file(Path(file): Path<String>) -> Response {
    let (kind, body) = match file.as_str() {
        "app.js" => ("text/javascript; charset=utf-8", APP_JS),
        "app.css" => ("text/css; charset=utf-8", APP_CSS),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    guarded(([(header::CONTENT_TYPE, kind)], body).into_response())
}

// ---------------------------------------------------------------- answers

/// A refusal: its status and what to tell the person, naming the cause and the fix.
pub struct Fail(pub StatusCode, pub String);

impl IntoResponse for Fail {
    fn into_response(self) -> Response {
        let mut response = (self.0, ok(json!({ "error": self.1 }))).into_response();
        *response.status_mut() = self.0;
        response
    }
}

pub fn bad(message: impl Into<String>) -> Fail {
    Fail(StatusCode::BAD_REQUEST, message.into())
}

pub fn ok(value: Value) -> Response {
    let mut response = (
        [(header::CONTENT_TYPE, "application/json")],
        value.to_string(),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    guarded(response)
}

pub type Answer = Result<Response, Fail>;

pub fn answer(result: Answer) -> Response {
    result.unwrap_or_else(IntoResponse::into_response)
}

/// A message from the core, as a sentence.
pub(crate) fn sentence(text: &str) -> String {
    let mut text = text.trim().to_string();
    if let Some(first) = text.get_mut(..1) {
        first.make_ascii_uppercase();
    }
    text
}

/// The signed-in admin, and for a change also a form from this console: a change from another site is refused.
pub async fn signed_in(
    console: &Console,
    headers: &HeaderMap,
    change: bool,
) -> Result<Admin, Fail> {
    if change && !same_origin(headers) {
        return Err(Fail(
            StatusCode::FORBIDDEN,
            "This change did not come from a console page at this address, so nothing was changed. Reload the console and try again.".into(),
        ));
    }
    console.admin(headers).await.ok_or_else(|| {
        Fail(
            StatusCode::UNAUTHORIZED,
            "You are not signed in, or your session ended. Sign in again at /console/sign-in."
                .into(),
        )
    })
}

pub fn body_of(bytes: &Bytes) -> Result<Map<String, Value>, Fail> {
    match serde_json::from_slice::<Value>(bytes) {
        Ok(Value::Object(map)) => Ok(map),
        // A plain HTML form (name=value&...) is read too, so a page can post without script.
        _ if bytes.contains(&b'=') => Ok(crate::Form::parse(&String::from_utf8_lossy(bytes))
            .pairs()
            .map(|(k, v)| (k.to_string(), Value::String(v.to_string())))
            .collect()),
        _ => Err(bad(
            "The request body is not a JSON object. Send the form's fields as JSON, for example {\"name\": \"openai\"}.",
        )),
    }
}

pub fn text<'a>(body: &'a Map<String, Value>, name: &str) -> &'a str {
    body.get(name).and_then(Value::as_str).unwrap_or("").trim()
}

/// A list of strings from a JSON list or a comma separated string, without blanks.
fn list(body: &Map<String, Value>, name: &str) -> Vec<String> {
    let items: Vec<String> = match body.get(name) {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        Some(Value::String(s)) => s.split(',').map(str::to_string).collect(),
        _ => Vec::new(),
    };
    items
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn strings(items: &[String]) -> Value {
    Value::Array(items.iter().map(|s| Value::String(s.clone())).collect())
}

fn name_ok(name: &str, what: &str, example: &str) -> Result<(), String> {
    if config::valid_name(name) {
        Ok(())
    } else {
        Err(format!(
            "A {what} name uses letters, digits, '.', '-', '_' and '@', at most 100 of them, for example {example}."
        ))
    }
}

// ---------------------------------------------------------------- the policy as a tree

/// The policy as it is now and the version it is, for a change to start from.
pub(crate) fn current(console: &Console) -> Result<(String, Option<i64>), Fail> {
    if let Some(v) = edit::live(console) {
        return Ok((v.text, Some(v.id)));
    }
    config::policy_text(&console.config().policy)
        .map(|t| (t, None))
        .map_err(|e| Fail(StatusCode::SERVICE_UNAVAILABLE, sentence(&e)))
}

fn read_tree(console: &Console) -> Result<Map<String, Value>, Fail> {
    let (text, _) = current(console)?;
    versions::tree(&text).map_err(|e| Fail(StatusCode::SERVICE_UNAVAILABLE, sentence(&e)))
}

/// The list section `name`, made when the policy has none.
fn section<'a>(map: &'a mut Map<String, Value>, name: &str) -> Result<&'a mut Vec<Value>, String> {
    match map.entry(name).or_insert_with(|| Value::Array(Vec::new())) {
        Value::Array(list) => Ok(list),
        _ => Err(format!(
            "The policy's {name} is not a list, so this page cannot change it. Fix it in the raw policy first."
        )),
    }
}

fn named(list: &[Value], name: &str) -> Option<usize> {
    list.iter()
        .position(|e| e.get("name").and_then(Value::as_str) == Some(name))
}

fn entry<'a>(
    map: &'a mut Map<String, Value>,
    list: &str,
    name: &str,
    what: &str,
) -> Result<&'a mut Map<String, Value>, String> {
    let items = section(map, list)?;
    let at = named(items, name).ok_or_else(|| {
        format!("There is no {what} named \"{name}\" in the policy: someone removed it. Reload the page.")
    })?;
    items[at].as_object_mut().ok_or_else(|| {
        format!("The {what} \"{name}\" is not a mapping. Fix it in the raw policy first.")
    })
}

fn remove_named(
    map: &mut Map<String, Value>,
    list: &str,
    name: &str,
    what: &str,
) -> Result<(), String> {
    let items = section(map, list)?;
    let at = named(items, name).ok_or_else(|| {
        format!("There is no {what} named \"{name}\" in the policy: someone removed it already. Reload the page.")
    })?;
    items.remove(at);
    if items.is_empty() && list != "providers" && list != "rules" {
        map.remove(list);
    }
    Ok(())
}

fn str_list(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|v| match v {
                Value::String(s) => Some(s.clone()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            })
            .collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------- saving

/// Makes one change to the policy: checked for the role, recorded with who made it, checked as `enterplace check`
/// checks a file, then saved. `edit` changes the policy's tree; its `Err` is what to tell the person.
async fn commit(
    console: &Console,
    admin: &Admin,
    action: &'static str,
    note: String,
    target: Value,
    edit: impl FnOnce(&mut Map<String, Value>) -> Result<(), String>,
) -> Answer {
    if !edit::edits_policy(admin) {
        read_only(console, admin, action).await;
        return Err(Fail(
            StatusCode::FORBIDDEN,
            "Your role may not change the policy. Ask an admin whose role has edit_policy to make this change.".into(),
        ));
    }
    let (before, base) = current(console)?;
    let mut tree = versions::tree(&before).map_err(|e| bad(sentence(&e)))?;
    let act = |target: Value| Act {
        action,
        by: Some((&admin.name, &admin.team)),
        key: None,
        target,
    };
    if let Err(error) = edit(&mut tree) {
        let _ = record(console, &act(target), Some("invalid_request"), None).await;
        return Err(bad(error));
    }
    let after = versions::with_comments(&before, &versions::to_yaml(&Value::Object(tree)));
    if after == before {
        return Ok(ok(
            json!({ "message": "Nothing changed: the policy already says this." }),
        ));
    }
    save_text(console, admin, action, note, target, before, after, base).await
}

/// Saves `after` (drafted on `before`, the store's version `base` when the policy is kept there) as the policy:
/// a new version in the store, or the file rewritten in one rename. Recorded first, with the whole text; checked
/// as `enterplace check` checks a file. The answer waits a few seconds for the gateways to report on it, so it
/// says where it is in force, or which gateway refused it and why.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn save_text(
    console: &Console,
    admin: &Admin,
    action: &'static str,
    note: String,
    target: Value,
    before: String,
    after: String,
    base: Option<i64>,
) -> Answer {
    if base.is_some() {
        return match edit::save_version(console, admin, action, after, base, note).await {
            Ok(v) if v.state == store::PENDING => Ok(ok(json!({
                "message": format!("Saved as version {}. It waits for a second admin to approve it under Policy, Versions.", v.id),
                "version": v.id,
            }))),
            Ok(v) => Ok(ok(json!({
                "message": edit::in_force(console, Some(v.id), &v.sha256).await,
                "version": v.id,
            }))),
            Err(err) => Err(refused(&err)),
        };
    }
    let sha256 = enterplace_core::id::sha256_hex(after.as_bytes());
    let mut target = target;
    if let Value::Object(t) = &mut target {
        t.insert("sha256".into(), sha256.clone().into());
        if !note.is_empty() {
            t.insert("note".into(), note.into());
        }
        // The policy holds no secrets: the chain keeps the whole text, as a saved version would. The file's
        // versions are read back from these records.
        t.insert("policy".into(), after.clone().into());
    }
    let act = Act {
        action,
        by: Some((&admin.name, &admin.team)),
        key: None,
        target,
    };
    if record(console, &act, None, None).await.is_err() {
        return Err(Fail(StatusCode::SERVICE_UNAVAILABLE, NOT_RECORDED.into()));
    }
    let c = console.config();
    let (policy, keys) = (c.policy.clone(), c.keys.clone());
    let written = tokio::task::spawn_blocking(move || write_file(&policy, &keys, &before, &after))
        .await
        .unwrap_or_else(|err| {
            Err(Refused::Store(format!(
                "nothing was changed: {err}. Try again."
            )))
        });
    match written {
        Ok(()) => Ok(ok(json!({
            "message": edit::in_force(console, None, &sha256).await,
        }))),
        Err(err) => {
            let _ = record(console, &act, Some("invalid_policy"), Some(&err.message())).await;
            Err(refused(&err))
        }
    }
}

pub(crate) fn refused(err: &Refused) -> Fail {
    let status = match err {
        Refused::Invalid(_) => StatusCode::BAD_REQUEST,
        Refused::ReadOnly(_) | Refused::Forbidden(_) => StatusCode::FORBIDDEN,
        Refused::Conflict(_) => StatusCode::CONFLICT,
        Refused::Unknown(_) => StatusCode::NOT_FOUND,
        Refused::Store(_) => StatusCode::SERVICE_UNAVAILABLE,
    };
    let message = match err {
        Refused::Invalid(problems) => format!(
            "The policy would not pass enterplace check with this change, so nothing was changed. {}",
            problems.join(" ")
        ),
        other => sentence(&other.message()),
    };
    Fail(status, message)
}

/// One writer at a time: two changes read, check and write the file in turn, so neither is lost.
static WRITING: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Writes the policy file when it still holds `before` and `after` passes the check: beside it, then renamed over
/// it, so a gateway reading it never sees half a file.
fn write_file(
    path: &std::path::Path,
    keys: &std::path::Path,
    before: &str,
    after: &str,
) -> Result<(), Refused> {
    let _held = WRITING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let now = std::fs::read_to_string(path).map_err(|err| {
        Refused::Store(format!(
            "{} cannot be read ({err}). Nothing was changed.",
            path.display()
        ))
    })?;
    if now != before {
        return Err(Refused::Conflict(
            "the policy changed since this page read it, so nothing was changed. Reload and make the change again.".into(),
        ));
    }
    let loaded = config::load(path, Some(keys)).map_err(Refused::Invalid)?;
    versions::check(path, keys, after, &loaded).map_err(Refused::Invalid)?;
    let temp = path.with_file_name(".enterplace.policy.console.yaml");
    let write = || -> std::io::Result<()> {
        use std::io::Write as _;
        let mut file = std::fs::File::create(&temp)?;
        file.write_all(after.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&temp, path)
    };
    write().map_err(|err| {
        let _ = std::fs::remove_file(&temp);
        Refused::Store(format!(
            "{} cannot be written ({err}), so nothing was changed. Give Enterplace write access to the policy's folder, or keep the policy in the store (store.policy_from: store).",
            path.display()
        ))
    })
}

// ---------------------------------------------------------------- who is signed in

async fn me(State(console): State<Console>, headers: HeaderMap) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, false).await?;
            let loaded = config::load(&console.config().policy, Some(&console.config().keys));
            let passthrough = |unnamed: bool| {
                loaded.as_ref().is_ok_and(|l| {
                    l.providers
                        .iter()
                        .any(|p| p.passthrough && (!unnamed || p.identity_optional))
                })
            };
            Ok(ok(json!({
                "name": admin.name,
                "role": admin.role,
                "edit_policy": edit::edits_policy(&admin),
                "credentials": admin.may(Permission::Credentials) && !admin.confined(),
                "source": if edit::live(&console).is_some() { "store" } else { "file" },
                "policy": console.config().policy.display().to_string(),
                // The pages an embedding binary adds (Members, Alerts and the like), server rendered, for the app's nav.
                "tools": crate::html::EXTRA.try_with(|e| e.nav.iter().map(|(href, label)| json!({ "href": href, "label": label })).collect::<Vec<Value>>()).unwrap_or_default(),
            // Every page says so, as the server-rendered pages do: nothing the policy refuses is stopped.
            "observe": loaded
                .as_ref()
                .is_ok_and(|l| l.policy.mode() == enterplace_core::policy::Mode::Observe),
            // Whether every request carries a person's name. Only a passthrough provider with identity: optional
            // lets one in without, recorded as the person unknown; the app warns while it does.
            "names": {
                "required": !passthrough(true),
                "passthrough": passthrough(false),
            },
            })))
        }
        .await,
    )
}

// ---------------------------------------------------------------- providers

async fn providers(State(console): State<Console>, headers: HeaderMap) -> Response {
    answer(async {
        signed_in(&console, &headers, false).await?;
        let tree = read_tree(&console)?;
        let list: Vec<Value> = str_objects(tree.get("providers"))
            .map(|p| {
                let key = if p.get("auth").and_then(Value::as_str) == Some("passthrough") {
                    "each caller's own login".to_string()
                } else if let Some(c) = p.get("credential").and_then(Value::as_str) {
                    format!("sealed credential {c}")
                } else if let Some(e) = p.get("key_env").and_then(Value::as_str) {
                    format!("environment variable {e}")
                } else if p.get("preset").or_else(|| p.get("kind")).and_then(Value::as_str).and_then(catalog::find).is_some_and(|c| c.key_need() == "none") {
                    "no key needed".to_string()
                } else {
                    "none".to_string()
                };
                json!({
                    "name": p.get("name").cloned().unwrap_or(Value::Null),
                    "kind": p.get("preset").or_else(|| p.get("kind")).cloned().unwrap_or(Value::Null),
                    "url": p.get("url").cloned().unwrap_or(Value::Null),
                    "key": key,
                    "models": str_list(p.get("models")),
                    "retries": p.get("retries").cloned().unwrap_or(Value::Null),
                    "fallback": p.get("fallback").cloned().unwrap_or(Value::Null),
                })
            })
            .collect();
        let presets: Vec<Value> = catalog::PRESETS
            .iter()
            .map(|p| {
                let models = catalog::default_models(p.id);
                json!({ "id": p.id, "name": p.name, "local": p.local, "needs_url": p.needs_url(), "key": p.key_need(), "models": models })
            })
            .collect();
        let policy = &console.config().policy;
        Ok(ok(json!({
            "providers": list,
            "catalog": presets,
            "sealing": store::credentials_for(&console.config().keys).is_some(),
            "master_key_agent": crate::start::master_key_prompt(&crate::base()),
            "docs": format!("{}/governance/provider-credentials/", crate::start::DOCS),
            "agent": crate::start::provider_prompt(&crate::base(), &policy.display().to_string(), store::policy_store(policy).is_some()),
        })))
    }.await)
}

fn str_objects(value: Option<&Value>) -> impl Iterator<Item = &Map<String, Value>> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
}

/// Seals a pasted provider key as credential `name`, recorded first as Credentials records it. The value is in no
/// record and in no answer.
async fn seal(
    console: &Console,
    admin: &Admin,
    name: &str,
    provider: &str,
    value: &str,
) -> Result<(), Fail> {
    let mut act = Act {
        action: "add_credential",
        by: Some((&admin.name, &admin.team)),
        key: None,
        target: json!({ "name": name, "provider": provider, "fingerprint": store::fingerprint(value), "via": "app" }),
    };
    if !admin.may(Permission::Credentials) || admin.confined() {
        read_only(console, admin, "add_credential").await;
        return Err(Fail(
            StatusCode::FORBIDDEN,
            "Your role may not add provider keys, which serve the whole install. Ask an admin, or name an environment variable instead of pasting the key.".into(),
        ));
    }
    if let Some(problem) = store::credential_value_problem(value) {
        let _ = record(console, &act, Some("invalid_request"), None).await;
        return Err(bad(sentence(problem)));
    }
    let Some(vault) = store::credentials_for(&console.config().keys) else {
        return Err(bad(
            "Provider keys are sealed under a master key, and this gateway has none. Set ENTERPLACE_MASTER_KEY (64 hex characters) and restart Enterplace, or name an environment variable that holds the key instead.",
        ));
    };
    let exists = vault
        .credentials()
        .map(|list| list.iter().any(|c| c.name == name))
        .unwrap_or(false);
    if exists {
        act.action = "rotate_credential";
    }
    record(console, &act, None, None)
        .await
        .map_err(|()| Fail(StatusCode::SERVICE_UNAVAILABLE, NOT_RECORDED.into()))?;
    let (n, p, v, by) = (
        name.to_string(),
        provider.to_string(),
        value.to_string(),
        admin.name.clone(),
    );
    let stored = tokio::task::spawn_blocking(move || {
        if exists {
            vault.rotate_credential(&n, &v, &by).map(|_| ())
        } else {
            vault.add_credential(&n, &p, &v, &by).map(|_| ())
        }
    })
    .await
    .unwrap_or_else(|err| Err(format!("nothing was changed: {err}. Try again.")));
    if let Err(err) = stored {
        let _ = record(console, &act, Some("store"), Some(&err)).await;
        return Err(Fail(StatusCode::SERVICE_UNAVAILABLE, sentence(&err)));
    }
    Ok(())
}

fn models_ok(models: &[String]) -> Result<(), String> {
    if models.is_empty() {
        return Err("List at least one model the provider serves, for example gpt-4o-mini, or * for every model it has.".into());
    }
    match models.iter().find(|m| m.contains(char::is_whitespace)) {
        Some(m) => Err(format!(
            "The model \"{m}\" has a space in it. Separate models with commas."
        )),
        None => Ok(()),
    }
}

/// Sets what an edit form changes of a provider: its models, retries and fallback provider.
fn provider_fields(
    entry: &mut Map<String, Value>,
    body: &Map<String, Value>,
) -> Result<(), String> {
    let models = list(body, "models");
    models_ok(&models)?;
    entry.insert("models".into(), strings(&models));
    match body.get("retries") {
        Some(Value::Number(n)) => match n.as_u64() {
            Some(r) if r <= 10 => {
                entry.insert("retries".into(), r.into());
            }
            _ => return Err("Retries is a whole number from 0 to 10.".into()),
        },
        Some(Value::String(s)) if !s.trim().is_empty() => match s.trim().parse::<u64>() {
            Ok(r) if r <= 10 => {
                entry.insert("retries".into(), r.into());
            }
            _ => return Err("Retries is a whole number from 0 to 10.".into()),
        },
        Some(_) => {
            entry.remove("retries");
        }
        None => {}
    }
    if body.contains_key("fallback") {
        match text(body, "fallback") {
            "" => {
                entry.remove("fallback");
            }
            f => {
                entry.insert("fallback".into(), f.into());
            }
        }
    }
    Ok(())
}

async fn provider_add(
    State(console): State<Console>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    answer(async {
        let admin = signed_in(&console, &headers, true).await?;
        let body = body_of(&bytes)?;
        let preset_id = text(&body, "preset");
        let name = match text(&body, "name") {
            "" => preset_id.to_string(),
            n => n.to_string(),
        };
        let target = json!({ "provider": name, "preset": preset_id });
        let Some(preset) = catalog::find(preset_id) else {
            return Err(bad(format!(
                "\"{preset_id}\" is not in the provider catalog. Pick a provider from the list."
            )));
        };
        name_ok(&name, "provider", "openai-prod").map_err(bad)?;
        let url = text(&body, "url").to_string();
        if preset.needs_url() && url.is_empty() {
            return Err(bad(format!(
                "{} needs its own URL, like {}. Paste the URL of your account.",
                preset.name, preset.url
            )));
        }
        // A provider that takes no key keeps none, whatever the form sent: the demo model is answered inside the
        // gateway, and AWS signs with its own credentials.
        let (key, key_env) = match preset.key_need() {
            "none" => (String::new(), String::new()),
            _ => (text(&body, "key").to_string(), text(&body, "key_env").to_string()),
        };
        if key.is_empty() && key_env.is_empty() && preset.key_need() == "required" {
            return Err(bad(format!(
                "{} needs a key: paste it to keep it sealed, or name the environment variable that holds it.",
                preset.name
            )));
        }
        // Checked before a key is sealed: a refused provider leaves no credential behind.
        let tree = read_tree(&console)?;
        if str_objects(tree.get("providers")).any(|p| p.get("name").and_then(Value::as_str) == Some(name.as_str())) {
            return Err(bad(format!(
                "There is a provider named \"{name}\" already. Give this one another name, for example {name}-2, or edit that one."
            )));
        }
        let models = list(&body, "models");
        models_ok(&models).map_err(bad)?;
        if !edit::edits_policy(&admin) {
            read_only(&console, &admin, "connect_provider").await;
            return Err(Fail(
                StatusCode::FORBIDDEN,
                "Your role may not change the policy. Ask an admin whose role has edit_policy to add a provider.".into(),
            ));
        }
        // A gateway refuses a policy whose provider key variable is unset and keeps the one it has: saved, it would
        // read as in force while no gateway used it.
        if key.is_empty() && !key_env.is_empty() && std::env::var_os(&key_env).is_none() {
            return Err(bad(format!(
                "{key_env} is not set where Enterplace runs, so every gateway would refuse the policy with this provider and keep the one it has. Paste the key above to keep it sealed in Enterplace, or set {key_env} on every gateway (export {key_env}=...), restart them, and add the provider again."
            )));
        }
        if !key.is_empty() {
            seal(&console, &admin, &name, preset.id, &key).await?;
        }
        let mut entry = Map::new();
        entry.insert("name".into(), name.clone().into());
        entry.insert("preset".into(), preset.id.into());
        if !key.is_empty() {
            entry.insert("credential".into(), name.clone().into());
        } else if !key_env.is_empty() {
            entry.insert("key_env".into(), key_env.into());
        }
        if !url.is_empty() {
            entry.insert("url".into(), url.clone().into());
        }
        if preset.local || (!url.is_empty() && config::is_private(&url)) {
            entry.insert("allow_private".into(), true.into());
        }
        entry.insert("models".into(), strings(&models));
        let note = format!("Add provider {name}");
        commit(&console, &admin, "connect_provider", note, target, move |tree| {
            section(tree, "providers")?.push(Value::Object(entry));
            Ok(())
        })
        .await
    }.await)
}

async fn provider_edit(
    State(console): State<Console>,
    Path(name): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            let body = body_of(&bytes)?;
            let target = json!({ "provider": name, "models": list(&body, "models") });
            let note = format!("Change provider {name}");
            commit(&console, &admin, "change_provider", note, target, |tree| {
                provider_fields(entry(tree, "providers", &name, "provider")?, &body)
            })
            .await
        }
        .await,
    )
}

async fn provider_remove(
    State(console): State<Console>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            let note = format!("Remove provider {name}");
            commit(
                &console,
                &admin,
                "remove_provider",
                note,
                json!({ "provider": name }),
                |tree| remove_named(tree, "providers", &name, "provider"),
            )
            .await
        }
        .await,
    )
}

// ---------------------------------------------------------------- MCP servers

/// Whether a rule entry (`github.create_issue`, `!github.*`) names a tool of `server`.
fn of_server(entry: &str, server: &str) -> bool {
    entry
        .strip_prefix('!')
        .unwrap_or(entry)
        .split_once('.')
        .is_some_and(|(s, _)| s == server)
}

async fn mcp_list(State(console): State<Console>, headers: HeaderMap) -> Response {
    answer(async {
        signed_in(&console, &headers, false).await?;
        let tree = read_tree(&console)?;
        let rules: Vec<&Map<String, Value>> = str_objects(tree.get("rules")).collect();
        let servers: Vec<Value> = str_objects(tree.get("mcp"))
            .map(|s| {
                let name = s.get("name").and_then(Value::as_str).unwrap_or("");
                let transport = s.get("transport").and_then(Value::as_str).unwrap_or(
                    if s.contains_key("command") { "stdio" } else { "http" },
                );
                let (auth, header, env) = match (s.get("user_auth").and_then(Value::as_str), s.get("headers_env").and_then(Value::as_object)) {
                    (Some(u), _) => (u.to_string(), String::new(), String::new()),
                    (None, Some(h)) => match h.iter().next() {
                        Some((k, v)) => ("header".into(), k.clone(), v.as_str().unwrap_or("").to_string()),
                        None => ("none".into(), String::new(), String::new()),
                    },
                    (None, None) => ("none".into(), String::new(), String::new()),
                };
                let access: Vec<Value> = rules
                    .iter()
                    .map(|r| {
                        let tools = str_list(r.get("tools"));
                        let mine = |deny: bool| -> Vec<String> {
                            tools
                                .iter()
                                .filter(|t| t.starts_with('!') == deny && of_server(t, name))
                                .map(|t| t.trim_start_matches('!').split_once('.').map_or(String::new(), |(_, tool)| tool.to_string()))
                                .collect()
                        };
                        json!({
                            "rule": r.get("name").cloned().unwrap_or(Value::Null),
                            "allow": mine(false),
                            "deny": mine(true),
                            "everything": tools.iter().any(|t| t == "*"),
                        })
                    })
                    .collect();
                json!({
                    "name": name,
                    "transport": transport,
                    "url": s.get("url").cloned().unwrap_or(Value::Null),
                    "command": s.get("command").cloned().unwrap_or(Value::Null),
                    "args": str_list(s.get("args")),
                    "auth": auth,
                    "auth_header": header,
                    "auth_env": env,
                    "allow_private": s.get("allow_private").and_then(Value::as_bool).unwrap_or(false),
                    "access": access,
                })
            })
            .collect();
        // Agents reach every server's tools at the gateway's one /mcp address, never at the server itself.
        Ok(ok(json!({ "servers": servers, "gateway": format!("{}/mcp", crate::base()) })))
    }.await)
}

/// Sets what the server form changes of an MCP server: how it is reached and how it signs in. Prices, tool change
/// handling and the rarer sign-in settings are kept.
fn mcp_fields(entry: &mut Map<String, Value>, body: &Map<String, Value>) -> Result<(), String> {
    for key in [
        "transport",
        "url",
        "command",
        "args",
        "headers_env",
        "user_auth",
        "allow_private",
    ] {
        entry.remove(key);
    }
    match text(body, "transport") {
        "" | "http" | "sse" => {
            let url = text(body, "url");
            if !(url.starts_with("https://") || url.starts_with("http://")) {
                return Err("An MCP server over HTTP needs its URL, starting with https://, for example https://mcp.example.com/mcp.".into());
            }
            if text(body, "transport") == "sse" {
                entry.insert("transport".into(), "sse".into());
            }
            entry.insert("url".into(), url.into());
            if config::is_private(url) {
                entry.insert("allow_private".into(), true.into());
            }
        }
        "stdio" => {
            let command = text(body, "command");
            if !command.starts_with('/') {
                return Err(format!(
                    "A stdio MCP server needs command, the absolute path of the program to start, for example /usr/local/bin/mcp-server-git. The gateway starts it only when {} lists that path.",
                    enterplace_core::mcp::STDIO_ALLOW_ENV
                ));
            }
            entry.insert("transport".into(), "stdio".into());
            entry.insert("command".into(), command.into());
            let args = list(body, "args");
            if !args.is_empty() {
                entry.insert("args".into(), strings(&args));
            }
        }
        other => {
            return Err(format!(
                "Transport \"{other}\" is not one Enterplace speaks. Pick http, sse or stdio."
            ));
        }
    }
    match text(body, "auth") {
        "" | "none" => {}
        "header" => {
            let header = match text(body, "auth_header") {
                "" => "Authorization",
                h => h,
            };
            let env = text(body, "auth_env");
            if env.is_empty() || !env.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err("Name the environment variable that holds the header's value, for example GITHUB_MCP_TOKEN: letters, digits and _ only. The value itself never goes in the policy.".into());
            }
            let mut headers = Map::new();
            headers.insert(header.into(), env.into());
            entry.insert("headers_env".into(), Value::Object(headers));
        }
        "oauth" => {
            entry.insert("user_auth".into(), "oauth".into());
        }
        other => {
            return Err(format!(
                "Sign-in \"{other}\" is not one this form sets. Pick none, header or oauth; the raw policy sets the others."
            ));
        }
    }
    Ok(())
}

async fn mcp_add(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    answer(async {
        let admin = signed_in(&console, &headers, true).await?;
        let body = body_of(&bytes)?;
        let name = text(&body, "name").to_string();
        let target = json!({ "server": name });
        let note = format!("Add MCP server {name}");
        commit(&console, &admin, "add_mcp_server", note, target, |tree| {
            if name.is_empty() || name.contains('.') || !config::valid_name(&name) {
                return Err("An MCP server name uses letters, digits, '-', '_' and '@', with no dot, for example github.".into());
            }
            let servers = section(tree, "mcp")?;
            if named(servers, &name).is_some() {
                return Err(format!("There is an MCP server named \"{name}\" already. Pick another name, or edit that one."));
            }
            let mut entry = Map::new();
            entry.insert("name".into(), name.clone().into());
            mcp_fields(&mut entry, &body)?;
            servers.push(Value::Object(entry));
            Ok(())
        })
        .await
    }.await)
}

async fn mcp_edit(
    State(console): State<Console>,
    Path(name): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            let body = body_of(&bytes)?;
            let note = format!("Change MCP server {name}");
            commit(
                &console,
                &admin,
                "change_mcp_server",
                note,
                json!({ "server": name }),
                |tree| mcp_fields(entry(tree, "mcp", &name, "MCP server")?, &body),
            )
            .await
        }
        .await,
    )
}

/// The rule lists that name MCP tools, prompts and resources by server.
const RULE_MCP_LISTS: [&str; 4] = ["tools", "approve_tools", "prompts", "resources"];

async fn mcp_remove(
    State(console): State<Console>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            let note = format!("Remove MCP server {name}");
            commit(
                &console,
                &admin,
                "remove_mcp_server",
                note,
                json!({ "server": name }),
                |tree| {
                    remove_named(tree, "mcp", &name, "MCP server")?;
                    // A rule naming a tool of a server that is gone does not load: what the rules said of it goes too.
                    for rule in section(tree, "rules")?
                        .iter_mut()
                        .filter_map(Value::as_object_mut)
                    {
                        for key in RULE_MCP_LISTS {
                            let kept: Vec<String> = str_list(rule.get(key))
                                .into_iter()
                                .filter(|e| !of_server(e, &name))
                                .collect();
                            if kept.is_empty() {
                                rule.remove(key);
                            } else if rule.contains_key(key) {
                                rule.insert(key.into(), strings(&kept));
                            }
                        }
                    }
                    Ok(())
                },
            )
            .await
        }
        .await,
    )
}

/// Sets, for each rule named, which tools of this server it allows and which it denies (`!server.tool`).
async fn mcp_tools(
    State(console): State<Console>,
    Path(name): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    answer(async {
        let admin = signed_in(&console, &headers, true).await?;
        let body = body_of(&bytes)?;
        let target = json!({ "server": name, "rules": body.get("rules").cloned().unwrap_or(Value::Null) });
        let note = format!("Change which tools of MCP server {name} each rule allows");
        commit(&console, &admin, "change_mcp_tools", note, target, |tree| {
            if named(section(tree, "mcp")?, &name).is_none() {
                return Err(format!("There is no MCP server named \"{name}\" in the policy: someone removed it. Reload the page."));
            }
            let Some(Value::Array(changes)) = body.get("rules") else {
                return Err("Send rules: a list of { rule, allow, deny }, each a list of tool names of this server, or * for all.".into());
            };
            for change in changes.iter().filter_map(Value::as_object) {
                let rule_name = text(change, "rule");
                let rule = entry(tree, "rules", rule_name, "rule")?;
                let mut tools: Vec<String> = str_list(rule.get("tools")).into_iter().filter(|t| !of_server(t, &name)).collect();
                for (key, mark) in [("allow", ""), ("deny", "!")] {
                    for tool in list(change, key) {
                        if tool.contains(char::is_whitespace) || tool.contains('*') && tool != "*" {
                            return Err(format!("\"{tool}\" is not a tool name. Write the tool's name as the server lists it, or * for every tool of the server."));
                        }
                        tools.push(format!("{mark}{name}.{tool}"));
                    }
                }
                if tools.is_empty() {
                    rule.remove("tools");
                } else {
                    rule.insert("tools".into(), strings(&tools));
                }
            }
            Ok(())
        })
        .await
    }.await)
}

// ---------------------------------------------------------------- policy basics

/// What a limit is for: one of these scopes, as `limits:` names them. Any but global and org may be kept to one
/// organization with `org:` beside it.
const SCOPES: [&str; 9] = [
    "global",
    "org",
    "team",
    "person",
    "key",
    "customer",
    "tag",
    "model",
    "model_group",
];
const PERIODS: [&str; 4] = ["hour", "day", "week", "month"];
const RATES: [&str; 5] = ["rpm", "tpm", "rph", "rpd", "tpd"];

async fn policy_get(State(console): State<Console>, headers: HeaderMap) -> Response {
    answer(async {
        signed_in(&console, &headers, false).await?;
        let tree = read_tree(&console)?;
        let rules: Vec<Value> = str_objects(tree.get("rules"))
            .map(|r| {
                let p = r.get("principals").and_then(Value::as_object);
                let who = p.map_or(json!({ "kind": "other", "value": "" }), |p| {
                    if p.get("any").and_then(Value::as_bool) == Some(true) {
                        json!({ "kind": "any", "value": "" })
                    } else if let Some(t) = p.get("team") {
                        json!({ "kind": "team", "value": t })
                    } else if let Some(n) = p.get("name") {
                        json!({ "kind": "name", "value": n })
                    } else if let Some(t) = p.get("tag") {
                        json!({ "kind": "tag", "value": t })
                    } else {
                        json!({ "kind": "other", "value": "" })
                    }
                });
                json!({
                    "name": r.get("name").cloned().unwrap_or(Value::Null),
                    "who": who,
                    "models": str_list(r.get("models")),
                    "guardrails": str_list(r.get("guardrails")),
                })
            })
            .collect();
        // Each limit with its place in the list and its text as read: a change names both, so it is refused when
        // someone else changed the list meanwhile.
        let limits: Vec<Value> = tree
            .get("limits")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
            .map(|(i, l)| json!({ "index": i, "entry": l }))
            .collect();
        let defaults = str_list(tree.get("default_guardrails"));
        let guardrails: Vec<Value> = str_objects(tree.get("guardrails"))
            .map(|g| {
                let name = g.get("name").and_then(Value::as_str).unwrap_or("");
                json!({
                    "name": name,
                    "type": g.get("type").cloned().unwrap_or(Value::Null),
                    "action": g.get("action").cloned().unwrap_or(Value::Null),
                    "on": defaults.iter().any(|d| d == name),
                    "entry": g,
                })
            })
            .collect();
        let aliases: Vec<Value> = str_objects(tree.get("aliases"))
            .map(|a| {
                let deployments: Vec<Value> = str_objects(a.get("deployments"))
                    .map(|d| json!({ "provider": d.get("provider").cloned().unwrap_or(Value::Null), "model": d.get("model").cloned().unwrap_or(Value::Null) }))
                    .collect();
                json!({
                    "name": a.get("name").cloned().unwrap_or(Value::Null),
                    "deployments": deployments,
                    "fallbacks": str_list(a.get("fallbacks")),
                })
            })
            .collect();
        let policy = &console.config().policy;
        let agent = crate::start::guardrail_prompt(
            &crate::base(),
            &policy.display().to_string(),
            enterplace_core::store::policy_store(policy).is_some(),
        );
        let limit_agent = crate::start::limit_prompt(
            &crate::base(),
            &policy.display().to_string(),
            enterplace_core::store::policy_store(policy).is_some(),
        );
        Ok(ok(json!({
            "guard_agent": agent,
            "limit_agent": limit_agent,
            "mode": tree.get("mode").and_then(Value::as_str).unwrap_or("enforce"),
            "rules": rules,
            "limits": limits,
            "guardrails": guardrails,
            "aliases": aliases,
        })))
    }.await)
}

async fn mode_set(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    answer(async {
        let admin = signed_in(&console, &headers, true).await?;
        let body = body_of(&bytes)?;
        let mode = text(&body, "mode").to_string();
        let note = format!("Set mode to {mode}");
        commit(&console, &admin, "set_mode", note, json!({ "mode": mode }), |tree| {
            match mode.as_str() {
                "enforce" => {
                    tree.remove("mode");
                }
                "observe" => {
                    tree.insert("mode".into(), "observe".into());
                }
                _ => return Err("Mode is enforce (refuse what the policy does not allow) or observe (let it through and record it).".into()),
            }
            Ok(())
        })
        .await
    }.await)
}

/// Whether a subscription request must name its person: `identity` on every passthrough provider at once, so the
/// install answers one way for Claude Code and Codex alike.
async fn identity_set(
    State(console): State<Console>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    answer(async {
        let admin = signed_in(&console, &headers, true).await?;
        let body = body_of(&bytes)?;
        let required = body.get("required").and_then(Value::as_bool).ok_or_else(|| {
            bad("Send {\"required\": true} to refuse a subscription request that names no person, or {\"required\": false} to record it as the person unknown.")
        })?;
        let note = if required {
            "Require a name on every request"
        } else {
            "Allow unnamed requests, recorded as unknown"
        };
        commit(&console, &admin, "set_identity", note.into(), json!({ "required": required }), |tree| {
            let mut found = false;
            for p in section(tree, "providers")?.iter_mut().filter_map(Value::as_object_mut) {
                if p.get("auth").and_then(Value::as_str) == Some("passthrough") {
                    p.insert("identity".into(), if required { "required" } else { "optional" }.into());
                    found = true;
                }
            }
            if found {
                Ok(())
            } else {
                Err("No provider takes subscription logins, so every request already carries an Enterplace key that names its person.".into())
            }
        })
        .await
    }.await)
}

/// Sets what the rule form changes of a rule: who it is for, its models and its guardrails.
fn rule_fields(rule: &mut Map<String, Value>, body: &Map<String, Value>) -> Result<(), String> {
    let who = body.get("who").and_then(Value::as_object);
    let kind = who.map_or("", |w| text(w, "kind"));
    let value = who.map_or("", |w| text(w, "value"));
    let principals = match kind {
        "any" => json!({ "any": true }),
        "team" | "name" | "tag" if config::valid_name(value) => json!({ kind: value }),
        "team" | "name" | "tag" => {
            return Err(format!(
                "Name the {} the rule is for: letters, digits, '.', '-', '_' and '@'.",
                if kind == "name" { "person" } else { kind }
            ));
        }
        _ => return Err("Pick who the rule is for: everyone, a team, a person or a tag.".into()),
    };
    rule.insert("principals".into(), principals);
    let models = list(body, "models");
    if models.is_empty() {
        return Err(
            "List the models the rule allows, for example gpt-4o-mini, or * for every model."
                .into(),
        );
    }
    rule.insert("models".into(), strings(&models));
    let guardrails = list(body, "guardrails");
    if guardrails.is_empty() {
        rule.remove("guardrails");
    } else {
        rule.insert("guardrails".into(), strings(&guardrails));
    }
    Ok(())
}

fn is_any(rule: &Value) -> bool {
    rule.get("principals")
        .and_then(|p| p.get("any"))
        .and_then(Value::as_bool)
        == Some(true)
}

async fn rule_add(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    answer(async {
        let admin = signed_in(&console, &headers, true).await?;
        let body = body_of(&bytes)?;
        let name = text(&body, "name").to_string();
        let note = format!("Add rule {name}");
        commit(&console, &admin, "add_rule", note, json!({ "rule": name }), |tree| {
            name_ok(&name, "rule", "payments-team")?;
            let mut rule = Map::new();
            rule.insert("name".into(), name.clone().into());
            rule_fields(&mut rule, &body)?;
            let rule = Value::Object(rule);
            let rules = section(tree, "rules")?;
            if named(rules, &name).is_some() {
                return Err(format!("There is a rule named \"{name}\" already. Pick another name, or edit that one."));
            }
            // The first rule that matches decides: a rule for a team goes before the one for everyone, or it never would.
            let at = if is_any(&rule) { None } else { rules.iter().position(is_any) };
            match at {
                Some(at) => rules.insert(at, rule),
                None => rules.push(rule),
            }
            Ok(())
        })
        .await
    }.await)
}

async fn rule_edit(
    State(console): State<Console>,
    Path(name): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            let body = body_of(&bytes)?;
            let note = format!("Change rule {name}");
            commit(
                &console,
                &admin,
                "change_rule",
                note,
                json!({ "rule": name }),
                |tree| rule_fields(entry(tree, "rules", &name, "rule")?, &body),
            )
            .await
        }
        .await,
    )
}

async fn rule_remove(
    State(console): State<Console>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            let note = format!("Remove rule {name}");
            commit(
                &console,
                &admin,
                "remove_rule",
                note,
                json!({ "rule": name }),
                |tree| remove_named(tree, "rules", &name, "rule"),
            )
            .await
        }
        .await,
    )
}

/// A number from a form: a JSON number or a string of one. `Ok(None)` for empty.
fn number(body: &Map<String, Value>, name: &str) -> Result<Option<f64>, String> {
    match body.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => Ok(n.as_f64()),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(Value::String(s)) => s
            .trim()
            .parse::<f64>()
            .map(Some)
            .map_err(|_| format!("{name} is a number, for example 500. \"{s}\" is not one.")),
        Some(_) => Err(format!("{name} is a number, for example 500.")),
    }
}

/// A whole number is written as one: `usd: 500`, as people write it, not `500.0`.
fn as_written(n: f64) -> Value {
    if n.fract() == 0.0 && n.abs() < 1e15 {
        json!(n as i64)
    } else {
        json!(n)
    }
}

/// A `limits:` entry from the limit form: who it is for, what it narrows to, its budget, rates and parallel cap.
/// Keys the form does not set (a shadow date, a sliding window) are kept from `old`.
fn limit_entry(
    body: &Map<String, Value>,
    old: Option<&Map<String, Value>>,
) -> Result<Value, String> {
    let mut entry = old.cloned().unwrap_or_default();
    for key in SCOPES.iter().chain(["budget", "rate", "parallel"].iter()) {
        entry.remove(*key);
    }
    let scope = text(body, "scope");
    let value = text(body, "value");
    match scope {
        "global" => {
            entry.insert("global".into(), true.into());
        }
        s if SCOPES.contains(&s) => {
            if value.is_empty() {
                return Err(format!("Name the {s} the limit is for."));
            }
            entry.insert(s.into(), value.into());
        }
        _ => return Err("Pick what the limit is for: everyone, an organization, a team, a person, a key, a customer, a tag, a model or a model group.".into()),
    }
    let org = text(body, "org");
    if !org.is_empty() {
        if scope == "global" || scope == "org" {
            return Err("Keeping a limit to one organization goes with a team, person, key, customer, tag or model. For a whole organization, pick organization.".into());
        }
        entry.insert("org".into(), org.into());
    }
    let mut set = false;
    if let Some(usd) = number(body, "usd")? {
        if !(usd.is_finite() && usd > 0.0) {
            return Err("A budget is a number of US dollars above 0, for example 500.".into());
        }
        let per = text(body, "per");
        if !PERIODS.contains(&per) {
            return Err("A budget resets every hour, day, week or month. Pick one.".into());
        }
        entry.insert(
            "budget".into(),
            json!({ "usd": as_written(usd), "per": per }),
        );
        set = true;
    }
    let mut rate = Map::new();
    for key in RATES {
        if let Some(n) = number(body, key)? {
            if n.fract() != 0.0 || n < 1.0 {
                return Err(format!(
                    "{key} is a whole number above 0, for example 600. Leave it empty for no limit."
                ));
            }
            rate.insert(key.into(), as_written(n));
        }
    }
    if !rate.is_empty() {
        entry.insert("rate".into(), Value::Object(rate));
        set = true;
    }
    if let Some(n) = number(body, "parallel")? {
        if n.fract() != 0.0 || n < 1.0 {
            return Err("Parallel is a whole number of requests above 0, for example 10.".into());
        }
        entry.insert("parallel".into(), as_written(n));
        set = true;
    }
    if !set {
        return Err(
            "Set a budget, a rate or a parallel cap: a limit with none of them limits nothing."
                .into(),
        );
    }
    Ok(Value::Object(entry))
}

/// The limit at `index`, when it is still the one the person read (`was`).
fn limit_at<'a>(
    tree: &'a mut Map<String, Value>,
    index: usize,
    body: &Map<String, Value>,
) -> Result<&'a mut Value, String> {
    let limits = section(tree, "limits")?;
    match limits.get_mut(index) {
        Some(l) if body.get("was") == Some(&*l) => Ok(l),
        _ => Err("The limits changed since this page read them, so nothing was changed. Reload the page and make the change again.".into()),
    }
}

async fn limit_add(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            let body = body_of(&bytes)?;
            let target = json!({ "limit": body });
            commit(
                &console,
                &admin,
                "add_limit",
                "Add a limit".into(),
                target,
                |tree| {
                    let entry = limit_entry(&body, None)?;
                    section(tree, "limits")?.push(entry);
                    Ok(())
                },
            )
            .await
        }
        .await,
    )
}

async fn limit_edit(
    State(console): State<Console>,
    Path(index): Path<usize>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            let body = body_of(&bytes)?;
            let target = json!({ "limit": body });
            commit(
                &console,
                &admin,
                "change_limit",
                "Change a limit".into(),
                target,
                |tree| {
                    let at = limit_at(tree, index, &body)?;
                    *at = limit_entry(&body, at.as_object())?;
                    Ok(())
                },
            )
            .await
        }
        .await,
    )
}

async fn limit_remove(
    State(console): State<Console>,
    Path(index): Path<usize>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            let body = body_of(&bytes)?;
            let target = json!({ "limit": body.get("was").cloned().unwrap_or(Value::Null) });
            commit(
                &console,
                &admin,
                "remove_limit",
                "Remove a limit".into(),
                target,
                |tree| {
                    limit_at(tree, index, &body)?;
                    let limits = section(tree, "limits")?;
                    limits.remove(index);
                    if limits.is_empty() {
                        tree.remove("limits");
                    }
                    Ok(())
                },
            )
            .await
        }
        .await,
    )
}

// ---------------------------------------------------------------- guardrail definitions

/// The keys the guardrail form sets; any other key of an entry (a vendor's own setting) is kept on an edit.
const GUARD_FORM_KEYS: [&str; 12] = [
    "type",
    "shadow_until",
    "action",
    "on",
    "url",
    "key_env",
    "model",
    "timeout_ms",
    "on_failure",
    "patterns",
    "keywords",
    "region",
];

/// A scalar as YAML would read it: a number or true/false when it is one, else the text.
fn scalar(text: &str) -> Value {
    match text {
        "true" => true.into(),
        "false" => false.into(),
        _ => text
            .parse::<i64>()
            .map(Value::from)
            .or_else(|_| text.parse::<f64>().map(as_written))
            .unwrap_or_else(|_| text.into()),
    }
}

/// Lines of `name: value` (or `name = value`) into a map, for a regex's patterns and a vendor's settings.
fn pairs(text: &str, what: &str) -> Result<Vec<(String, String)>, String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| {
            l.split_once(": ")
                .or_else(|| l.split_once('='))
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                .filter(|(k, v)| !k.is_empty() && !v.is_empty())
                .ok_or_else(|| format!("\"{l}\" is not name: value. Write one {what} per line, for example card: \\d{{16}}."))
        })
        .collect()
}

/// Sets what the guardrail form changes of a guardrail.
fn guard_fields(entry: &mut Map<String, Value>, body: &Map<String, Value>) -> Result<(), String> {
    for key in GUARD_FORM_KEYS {
        entry.remove(key);
    }
    let kind = text(body, "type");
    if kind.is_empty() {
        return Err("Pick the guardrail's type, for example secrets or pii.".into());
    }
    entry.insert("type".into(), kind.into());
    match text(body, "action") {
        "" => {}
        a @ ("block" | "mask" | "warn") => {
            entry.insert("action".into(), a.into());
        }
        other => {
            return Err(format!(
                "Action \"{other}\" is not one. Pick block, mask or warn."
            ));
        }
    }
    let sides = list(body, "on");
    if !sides.is_empty() {
        if let Some(bad) = sides.iter().find(|s| *s != "request" && *s != "answer") {
            return Err(format!(
                "\"{bad}\" is not a side. A guardrail checks the request, the answer, or both."
            ));
        }
        entry.insert("on".into(), strings(&sides));
    }
    // Try first until: the check refuses a date it cannot read, naming the form it wants.
    for key in ["url", "key_env", "model", "region", "shadow_until"] {
        let v = text(body, key);
        if !v.is_empty() {
            entry.insert(key.into(), v.into());
        }
    }
    if let Some(ms) = number(body, "timeout_ms")? {
        entry.insert("timeout_ms".into(), as_written(ms));
    }
    match text(body, "on_failure") {
        "" => {}
        f @ ("fail_closed" | "fail_open") => {
            entry.insert("on_failure".into(), f.into());
        }
        other => {
            return Err(format!(
                "On failure \"{other}\" is not one. Pick fail_closed or fail_open."
            ));
        }
    }
    let patterns = pairs(text(body, "patterns"), "pattern")?;
    if !patterns.is_empty() {
        entry.insert(
            "patterns".into(),
            Value::Object(patterns.into_iter().map(|(k, v)| (k, v.into())).collect()),
        );
    }
    let keywords = pairs(text(body, "keywords"), "list")?;
    if !keywords.is_empty() {
        entry.insert(
            "keywords".into(),
            Value::Object(
                keywords
                    .into_iter()
                    .map(|(k, v)| {
                        (
                            k,
                            strings(
                                &v.split(',')
                                    .map(|w| w.trim().to_string())
                                    .filter(|w| !w.is_empty())
                                    .collect::<Vec<_>>(),
                            ),
                        )
                    })
                    .collect(),
            ),
        );
    }
    for (key, value) in pairs(text(body, "settings"), "setting")? {
        if key == "name" || GUARD_FORM_KEYS.contains(&key.as_str()) {
            return Err(format!(
                "{key} has its own field in this form: set it there, not under other settings."
            ));
        }
        entry.insert(key, scalar(&value));
    }
    Ok(())
}

async fn guard_add(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    answer(async {
        let admin = signed_in(&console, &headers, true).await?;
        let body = body_of(&bytes)?;
        let name = text(&body, "name").to_string();
        let note = format!("Add guardrail {name}");
        commit(&console, &admin, "add_guardrail", note, json!({ "guardrail": name }), |tree| {
            name_ok(&name, "guardrail", "no-secrets")?;
            let guards = section(tree, "guardrails")?;
            if named(guards, &name).is_some() {
                return Err(format!("There is a guardrail named \"{name}\" already. Pick another name, or edit that one."));
            }
            let mut entry = Map::new();
            entry.insert("name".into(), name.clone().into());
            guard_fields(&mut entry, &body)?;
            guards.push(Value::Object(entry));
            // A guardrail no rule names runs nowhere: the form adds it to every request unless the admin says not to.
            if body.get("every").and_then(Value::as_bool) == Some(true) {
                let mut defaults = str_list(tree.get("default_guardrails"));
                defaults.push(name.clone());
                tree.insert("default_guardrails".into(), strings(&defaults));
            }
            Ok(())
        })
        .await
    }.await)
}

async fn guard_edit(
    State(console): State<Console>,
    Path(name): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            let body = body_of(&bytes)?;
            let note = format!("Change guardrail {name}");
            commit(
                &console,
                &admin,
                "change_guardrail",
                note,
                json!({ "guardrail": name }),
                |tree| guard_fields(entry(tree, "guardrails", &name, "guardrail")?, &body),
            )
            .await
        }
        .await,
    )
}

async fn guard_remove(
    State(console): State<Console>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            let note = format!("Remove guardrail {name}");
            commit(
                &console,
                &admin,
                "remove_guardrail",
                note,
                json!({ "guardrail": name }),
                |tree| {
                    remove_named(tree, "guardrails", &name, "guardrail")?;
                    // A rule or the defaults naming a guardrail that is gone does not load: the name goes from them too.
                    let defaults: Vec<String> = str_list(tree.get("default_guardrails"))
                        .into_iter()
                        .filter(|g| *g != name)
                        .collect();
                    if defaults.is_empty() {
                        tree.remove("default_guardrails");
                    } else {
                        tree.insert("default_guardrails".into(), strings(&defaults));
                    }
                    for list in ["rules", "profiles"] {
                        if let Some(Value::Array(items)) = tree.get_mut(list) {
                            for item in items.iter_mut().filter_map(Value::as_object_mut) {
                                let kept: Vec<String> = str_list(item.get("guardrails"))
                                    .into_iter()
                                    .filter(|g| *g != name)
                                    .collect();
                                if kept.is_empty() {
                                    item.remove("guardrails");
                                } else if item.contains_key("guardrails") {
                                    item.insert("guardrails".into(), strings(&kept));
                                }
                            }
                        }
                    }
                    Ok(())
                },
            )
            .await
        }
        .await,
    )
}

async fn guardrail_set(
    State(console): State<Console>,
    Path(name): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    answer(async {
        let admin = signed_in(&console, &headers, true).await?;
        let body = body_of(&bytes)?;
        let on = body.get("on").and_then(Value::as_bool);
        let note = format!("Turn guardrail {name} {}", if on == Some(true) { "on" } else { "off" });
        commit(&console, &admin, "set_guardrail", note, json!({ "guardrail": name, "on": on }), |tree| {
            let on = on.ok_or("Send on: true to run the guardrail on every request, or on: false to stop.")?;
            if named(section(tree, "guardrails")?, &name).is_none() {
                return Err(format!("There is no guardrail named \"{name}\" in the policy. Reload the page."));
            }
            let mut defaults: Vec<String> = str_list(tree.get("default_guardrails")).into_iter().filter(|g| *g != name).collect();
            if on {
                defaults.push(name.clone());
            }
            if defaults.is_empty() {
                tree.remove("default_guardrails");
            } else {
                tree.insert("default_guardrails".into(), strings(&defaults));
            }
            Ok(())
        })
        .await
    }.await)
}

/// Runs a guardrail of the policy over a sample the admin types, as its rule would on a request. Nothing is sent
/// anywhere and the sample is not kept: the answer gives each kind found and a masked span, never the text.
async fn guardrail_test(
    State(console): State<Console>,
    Path(name): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    answer(
        async {
            signed_in(&console, &headers, true).await?;
            let body = body_of(&bytes)?;
            let sample = text(&body, "text");
            if sample.trim().is_empty() {
                return Err(bad("Type a sample prompt to test the guardrail on."));
            }
            let tree = read_tree(&console)?;
            let entry = str_objects(tree.get("guardrails"))
                .find(|g| g.get("name").and_then(Value::as_str) == Some(name.as_str()))
                .ok_or_else(|| bad(format!("There is no guardrail named \"{name}\" in the policy. Reload the page.")))?;
            let def: enterplace_core::guard::GuardrailFile = serde_json::from_value(Value::Object(entry.clone()))
                .map_err(|err| bad(format!("Guardrail {name} does not read: {err}. Fix it with Edit, then test again.")))?;
            let action = def.action.map_or("block".to_string(), |a| format!("{a:?}").to_lowercase());
            let guard = enterplace_core::guard::guardrails(&[def])
                .map_err(|errors| bad(errors.join(" ")))?
                .pop()
                .ok_or_else(|| bad(format!("Guardrail {name} holds no check.")))?;
            let sample = enterplace_core::guard::sample(&json!({ "text": sample }), 1).map_err(bad)?;
            let report = enterplace_core::guard::backtest(&guard, &[sample]).map_err(bad)?;
            let message = if report.hits == 0 {
                format!("{name} finds nothing in this sample: a request like it goes through.")
            } else {
                let kinds: Vec<String> = report.kinds.iter().map(|(k, n)| format!("{k} ({n})")).collect();
                let does = match action.as_str() {
                    "mask" => "masks each finding and sends the request on",
                    "warn" => "sends it on and records the finding",
                    _ => "refuses a request like it",
                };
                format!("{name} finds {} in this sample. With action {action}, it {does} once the policy enforces.", kinds.join(", "))
            };
            Ok(ok(json!({
                "message": message,
                "hits": report.hits,
                "masked": report.samples.iter().map(|s| json!({ "kind": s.kind, "masked": s.masked })).collect::<Vec<_>>(),
            })))
        }
        .await,
    )
}

/// Sets what the alias form changes: where the alias sends a request, and the fallbacks tried after.
fn alias_fields(alias: &mut Map<String, Value>, body: &Map<String, Value>) -> Result<(), String> {
    let mut deployments = Vec::new();
    for d in list(body, "deployments") {
        let Some((provider, model)) = d
            .split_once('/')
            .filter(|(p, m)| !p.is_empty() && !m.is_empty())
        else {
            return Err(format!(
                "\"{d}\" is not provider/model. Write each place the alias sends to as provider/model, for example openai/gpt-4o."
            ));
        };
        deployments.push(json!({ "provider": provider.trim(), "model": model.trim() }));
    }
    if deployments.is_empty() {
        return Err(
            "An alias sends to at least one provider/model, for example openai/gpt-4o.".into(),
        );
    }
    alias.insert("deployments".into(), Value::Array(deployments));
    let fallbacks = list(body, "fallbacks");
    if fallbacks.is_empty() {
        alias.remove("fallbacks");
    } else {
        alias.insert("fallbacks".into(), strings(&fallbacks));
    }
    Ok(())
}

async fn alias_add(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    answer(async {
        let admin = signed_in(&console, &headers, true).await?;
        let body = body_of(&bytes)?;
        let name = text(&body, "name").to_string();
        let note = format!("Add alias {name}");
        commit(&console, &admin, "add_alias", note, json!({ "alias": name }), |tree| {
            name_ok(&name, "alias", "smart")?;
            let aliases = section(tree, "aliases")?;
            if named(aliases, &name).is_some() {
                return Err(format!("There is an alias named \"{name}\" already. Pick another name, or edit that one."));
            }
            let mut alias = Map::new();
            alias.insert("name".into(), name.clone().into());
            alias_fields(&mut alias, &body)?;
            aliases.push(Value::Object(alias));
            Ok(())
        })
        .await
    }.await)
}

async fn alias_edit(
    State(console): State<Console>,
    Path(name): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            let body = body_of(&bytes)?;
            let note = format!("Change alias {name}");
            commit(
                &console,
                &admin,
                "change_alias",
                note,
                json!({ "alias": name }),
                |tree| alias_fields(entry(tree, "aliases", &name, "alias")?, &body),
            )
            .await
        }
        .await,
    )
}

async fn alias_remove(
    State(console): State<Console>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            let note = format!("Remove alias {name}");
            commit(
                &console,
                &admin,
                "remove_alias",
                note,
                json!({ "alias": name }),
                |tree| remove_named(tree, "aliases", &name, "alias"),
            )
            .await
        }
        .await,
    )
}
