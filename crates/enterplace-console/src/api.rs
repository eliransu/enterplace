//! The JSON the console app (`console-ui/`, served at `/console/app/`) reads and writes: providers and their models,
//! MCP servers and which of their tools each rule allows, and the policy's basics (mode, rules, budgets, guardrails,
//! aliases). The app signs in with the console's own session cookie, so every call is checked as a page is.
//!
//! Every change goes through [`commit`]: the role must hold `edit_policy`, the change is recorded in the audit chain
//! with who made it before it is made, the new text is checked as `enterplace check` checks a file, and it is then
//! saved as a new version (policy kept in the store) or written over the file in one rename (policy kept in the
//! file). Either way every gateway uses it within 2 seconds. A form edit writes the policy without its comments.

use axum::{
    Router,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
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
        .route("/api/policy/rules", post(rule_add))
        .route(
            "/api/policy/rules/{name}",
            put(rule_edit).delete(rule_remove),
        )
        .route("/api/policy/budgets", put(budget_set))
        .route("/api/policy/budgets/{scope}/{name}", delete(budget_remove))
        .route("/api/policy/guardrails/{name}", put(guardrail_set))
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
pub(crate) struct Fail(StatusCode, String);

impl IntoResponse for Fail {
    fn into_response(self) -> Response {
        let mut response = (self.0, ok(json!({ "error": self.1 }))).into_response();
        *response.status_mut() = self.0;
        response
    }
}

fn bad(message: impl Into<String>) -> Fail {
    Fail(StatusCode::BAD_REQUEST, message.into())
}

fn ok(value: Value) -> Response {
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

type Answer = Result<Response, Fail>;

fn answer(result: Answer) -> Response {
    result.unwrap_or_else(IntoResponse::into_response)
}

/// A message from the core, as a sentence.
fn sentence(text: &str) -> String {
    let mut text = text.trim().to_string();
    if let Some(first) = text.get_mut(..1) {
        first.make_ascii_uppercase();
    }
    text
}

/// The signed-in admin, and for a change also a form from this console: a change from another site is refused.
async fn signed_in(console: &Console, headers: &HeaderMap, change: bool) -> Result<Admin, Fail> {
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

fn body_of(bytes: &Bytes) -> Result<Map<String, Value>, Fail> {
    match serde_json::from_slice::<Value>(bytes) {
        Ok(Value::Object(map)) => Ok(map),
        _ => Err(bad(
            "The request body is not a JSON object. Send the form's fields as JSON, for example {\"name\": \"openai\"}.",
        )),
    }
}

fn text<'a>(body: &'a Map<String, Value>, name: &str) -> &'a str {
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
fn current(console: &Console) -> Result<(String, Option<i64>), Fail> {
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
    let after = versions::to_yaml(&Value::Object(tree));
    if after == before {
        return Ok(ok(
            json!({ "message": "Nothing changed: the policy already says this." }),
        ));
    }
    if base.is_some() {
        return match edit::save_version(console, admin, action, after, base, note).await {
            Ok(v) if v.state == store::PENDING => Ok(ok(json!({
                "message": format!("Saved as version {}. It waits for a second admin to approve it under Policy, Versions.", v.id),
                "version": v.id,
            }))),
            Ok(v) => Ok(ok(json!({
                "message": format!("Saved as version {}. Every gateway uses it within 2 seconds.", v.id),
                "version": v.id,
            }))),
            Err(err) => Err(refused(&err)),
        };
    }
    let mut target = target;
    if let Value::Object(t) = &mut target {
        t.insert(
            "sha256".into(),
            enterplace_core::id::sha256_hex(after.as_bytes()).into(),
        );
        // The policy holds no secrets: the chain keeps the whole text, as a saved version would.
        t.insert("policy".into(), after.clone().into());
    }
    let act = act(target);
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
            "message": "Saved. Every gateway uses it within 2 seconds.",
        }))),
        Err(err) => {
            let _ = record(console, &act, Some("invalid_policy"), Some(&err.message())).await;
            Err(refused(&err))
        }
    }
}

fn refused(err: &Refused) -> Fail {
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
            Ok(ok(json!({
                "name": admin.name,
                "role": admin.role,
                "edit_policy": edit::edits_policy(&admin),
                "credentials": admin.may(Permission::Credentials) && !admin.confined(),
                "source": if edit::live(&console).is_some() { "store" } else { "file" },
                "policy": console.config().policy.display().to_string(),
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
                let models = catalog::START_PROVIDERS
                    .iter()
                    .find(|(id, _)| *id == p.id)
                    .map(|(_, m)| m.to_vec())
                    .unwrap_or_default();
                json!({ "id": p.id, "name": p.name, "local": p.local, "needs_url": p.needs_url(), "models": models })
            })
            .collect();
        Ok(ok(json!({
            "providers": list,
            "catalog": presets,
            "sealing": store::credentials_for(&console.config().keys).is_some(),
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
        let (key, key_env) = (text(&body, "key").to_string(), text(&body, "key_env").to_string());
        if key.is_empty() && key_env.is_empty() && !preset.local {
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
        Ok(ok(json!({ "servers": servers })))
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

/// The scopes a budget form sets: everyone, one team, one person.
const SCOPES: [&str; 3] = ["global", "team", "person"];
const PERIODS: [&str; 4] = ["hour", "day", "week", "month"];

/// A `limits:` entry this page shows: one budget of one scope and nothing else that narrows it.
fn simple_limit(limit: &Map<String, Value>) -> Option<(String, String)> {
    let narrows = ["org", "key", "customer", "tag", "model", "model_group"];
    if narrows.iter().any(|k| limit.contains_key(*k)) {
        return None;
    }
    if limit.get("global").and_then(Value::as_bool) == Some(true) {
        return Some(("global".into(), "everyone".into()));
    }
    for scope in ["team", "person"] {
        if let Some(name) = limit.get(scope).and_then(Value::as_str) {
            return Some((scope.into(), name.into()));
        }
    }
    None
}

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
        let limits: Vec<&Map<String, Value>> = str_objects(tree.get("limits")).collect();
        let mut budgets = Vec::new();
        let mut other_limits = 0;
        for limit in &limits {
            let budget = limit.get("budget").and_then(Value::as_object);
            match (simple_limit(limit), budget) {
                (Some((scope, name)), Some(b)) if b.get("per").is_some_and(Value::is_string) => budgets.push(json!({
                    "scope": scope,
                    "name": name,
                    "usd": b.get("usd").cloned().unwrap_or(Value::Null),
                    "per": b.get("per").cloned().unwrap_or(Value::Null),
                })),
                _ => other_limits += 1,
            }
        }
        let defaults = str_list(tree.get("default_guardrails"));
        let guardrails: Vec<Value> = str_objects(tree.get("guardrails"))
            .map(|g| {
                let name = g.get("name").and_then(Value::as_str).unwrap_or("");
                json!({
                    "name": name,
                    "type": g.get("type").cloned().unwrap_or(Value::Null),
                    "action": g.get("action").cloned().unwrap_or(Value::Null),
                    "on": defaults.iter().any(|d| d == name),
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
        Ok(ok(json!({
            "mode": tree.get("mode").and_then(Value::as_str).unwrap_or("enforce"),
            "rules": rules,
            "budgets": budgets,
            "other_limits": other_limits,
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

fn limit_at(limits: &[Value], scope: &str, name: &str) -> Option<usize> {
    limits.iter().position(|l| {
        l.as_object()
            .and_then(simple_limit)
            .is_some_and(|(s, n)| s == scope && (scope == "global" || n == name))
    })
}

async fn budget_set(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            let body = body_of(&bytes)?;
            let (scope, name, per) = (
                text(&body, "scope").to_string(),
                text(&body, "name").to_string(),
                text(&body, "per").to_string(),
            );
            let usd = match body.get("usd") {
                Some(Value::Number(n)) => n.as_f64(),
                Some(Value::String(s)) => s.trim().parse::<f64>().ok(),
                _ => None,
            };
            let target = json!({ "scope": scope, "name": name, "usd": usd, "per": per });
            let note = format!("Set the {scope} budget {name}");
            commit(&console, &admin, "set_budget", note, target, |tree| {
                if !SCOPES.contains(&scope.as_str()) {
                    return Err(
                        "A budget is for everyone (global), a team or a person. Pick one.".into(),
                    );
                }
                if scope != "global" {
                    name_ok(&name, scope.as_str(), "payments")?;
                }
                let usd = usd
                    .filter(|u| u.is_finite() && *u > 0.0)
                    .ok_or("A budget is a number of US dollars above 0, for example 500.")?;
                if !PERIODS.contains(&per.as_str()) {
                    return Err("A budget resets every hour, day, week or month. Pick one.".into());
                }
                // A whole number is written as one: `usd: 500`, as people write it, not `500.0`.
                let usd = if usd.fract() == 0.0 && usd < 1e15 {
                    json!(usd as u64)
                } else {
                    json!(usd)
                };
                let budget = json!({ "usd": usd, "per": per });
                let limits = section(tree, "limits")?;
                match limit_at(limits, &scope, &name) {
                    Some(at) => {
                        if let Value::Object(l) = &mut limits[at] {
                            l.insert("budget".into(), budget);
                        }
                    }
                    None => {
                        let mut l = Map::new();
                        if scope == "global" {
                            l.insert("global".into(), true.into());
                        } else {
                            l.insert(scope.clone(), name.clone().into());
                        }
                        l.insert("budget".into(), budget);
                        limits.push(Value::Object(l));
                    }
                }
                Ok(())
            })
            .await
        }
        .await,
    )
}

async fn budget_remove(
    State(console): State<Console>,
    Path((scope, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    answer(async {
        let admin = signed_in(&console, &headers, true).await?;
        let note = format!("Remove the {scope} budget {name}");
        commit(&console, &admin, "remove_budget", note, json!({ "scope": scope, "name": name }), |tree| {
            let limits = section(tree, "limits")?;
            let at = limit_at(limits, &scope, &name)
                .ok_or_else(|| format!("There is no {scope} budget for \"{name}\": someone removed it already. Reload the page."))?;
            let keep = match &mut limits[at] {
                Value::Object(l) => {
                    l.remove("budget");
                    // What is left still limits (a rate, parallel requests): only the budget goes.
                    l.keys().any(|k| !SCOPES.contains(&k.as_str()))
                }
                _ => false,
            };
            if !keep {
                limits.remove(at);
            }
            if limits.is_empty() {
                tree.remove("limits");
            }
            Ok(())
        })
        .await
    }.await)
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
