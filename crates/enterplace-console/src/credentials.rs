//! Provider credentials in the console app (`/console/app/#/credentials`): the provider keys sealed under the master
//! key, by name, vendor, last 4 characters and the providers of the policy that name them; add, rotate and remove one.
//!
//! A change is recorded in the audit chain first, as the admin API records it, and only then made in the store or the
//! file vault. The value typed is in no answer, no record and no page: only its last 4 characters are ever shown.

use axum::{
    Router,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, Uri},
    response::Response,
    routing::{get, post},
};
use enterplace_core::{config, policy::Permission, store};
use serde_json::{Value, json};

use crate::{
    Act, Console, Form, NOT_RECORDED,
    api::{Fail, answer, bad, body_of, ok, sentence, signed_in, text},
    figures, read_only, record, redirect,
};

pub(crate) fn routes() -> Router<Console> {
    Router::new()
        // The server-rendered page moved to the app: old links land on the same dialog there.
        .route("/credentials", get(|uri: Uri| async move { moved(&uri) }))
        .route("/api/credentials", get(list))
        .route("/api/credentials/{action}", post(change))
}

/// The app's Credentials route for an old address, keeping the dialog or the toast its query asked for.
fn moved(uri: &Uri) -> Response {
    let query = Form::of(uri);
    let kept: Vec<String> = ["add", "rotate", "remove", "done", "name"]
        .into_iter()
        .filter(|name| !query.get(name).is_empty())
        .map(|name| format!("{name}={}", crate::html::enc(query.get(name))))
        .collect();
    let mut to = "/console/app/#/credentials".to_string();
    if !kept.is_empty() {
        to.push('?');
        to.push_str(&kept.join("&"));
    }
    redirect(&to)
}

async fn list(State(console): State<Console>, headers: HeaderMap) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, false).await?;
            let config = console.config();
            let mut out = json!({
                "lead": "Provider keys, stored encrypted. Never shown after saving.",
                "read_only": admin.read_only,
                // The same test a change passes: a role that would be refused sees no button.
                "may_change": !admin.read_only && admin.may(Permission::Credentials) && !admin.confined(),
            });
            let list = match store::credentials_for(&config.keys).map(|s| s.credentials()) {
                None => {
                    out["off"] = json!({
                        "title": "Provider keys need a master key",
                        "body": "Enterplace keeps pasted provider keys encrypted under a master key, and this gateway has none. Set one on every gateway and restart them: Copy for your agent has the steps. Until then each provider reads its key from an environment variable on the gateway.",
                        "agent": crate::start::master_key_prompt(&crate::base()),
                        "docs": format!("{}/governance/provider-credentials/", crate::start::DOCS),
                    });
                    return Ok(ok(out));
                }
                Some(Err(why)) => {
                    out["off"] = json!({ "title": "Credentials are off", "body": sentence(&why) });
                    return Ok(ok(out));
                }
                Some(Ok(list)) => list,
            };
            let named = config::credentials_named(&config.policy);
            let rows: Vec<Value> = list
                .iter()
                .map(|c| {
                    let used: Vec<&str> = named
                        .iter()
                        .filter(|(_, n)| *n == c.name)
                        .map(|(p, _)| p.as_str())
                        .collect();
                    json!({
                        "name": c.name,
                        "provider": c.provider,
                        "fingerprint": c.fingerprint,
                        "used_by": if used.is_empty() { "not named".to_string() } else { used.join(", ") },
                        "added": format!("{} by {}", figures::time_full(&c.created_at), c.created_by),
                        "rotated": match (&c.rotated_at, &c.rotated_by) {
                            (Some(at), Some(by)) => format!("{} by {by}", figures::time_full(at)),
                            _ => "never".to_string(),
                        },
                    })
                })
                .collect();
            out["credentials"] = Value::Array(rows);
            out["empty"] = json!({
                "title": "No credentials yet",
                "body": "Add a provider key here, then name it in the policy with credential: in place of key_env.",
            });
            Ok(ok(out))
        }
        .await,
    )
}

/// Adds, rotates or removes a provider credential, recorded first as the admin API records it.
async fn change(
    State(console): State<Console>,
    Path(action): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    answer(
        async {
            let (action, done) = match action.as_str() {
                "add" => ("add_credential", "is added. A provider can name it with credential: now."),
                "rotate" => ("rotate_credential", "is rotated. Every gateway sends the new value within 2 seconds."),
                "remove" => ("remove_credential", "is removed."),
                _ => {
                    return Err(Fail(
                        StatusCode::NOT_FOUND,
                        "A credential can be added, rotated or removed: post to /console/api/credentials/add, rotate or remove.".into(),
                    ));
                }
            };
            let admin = signed_in(&console, &headers, true).await?;
            let body = body_of(&bytes)?;
            let (name, provider) = (text(&body, "name").to_string(), text(&body, "provider").to_string());
            // Untrimmed, as pasted: the store checks it and trims it itself.
            let value = body.get("value").and_then(Value::as_str).unwrap_or("").to_string();
            if !admin.may(Permission::Credentials) || admin.confined() {
                read_only(&console, &admin, action).await;
                return Err(Fail(
                    StatusCode::FORBIDDEN,
                    "Your role may not change credentials, which serve the whole install: ask an admin to change them.".into(),
                ));
            }
            let Some(vault) = store::credentials_for(&console.config().keys) else {
                return Err(Fail(
                    StatusCode::CONFLICT,
                    "Credentials need a master key: set ENTERPLACE_MASTER_KEY (or ENTERPLACE_MASTER_KEY_FILE) and restart Enterplace. enterplace start makes one. Until then keep provider keys in key_env.".into(),
                ));
            };
            let mut act = Act {
                action,
                by: Some((&admin.name, &admin.team)),
                key: None,
                target: json!({ "name": name }),
            };
            let problem = match action {
                _ if !config::valid_name(&name) => Some(
                    "A name uses letters, digits, dots, dashes, underscores and @ only, for example openai-prod.".to_string(),
                ),
                "add_credential" if !config::valid_name(&provider) => {
                    Some("Name the vendor the key is for, for example openai or anthropic.".to_string())
                }
                "remove_credential" if text(&body, "confirm") != name => {
                    Some(format!("Type {name} exactly, to confirm which credential goes."))
                }
                // A provider reading this credential would lose its key on the next request.
                "remove_credential" => config::credentials_named(&console.config().policy)
                    .into_iter()
                    .find(|(_, c)| *c == name)
                    .map(|(p, _)| format!(
                        "Provider {p} in the policy takes its key from this credential. Point it at another credential or key_env first, or rotate this one."
                    )),
                _ => store::credential_value_problem(&value).map(sentence),
            };
            if action != "remove_credential" {
                act.target = json!({ "name": name, "provider": provider, "fingerprint": store::fingerprint(value.trim()) });
            }
            if let Some(problem) = problem {
                let _ = record(&console, &act, Some("invalid_request"), None).await;
                return Err(bad(problem));
            }
            if record(&console, &act, None, None).await.is_err() {
                return Err(Fail(StatusCode::SERVICE_UNAVAILABLE, NOT_RECORDED.into()));
            }
            let (n, p, by) = (name.clone(), provider, admin.name.clone());
            let done_now = tokio::task::spawn_blocking(move || match action {
                "add_credential" => vault.add_credential(&n, &p, &value, &by).map(|c| {
                    c.map(|_| ()).ok_or((
                        StatusCode::CONFLICT,
                        "A credential with this name is already in the store. Rotate it, or choose another name.",
                    ))
                }),
                "rotate_credential" => vault.rotate_credential(&n, &value, &by).map(|c| {
                    c.map(|_| ()).ok_or((
                        StatusCode::NOT_FOUND,
                        "There is no credential with this name: someone removed it. Reload the page.",
                    ))
                }),
                _ => vault.remove_credential(&n).map(|c| {
                    c.map(|_| ()).ok_or((
                        StatusCode::NOT_FOUND,
                        "There is no credential with this name: someone removed it already. Reload the page.",
                    ))
                }),
            })
            .await
            .unwrap_or_else(|err| Err(format!("Nothing was changed: {err}. Try again.")));
            let (status, error) = match done_now {
                Ok(Ok(())) => return Ok(ok(json!({ "message": format!("Credential {name} {done}") }))),
                Ok(Err((status, refused))) => (status, refused.to_string()),
                Err(error) => (StatusCode::SERVICE_UNAVAILABLE, sentence(&error)),
            };
            // The record above says it was allowed; this one says it did not happen.
            let _ = record(&console, &act, Some("store"), Some(&error)).await;
            Err(Fail(status, error))
        }
        .await,
    )
}
