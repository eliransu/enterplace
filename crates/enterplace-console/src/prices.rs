//! Prices in the console app (`/console/app/#/prices`): each model the providers serve, its provider, its price per
//! million tokens (set in the policy, else built in, else none and its spend is not counted) and its aliases; add a
//! model with its price, or change a model's price.
//!
//! A change is made only when the policy is kept in the store: it is saved as a new policy version through
//! `edit::save_version`, recorded in the audit chain first with who made it, checked as `enterplace check` checks a
//! file, and live on every gateway within 2 seconds, or waiting for a second admin. A policy kept in a file is shown
//! read only, with where to change it.

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, Uri},
    response::Response,
    routing::{get, post},
};
use enterplace_core::{config, store, usage, versions};
use serde_json::{Map, Value, json};

use crate::{
    Act, Console, Form,
    api::{Fail, answer, bad, body_of, ok, refused, sentence, signed_in, text},
    edit::{self, edits_policy},
    figures::money,
    read_only, record, redirect,
};

pub(crate) fn routes() -> Router<Console> {
    Router::new()
        // The server-rendered page moved to the app: old links land on the same dialog there.
        .route("/models", get(|uri: Uri| async move { moved(&uri) }))
        .route("/api/prices", get(list))
        .route("/api/prices/add", post(add))
        .route("/api/prices/price", post(price))
}

/// The app's Prices route for an old address, keeping the dialog its query opened.
fn moved(uri: &Uri) -> Response {
    let query = Form::of(uri);
    let kept: Vec<String> = ["add", "price", "provider", "model"]
        .into_iter()
        .filter(|name| !query.get(name).is_empty())
        .map(|name| format!("{name}={}", crate::html::enc(query.get(name))))
        .collect();
    let mut to = "/console/app/#/prices".to_string();
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
            let c = console.config();
            let loaded = match config::load(&c.policy, Some(&c.keys)) {
                Ok(loaded) => loaded,
                Err(problems) => {
                    return Ok(ok(json!({
                        "error": format!("The policy did not load: {} Open the raw policy to fix it.", problems.join(" ")),
                    })));
                }
            };
            let live = edit::live(&console);
            let editable = live.is_some() && edits_policy(&admin);
            // Read only is how a file-kept policy works, nothing went wrong: the page says so in a plain line.
            let file = live.is_none().then(|| {
                c.policy.file_name().map_or_else(
                    || c.policy.display().to_string(),
                    |n| n.to_string_lossy().into_owned(),
                )
            });
            let prices = loaded.policy.prices();
            let mut models = Vec::new();
            for provider in &loaded.providers {
                for model in &provider.models {
                    let (set, source) = match (prices.get(model), usage::price_for(model, prices)) {
                        (Some(p), _) => (Some(p.clone()), "policy"),
                        (None, Some(p)) => (Some(p), "built in"),
                        (None, None) => (None, "spend is not counted"),
                    };
                    let aliases: Vec<&str> = loaded
                        .aliases
                        .iter()
                        .filter(|a| {
                            a.deployments
                                .iter()
                                .any(|d| d.provider == provider.name && d.model == *model)
                        })
                        .map(|a| a.name.as_str())
                        .collect();
                    models.push(json!({
                        "model": model,
                        "provider": format!("{} ({})", provider.name, provider.kind.word()),
                        "price": set.as_ref().map_or_else(|| "no price".to_string(), |p| format!("{} / {}", money(p.input), money(p.output))),
                        "source": source,
                        "aliases": if aliases.is_empty() { "none".to_string() } else { aliases.join(", ") },
                        // What the price dialog starts from.
                        "input": set.as_ref().map(|p| p.input.to_string()).unwrap_or_default(),
                        "output": set.as_ref().map(|p| p.output.to_string()).unwrap_or_default(),
                    }));
                }
            }
            let mut note = "A price set in the policy is used over the built-in one.".to_string();
            if editable {
                note.push_str(" A form edit saves the policy without its comments: the editor keeps them.");
            }
            Ok(ok(json!({
                "lead": "Each model, its provider and its price.",
                "editable": editable,
                "base": live.map(|v| v.id),
                "file": file,
                "docs": format!("{}/operations/console-editing/", crate::start::DOCS),
                "providers": loaded.providers.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
                "models": models,
                "note": note,
                "empty": {
                    "title": "No models yet",
                    "body": "Add a provider in the policy editor, then add its models here.",
                },
            })))
        }
        .await,
    )
}

async fn add(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    answer(change(&console, &headers, &bytes, "add_model").await)
}

async fn price(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    answer(change(&console, &headers, &bytes, "price_model").await)
}

/// A price is US dollars per million tokens, 0 or more.
fn price_of(input: &str, output: &str) -> Result<(f64, f64), String> {
    match (input.parse::<f64>(), output.parse::<f64>()) {
        (Ok(i), Ok(o)) if i.is_finite() && o.is_finite() && i >= 0.0 && o >= 0.0 => Ok((i, o)),
        _ => Err("A price is a number of US dollars per million tokens, 0 or more, for example 0.15 and 0.60.".into()),
    }
}

async fn change(
    console: &Console,
    headers: &HeaderMap,
    bytes: &Bytes,
    act: &'static str,
) -> crate::api::Answer {
    let admin = signed_in(console, headers, true).await?;
    let body = body_of(bytes)?;
    if !edits_policy(&admin) {
        read_only(console, &admin, act).await;
        return Err(Fail(
            StatusCode::FORBIDDEN,
            "You are signed in read only: ask an admin to change models.".into(),
        ));
    }
    let Some(live) = edit::live(console) else {
        return Err(Fail(
            StatusCode::FORBIDDEN,
            sentence(&versions::read_only_message(&console.config().policy)),
        ));
    };
    // The version the page read: a change made since is refused rather than overwritten.
    let base = body.get("base").and_then(|v| {
        v.as_i64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
    });
    let model = text(&body, "model").to_string();
    let provider = text(&body, "provider");
    let edited = price_of(text(&body, "input"), text(&body, "output")).and_then(|p| {
        if !config::valid_name(&model) {
            return Err("A model name uses letters, digits, '.', '-', '_' and '@', for example gpt-4o-mini.".into());
        }
        if act == "add_model" {
            let aliases = aliases(&body);
            if let Some(bad) = aliases.iter().find(|a| !config::valid_name(a)) {
                return Err(format!("The alias \"{bad}\" uses a character a model name cannot. Use letters, digits, '.', '-', '_' and '@'."));
            }
            versions::add_model(&live.text, provider, &model, Some(p), &aliases)
                .map_err(|e| sentence(&e))
        } else {
            versions::set_price(&live.text, &model, p).map_err(|e| sentence(&e))
        }
    });
    let policy = match edited {
        Ok(policy) => policy,
        Err(error) => {
            let _ = record(
                console,
                &Act {
                    action: act,
                    by: Some((&admin.name, &admin.team)),
                    key: None,
                    target: json!({ "model": model }),
                },
                Some("invalid_request"),
                None,
            )
            .await;
            return Err(bad(error));
        }
    };
    let note = if act == "add_model" {
        format!("Add model {model} to provider {provider}")
    } else {
        format!("Change the price of {model}")
    };
    match edit::save_version(console, &admin, act, policy, base, note).await {
        Ok(v) if v.state == store::PENDING => Ok(ok(json!({
            "message": format!("Saved as version {}. It waits for a second admin to approve it under Policy, Versions.", v.id),
            "version": v.id,
        }))),
        Ok(v) => Ok(ok(json!({
            "message": edit::in_force(console, Some(v.id), &v.sha256).await,
            "version": v.id,
        }))),
        Err(err) => Err(refused(&err)),
    }
}

/// The aliases a form names, from a JSON list or a comma separated string, without blanks.
fn aliases(body: &Map<String, Value>) -> Vec<String> {
    match body.get("aliases") {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(|a| a.trim().to_string())
            .filter(|a| !a.is_empty())
            .collect(),
        _ => text(body, "aliases")
            .split(',')
            .map(|a| a.trim().to_string())
            .filter(|a| !a.is_empty())
            .collect(),
    }
}
