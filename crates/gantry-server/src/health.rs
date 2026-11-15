//! Each deployment's health as every gateway sees it: `GET /admin/deployments`, the console's Deployments page, and
//! a provider's connection test (`POST /admin/providers/{name}/test`, and a button on that page).
//!
//! A gateway knows its own circuits, probes, latency and key pool. With a store that shares routing state, each
//! gateway writes what it knows there every 2 seconds ([`publish`]) and reads the others', so the view is the same
//! whichever replica answers: a deployment cooling down on any gateway is cooling, latency is over every gateway's
//! samples, load is summed, a key set aside anywhere is resting. Without such a store the view is this gateway's.
//!
//! The page is built from the console's existing components (head, row, tag, button) and needs a design pass.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
    routing::get,
};
use gantry_console::{Console, Form, html};
use gantry_core::policy::Permission;
use serde_json::{Map, Value, json};

use crate::{AppState, Hop, MODELS, Snapshot, alias};

const TITLE: &str = "Deployments";

/// Hands this gateway's report to the store every 2 seconds, for the life of the gateway. Nothing to do without a
/// store that shares routing state.
pub(crate) fn publish(state: std::sync::Weak<AppState>) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    runtime.spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        loop {
            tick.tick().await;
            let Some(state) = state.upgrade() else {
                return;
            };
            let Some(store) = state.pool.store().filter(|s| s.shares_routing()) else {
                return;
            };
            store.publish_health(state.pool.report().to_string());
        }
    });
}

/// Every gateway's reports: this one's, then the others' from the store.
fn reports(state: &AppState) -> (Vec<Value>, bool) {
    let mut all = vec![state.pool.report()];
    let shared = state.pool.store().filter(|s| s.shares_routing());
    if let Some(store) = shared {
        all.extend(
            store
                .health_reports()
                .iter()
                .filter_map(|text| serde_json::from_str(text).ok()),
        );
    }
    (all, shared.is_some())
}

/// The view `GET /admin/deployments` answers and the console page shows.
pub(crate) fn deployments(state: &AppState, version: &Snapshot) -> Value {
    let (reports, shared) = reports(state);
    merged(
        version,
        &reports,
        &state.pool.store().map(|s| s.cooling()).unwrap_or_default(),
        shared,
    )
}

/// Merges gateways' reports over the policy's alias deployments and key pools.
fn merged(
    version: &Snapshot,
    reports: &[Value],
    cooling: &std::collections::HashMap<String, Instant>,
    shared: bool,
) -> Value {
    // Every deployment an alias names, with its aliases and limits, then any other a gateway has seen.
    let mut known: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    for a in &version.aliases {
        for d in &a.deployments {
            let entry = known
                .entry(alias::label(&d.provider, &d.model))
                .or_insert_with(|| {
                    let mut entry = Map::new();
                    entry.insert("provider".into(), d.provider.as_str().into());
                    entry.insert("model".into(), d.model.as_str().into());
                    entry.insert("aliases".into(), json!([]));
                    entry.insert(
                        "limits".into(),
                        json!({ "rpm": d.rpm, "tpm": d.tpm, "max_parallel": d.max_parallel }),
                    );
                    entry.insert("probed".into(), d.probe.is_some().into());
                    entry
                });
            if let Some(aliases) = entry.get_mut("aliases").and_then(Value::as_array_mut)
                && !aliases.iter().any(|n| n == a.name.as_str())
            {
                aliases.push(a.name.as_str().into());
            }
        }
    }
    for report in reports {
        for name in report["deployments"].as_object().into_iter().flatten() {
            known.entry(name.0.clone()).or_default();
        }
    }
    let now = Instant::now();
    let mut list = Vec::new();
    for (name, mut entry) in known {
        let seen: Vec<&Value> = reports
            .iter()
            .map(|r| &r["deployments"][name.as_str()])
            .filter(|d| d.is_object())
            .collect();
        let sum = |field: &str| -> u64 { seen.iter().filter_map(|d| d[field].as_u64()).sum() };
        let most = |field: &str| -> f64 {
            seen.iter()
                .filter_map(|d| d[field].as_f64())
                .fold(0.0, f64::max)
        };
        let from_store = cooling
            .get(&name)
            .and_then(|until| until.checked_duration_since(now))
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let cooling_ms = seen
            .iter()
            .filter_map(|d| d["cooling_ms"].as_u64())
            .max()
            .unwrap_or(0)
            .max(from_store);
        // The newest probe any gateway ran: one gateway at a time holds a deployment's probe.
        let probe = seen
            .iter()
            .map(|d| &d["probe"])
            .filter(|p| p.is_object())
            .max_by_key(|p| p["time"].as_str().unwrap_or_default().to_string())
            .cloned();
        let samples: VecDeque<u32> = seen
            .iter()
            .flat_map(|d| d["latency"].as_array().into_iter().flatten())
            .filter_map(|ms| ms.as_u64().and_then(|ms| u32::try_from(ms).ok()))
            .collect();
        let headroom = seen
            .iter()
            .filter_map(|d| d["headroom"].as_f64())
            .min_by(f64::total_cmp);
        let probe_down = probe.as_ref().is_some_and(|p| p["up"] == false);
        let state = if cooling_ms > 0 {
            "cooling"
        } else if probe_down {
            "down"
        } else {
            "up"
        };
        entry.insert("deployment".into(), name.into());
        entry.insert("state".into(), state.into());
        entry.insert("cooling_seconds".into(), cooling_ms.div_ceil(1000).into());
        entry.insert("cooldowns".into(), sum("cooldowns").into());
        entry.insert("probe".into(), probe.unwrap_or(Value::Null));
        entry.insert(
            "latency_p50_ms".into(),
            alias::percentile(&samples, 50).into(),
        );
        entry.insert(
            "latency_p90_ms".into(),
            alias::percentile(&samples, 90).into(),
        );
        // A moving share of recent attempts that failed; the highest any gateway sees.
        entry.insert(
            "error_rate".into(),
            ((most("errors") * 1000.0).round() / 1000.0).into(),
        );
        entry.insert("in_flight".into(), sum("in_flight").into());
        entry.insert("requests_this_minute".into(), sum("requests").into());
        entry.insert("tokens_this_minute".into(), sum("tokens").into());
        entry.insert("rate_headroom".into(), headroom.into());
        list.push(Value::Object(entry));
    }
    let mut providers = Vec::new();
    for provider in &version.providers {
        let keys: Vec<Value> = provider
            .pool
            .iter()
            .map(|(_, id)| {
                let name = format!("{}/{id}", provider.name);
                let seen: Vec<&Value> = reports
                    .iter()
                    .map(|r| &r["keys"][name.as_str()])
                    .filter(|k| k.is_object())
                    .collect();
                let resting = seen
                    .iter()
                    .filter_map(|k| k["resting_ms"].as_u64())
                    .max()
                    .unwrap_or(0);
                json!({
                    "key": id,
                    "state": if resting > 0 { "resting" } else { "ready" },
                    "resting_seconds": resting.div_ceil(1000),
                    "uses": seen.iter().filter_map(|k| k["uses"].as_u64()).sum::<u64>(),
                })
            })
            .collect();
        providers.push(json!({
            "name": provider.name,
            "kind": provider.kind.word(),
            "models": provider.models,
            "keys": keys,
        }));
    }
    json!({
        "counted_by": if shared { "store" } else { "this gateway" },
        "gateways": reports.len(),
        "deployments": list,
        "providers": providers,
    })
}

/// Tests the connection to a provider with the cheapest call it documents: its model list, which bills nothing.
/// Any 2xx means the address, the key and the network all hold.
pub(crate) async fn test_provider(state: &AppState, version: &Snapshot, index: usize) -> Value {
    let Some(provider) = version.providers.get(index) else {
        return json!({ "ok": false, "outcome": "no_such_provider" });
    };
    if provider.passthrough {
        // No key of Gantry's to test: each person's own login is tested by their first request.
        return json!({
            "ok": true,
            "outcome": "passthrough",
            "message": "This provider sends each person's own Claude login. Gantry holds no key to test: the first request from Claude Code shows whether it works.",
        });
    }
    let started = Instant::now();
    let ids: Vec<String> = provider.pool.iter().map(|(_, id)| id.clone()).collect();
    let key = state.pool.key(
        &provider.name,
        &ids,
        &provider.key_weights,
        provider.least_used_key,
    );
    let built = axum::http::Request::builder()
        .method(Method::GET)
        .uri(MODELS)
        .header("anthropic-version", "2023-06-01")
        .body(())
        .map_err(|err| err.to_string())
        .and_then(|request| {
            let (parts, ()) = request.into_parts();
            crate::outbound(
                provider,
                &parts,
                &axum::body::Bytes::new(),
                MODELS,
                None,
                "",
                key,
            )
            .map_err(|refusal| refusal.message)
        });
    let hop = Hop::default();
    let outcome = match built {
        Ok(request) => {
            crate::attempt_within(state, provider, request, &state.limits(provider, &hop))
                .await
                .map_err(|refusal| (refusal.code.to_string(), refusal.message))
        }
        Err(message) => Err(("not_sent".to_string(), message)),
    };
    let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let mut result = json!({
        "provider": provider.name,
        "call": format!("GET {MODELS}"),
        "latency_ms": latency_ms,
        "key": key.and_then(|k| ids.get(k).cloned()),
    });
    match outcome {
        Ok(response) => {
            let status = response.status();
            // The list is read to count it, up to 1 MiB: never shown, since a provider's error text is its own.
            let body = http_body_util::BodyExt::collect(http_body_util::Limited::new(
                response.into_body(),
                1 << 20,
            ))
            .await
            .map(|b| b.to_bytes())
            .unwrap_or_default();
            let listed = serde_json::from_slice::<Value>(&body).ok().and_then(|v| {
                ["data", "models", "modelSummaries"]
                    .iter()
                    .find_map(|field| v[*field].as_array().map(Vec::len))
            });
            result["ok"] = status.is_success().into();
            result["status"] = status.as_u16().into();
            result["outcome"] = status.as_u16().to_string().into();
            result["models_listed"] = listed.into();
            result["detail"] = match status.as_u16() {
                200..=299 => "The provider answered: its address and key work.".to_string(),
                401 | 403 => format!("The provider refused the key ({status}). Check the provider's credential (its key_env or its entry on the Credentials page) and that the key may list models."),
                404 => "The provider has no model list at this address (404). Check the provider's url in the policy; some providers serve no model list, and a request is the only test.".to_string(),
                429 => "The provider answered 429: the address and key work, and the key is out of quota or rate limited now.".to_string(),
                _ => format!("The provider answered {status}. Try again; if it stays, check the provider's status page and its url in the policy."),
            }
            .into();
        }
        Err((code, message)) => {
            result["ok"] = false.into();
            result["outcome"] = code.into();
            result["detail"] = format!("{message} Check the provider's url in the policy and that this gateway can reach it.").into();
        }
    }
    result
}

/// The console's Deployments page and its connection test.
pub(crate) fn console(state: Arc<AppState>) -> gantry_console::Extension {
    let (shown, tested) = (state.clone(), state);
    let routes: Router<Console> = Router::new().route(
        "/deployments",
        get(
            move |State(console): State<Console>, headers: HeaderMap, uri: Uri| {
                let state = shown.clone();
                async move { page(&state, &console, &headers, &uri, None).await }
            },
        )
        .post(
            move |State(console): State<Console>, headers: HeaderMap, uri: Uri, body: String| {
                let state = tested.clone();
                async move { test(&state, &console, &headers, &uri, &body).await }
            },
        ),
    );
    gantry_console::Extension {
        nav: vec![("/console/deployments".into(), TITLE.into())],
        routes,
        ..gantry_console::Extension::default()
    }
}

fn number(value: &Value, unit: &str) -> String {
    match value.as_f64() {
        Some(n) => format!("{n}{unit}"),
        None => "-".into(),
    }
}

async fn page(
    state: &AppState,
    console: &Console,
    headers: &HeaderMap,
    uri: &Uri,
    tested: Option<&Value>,
) -> Response {
    let Some(admin) = console.signed_in(headers).await else {
        return gantry_console::redirect("/console/sign-in");
    };
    let version = state.version();
    let view = deployments(state, &version);
    let mut rows = String::new();
    for d in view["deployments"].as_array().into_iter().flatten() {
        let text = |field: &str| d[field].as_str().unwrap_or_default();
        let state_tag = match text("state") {
            "up" => html::tag("allow", "up", ""),
            "cooling" => html::tag(
                "warn",
                "cooling",
                &format!("{} s left", d["cooling_seconds"].as_u64().unwrap_or(0)),
            ),
            _ => html::tag("block", "down", ""),
        };
        let probe = match &d["probe"] {
            Value::Object(p) => format!(
                "probe {} at {}",
                p.get("outcome").and_then(Value::as_str).unwrap_or_default(),
                p.get("time").and_then(Value::as_str).unwrap_or_default()
            ),
            _ if d["probed"] == true => "probe not run yet".to_string(),
            _ => "no probe".to_string(),
        };
        let limits = ["rpm", "tpm", "max_parallel"]
            .iter()
            .filter_map(|l| d["limits"][*l].as_u64().map(|n| format!("{l} {n}")))
            .collect::<Vec<_>>();
        let aliases: Vec<&str> = d["aliases"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let meta = format!(
            "alias {} · {} · limits {} · now {} in flight, {} requests and {} tokens this minute · p50 {} p90 {} · error rate {} · {} cooldowns",
            html::esc(&if aliases.is_empty() {
                "none".to_string()
            } else {
                aliases.join(", ")
            }),
            html::esc(&probe),
            html::esc(&if limits.is_empty() {
                "none".to_string()
            } else {
                limits.join(", ")
            }),
            d["in_flight"].as_u64().unwrap_or(0),
            d["requests_this_minute"].as_u64().unwrap_or(0),
            d["tokens_this_minute"].as_u64().unwrap_or(0),
            number(&d["latency_p50_ms"], " ms"),
            number(&d["latency_p90_ms"], " ms"),
            d["error_rate"].as_f64().unwrap_or(0.0),
            d["cooldowns"].as_u64().unwrap_or(0),
        );
        rows.push_str(&html::row(
            &html::esc(text("deployment")),
            &meta,
            &state_tag,
            true,
        ));
    }
    if rows.is_empty() {
        rows = html::empty(
            "",
            "No deployments yet",
            "A deployment is a provider and model an alias names under aliases: in the policy. Its circuit, probe, limits and latency show here once the policy has one.",
            "",
        );
    }
    let may_test = admin.may(Permission::EditPolicy) && !admin.confined();
    let mut providers = String::new();
    for p in view["providers"].as_array().into_iter().flatten() {
        let name = p["name"].as_str().unwrap_or_default();
        let keys: Vec<String> = p["keys"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|k| {
                let state = match k["state"].as_str() {
                    Some("resting") => {
                        format!("resting {} s", k["resting_seconds"].as_u64().unwrap_or(0))
                    }
                    _ => "ready".to_string(),
                };
                format!(
                    "{} {state}, {} uses",
                    k["key"].as_str().unwrap_or_default(),
                    k["uses"].as_u64().unwrap_or(0)
                )
            })
            .collect();
        let mut meta = format!(
            "{} · {}",
            html::esc(p["kind"].as_str().unwrap_or_default()),
            html::esc(&if keys.is_empty() {
                "one key".to_string()
            } else {
                format!("key pool: {}", keys.join("; "))
            })
        );
        let mut end = String::new();
        if let Some(result) = tested.filter(|t| t["provider"] == name) {
            end.push_str(&if result["ok"] == true {
                html::tag("allow", "connected", &number(&result["latency_ms"], " ms"))
            } else {
                html::tag(
                    "block",
                    "failed",
                    result["outcome"].as_str().unwrap_or_default(),
                )
            });
            meta.push_str(&format!(
                " · <b>{}</b>",
                html::esc(result["detail"].as_str().unwrap_or_default())
            ));
        }
        if may_test {
            end.push_str(&format!(
                r#"<form method="post" action="/console/deployments"><input type="hidden" name="provider" value="{}">{}</form>"#,
                html::esc(name),
                html::button("Test connection", "quiet", "submit", "")
            ));
        }
        providers.push_str(&html::row(&html::esc(name), &meta, &end, true));
    }
    let lead = format!(
        "Each deployment of an alias: whether it takes requests, its last probe, its limits and load, latency and error rate, as {} sees them. Below, each provider with its key pool; a connection test asks for its model list, which bills nothing, and is recorded in the audit log.",
        if view["counted_by"] == "store" {
            format!(
                "every gateway on the store ({} now)",
                view["gateways"].as_u64().unwrap_or(1)
            )
        } else {
            "this gateway".to_string()
        }
    );
    let main = format!(
        "{}{rows}{}{providers}",
        html::head(TITLE, &lead, ""),
        html::head(
            "Providers",
            "Each provider of the policy and the keys of its pool.",
            ""
        ),
    );
    console.page(StatusCode::OK, &admin, TITLE, uri, &main)
}

async fn test(
    state: &AppState,
    console: &Console,
    headers: &HeaderMap,
    uri: &Uri,
    body: &str,
) -> Response {
    if !gantry_console::same_origin(headers) {
        return gantry_console::foreign();
    }
    let Some(admin) = console.signed_in(headers).await else {
        return gantry_console::redirect("/console/sign-in");
    };
    let form = Form::parse(body);
    let name = form.get("provider").to_string();
    let version = state.version();
    let index = version.providers.iter().position(|p| p.name == name);
    let allowed = admin.may(Permission::EditPolicy) && !admin.confined();
    let (Some(index), true) = (index, allowed) else {
        let code = if allowed {
            "no_such_provider"
        } else {
            "not_permitted"
        };
        let _ = console
            .audit(
                Some(&admin),
                "test_provider",
                json!({ "provider": name }),
                Some(code),
            )
            .await;
        return page(state, console, headers, uri, None).await;
    };
    let result = test_provider(state, &version, index).await;
    // The test's outcome is the record: who tested which provider, and what it answered.
    if let Err(message) = console
        .audit(Some(&admin), "test_provider", result.clone(), None)
        .await
    {
        let failed =
            json!({ "provider": name, "ok": false, "outcome": "not_recorded", "detail": message });
        return page(state, console, headers, uri, Some(&failed)).await;
    }
    page(state, console, headers, uri, Some(&result)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateways_reports_merge_into_one_view() {
        let version = Snapshot {
            policy: None,
            providers: Vec::new(),
            aliases: Vec::new(),
            policy_sha256: String::new(),
            keys_sha256: String::new(),
            mcp: Arc::default(),
        };
        let a = json!({"deployments": {"p/m": {"cooling_ms": 0, "cooldowns": 1, "errors": 0.2, "latency": [10, 20, 30], "in_flight": 1, "requests": 4, "tokens": 100,
            "probe": {"up": true, "outcome": "200", "time": "2026-11-15T10:00:00.000Z"}}}, "keys": {}});
        let b = json!({"deployments": {"p/m": {"cooling_ms": 4200, "cooldowns": 2, "errors": 0.5, "latency": [40, 50], "in_flight": 2, "requests": 1, "tokens": 50,
            "probe": {"up": false, "outcome": "503", "time": "2026-11-15T10:00:05.000Z"}}}, "keys": {}});
        let view = merged(
            &version,
            &[a.clone(), b],
            &std::collections::HashMap::new(),
            true,
        );
        let d = &view["deployments"][0];
        assert_eq!(view["counted_by"], "store");
        assert_eq!(view["gateways"], 2);
        assert_eq!(d["state"], "cooling", "cooling on any gateway is cooling");
        assert_eq!(d["cooling_seconds"], 5);
        assert_eq!(d["cooldowns"], 3);
        assert_eq!(d["in_flight"], 3);
        assert_eq!(d["requests_this_minute"], 5);
        assert_eq!(d["error_rate"], 0.5);
        assert_eq!(d["probe"]["outcome"], "503", "the newest probe");
        assert!(d["latency_p90_ms"].as_u64() >= d["latency_p50_ms"].as_u64());
        let alone = merged(&version, &[a], &std::collections::HashMap::new(), false);
        assert_eq!(alone["deployments"][0]["state"], "up");
        assert_eq!(alone["counted_by"], "this gateway");
    }
}
