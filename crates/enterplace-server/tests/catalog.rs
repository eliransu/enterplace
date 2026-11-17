//! A smoke test for every provider of the catalog: a policy that names it with `preset:`, its URL moved to a mock on
//! 127.0.0.1 with the entry's own path kept, and one governed chat request. The provider must get the request on the
//! entry's path with the key in the entry's header, and the request must be recorded.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, header},
    response::IntoResponse,
};
use enterplace_core::{
    catalog::{PRESETS, Preset},
    config::Kind,
    id::sha256_hex,
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

type Error = Box<dyn std::error::Error>;

const MAYA: &str = "enterplace_maya_0123456789abcdef0123456789";

type Seen = Arc<Mutex<Vec<(String, HeaderMap)>>>;

/// A provider that answers every API Enterplace speaks: the reply follows the path it was sent to.
async fn mock() -> Result<(u16, Seen), Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let seen: Seen = Arc::default();
    let log = seen.clone();
    let app = Router::new().fallback(move |request: Request<Body>| {
        let log = log.clone();
        async move {
            let path = request.uri().path().to_string();
            if let Ok(mut log) = log.lock() {
                log.push((path.clone(), request.headers().clone()));
            }
            let body = if path.ends_with(":generateContent") {
                r#"{"candidates":[{"content":{"role":"model","parts":[{"text":"hi"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1}}"#
            } else if path.ends_with("/messages") {
                r#"{"id":"msg_1","type":"message","role":"assistant","model":"m","content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}"#
            } else {
                r#"{"id":"c1","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#
            };
            ([(header::CONTENT_TYPE, "application/json")], body).into_response()
        }
    });
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((port, seen))
}

/// The entry's path, which the mock must see in front of the route.
fn path_of(url: &str) -> &str {
    url.split_once("://")
        .and_then(|(_, rest)| rest.find('/').map(|at| &rest[at..]))
        .unwrap_or_default()
}

fn dir(id: &str) -> std::io::Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!("enterplace-catalog-{}-{id}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// One governed request through the preset. Returns what went wrong, if anything.
async fn smoke(preset: &Preset, port: u16, seen: &Seen) -> Result<(), Error> {
    // watsonx.ai trades its key for an IAM token first, SageMaker signs with AWS credentials and its region, and
    // Replicate answers with a prediction: providers_cloud.rs runs each against a mock of its own. The demo model
    // is answered inside the gateway and sends nothing: the enterplace-cli start tests and ftue_check.py cover it.
    if matches!(
        preset.kind,
        Kind::Watsonx | Kind::Sagemaker | Kind::Replicate | Kind::Demo
    ) {
        return Ok(());
    }
    let path = path_of(preset.url);
    let dir = dir(preset.id)?;
    let policy = dir.join("enterplace.policy.yaml");
    // The url is the one field moved, to the mock; kind comes from the preset.
    std::fs::write(
        &policy,
        format!(
            "version: 1
providers:
  - name: under-test
    preset: {}
    url: http://127.0.0.1:{port}{path}
    allow_private: true
    key_env: PROVIDER_KEY
    models: [m]
rules:
  - name: everyone
    principals: {{ any: true }}
    models: [m]
",
            preset.id
        ),
    )?;
    std::fs::write(
        dir.join("enterplace.keys.yaml"),
        format!(
            "keys:\n  - name: maya.cohen\n    team: payments\n    sha256: {}\n",
            sha256_hex(MAYA.as_bytes())
        ),
    )?;
    let secret = format!("{}-provider-key", preset.id);
    let gw = enterplace_server::governed(&policy, None, &|_| Some(secret.clone()))?;
    if gw.loaded.providers.first().map(|p| p.kind) != Some(preset.kind) {
        return Err("the policy did not take the preset's kind".into());
    }
    let (route, body, want_path) = match preset.kind {
        Kind::Anthropic => (
            "/v1/messages",
            r#"{"model":"m","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}"#,
            format!("{path}/messages"),
        ),
        Kind::Gemini => (
            "/v1/chat/completions",
            r#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#,
            format!("{path}/models/m:generateContent"),
        ),
        Kind::Cohere => (
            "/v1/chat/completions",
            r#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#,
            format!("{path}/chat"),
        ),
        _ => (
            "/v1/chat/completions",
            r#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#,
            format!("{path}/chat/completions"),
        ),
    };
    if let Ok(mut seen) = seen.lock() {
        seen.clear();
    }
    let response = gw
        .router
        .clone()
        .oneshot(
            Request::post(route)
                .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))?,
        )
        .await?;
    let status = response.status();
    let text = String::from_utf8(response.into_body().collect().await?.to_bytes().to_vec())?;
    if !status.is_success() {
        return Err(format!("answered {status}: {text}").into());
    }
    let (got_path, headers) = seen
        .lock()
        .map_err(|_| "poisoned")?
        .first()
        .cloned()
        .ok_or("the provider was sent nothing")?;
    if got_path != want_path {
        return Err(format!("the provider was sent {got_path}, not {want_path}").into());
    }
    let (name, want) = match preset.key_header() {
        "Authorization: Bearer" => ("authorization", format!("Bearer {secret}")),
        other => (other, secret.clone()),
    };
    let got = headers.get(name).and_then(|v| v.to_str().ok());
    if got != Some(want.as_str()) {
        return Err(format!("{name} was {got:?}, not the provider key").into());
    }
    let audit = std::fs::read_to_string(dir.join("enterplace-audit.jsonl"))?;
    let recorded = audit
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .any(|r| r["provider"] == "under-test" && r["verdict"] == "allow" && r["model"] == "m");
    if !recorded {
        return Err(format!("no allow record for the request in {audit}").into());
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn every_catalog_provider_gets_a_governed_request_on_its_path_with_its_key_header()
-> Result<(), Error> {
    let (port, seen) = mock().await?;
    let mut failed = Vec::new();
    for preset in PRESETS {
        if let Err(err) = smoke(preset, port, &seen).await {
            failed.push(format!("{}: {err}", preset.id));
        }
    }
    assert!(failed.is_empty(), "{}", failed.join("\n"));
    Ok(())
}
