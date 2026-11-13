//! Acceptance tests for package 1.8: a native provider call goes through `/passthrough/<provider>/<path>` with the
//! caller's Gantry key swapped for the provider key, only on paths the caller's rule names, recorded, with spend.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::{get, post},
};
use gantry_core::id::sha256_hex;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

type Error = Box<dyn std::error::Error>;

const DATA: &str = "gantry_passthrough_data_key";
const OTHER: &str = "gantry_passthrough_other_key";

/// What the provider saw: method, path and query, and the authorization header.
type Seen = Arc<Mutex<Vec<(String, String, String)>>>;

async fn provider() -> Result<(u16, Seen), Error> {
    let seen: Seen = Arc::default();
    let note = |seen: Seen| {
        move |request: Request<Body>| {
            let auth = request
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let target = request
                .uri()
                .path_and_query()
                .map_or("", |p| p.as_str())
                .to_string();
            if let Ok(mut all) = seen.lock() {
                all.push((request.method().to_string(), target, auth));
            }
        }
    };
    let (a, b) = (note(seen.clone()), note(seen.clone()));
    let app = Router::new()
        // The legacy completions API: a native route Gantry does not serve itself.
        .route(
            "/v1/completions",
            post(move |request: Request<Body>| {
                a(request);
                async {
                    (
                        [(header::CONTENT_TYPE, "application/json")],
                        r#"{"id":"c","object":"text_completion","model":"model-a","choices":[{"text":"hi"}],"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10}}"#,
                    )
                }
            }),
        )
        .route(
            "/v1/batches/b1",
            get(move |request: Request<Body>| {
                b(request);
                async { ([(header::CONTENT_TYPE, "application/json")], r#"{"id":"b1","status":"completed"}"#) }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((port, seen))
}

fn files(name: &str, port: u16) -> Result<(PathBuf, PathBuf), Error> {
    let dir =
        std::env::temp_dir().join(format!("gantry-passthrough-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let policy = dir.join("gantry.policy.yaml");
    std::fs::write(
        &policy,
        format!(
            "version: 1
providers:
  - name: mock
    kind: openai
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: MOCK_KEY
    models: [model-a]
prices:
  model-a: {{ input: 1000, output: 2000 }}
rules:
  - name: data
    principals: {{ team: data }}
    models: [model-a]
    passthrough:
      - {{ provider: mock, paths: [/v1/completions, /v1/batches] }}
  - name: others
    principals: {{ team: others }}
    models: [model-a]
"
        ),
    )?;
    let key = |name: &str, team: &str, key: &str| {
        format!(
            "  - name: {name}\n    team: {team}\n    sha256: {}\n",
            sha256_hex(key.as_bytes())
        )
    };
    std::fs::write(
        dir.join("gantry.keys.yaml"),
        format!(
            "keys:\n{}{}",
            key("dana", "data", DATA),
            key("omer", "others", OTHER)
        ),
    )?;
    Ok((policy, dir.join("gantry-audit.jsonl")))
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    key: &str,
    body: &str,
) -> Result<(StatusCode, String), Error> {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header(header::AUTHORIZATION, format!("Bearer {key}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))?,
        )
        .await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, String::from_utf8(body.to_vec())?))
}

fn records(path: &PathBuf) -> Result<Vec<Value>, Error> {
    std::fs::read_to_string(path)?
        .lines()
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

#[tokio::test]
async fn a_native_call_passes_through_with_the_provider_key_and_its_spend_is_recorded()
-> Result<(), Error> {
    let (port, seen) = provider().await?;
    let (policy, audit) = files("native", port)?;
    let gw = gantry_server::governed(&policy, None, &|_| Some("provider-secret".into()))?;
    let app = gw.router.clone();

    let (status, body) = call(
        &app,
        "POST",
        "/passthrough/mock/v1/completions",
        DATA,
        r#"{"model":"model-a","prompt":"hi"}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.contains("text_completion"),
        "the provider's native answer comes back as sent: {body}"
    );

    let (status, body) = call(&app, "GET", "/passthrough/mock/v1/batches/b1", DATA, "").await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "a call with no body and no model reaches a listed path: {body}"
    );

    let sent = seen.lock().map_err(|_| "poisoned")?.clone();
    assert_eq!(
        sent,
        vec![
            (
                "POST".to_string(),
                "/v1/completions".to_string(),
                "Bearer provider-secret".to_string()
            ),
            (
                "GET".to_string(),
                "/v1/batches/b1".to_string(),
                "Bearer provider-secret".to_string()
            ),
        ],
        "the provider gets its own path and the provider key, never the Gantry key"
    );

    // Spend: the usage record of the native call carries the provider's tokens and their cost.
    let mut usage = None;
    for _ in 0..50 {
        usage = records(&audit)?
            .into_iter()
            .find(|r| r["event"] == "usage" && r["path"].is_null() && r["input_tokens"] == 7);
        if usage.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let usage = usage.ok_or("no usage record for the native call")?;
    assert_eq!(usage["output_tokens"], 3);
    let cost = usage["charged_usd"].as_f64().ok_or("no cost")?;
    assert!(
        (cost - (7.0 * 1000.0 + 3.0 * 2000.0) / 1e6).abs() < 1e-9,
        "charged {cost}"
    );
    Ok(())
}

#[tokio::test]
async fn passthrough_reaches_only_what_the_rule_names_and_every_refusal_is_recorded()
-> Result<(), Error> {
    let (port, seen) = provider().await?;
    let (policy, audit) = files("refused", port)?;
    let gw = gantry_server::governed(&policy, None, &|_| Some("provider-secret".into()))?;
    let app = gw.router.clone();

    for (method, path, key, body, code) in [
        // A path the rule does not list, though the provider has it: the org's provider key must not reach it.
        (
            "GET",
            "/passthrough/mock/v1/organization/admin_api_keys",
            DATA,
            "",
            "passthrough_not_allowed",
        ),
        // A rule with no passthrough reaches nothing.
        (
            "POST",
            "/passthrough/mock/v1/completions",
            OTHER,
            r#"{"model":"model-a"}"#,
            "passthrough_not_allowed",
        ),
        // A model the rule does not allow is refused here as on every other route.
        (
            "POST",
            "/passthrough/mock/v1/completions",
            DATA,
            r#"{"model":"gpt-9"}"#,
            "model_not_allowed",
        ),
        (
            "POST",
            "/passthrough/nope/v1/completions",
            DATA,
            r#"{"model":"model-a"}"#,
            "unknown_provider",
        ),
        // No way out of a listed prefix.
        (
            "GET",
            "/passthrough/mock/v1/batches/../organization/x",
            DATA,
            "",
            "passthrough_not_allowed",
        ),
    ] {
        let (status, answer) = call(&app, method, path, key, body).await?;
        assert!(status.is_client_error(), "{path}: {status} {answer}");
        assert!(answer.contains(code), "{path}: {answer}");
    }
    assert!(
        seen.lock().map_err(|_| "poisoned")?.is_empty(),
        "no refused call reached the provider"
    );
    let refused = records(&audit)?
        .into_iter()
        .filter(|r| r["verdict"] == "refused")
        .count();
    assert_eq!(refused, 5, "each refusal is recorded");
    Ok(())
}

#[tokio::test]
async fn guardrails_read_every_string_of_a_passthrough_body() -> Result<(), Error> {
    let (port, seen) = provider().await?;
    let (policy, _audit) = files("guarded", port)?;
    let text = std::fs::read_to_string(&policy)?
        .replace(
            "rules:\n",
            "guardrails:\n  - name: no-secrets\n    type: secrets\n    action: block\nrules:\n",
        )
        .replace(
            "    passthrough:\n",
            "    guardrails: [no-secrets]\n    passthrough:\n",
        );
    std::fs::write(&policy, text)?;
    let gw = gantry_server::governed(&policy, None, &|_| Some("provider-secret".into()))?;
    let app = gw.router.clone();
    // A field no chat route has: the secret is still found.
    let (status, body) = call(
        &app,
        "POST",
        "/passthrough/mock/v1/completions",
        DATA,
        r#"{"model":"model-a","suffix":{"note":"AKIAIOSFODNN7EXAMPLE"}}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("guardrail_blocked"), "{body}");
    // A call with no body has nothing to scan and still goes through.
    let (status, body) = call(&app, "GET", "/passthrough/mock/v1/batches/b1", DATA, "").await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        seen.lock().map_err(|_| "poisoned")?.len(),
        1,
        "only the call with no secret reached the provider"
    );
    Ok(())
}
