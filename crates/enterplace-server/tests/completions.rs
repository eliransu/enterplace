//! Acceptance test for OpenAI's legacy text completions (`POST /v1/completions`): decided, guarded on its prompt,
//! forwarded as sent and charged from its usage.

use std::path::PathBuf;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::post,
};
use enterplace_core::id::sha256_hex;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

type Error = Box<dyn std::error::Error>;

const DANA: &str = "enterplace_completions_dana_key_00000";

async fn provider() -> Result<u16, Error> {
    let app = Router::new().route(
        "/v1/completions",
        post(|| async {
            (
                [(header::CONTENT_TYPE, "application/json")],
                r#"{"id":"c","object":"text_completion","model":"model-a","choices":[{"text":"hi"}],"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10}}"#,
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

fn files(port: u16) -> Result<(PathBuf, PathBuf), Error> {
    let dir = std::env::temp_dir().join(format!("enterplace-completions-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let policy = dir.join("enterplace.policy.yaml");
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
guardrails:
  - name: no-secrets
    type: secrets
    action: block
rules:
  - name: data
    principals: {{ team: data }}
    models: [model-a]
    guardrails: [no-secrets]
"
        ),
    )?;
    std::fs::write(
        dir.join("enterplace.keys.yaml"),
        format!(
            "keys:\n  - name: dana\n    team: data\n    sha256: {}\n",
            sha256_hex(DANA.as_bytes())
        ),
    )?;
    Ok((policy, dir.join("enterplace-audit.jsonl")))
}

async fn complete(app: &Router, body: &str) -> Result<(StatusCode, String), Error> {
    let response = app
        .clone()
        .oneshot(
            Request::post("/v1/completions")
                .header(header::AUTHORIZATION, format!("Bearer {DANA}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))?,
        )
        .await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, String::from_utf8(body.to_vec())?))
}

#[tokio::test]
async fn a_completion_is_guarded_on_its_prompt_and_charged_from_its_usage() -> Result<(), Error> {
    let (policy, audit) = files(provider().await?)?;
    let app =
        enterplace_server::governed(&policy, None, &|_| Some("provider-secret".into()))?.router;
    let (status, body) = complete(
        &app,
        r#"{"model":"model-a","prompt":"say hi","max_tokens":5}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = complete(
        &app,
        r#"{"model":"model-a","prompt":["AKIAIOSFODNN7EXAMPLE"]}"#,
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the guardrails read the prompt: {body}"
    );
    let (status, body) = complete(&app, r#"{"model":"model-a","prompt":[[1,2,3]]}"#).await?;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "token IDs are text the guardrails cannot read: {body}"
    );
    let (status, _) = complete(&app, r#"{"model":"gpt-9","prompt":"hi"}"#).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let mut charged = None;
    for _ in 0..50 {
        charged = std::fs::read_to_string(&audit)?
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .find(|r| r["event"] == "usage" && r["input_tokens"] == 7)
            .and_then(|r| r["charged_usd"].as_f64());
        if charged.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let charged = charged.ok_or("no usage record")?;
    assert!(
        (charged - (7.0 * 1000.0 + 3.0 * 2000.0) / 1e6).abs() < 1e-9,
        "{charged}"
    );
    Ok(())
}
