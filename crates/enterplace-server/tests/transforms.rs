//! Transforms: the embedding binary's `Transform` hook and `type: transform` services rewrite the request before it
//! is checked and sent and the answer before it is checked and returned, each change recorded as paths only.
//! The provider echoes the request it got as the answer's text, so a test sees what was sent.

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
    routing::post,
};
use enterplace_core::id::sha256_hex;
use enterplace_server::{Extension, Governed, Transform, TransformContext};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Error = Box<dyn std::error::Error>;

const MAYA: &str = "enterplace_maya_0123456789abcdef0123456789";
const AWS: &str = "AKIAIOSFODNN7EXAMPLE";

async fn serve(app: Router) -> Result<u16, Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

/// The provider: its answer's text is the request it was sent.
async fn provider() -> Result<u16, Error> {
    serve(Router::new().route(
        "/v1/chat/completions",
        post(|body: Bytes| async move {
            let sent = String::from_utf8_lossy(&body).to_string();
            (
                [(header::CONTENT_TYPE, "application/json")],
                json!({"id": "c", "object": "chat.completion", "model": "model-a",
                    "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": sent}}],
                    "usage": {"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10}})
                .to_string(),
            )
        }),
    ))
    .await
}

/// The transform service: on a request it puts a system message first; on an answer it appends a footer. Under
/// /model it changes the model, which Enterplace refuses.
async fn service() -> Result<u16, Error> {
    serve(
        Router::new()
            .route(
                "/style",
                post(|body: Bytes| async move {
                    let sent: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                    let mut out = sent["body"].clone();
                    if sent["side"] == "request" {
                        if let Some(list) = out["messages"].as_array_mut() {
                            list.insert(0, json!({"role": "system", "content": "house style"}));
                        }
                    } else if let Some(text) = out["choices"][0]["message"]["content"].as_str() {
                        out["choices"][0]["message"]["content"] = json!(format!("{text} [footer]"));
                    }
                    json!({"body": out}).to_string()
                }),
            )
            .route(
                "/model",
                post(|body: Bytes| async move {
                    let sent: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                    let mut out = sent["body"].clone();
                    out["model"] = json!("bigger-model");
                    json!({"body": out}).to_string()
                }),
            ),
    )
    .await
}

fn policy(port: u16, guardrails: &str, names: &str) -> String {
    format!(
        "version: 1
providers:
  - name: mock
    kind: openai
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: MOCK_KEY
    models: [model-a]
guardrails:
{guardrails}  - name: no-secrets
    type: secrets
    action: block
rules:
  - name: everyone
    principals: {{ any: true }}
    models: [\"*\"]
    guardrails: [{names}]
"
    )
}

fn transform(name: &str, url: &str, on_failure: &str) -> String {
    format!(
        "  - name: {name}\n    type: transform\n    url: {url}\n    on: [request, answer]\n    timeout_ms: 2000\n    on_failure: {on_failure}\n"
    )
}

struct Setup {
    audit: std::path::PathBuf,
    gw: Governed,
}

fn setup(name: &str, policy: &str, own: Option<Arc<dyn Transform>>) -> Result<Setup, Error> {
    let dir = std::env::temp_dir().join(format!(
        "enterplace-transform-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("enterplace.policy.yaml");
    std::fs::write(&path, policy)?;
    std::fs::write(
        dir.join("enterplace.keys.yaml"),
        format!(
            "keys:\n  - name: maya.cohen\n    team: payments\n    sha256: {}\n",
            sha256_hex(MAYA.as_bytes())
        ),
    )?;
    let gw = enterplace_server::governed_with(&path, None, &|_| Some("k".into()), &move |_| {
        Ok(Extension {
            transform: own.clone(),
            ..Extension::default()
        })
    })?;
    Ok(Setup {
        audit: dir.join("enterplace-audit.jsonl"),
        gw,
    })
}

async fn chat(gw: &Governed, text: &str) -> Result<(StatusCode, Value), Error> {
    let body = json!({"model": "model-a", "messages": [{"role": "user", "content": text}]});
    let request = Request::post("/v1/chat/completions")
        .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
        .body(Body::from(body.to_string()))?;
    let response = gw.router.clone().oneshot(request).await?;
    let status = response.status();
    let bytes = response.into_body().collect().await?.to_bytes();
    Ok((status, serde_json::from_slice(&bytes)?))
}

fn records(s: &Setup) -> Result<Vec<Value>, Error> {
    std::fs::read_to_string(&s.audit)?
        .lines()
        .map(|l| Ok(serde_json::from_str::<Value>(l)?))
        .collect()
}

/// The text the provider says it was sent, as JSON.
fn sent(answer: &Value) -> Result<Value, Error> {
    let text = answer["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or_default();
    let json = text.trim_end_matches(" [footer]");
    Ok(serde_json::from_str(json)?)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_transform_service_rewrites_both_sides_and_the_record_has_paths_only() -> TestResult {
    let svc = service().await?;
    let s = setup(
        "service",
        &policy(
            provider().await?,
            &transform(
                "style",
                &format!("http://127.0.0.1:{svc}/style"),
                "fail_closed",
            ),
            "no-secrets, style",
        ),
        None,
    )?;
    let (status, answer) = chat(&s.gw, "hello").await?;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let forwarded = sent(&answer)?;
    assert_eq!(forwarded["messages"][0]["content"], "house style");
    assert!(
        answer["choices"][0]["message"]["content"]
            .as_str()
            .is_some_and(|t| t.ends_with(" [footer]"))
    );
    let all = records(&s)?;
    let request = all
        .iter()
        .find(|r| r.get("event").is_none())
        .ok_or("no record")?;
    assert_eq!(request["transforms"][0]["transform"], "style");
    assert_eq!(request["transforms"][0]["outcome"], "changed");
    // Arrays are compared by position: a message put first changes message 1 and adds message 2.
    let changes = request["transforms"][0]["changes"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        changes.contains(&json!({"op": "add", "path": "/messages/1"})),
        "{changes:?}"
    );
    let text = serde_json::to_string(&all)?;
    assert!(
        !text.contains("house style") && !text.contains("hello"),
        "{text}"
    );
    let on_answer = all
        .iter()
        .find(|r| r["event"] == "answer_guardrails")
        .ok_or("no answer record")?;
    assert_eq!(on_answer["transforms"][0]["side"], "answer");

    // The guardrails read what the transform wrote, so a secret it carries is still refused.
    let (status, _) = chat(&s.gw, &format!("key {AWS}")).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_transform_that_changes_the_model_or_is_down_follows_on_failure() -> TestResult {
    let svc = service().await?;
    let port = provider().await?;
    let s = setup(
        "model",
        &policy(
            port,
            &transform("t", &format!("http://127.0.0.1:{svc}/model"), "fail_closed"),
            "t",
        ),
        None,
    )?;
    let (status, body) = chat(&s.gw, "hello").await?;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(body["error"]["code"], "transform_failed");

    let down = std::net::TcpListener::bind(("127.0.0.1", 0))?
        .local_addr()?
        .port();
    let s = setup(
        "open",
        &policy(
            port,
            &transform("t", &format!("http://127.0.0.1:{down}/x"), "fail_open"),
            "t",
        ),
        None,
    )?;
    let (status, answer) = chat(&s.gw, "hello").await?;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(sent(&answer)?["messages"][0]["content"], "hello");
    let record = records(&s)?
        .into_iter()
        .find(|r| r.get("event").is_none())
        .ok_or("no record")?;
    assert_eq!(record["transforms"][0]["outcome"], "skipped");
    Ok(())
}

struct Redact;

impl Transform for Redact {
    fn request(&self, _: &TransformContext<'_>, body: &mut Value) -> Result<(), String> {
        if let Some(text) = body["messages"][0]["content"].as_str() {
            body["messages"][0]["content"] = json!(text.replace("Project Falcon", "[codename]"));
        }
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_binarys_transform_runs_first_and_is_recorded() -> TestResult {
    let s = setup(
        "extension",
        &policy(provider().await?, "", "no-secrets"),
        Some(Arc::new(Redact)),
    )?;
    let (status, answer) = chat(&s.gw, "status of Project Falcon").await?;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(
        sent(&answer)?["messages"][0]["content"],
        "status of [codename]"
    );
    let record = records(&s)?
        .into_iter()
        .find(|r| r.get("event").is_none())
        .ok_or("no record")?;
    assert_eq!(record["transforms"][0]["transform"], "extension");
    assert_eq!(record["transforms"][0]["outcome"], "changed");
    Ok(())
}
