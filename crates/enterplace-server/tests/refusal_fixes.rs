//! A refusal a gateway admin can fix carries the fix: `fix: { steps, console, docs }` beside the code, and the same
//! steps at the end of the message, since most clients show only the message. The console link opens the dialog
//! that fixes it, filled in with the model, caller or rule, on this gateway as the caller reached it. The fields are
//! additive: the code, the message's start and the decision stay as they were.

use std::path::PathBuf;

use axum::{
    Router,
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
    routing::post,
};
use enterplace_core::id::sha256_hex;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Error = Box<dyn std::error::Error>;

const BOT: &str = "enterplace_bot_00123456789abcdef0123456789";
const LIMITED: &str = "enterplace_lim_00123456789abcdef0123456789";
const NEWBIE: &str = "enterplace_new_00123456789abcdef0123456789";
const DOCS: &str = "https://docs.enterplace.dev/reference/refusal-codes/";

async fn provider() -> Result<u16, Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let app = Router::new().route(
        "/v1/chat/completions",
        post(|_: Bytes| async move {
            axum::response::Response::builder()
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"choices":[]}"#))
                .unwrap_or_default()
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

async fn gateway(name: &str) -> Result<enterplace_server::Governed, Error> {
    let port = provider().await?;
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "enterplace-refusal-fixes-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let entry = |name: &str, team: &str, key: &str| {
        format!(
            "  - name: {name}\n    team: {team}\n    sha256: {}\n",
            sha256_hex(key.as_bytes())
        )
    };
    std::fs::write(
        dir.join("enterplace.keys.yaml"),
        format!(
            "keys:\n{}{}{}",
            entry("adamainewapp", "backend", BOT),
            entry("narrow-bot", "limited", LIMITED),
            entry("fresh-bot", "backend", NEWBIE),
        ),
    )?;
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
    key_env: MOCK_PROVIDER_KEY
    models: [model-a, model-b]
  - name: claude-subscriptions
    kind: anthropic
    url: http://127.0.0.1:{port}
    allow_private: true
    auth: passthrough
    models: [claude-sonnet-5-5]
rules:
  - name: narrow
    principals: {{ team: limited }}
    models: [model-a]
  - name: everyone
    principals: {{ any: true }}
    models: [\"*\"]
new_callers:
  mode: hold
  allowed: [adamainewapp, narrow-bot]
"
        ),
    )?;
    Ok(enterplace_server::governed(&policy, None, &|_| {
        Some("provider-secret".into())
    })?)
}

fn call(path: &str, key: &str, model: &str) -> Result<Request<Body>, axum::http::Error> {
    Request::post(path)
        .header(header::HOST, "gw.example.com")
        .header("x-forwarded-proto", "https")
        .header(header::AUTHORIZATION, format!("Bearer {key}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(format!(
            r#"{{"model":"{model}","max_tokens":16,"messages":[{{"role":"user","content":"hi"}}]}}"#
        )))
}

async fn answer(app: &Router, request: Request<Body>) -> Result<(StatusCode, Value), Error> {
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, serde_json::from_slice(&body).unwrap_or(Value::Null)))
}

/// The refusal's code, its fix and its message, from the OpenAI or the Anthropic shape.
fn parts(body: &Value) -> (&str, &Value, &str) {
    let code = body["error"]["code"]
        .as_str()
        .or(body["enterplace_code"].as_str())
        .unwrap_or("");
    let fix = if body["error"]["fix"].is_null() {
        &body["fix"]
    } else {
        &body["error"]["fix"]
    };
    (code, fix, body["error"]["message"].as_str().unwrap_or(""))
}

/// Checks a refusal's fix: its console link, its docs section, and steps that end with the retry.
fn fixed(body: &Value, code: &str, console: &str, names: &[&str]) {
    let (got, fix, message) = parts(body);
    assert_eq!(got, code, "{body}");
    let link = format!("https://gw.example.com/console/app/#/{console}");
    assert_eq!(fix["console"], link.as_str(), "{body}");
    assert_eq!(fix["docs"], format!("{DOCS}#{code}").as_str(), "{body}");
    let steps: Vec<&str> = fix["steps"]
        .as_array()
        .map(|s| s.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    assert!(steps.len() >= 2, "{body}");
    assert!(
        steps[0].contains(&link),
        "the first step opens the link: {body}"
    );
    assert!(
        steps.last().is_some_and(|s| s.contains("retry")),
        "the last step is the retry: {body}"
    );
    for name in names {
        assert!(
            steps.iter().any(|s| s.contains(name)),
            "steps name {name}: {body}"
        );
    }
    // Most clients show only the message: it carries the link and the docs too.
    assert!(message.contains(&link), "{message}");
    assert!(message.contains(&format!("{DOCS}#{code}")), "{message}");
    assert!(
        message.starts_with(&format!("Refused ({code}): ")),
        "{message}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_model_no_provider_serves_names_add_a_provider_with_it_filled_in() -> TestResult {
    let gw = gateway("unknown").await?;
    let (status, body) = answer(
        &gw.router,
        call("/v1/chat/completions", BOT, "anthropic/claude-sonnet-5")?,
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    fixed(
        &body,
        "unknown_model",
        "providers?model=anthropic%2Fclaude-sonnet-5",
        &["anthropic/claude-sonnet-5", "OpenRouter"],
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_model_only_a_login_provider_serves_names_a_provider_with_its_own_key() -> TestResult {
    let gw = gateway("login").await?;
    let (_, chat) = answer(
        &gw.router,
        call("/v1/chat/completions", BOT, "claude-sonnet-5-5")?,
    )
    .await?;
    fixed(
        &chat,
        "wrong_route",
        "providers?model=claude-sonnet-5-5",
        &["claude-sonnet-5-5"],
    );
    let (_, messages) = answer(&gw.router, call("/v1/messages", BOT, "claude-sonnet-5-5")?).await?;
    fixed(
        &messages,
        "login_needed",
        "providers?model=claude-sonnet-5-5",
        &["claude-sonnet-5-5", "own key"],
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_model_the_rule_leaves_out_opens_the_rule_with_it_added() -> TestResult {
    let gw = gateway("rule").await?;
    let (_, body) = answer(
        &gw.router,
        call("/v1/chat/completions", LIMITED, "model-b")?,
    )
    .await?;
    fixed(
        &body,
        "model_not_allowed",
        "policy?rule=narrow&model=model-b",
        &["narrow", "model-b"],
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_held_caller_opens_allow_for_it() -> TestResult {
    let gw = gateway("held").await?;
    let (_, body) = answer(&gw.router, call("/v1/chat/completions", NEWBIE, "model-a")?).await?;
    fixed(
        &body,
        "awaiting_approval",
        "apps/new?allow=fresh-bot",
        &["fresh-bot", "Allow"],
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_the_caller_fixes_carries_no_gateway_fix() -> TestResult {
    let gw = gateway("caller").await?;
    let (status, body) = answer(
        &gw.router,
        call(
            "/v1/chat/completions",
            "enterplace_nope_0123456789abcdef0123456",
            "model-a",
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(parts(&body).1.is_null(), "{body}");
    Ok(())
}
