//! The policy kept in its file (`store.policy_from: file`, the default), changed from the console: each save is
//! recorded whole in the audit chain, the gateway reloads the file, and the console says whether it runs it or
//! refused it and why. No database needed.

use std::path::{Path, PathBuf};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::post,
};
use enterplace_server::Governed;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Error = Box<dyn std::error::Error>;

const ADMIN: &str = "enterplace_admin_0123456789abcdef012345678";
const HOST: &str = "enterplace.test";

async fn provider() -> Result<u16, Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let app = Router::new().route(
        "/v1/chat/completions",
        post(|| async { r#"{"id":"c","object":"chat.completion","choices":[]}"# }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

fn policy(port: u16) -> String {
    format!(
        "version: 1
providers:
  - name: mock
    kind: openai
    url: http://127.0.0.1:{port}
    allow_private: true
    models: [m]
rules:
  - name: everyone
    principals: {{ any: true }}
    models: [m]
"
    )
}

fn dir(name: &str) -> Result<PathBuf, Error> {
    let dir = std::env::temp_dir().join(format!(
        "enterplace-file-versions-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn gateway(dir: &Path, text: &str) -> Result<Governed, String> {
    let policy = dir.join("enterplace.policy.yaml");
    std::fs::write(&policy, text).map_err(|e| e.to_string())?;
    let gw = enterplace_server::governed(&policy, None, &|_| None)?;
    gw.reloader.watch();
    Ok(gw)
}

async fn cookie(app: &Router) -> Result<String, Error> {
    let request = Request::builder()
        .method("POST")
        .uri("/console/sign-in")
        .header(header::HOST, HOST)
        .header(header::ORIGIN, format!("http://{HOST}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("key={ADMIN}")))?;
    let response = app.clone().oneshot(request).await?;
    Ok(response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|c| c.split(';').next())
        .ok_or("no cookie")?
        .to_string())
}

async fn api(
    app: &Router,
    cookie: &str,
    method: &str,
    path: &str,
    body: Value,
) -> Result<(StatusCode, Value), Error> {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, HOST)
        .header(header::ORIGIN, format!("http://{HOST}"))
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))?;
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    let bytes = response.into_body().collect().await?.to_bytes();
    Ok((
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into_owned())),
    ))
}

async fn started(name: &str) -> Result<(Governed, PathBuf, String), Error> {
    let port = provider().await?;
    let dir = dir(name)?;
    let gw = gateway(&dir, &policy(port))?;
    enterplace_core::keyfile::add_entry("admin", "ops", ADMIN, true, &gw.loaded.keys_path)?;
    gw.reloader.check(enterplace_server::Trigger::FileChange);
    let cookie = cookie(&gw.router).await?;
    Ok((gw, dir, cookie))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_file_save_the_gateway_refuses_says_so_with_the_reason() -> TestResult {
    let (gw, dir, cookie) = started("refused").await?;
    // A change the gateway runs: the console says it is in force.
    let (status, body) = api(
        &gw.router,
        &cookie,
        "PUT",
        "/console/api/policy/mode",
        json!({ "mode": "observe" }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["message"], "Saved; in force on the gateway.", "{body}");

    // A guardrail whose credential variable is unset: `enterplace check` passes it, the gateway refuses it.
    let unset = "ENTERPLACE_TEST_GUARD_KEY_NOBODY_SET";
    let (status, body) = api(
        &gw.router,
        &cookie,
        "POST",
        "/console/api/policy/guardrails",
        json!({ "name": "hook", "type": "lakera", "key_env": unset, "on_failure": "fail_closed", "every": true }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let message = body["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("the gateway refused it") && message.contains(unset),
        "{body}"
    );
    assert!(!message.contains("Every gateway uses it"), "{body}");
    // The file holds the save, and the gateway keeps what it ran.
    let file = std::fs::read_to_string(dir.join("enterplace.policy.yaml"))?;
    assert!(file.contains(unset), "{file}");
    Ok(())
}
