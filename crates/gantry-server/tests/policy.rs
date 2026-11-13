//! Acceptance tests for the in-path policy check: an allowed request passes unchanged,
//! and everything else is refused before it reaches the upstream, with a reason.

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::post,
};
use gantry_core::policy::Policy;
use gantry_server::Config;
use http_body_util::BodyExt;
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// An upstream that echoes the body and counts how many requests reached it.
async fn counting_upstream() -> Result<(SocketAddr, Arc<AtomicUsize>), Box<dyn std::error::Error>> {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = hits.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move |request: Request<Body>| {
            seen.fetch_add(1, Ordering::SeqCst);
            async move { request.into_body() }
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((addr, hits))
}

async fn gateway() -> Result<(Router, Arc<AtomicUsize>), Box<dyn std::error::Error>> {
    let (upstream, hits) = counting_upstream().await?;
    let policy = Policy::new()
        .with_key("key-maya", "maya.cohen", "payments")
        .with_models("payments", ["claude-haiku-5-5"]);
    let app = gantry_server::app(Config {
        upstream: Some(format!("http://{upstream}")),
        policy: Some(policy),
        ..Config::default()
    })?;
    Ok((app, hits))
}

fn chat(key: Option<&str>, body: impl Into<Body>) -> Result<Request<Body>, axum::http::Error> {
    let mut request =
        Request::post("/v1/chat/completions").header(header::CONTENT_TYPE, "application/json");
    if let Some(key) = key {
        request = request.header(header::AUTHORIZATION, format!("Bearer {key}"));
    }
    request.body(body.into())
}

async fn text(response: axum::response::Response) -> Result<String, Box<dyn std::error::Error>> {
    Ok(String::from_utf8(
        response.into_body().collect().await?.to_bytes().to_vec(),
    )?)
}

#[tokio::test]
async fn an_allowed_request_reaches_the_upstream_unchanged() -> TestResult {
    let (app, hits) = gateway().await?;
    let body = r#"{"model":"claude-haiku-5-5","messages":[],"made_up_param":{"keep":"me"}}"#;
    let response = app.oneshot(chat(Some("key-maya"), body)?).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(text(response).await?, body);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn no_key_and_unknown_key_are_refused_before_the_upstream() -> TestResult {
    let (app, hits) = gateway().await?;
    let body = r#"{"model":"claude-haiku-5-5","messages":[]}"#;
    for key in [None, Some("key-nobody")] {
        let response = app.clone().oneshot(chat(key, body)?).await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn a_model_outside_the_policy_is_refused_with_the_reason() -> TestResult {
    let (app, hits) = gateway().await?;
    let response = app
        .oneshot(chat(
            Some("key-maya"),
            r#"{"model":"claude-opus-5-5","messages":[]}"#,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let message = text(response).await?;
    assert!(
        message.contains("payments") && message.contains("claude-opus-5-5"),
        "the reason must name the team and the model, got: {message}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn a_body_that_cannot_be_checked_is_refused() -> TestResult {
    let (app, hits) = gateway().await?;
    for body in ["not json", r#"{"messages":[]}"#, r#"{"model":7}"#] {
        let response = app.clone().oneshot(chat(Some("key-maya"), body)?).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "body: {body}");
    }
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn a_body_over_the_limit_is_refused() -> TestResult {
    let (app, hits) = gateway().await?;
    let huge = vec![b' '; gantry_server::MAX_BODY_BYTES + 1];
    let response = app.oneshot(chat(Some("key-maya"), huge)?).await?;

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    Ok(())
}
