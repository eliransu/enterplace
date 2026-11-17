//! Acceptance tests for the pass-through route: the request reaches the upstream
//! unchanged, and the response comes back unchanged, streamed or not.

use std::net::SocketAddr;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::post,
};
use enterplace_server::Config;
use http_body_util::BodyExt;
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// An upstream that answers with the exact body and authorization header it received.
async fn echo_upstream() -> Result<SocketAddr, Box<dyn std::error::Error>> {
    async fn echo(request: Request<Body>) -> ([(header::HeaderName, String); 1], Body) {
        let auth = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        (
            [(header::HeaderName::from_static("x-seen-auth"), auth)],
            request.into_body(),
        )
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = Router::new().route("/v1/chat/completions", post(echo));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(addr)
}

fn chat_request(body: &'static str) -> Result<Request<Body>, axum::http::Error> {
    Request::post("/v1/chat/completions")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer test-key")
        .body(Body::from(body))
}

#[tokio::test]
async fn forwards_body_and_headers_unchanged() -> TestResult {
    let upstream = echo_upstream().await?;
    let app = enterplace_server::app(Config {
        upstream: Some(format!("http://{upstream}")),
        ..Config::default()
    })?;

    // `made_up_param` is not an OpenAI field. It must reach the upstream untouched.
    let body = r#"{"model":"m","messages":[],"made_up_param":{"keep":"me"}}"#;
    let response = app.oneshot(chat_request(body)?).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-seen-auth")
            .and_then(|v| v.to_str().ok()),
        Some("Bearer test-key")
    );
    let returned = response.into_body().collect().await?.to_bytes();
    assert_eq!(returned, body.as_bytes());
    Ok(())
}

#[tokio::test]
async fn without_upstream_says_how_to_fix_it() -> TestResult {
    let app = enterplace_server::app(Config::default())?;
    let response = app.oneshot(chat_request("{}")?).await?;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let text = String::from_utf8(response.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(
        text.contains("ENTERPLACE_UPSTREAM"),
        "the error must name the setting to change, got: {text}"
    );
    Ok(())
}

#[tokio::test]
async fn unreachable_upstream_is_a_bad_gateway() -> TestResult {
    // Port 1 on loopback refuses connections.
    let app = enterplace_server::app(Config {
        upstream: Some("http://127.0.0.1:1".into()),
        ..Config::default()
    })?;
    let response = app.oneshot(chat_request("{}")?).await?;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    Ok(())
}

#[tokio::test]
async fn rejects_an_upstream_it_cannot_reach_safely() {
    assert!(
        enterplace_server::app(Config {
            upstream: Some("https://api.example.com".into()),
            ..Config::default()
        })
        .is_ok()
    );
    assert!(
        enterplace_server::app(Config {
            upstream: Some("not a url".into()),
            ..Config::default()
        })
        .is_err()
    );
}
