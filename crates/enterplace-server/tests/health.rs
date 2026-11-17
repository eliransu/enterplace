use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use enterplace_server::Config;
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn healthz_returns_ok() -> TestResult {
    let request = Request::get("/healthz").body(Body::empty())?;
    let response = enterplace_server::app(Config::default())?
        .oneshot(request)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn unknown_route_returns_404() -> TestResult {
    let request = Request::get("/nope").body(Body::empty())?;
    let response = enterplace_server::app(Config::default())?
        .oneshot(request)
        .await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}
