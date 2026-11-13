//! Acceptance test for package 4.5 (traces): a request's span reaches a test collector over OTLP/HTTP, joins the
//! caller's trace, and the provider gets a `traceparent` that names Gantry's span.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::post,
};
use gantry_core::{audit::AuditLog, id::sha256_hex};
use gantry_server::{Audit, Config, Secret, TraceExport};
use http_body_util::BodyExt;
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const KEY: &str = "gantry_trace_test_key";
const CALLER: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

async fn listen(app: Router) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(addr)
}

#[tokio::test]
async fn a_requests_span_reaches_the_collector_inside_the_callers_trace() -> TestResult {
    // The provider: answers with usage, and keeps the traceparent it was sent.
    let upstream_saw = Arc::new(Mutex::new(Vec::<String>::new()));
    let saw = upstream_saw.clone();
    let provider = listen(Router::new().route(
        "/v1/chat/completions",
        post(move |request: Request<Body>| {
            if let Some(v) = request.headers().get("traceparent").and_then(|v| v.to_str().ok())
                && let Ok(mut all) = saw.lock()
            {
                all.push(v.to_string());
            }
            async {
                (
                    [(header::CONTENT_TYPE, "application/json")],
                    r#"{"id":"x","object":"chat.completion","choices":[],"usage":{"prompt_tokens":12,"completion_tokens":5,"total_tokens":17}}"#,
                )
            }
        }),
    ))
    .await?;
    // The collector: keeps every export body.
    let exported = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
    let keep = exported.clone();
    let collector = listen(Router::new().route(
        "/v1/traces",
        post(move |body: String| {
            if let (Ok(v), Ok(mut all)) = (serde_json::from_str(&body), keep.lock()) {
                all.push(v);
            }
            async { StatusCode::OK }
        }),
    ))
    .await?;

    let dir = std::env::temp_dir().join(format!("gantry-traces-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        dir.join("gantry.policy.yaml"),
        format!(
            "version: 1\nproviders:\n  - name: mock\n    kind: openai\n    url: http://{provider}\n    allow_private: true\n    key_env: UNUSED\n    models: [model-a]\nrules:\n  - name: everyone\n    principals: {{ any: true }}\n    models: [model-a]\n"
        ),
    )?;
    std::fs::write(
        dir.join("gantry.keys.yaml"),
        format!(
            "keys:\n  - name: maya@example.com\n    team: payments\n    sha256: {}\n",
            sha256_hex(KEY.as_bytes())
        ),
    )?;
    let loaded = gantry_core::config::load(&dir.join("gantry.policy.yaml"), None)
        .map_err(|e| e.join("\n"))?;
    let app = gantry_server::app(Config {
        upstream: Some(loaded.providers[0].url.clone()),
        provider_key: Some(Secret::new("provider-secret")),
        audit: Some(Audit {
            log: Arc::new(AuditLog::open(&dir.join("gantry-audit.jsonl"))?),
            provider: "mock".into(),
            policy_sha256: loaded.policy_sha256.clone(),
            keys_sha256: loaded.keys_sha256.clone(),
        }),
        policy: Some(loaded.policy),
        traces: Some(TraceExport {
            endpoint: format!("http://{collector}/v1/traces"),
            headers: vec![],
            service: "gantry-test".into(),
        }),
        ..Config::default()
    })?;

    let response = app
        .clone()
        .oneshot(
            Request::post("/v1/chat/completions")
                .header(header::AUTHORIZATION, format!("Bearer {KEY}"))
                .header("traceparent", CALLER)
                .body(Body::from(r#"{"model":"model-a","messages":[]}"#))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let decision = response
        .headers()
        .get("x-gantry-decision")
        .ok_or("no decision")?
        .to_str()?
        .to_string();
    response.into_body().collect().await?;

    // Export runs once a second.
    let mut span = None;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let all = exported.lock().map_err(|_| "poisoned")?.clone();
        if let Some(body) = all.first() {
            span = Some(body.clone());
            break;
        }
    }
    let body = span.ok_or("no span reached the collector")?;
    assert_eq!(
        body["resourceSpans"][0]["resource"]["attributes"][0]["value"]["stringValue"],
        "gantry-test"
    );
    let s = &body["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
    assert_eq!(
        s["traceId"], "4bf92f3577b34da6a3ce929d0e0e4736",
        "the span joins the caller's trace"
    );
    assert_eq!(s["parentSpanId"], "00f067aa0ba902b7");
    let text = s.to_string();
    assert!(
        text.contains(&decision),
        "the span names the decision, to find its audit record"
    );
    assert!(text.contains("gen_ai.usage.output_tokens"), "{text}");
    assert!(
        !text.contains("maya@example.com"),
        "no person's name in a trace"
    );

    let sent = upstream_saw.lock().map_err(|_| "poisoned")?.clone();
    let expected = format!(
        "00-4bf92f3577b34da6a3ce929d0e0e4736-{}-01",
        s["spanId"].as_str().ok_or("no span id")?
    );
    assert_eq!(
        sent,
        vec![expected],
        "the provider's parent is Gantry's span"
    );
    Ok(())
}
