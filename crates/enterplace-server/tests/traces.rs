//! Acceptance test for package 4.5 (traces): a request's span reaches a test collector over OTLP/HTTP, joins the
//! caller's trace, and the provider gets a `traceparent` that names Enterplace's span.

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
use enterplace_core::{audit::AuditLog, id::sha256_hex};
use enterplace_server::{Audit, Config, Secret, TraceExport};
use http_body_util::BodyExt;
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const KEY: &str = "enterplace_trace_test_key";
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

    let dir = std::env::temp_dir().join(format!("enterplace-traces-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        dir.join("enterplace.policy.yaml"),
        format!(
            "version: 1\nproviders:\n  - name: mock\n    kind: openai\n    url: http://{provider}\n    allow_private: true\n    key_env: UNUSED\n    models: [model-a]\nrules:\n  - name: everyone\n    principals: {{ any: true }}\n    models: [model-a]\n"
        ),
    )?;
    std::fs::write(
        dir.join("enterplace.keys.yaml"),
        format!(
            "keys:\n  - name: maya@example.com\n    team: payments\n    sha256: {}\n",
            sha256_hex(KEY.as_bytes())
        ),
    )?;
    let loaded = enterplace_core::config::load(&dir.join("enterplace.policy.yaml"), None)
        .map_err(|e| e.join("\n"))?;
    let app = enterplace_server::app(Config {
        upstream: Some(loaded.providers[0].url.clone()),
        provider_key: Some(Secret::new("provider-secret")),
        audit: Some(Audit {
            log: Arc::new(AuditLog::open(&dir.join("enterplace-audit.jsonl"))?),
            provider: "mock".into(),
            policy_sha256: loaded.policy_sha256.clone(),
            keys_sha256: loaded.keys_sha256.clone(),
        }),
        policy: Some(loaded.policy),
        traces: Some(TraceExport {
            endpoint: format!("http://{collector}/v1/traces"),
            service: "enterplace-test".into(),
            ..TraceExport::default()
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
        .get("x-enterplace-decision")
        .ok_or("no decision")?
        .to_str()?
        .to_string();
    response.into_body().collect().await?;

    // Export runs once a second, and an attempt's span may leave a batch before its request's.
    let mut spans = Vec::new();
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let all = exported.lock().map_err(|_| "poisoned")?.clone();
        spans = all
            .iter()
            .flat_map(|body| {
                body["resourceSpans"][0]["scopeSpans"][0]["spans"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
            })
            .collect();
        if spans.len() >= 2 {
            assert_eq!(
                all[0]["resourceSpans"][0]["resource"]["attributes"][0]["value"]["stringValue"],
                "enterplace-test"
            );
            break;
        }
    }
    let s = spans
        .iter()
        .find(|s| s["name"] == "POST /v1/chat/completions")
        .ok_or("the request's span never reached the collector")?;
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
    assert!(text.contains("gen_ai.operation.name"), "{text}");
    assert!(
        !text.contains("maya@example.com"),
        "no person's name in a trace"
    );
    // The attempt at the provider is a child span named by the GenAI conventions, and the provider's parent.
    let attempt = spans
        .iter()
        .find(|s| s["name"] == "chat model-a")
        .ok_or("no span for the attempt at the provider")?;
    assert_eq!(attempt["parentSpanId"], s["spanId"]);
    assert_eq!(attempt["traceId"], s["traceId"]);
    assert_eq!(attempt["kind"], 3, "a client span");
    let text = attempt.to_string();
    for wanted in [
        "gen_ai.provider.name",
        "gen_ai.request.model",
        "server.address",
        "http.response.status_code",
    ] {
        assert!(text.contains(wanted), "{wanted} missing from {text}");
    }

    let sent = upstream_saw.lock().map_err(|_| "poisoned")?.clone();
    let expected = format!(
        "00-4bf92f3577b34da6a3ce929d0e0e4736-{}-01",
        attempt["spanId"].as_str().ok_or("no span id")?
    );
    assert_eq!(
        sent,
        vec![expected],
        "the provider's parent is the attempt's span"
    );
    Ok(())
}

/// A gateway on `dir` whose provider is `provider`, exporting as `export` says.
fn gateway(
    dir: &std::path::Path,
    provider: SocketAddr,
    export: TraceExport,
) -> Result<Router, Box<dyn std::error::Error>> {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir)?;
    std::fs::write(
        dir.join("enterplace.policy.yaml"),
        format!(
            "version: 1\nproviders:\n  - name: mock\n    kind: openai\n    url: http://{provider}\n    allow_private: true\n    key_env: UNUSED\n    models: [model-a]\nrules:\n  - name: everyone\n    principals: {{ any: true }}\n    models: [model-a]\n"
        ),
    )?;
    std::fs::write(
        dir.join("enterplace.keys.yaml"),
        format!(
            "keys:\n  - name: maya@example.com\n    team: payments\n    sha256: {}\n",
            sha256_hex(KEY.as_bytes())
        ),
    )?;
    let loaded = enterplace_core::config::load(&dir.join("enterplace.policy.yaml"), None)
        .map_err(|e| e.join("\n"))?;
    Ok(enterplace_server::app(Config {
        upstream: Some(loaded.providers[0].url.clone()),
        provider_key: Some(Secret::new("provider-secret")),
        audit: Some(Audit {
            log: Arc::new(AuditLog::open(&dir.join("enterplace-audit.jsonl"))?),
            provider: "mock".into(),
            policy_sha256: loaded.policy_sha256.clone(),
            keys_sha256: loaded.keys_sha256.clone(),
        }),
        policy: Some(loaded.policy),
        traces: Some(export),
        ..Config::default()
    })?)
}

#[tokio::test]
async fn spans_reach_a_grpc_collector_and_propagation_can_be_turned_off() -> TestResult {
    let upstream_saw = Arc::new(Mutex::new(Vec::<String>::new()));
    let saw = upstream_saw.clone();
    let provider = listen(Router::new().route(
        "/v1/chat/completions",
        post(move |request: Request<Body>| {
            if let Ok(mut all) = saw.lock() {
                all.push(format!(
                    "{:?} {:?}",
                    request.headers().get("traceparent"),
                    request.headers().get("tracestate")
                ));
            }
            async {
                (
                    [(header::CONTENT_TYPE, "application/json")],
                    r#"{"id":"x","object":"chat.completion","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#,
                )
            }
        }),
    ))
    .await?;
    // An OTLP/gRPC collector: HTTP/2 without TLS, one length-prefixed protobuf message a call, grpc-status 0.
    let exported = Arc::new(Mutex::new(Vec::<(String, String, Vec<u8>)>::new()));
    let keep = exported.clone();
    let collector = listen(Router::new().route(
        "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
        post(move |request: Request<Body>| {
            let keep = keep.clone();
            async move {
                let version = format!("{:?}", request.version());
                let kind = request
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                let body = request
                    .into_body()
                    .collect()
                    .await
                    .map(|b| b.to_bytes().to_vec())
                    .unwrap_or_default();
                if let Ok(mut all) = keep.lock() {
                    all.push((version, kind, body));
                }
                (
                    [
                        (header::CONTENT_TYPE, "application/grpc"),
                        (header::HeaderName::from_static("grpc-status"), "0"),
                    ],
                    // An empty ExportTraceServiceResponse, framed.
                    vec![0u8, 0, 0, 0, 0],
                )
            }
        }),
    ))
    .await?;
    let dir = std::env::temp_dir().join(format!("enterplace-traces-grpc-{}", std::process::id()));
    let export = TraceExport::from_env(|name| match name {
        "OTEL_EXPORTER_OTLP_ENDPOINT" => Some(format!("http://{collector}")),
        "OTEL_EXPORTER_OTLP_PROTOCOL" => Some("grpc".into()),
        "ENTERPLACE_TRACE_PROPAGATION" => Some("none".into()),
        _ => None,
    })?
    .ok_or("no export")?;
    let app = gateway(&dir, provider, export)?;
    let response = app
        .oneshot(
            Request::post("/v1/chat/completions")
                .header(header::AUTHORIZATION, format!("Bearer {KEY}"))
                .header("traceparent", CALLER)
                .header("tracestate", "vendor=1")
                .body(Body::from(r#"{"model":"model-a","messages":[]}"#))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    response.into_body().collect().await?;
    let mut all = Vec::new();
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        all = exported.lock().map_err(|_| "poisoned")?.clone();
        let bytes: Vec<u8> = all.iter().flat_map(|(_, _, b)| b.clone()).collect();
        if bytes
            .windows(b"POST /v1/chat/completions".len())
            .any(|w| w == b"POST /v1/chat/completions")
        {
            break;
        }
    }
    let (version, kind, first) = all.first().ok_or("nothing reached the gRPC collector")?;
    assert_eq!(version, "HTTP/2.0");
    assert_eq!(kind, "application/grpc");
    // The frame: not compressed, then the message's length.
    assert_eq!(first[0], 0);
    let length = u32::from_be_bytes([first[1], first[2], first[3], first[4]]) as usize;
    assert_eq!(length, first.len() - 5);
    // The message opens with resource_spans (field 1, length-delimited).
    assert_eq!(first[5], 0x0a);
    let bytes: Vec<u8> = all.iter().flat_map(|(_, _, b)| b.clone()).collect();
    let has = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
    assert!(has(b"POST /v1/chat/completions"), "the request's span");
    assert!(has(b"chat model-a"), "the attempt's span");
    assert!(has(b"gen_ai.request.model"));
    assert!(
        !has(&[0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6]),
        "with propagation off the span does not join the caller's trace"
    );
    assert_eq!(
        upstream_saw.lock().map_err(|_| "poisoned")?.clone(),
        vec!["None None".to_string()],
        "with propagation off the provider gets no trace context, the caller's included"
    );
    Ok(())
}
