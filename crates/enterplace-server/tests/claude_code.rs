//! Acceptance tests for slice 2:
//! Claude Code's routes reach an Anthropic provider, chat reaches an OpenAI one, each with its own key,
//! and every refusal on the messages routes is in the shape Claude Code shows.

use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::{Body, Bytes},
    http::{HeaderMap, Request, StatusCode, header},
    response::{IntoResponse, Response},
};
use enterplace_core::{
    audit::AuditLog,
    config::Kind,
    id::sha256_hex,
    policy::{Models, Policy, Who},
};
use enterplace_server::{Audit, Config, ProviderRoute, Secret};
use http_body_util::BodyExt;
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const MAYA: &str = "enterplace_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const OMER: &str = "enterplace_fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
const OPENAI_KEY: &str = "sk-openai-test-1";
const ANTHROPIC_KEY: &str = "sk-ant-test-2";

/// What one mock provider was sent.
#[derive(Default)]
struct Seen {
    hits: AtomicUsize,
    requests: Mutex<Vec<(String, HeaderMap, Bytes)>>,
}

/// How a mock provider answers.
#[derive(Clone, Copy)]
enum Answer {
    Echo,
    /// A provider error, which must reach the caller unchanged.
    Status(u16),
    /// Two events with a pause between them, which must reach the caller one at a time.
    Stream,
    /// A tool call, the first half of a tool use round trip.
    ToolUse,
}

async fn mock(answer: Answer) -> Result<(SocketAddr, Arc<Seen>), Box<dyn std::error::Error>> {
    let seen = Arc::new(Seen::default());
    let record = seen.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = Router::new().fallback(move |request: Request<Body>| {
        let record = record.clone();
        async move {
            let (parts, body) = request.into_parts();
            let bytes = body.collect().await.map(|b| b.to_bytes()).unwrap_or_default();
            record.hits.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut all) = record.requests.lock() {
                let uri = parts.uri.path_and_query().map_or(String::new(), |pq| pq.to_string());
                all.push((uri, parts.headers.clone(), bytes.clone()));
            }
            match answer {
                Answer::Echo => bytes.into_response(),
                Answer::Status(code) => (
                    StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_GATEWAY),
                    [(header::CONTENT_TYPE, "application/json")],
                    r#"{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#,
                )
                    .into_response(),
                Answer::ToolUse => (
                    [(header::CONTENT_TYPE, "application/json")],
                    TOOL_USE_ANSWER,
                )
                    .into_response(),
                Answer::Stream => {
                    let events = async_stream(vec![
                        (Duration::ZERO, "event: message_start\ndata: {}\n\n"),
                        (Duration::from_millis(1500), "event: message_stop\ndata: {}\n\n"),
                    ]);
                    Response::builder()
                        .header(header::CONTENT_TYPE, "text/event-stream")
                        .body(Body::from_stream(events))
                        .unwrap_or_default()
                }
            }
        }
    });
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((addr, seen))
}

/// A body that sends each piece after its pause.
fn async_stream(
    pieces: Vec<(Duration, &'static str)>,
) -> impl futures_core::Stream<Item = Result<Bytes, std::io::Error>> {
    struct Pieces {
        left: std::collections::VecDeque<(Duration, &'static str)>,
        sleep: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    }
    impl futures_core::Stream for Pieces {
        type Item = Result<Bytes, std::io::Error>;
        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            let Some((pause, _)) = self.left.front().copied() else {
                return std::task::Poll::Ready(None);
            };
            let sleep = self
                .sleep
                .get_or_insert_with(|| Box::pin(tokio::time::sleep(pause)));
            if sleep.as_mut().poll(cx).is_pending() {
                return std::task::Poll::Pending;
            }
            self.sleep = None;
            let piece = self.left.pop_front().map(|(_, text)| Ok(Bytes::from(text)));
            std::task::Poll::Ready(piece)
        }
    }
    use std::future::Future;
    Pieces {
        left: pieces.into(),
        sleep: None,
    }
}

struct Gateway {
    app: Router,
    openai: Arc<Seen>,
    anthropic: Arc<Seen>,
    log: std::path::PathBuf,
}

async fn gateway(
    name: &str,
    anthropic_answer: Answer,
) -> Result<Gateway, Box<dyn std::error::Error>> {
    let (openai_at, openai) = mock(Answer::Echo).await?;
    let (anthropic_at, anthropic) = mock(anthropic_answer).await?;
    let log = std::env::temp_dir().join(format!(
        "enterplace-slice2-{}-{name}.jsonl",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&log);
    let policy = Policy::new()
        .with_key(MAYA, "maya.cohen", "payments")
        .with_key(OMER, "omer.katz", "support")
        .with_rule("payments-team", Who::Team("payments".into()), Models::Any)
        .with_rule(
            "support-team",
            Who::Team("support".into()),
            Models::Only(vec!["gpt-4o-mini".into()]),
        );
    let app = enterplace_server::app(Config {
        providers: vec![
            ProviderRoute {
                name: "openai".into(),
                kind: Kind::OpenAi,
                url: format!("http://{openai_at}"),
                key: Some(Secret::new(OPENAI_KEY)),
                models: vec!["gpt-4o-mini".into(), "gpt-4o".into()],
                ..ProviderRoute::default()
            },
            ProviderRoute {
                name: "anthropic".into(),
                kind: Kind::Anthropic,
                url: format!("http://{anthropic_at}"),
                key: Some(Secret::new(ANTHROPIC_KEY)),
                models: vec!["claude-sonnet-5-5".into(), "claude-haiku-5-5".into()],
                ..ProviderRoute::default()
            },
        ],
        policy: Some(policy),
        audit: Some(Audit {
            log: Arc::new(AuditLog::open(&log)?),
            provider: String::new(),
            policy_sha256: sha256_hex(b"policy"),
            keys_sha256: sha256_hex(b"keys"),
        }),
        ..Config::default()
    })?;
    Ok(Gateway {
        app,
        openai,
        anthropic,
        log,
    })
}

const MESSAGE: &str = r#"{"model":"claude-sonnet-5-5","max_tokens":64,"messages":[{"role":"user","content":"Say hello."}]}"#;
const CHAT: &str = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Say hello."}]}"#;

fn post(path: &str, body: &'static str) -> axum::http::request::Builder {
    let _ = body;
    Request::post(path).header(header::CONTENT_TYPE, "application/json")
}

async fn send(
    app: &Router,
    request: Request<Body>,
) -> Result<(StatusCode, HeaderMap, String), Box<dyn std::error::Error>> {
    let response = app.clone().oneshot(request).await?;
    let (status, headers) = (response.status(), response.headers().clone());
    let body = String::from_utf8(response.into_body().collect().await?.to_bytes().to_vec())?;
    Ok((status, headers, body))
}

fn records(path: &std::path::Path) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    std::fs::read_to_string(path)?
        .lines()
        // Decision records. Each forwarded request also gets a usage record when its answer ends: tests/spend.rs.
        .filter(|line| !line.contains("\"event\":\"usage\""))
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

#[tokio::test]
async fn each_route_reaches_its_own_provider_with_that_providers_key_in_its_own_header()
-> TestResult {
    let gw = gateway("routes", Answer::Echo).await?;

    // Claude Code sends its key in x-api-key.
    let message = post("/v1/messages?beta=true", MESSAGE)
        .header("x-api-key", MAYA)
        .header("anthropic-version", "2023-06-01")
        .header(
            "anthropic-beta",
            "tools-2024-05-16,  prompt-caching-2024-07-31",
        )
        .body(Body::from(MESSAGE))?;
    let (status, headers, body) = send(&gw.app, message).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body, MESSAGE,
        "the body must reach the provider byte for byte"
    );
    assert!(headers.contains_key("x-enterplace-decision"));

    let chat = post("/v1/chat/completions", CHAT)
        .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
        .body(Body::from(CHAT))?;
    let (status, _, body) = send(&gw.app, chat).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, CHAT);

    let sent = gw.anthropic.requests.lock().map_err(|_| "lock")?;
    let (uri, headers, bytes) = sent
        .first()
        .ok_or("nothing reached the anthropic provider")?;
    assert_eq!(uri, "/v1/messages?beta=true");
    assert_eq!(bytes.as_ref(), MESSAGE.as_bytes());
    assert_eq!(
        headers.get("x-api-key").and_then(|v| v.to_str().ok()),
        Some(ANTHROPIC_KEY)
    );
    assert!(!headers.contains_key(header::AUTHORIZATION), "{headers:?}");
    assert_eq!(
        headers
            .get("anthropic-version")
            .and_then(|v| v.to_str().ok()),
        Some("2023-06-01")
    );
    assert_eq!(
        headers.get("anthropic-beta").and_then(|v| v.to_str().ok()),
        Some("tools-2024-05-16,  prompt-caching-2024-07-31"),
        "anthropic-beta must arrive byte for byte"
    );
    assert!(
        !format!("{headers:?}").contains(MAYA),
        "the caller's key reached the provider"
    );

    let sent = gw.openai.requests.lock().map_err(|_| "lock")?;
    let (uri, headers, _) = sent.first().ok_or("nothing reached the openai provider")?;
    assert_eq!(uri, "/v1/chat/completions");
    assert_eq!(
        headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok()),
        Some(format!("Bearer {OPENAI_KEY}").as_str())
    );
    assert!(!headers.contains_key("x-api-key"));
    assert_eq!(gw.anthropic.hits.load(Ordering::SeqCst), 1);
    assert_eq!(gw.openai.hits.load(Ordering::SeqCst), 1);

    let records = records(&gw.log)?;
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["provider"], "anthropic");
    assert_eq!(records[0]["path"], "/v1/messages");
    assert_eq!(records[1]["provider"], "openai");
    Ok(())
}

#[tokio::test]
async fn count_tokens_is_checked_recorded_and_forwarded_like_a_message() -> TestResult {
    let gw = gateway("count", Answer::Echo).await?;
    let request = post("/v1/messages/count_tokens", MESSAGE)
        .header("x-api-key", MAYA)
        .body(Body::from(MESSAGE))?;
    let (status, _, _) = send(&gw.app, request).await?;
    assert_eq!(status, StatusCode::OK);
    // support may only use gpt-4o-mini, and counting tokens for another model is a use of it.
    let refused = post("/v1/messages/count_tokens", MESSAGE)
        .header("x-api-key", OMER)
        .body(Body::from(MESSAGE))?;
    let (status, _, body) = send(&gw.app, refused).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(gw.anthropic.hits.load(Ordering::SeqCst), 1);
    let records = records(&gw.log)?;
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["path"], "/v1/messages/count_tokens");
    assert_eq!(records[1]["code"], "model_not_allowed");
    Ok(())
}

/// The refusals new in this slice, and the shape every refusal takes on the messages routes.
#[tokio::test]
async fn refusals_on_the_messages_routes_are_in_the_shape_claude_code_shows() -> TestResult {
    let gw = gateway("refusals", Answer::Echo).await?;
    let unknown_model = r#"{"model":"claude-nonexistent","messages":[]}"#;
    let cases: Vec<(Request<Body>, StatusCode, &str, &str)> = vec![
        (
            post("/v1/messages", "")
                .header("x-api-key", MAYA)
                .body(Body::from(unknown_model))?,
            StatusCode::FORBIDDEN,
            "unknown_model",
            "permission_error",
        ),
        (
            // A Claude model asked for on the chat route: the provider that serves it speaks the messages API.
            post("/v1/messages", "")
                .header("x-api-key", MAYA)
                .body(Body::from(CHAT))?,
            StatusCode::BAD_REQUEST,
            "wrong_route",
            "invalid_request_error",
        ),
        (
            post("/v1/messages?debug=1", "")
                .header("x-api-key", MAYA)
                .body(Body::from(MESSAGE))?,
            StatusCode::BAD_REQUEST,
            "unknown_query",
            "invalid_request_error",
        ),
        (
            post("/v1/messages", "")
                .header("x-api-key", MAYA)
                .header(header::AUTHORIZATION, format!("Bearer {OMER}"))
                .body(Body::from(MESSAGE))?,
            StatusCode::BAD_REQUEST,
            "ambiguous_key",
            "invalid_request_error",
        ),
        (
            post("/v1/messages", "")
                .header("x-api-key", "sk-ant-api03-real-provider-key")
                .body(Body::from(MESSAGE))?,
            StatusCode::UNAUTHORIZED,
            "unknown_key",
            "authentication_error",
        ),
        (
            post("/v1/messages", "").body(Body::from(MESSAGE))?,
            StatusCode::UNAUTHORIZED,
            "no_key",
            "authentication_error",
        ),
        (
            post("/v1/messages", "")
                .header("x-api-key", OMER)
                .body(Body::from(MESSAGE))?,
            StatusCode::FORBIDDEN,
            "model_not_allowed",
            "permission_error",
        ),
    ];
    let count = cases.len();
    for (request, status, code, kind) in cases {
        let (got, headers, body) = send(&gw.app, request).await?;
        assert_eq!(got, status, "{code}: {body}");
        let json: serde_json::Value = serde_json::from_str(&body)?;
        assert_eq!(json["type"], "error", "{body}");
        assert_eq!(json["error"]["type"], kind, "{body}");
        assert_eq!(json["enterplace_code"], code, "{body}");
        let decision = headers
            .get("x-enterplace-decision")
            .and_then(|v| v.to_str().ok())
            .ok_or("no decision header")?;
        assert_eq!(json["decision"], decision);
        // Claude Code reads x-should-retry: a refusal that retrying cannot fix must say so, or it is sent again and again.
        assert_eq!(
            headers.get("x-should-retry").and_then(|v| v.to_str().ok()),
            Some("false"),
            "{code}"
        );
        let message = json["error"]["message"].as_str().ok_or("no message")?;
        assert!(
            message.starts_with(&format!("Refused ({code}): "))
                && message.ends_with(&format!("Decision {decision}.")),
            "{message}"
        );
        // UX13 q6: Claude Code asks for its own default model; the fix is a variable, not an admin.
        if code == "model_not_allowed" {
            assert!(
                message.contains("In Claude Code, set ANTHROPIC_MODEL and ANTHROPIC_SMALL_FAST_MODEL to models it allows."),
                "{message}"
            );
        }
        if code == "unknown_key" {
            assert!(
                message.contains("provider key"),
                "a provider key sent by mistake gets a hint: {message}"
            );
        }
        if code == "wrong_route" {
            assert!(
                message.contains("/v1/chat/completions"),
                "the refusal names the route to use: {message}"
            );
        }
        if code == "unknown_query" {
            assert!(
                message.contains("debug"),
                "the refusal names the parameter: {message}"
            );
        }
    }
    assert_eq!(gw.anthropic.hits.load(Ordering::SeqCst), 0);
    assert_eq!(gw.openai.hits.load(Ordering::SeqCst), 0);
    assert_eq!(records(&gw.log)?.len(), count, "every refusal has a record");
    Ok(())
}

#[tokio::test]
async fn the_chat_route_refuses_a_model_served_on_the_messages_api_and_keeps_its_own_shape()
-> TestResult {
    let gw = gateway("chat-shape", Answer::Echo).await?;
    let request = post("/v1/chat/completions", "")
        .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
        .body(Body::from(MESSAGE))?;
    let (status, _, body) = send(&gw.app, request).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let json: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(json["error"]["code"], "wrong_route");
    assert_eq!(json["error"]["type"], "enterplace_error");
    let message = json["error"]["message"].as_str().ok_or("no message")?;
    assert!(
        message.starts_with("Refused (wrong_route): ") && message.contains("/v1/messages"),
        "{message}"
    );
    // The same key in both headers is one credential, not two.
    let request = post("/v1/chat/completions", "")
        .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
        .header("x-api-key", MAYA)
        .body(Body::from(CHAT))?;
    assert_eq!(send(&gw.app, request).await?.0, StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn a_provider_error_reaches_the_caller_unchanged_with_the_decision() -> TestResult {
    let gw = gateway("provider-error", Answer::Status(529)).await?;
    let request = post("/v1/messages", MESSAGE)
        .header("x-api-key", MAYA)
        .body(Body::from(MESSAGE))?;
    let (status, headers, body) = send(&gw.app, request).await?;
    assert_eq!(status.as_u16(), 529);
    assert_eq!(
        body,
        r#"{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#
    );
    assert!(headers.contains_key("x-enterplace-decision"));
    Ok(())
}

#[tokio::test]
async fn a_streamed_answer_reaches_the_caller_event_by_event() -> TestResult {
    let gw = gateway("stream", Answer::Stream).await?;
    let request = post("/v1/messages", MESSAGE)
        .header("x-api-key", MAYA)
        .body(Body::from(MESSAGE))?;
    let started = Instant::now();
    let response = gw.app.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    let first = body.frame().await.ok_or("no first event")??;
    let first = first.into_data().map_err(|_| "not data")?;
    assert!(String::from_utf8_lossy(&first).contains("message_start"));
    assert!(
        started.elapsed() < Duration::from_millis(1000),
        "the first event waited for the second: {:?}",
        started.elapsed()
    );
    Ok(())
}

#[tokio::test]
async fn anthropic_and_claude_code_headers_pass_as_an_open_list() -> TestResult {
    let gw = gateway("open-list", Answer::Echo).await?;
    // Headers Enterplace has never seen, as a future Claude Code release would send them.
    let request = post("/v1/messages", MESSAGE)
        .header("x-api-key", MAYA)
        .header("anthropic-version", "2023-06-01")
        .header("anthropic-some-future-capability", "on")
        .header("x-claude-code-session-id", "session-42")
        .header("x-claude-code-agent-id", "agent-7")
        .body(Body::from(MESSAGE))?;
    assert_eq!(send(&gw.app, request).await?.0, StatusCode::OK);
    let sent = gw.anthropic.requests.lock().map_err(|_| "lock")?;
    let (_, headers, _) = sent.first().ok_or("nothing reached the provider")?;
    for (name, value) in [
        ("anthropic-some-future-capability", "on"),
        ("x-claude-code-session-id", "session-42"),
        ("x-claude-code-agent-id", "agent-7"),
    ] {
        assert_eq!(
            headers.get(name).and_then(|v| v.to_str().ok()),
            Some(value),
            "{name}"
        );
    }
    Ok(())
}

/// Claude Code asks GET /v1/models at startup to fill its model picker, sending the key in both headers.
#[tokio::test]
async fn the_model_list_shows_each_caller_only_the_models_their_rule_allows() -> TestResult {
    let gw = gateway("models", Answer::Echo).await?;
    let list = |key: &str| {
        Request::get("/v1/models?limit=1000")
            .header("x-api-key", key)
            .header(header::AUTHORIZATION, format!("Bearer {key}"))
            .body(Body::empty())
    };
    let ids = |body: &str| -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let json: serde_json::Value = serde_json::from_str(body)?;
        Ok(json["data"]
            .as_array()
            .ok_or("no data")?
            .iter()
            .filter_map(|m| m["id"].as_str().map(String::from))
            .collect())
    };
    let (status, _, body) = send(&gw.app, list(MAYA)?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mut everything = ids(&body)?;
    everything.sort();
    // Only models on the messages API: Claude Code would offer an openai model and then be refused on every request.
    assert_eq!(everything, ["claude-haiku-5-5", "claude-sonnet-5-5"]);
    let json: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(json["data"][0]["type"], "model");
    assert!(
        json["data"][0]["description"]
            .as_str()
            .is_some_and(|d| d.contains("payments-team")),
        "{body}"
    );

    let (status, _, body) = send(&gw.app, list(OMER)?).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        ids(&body)?.is_empty(),
        "support may use gpt-4o-mini only, which is not on the messages API: {body}"
    );

    let (status, _, _) = send(
        &gw.app,
        list("enterplace_nobody_0000000000000000000000000000")?,
    )
    .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        gw.anthropic.hits.load(Ordering::SeqCst) + gw.openai.hits.load(Ordering::SeqCst),
        0
    );
    let records = records(&gw.log)?;
    assert_eq!(
        records.len(),
        3,
        "every model list is a decision about a caller, and is recorded"
    );
    assert_eq!(records[0]["path"], "/v1/models");
    assert_eq!(records[0]["verdict"], "allow");
    Ok(())
}

#[tokio::test]
async fn the_startup_probe_is_answered_without_a_record() -> TestResult {
    let gw = gateway("hello", Answer::Echo).await?;
    let probe = Request::head("/api/hello").body(Body::empty())?;
    let response = gw.app.clone().oneshot(probe).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!gw.log.exists() || records(&gw.log)?.is_empty());
    Ok(())
}

const TOOL_USE_ANSWER: &str = r#"{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-5-5","content":[{"type":"tool_use","id":"toolu_1","name":"Read","input":{"file_path":"/tmp/a.txt"}}],"stop_reason":"tool_use","usage":{"input_tokens":20,"output_tokens":10}}"#;

/// The shape of a Claude Code turn that uses a tool, as Claude Code 2.1.323 sent it: the main model asks for a
/// tool, the tool result goes back in the next request, and a background model is asked something on the side.
#[tokio::test]
async fn a_tool_use_round_trip_and_a_background_call_pass_byte_for_byte() -> TestResult {
    let gw = gateway("tools", Answer::ToolUse).await?;
    let first = r#"{"model":"claude-sonnet-5-5","max_tokens":1024,"stream":false,"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.323"},{"type":"text","text":"You are Claude Code."}],"tools":[{"name":"Read","description":"Reads a file","input_schema":{"type":"object","properties":{"file_path":{"type":"string"}},"required":["file_path"]}}],"messages":[{"role":"user","content":"What is in /tmp/a.txt?"}]}"#;
    let second = r#"{"model":"claude-sonnet-5-5","max_tokens":1024,"stream":false,"tools":[{"name":"Read","description":"Reads a file","input_schema":{"type":"object","properties":{"file_path":{"type":"string"}},"required":["file_path"]}}],"messages":[{"role":"user","content":"What is in /tmp/a.txt?"},{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"Read","input":{"file_path":"/tmp/a.txt"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"hello"}]}]}"#;
    let background = r#"{"model":"claude-haiku-5-5","max_tokens":64,"messages":[{"role":"user","content":"Give this conversation a title."}]}"#;
    for body in [first, second, background] {
        let request = post("/v1/messages?beta=true", body)
            .header("x-api-key", MAYA)
            .header("anthropic-version", "2023-06-01")
            .header(
                "anthropic-beta",
                "claude-code-20250219,interleaved-thinking-2025-05-14",
            )
            .header("x-claude-code-session-id", "session-1")
            .body(Body::from(body))?;
        let (status, _, answer) = send(&gw.app, request).await?;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(
            answer, TOOL_USE_ANSWER,
            "the answer must reach Claude Code unchanged"
        );
    }
    let sent = gw.anthropic.requests.lock().map_err(|_| "lock")?;
    let bodies: Vec<&[u8]> = sent.iter().map(|(_, _, b)| b.as_ref()).collect();
    assert_eq!(
        bodies,
        [first.as_bytes(), second.as_bytes(), background.as_bytes()]
    );
    let records = records(&gw.log)?;
    let models: Vec<&str> = records.iter().filter_map(|r| r["model"].as_str()).collect();
    assert_eq!(
        models,
        ["claude-sonnet-5-5", "claude-sonnet-5-5", "claude-haiku-5-5"]
    );
    assert!(
        records
            .iter()
            .all(|r| r["verdict"] == "allow" && r["provider"] == "anthropic")
    );
    Ok(())
}

/// A query parameter is checked by name, once, and by value: a free value would carry anything to the provider,
/// the caller's own Enterplace key included. The refusal names the parameter and never repeats the value.
#[tokio::test]
async fn query_parameters_are_checked_by_name_and_value() -> TestResult {
    let gw = gateway("query-values", Answer::Echo).await?;
    let refused = [
        format!("/v1/messages?beta={MAYA}"),
        "/v1/messages?betax=1".to_string(),
        "/v1/messages?betax=true".to_string(),
        "/v1/messages?beta=1".to_string(),
        "/v1/messages?beta".to_string(),
        "/v1/messages?beta=true;evil=2".to_string(),
        "/v1/messages?beta=true&beta=true".to_string(),
        "/v1/messages/count_tokens?beta=true&x=1".to_string(),
        "/v1/messages/count_tokens?x=1".to_string(),
    ];
    for uri in &refused {
        let request = post(uri, "")
            .header("x-api-key", MAYA)
            .body(Body::from(MESSAGE))?;
        let (status, headers, body) = send(&gw.app, request).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}: {body}");
        let json: serde_json::Value = serde_json::from_str(&body)?;
        assert_eq!(json["enterplace_code"], "unknown_query", "{uri}: {body}");
        assert!(headers.contains_key("x-enterplace-decision"), "{uri}");
        assert!(
            !body.contains(&MAYA[11..]),
            "{uri}: the key was repeated: {body}"
        );
    }
    assert_eq!(gw.anthropic.hits.load(Ordering::SeqCst), 0);
    for uri in [
        "/v1/messages?beta=true",
        "/v1/messages?beta=false",
        "/v1/messages/count_tokens?beta=true",
    ] {
        let request = post(uri, "")
            .header("x-api-key", MAYA)
            .body(Body::from(MESSAGE))?;
        assert_eq!(send(&gw.app, request).await?.0, StatusCode::OK, "{uri}");
    }
    for (uri, status) in [
        ("/v1/models?limit=20", StatusCode::OK),
        ("/v1/models?limit=0", StatusCode::BAD_REQUEST),
        ("/v1/models?limit=1001", StatusCode::BAD_REQUEST),
        ("/v1/models?limit=abc", StatusCode::BAD_REQUEST),
        ("/v1/models?limit=+20", StatusCode::BAD_REQUEST),
    ] {
        let request = Request::get(uri)
            .header("x-api-key", MAYA)
            .body(Body::empty())?;
        assert_eq!(send(&gw.app, request).await?.0, status, "{uri}");
    }
    assert_eq!(records(&gw.log)?.len(), refused.len() + 3 + 5);
    Ok(())
}

/// Only `HEAD /api/hello` and `GET /healthz` are answered without a record. Every other method on those paths is
/// refused like any other request: a decision ID and a record, nothing forwarded.
#[tokio::test]
async fn other_methods_on_the_probe_and_health_paths_are_refused_and_recorded() -> TestResult {
    let gw = gateway("probe-methods", Answer::Echo).await?;
    let cases = [
        ("GET", "/api/hello"),
        ("POST", "/api/hello"),
        ("OPTIONS", "/api/hello"),
        ("POST", "/healthz"),
        ("DELETE", "/healthz"),
    ];
    for (method, path) in cases {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("x-api-key", MAYA)
            .body(Body::empty())?;
        let (status, headers, body) = send(&gw.app, request).await?;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}: {body}");
        assert!(body.contains("unknown_route"), "{method} {path}: {body}");
        assert!(
            headers.contains_key("x-enterplace-decision"),
            "{method} {path}"
        );
    }
    let records = records(&gw.log)?;
    assert_eq!(records.len(), cases.len());
    assert!(records.iter().all(|r| r["code"] == "unknown_route"));
    assert_eq!(
        gw.anthropic.hits.load(Ordering::SeqCst) + gw.openai.hits.load(Ordering::SeqCst),
        0
    );
    Ok(())
}

/// An empty credential beside a real one is refused with that cause, and a short key standing as a word of its
/// own in another header does not travel to the provider.
#[tokio::test]
async fn empty_credentials_are_named_as_such() -> TestResult {
    let gw = gateway("empty-credentials", Answer::Echo).await?;
    let request = post("/v1/messages", "")
        .header("x-api-key", "")
        .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
        .body(Body::from(MESSAGE))?;
    let (status, _, body) = send(&gw.app, request).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("an empty x-api-key"), "{body}");
    let request = post("/v1/messages", "")
        .header("x-api-key", MAYA)
        .header(header::AUTHORIZATION, "Basic dXNlcjpwYXNz")
        .body(Body::from(MESSAGE))?;
    let (status, _, body) = send(&gw.app, request).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(body.contains("holds no Bearer token"), "{body}");
    assert_eq!(gw.anthropic.hits.load(Ordering::SeqCst), 0);
    Ok(())
}
