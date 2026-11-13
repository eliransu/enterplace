//! Providers and routing: base URLs with a path, Azure OpenAI, Amazon Bedrock for Claude, retries and fallbacks,
//! and chat completions translated for messages providers. Every provider here is a mock on 127.0.0.1.

use std::{
    collections::VecDeque,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Router,
    body::{Body, Bytes},
    http::{HeaderMap, Request, StatusCode, header},
    response::{IntoResponse, Response},
};
use gantry_core::{
    audit::AuditLog,
    config::Kind,
    eventstream,
    guard::{Action, Check, Guardrail},
    id::sha256_hex,
    policy::{Limits, Models, Policy, Who},
    sigv4,
};
use gantry_server::{Audit, Config, ProviderRoute, Secret, Timeouts};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const MAYA: &str = "gantry_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// One answer of a mock provider.
#[derive(Clone)]
enum Reply {
    Status(u16),
    Body(&'static str, Vec<u8>),
    /// Waits, then answers 200 with a small JSON body.
    Slow(u64),
    /// Bedrock's error: a status, its `x-amzn-ErrorType` and a body with a message.
    AwsError(u16, &'static str),
}

/// What a mock provider was sent, and the answers it gives in turn. The last answer repeats.
#[derive(Default)]
struct Mock {
    hits: AtomicUsize,
    seen: Mutex<Vec<(String, HeaderMap, Bytes)>>,
    replies: Mutex<VecDeque<Reply>>,
}

impl Mock {
    fn first(&self) -> Result<(String, HeaderMap, Bytes), &'static str> {
        self.seen
            .lock()
            .map_err(|_| "poisoned")?
            .first()
            .cloned()
            .ok_or("the provider was sent nothing")
    }
}

async fn mock(replies: Vec<Reply>) -> Result<(SocketAddr, Arc<Mock>), Box<dyn std::error::Error>> {
    let state = Arc::new(Mock {
        replies: Mutex::new(replies.into()),
        ..Mock::default()
    });
    let mock = state.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = Router::new().fallback(move |request: Request<Body>| {
        let mock = mock.clone();
        async move {
            mock.hits.fetch_add(1, Ordering::SeqCst);
            let target = request
                .uri()
                .path_and_query()
                .map_or(String::new(), |pq| pq.as_str().to_string());
            let headers = request.headers().clone();
            let body = request
                .into_body()
                .collect()
                .await
                .map(|b| b.to_bytes())
                .unwrap_or_default();
            if let Ok(mut seen) = mock.seen.lock() {
                seen.push((target, headers, body));
            }
            let reply = match mock.replies.lock() {
                Ok(mut replies) if replies.len() > 1 => replies.pop_front(),
                Ok(replies) => replies.front().cloned(),
                Err(_) => None,
            };
            answer(reply.unwrap_or(Reply::Status(200))).await
        }
    });
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((addr, state))
}

async fn answer(reply: Reply) -> Response {
    match reply {
        Reply::Status(code) => (
            StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            [(header::CONTENT_TYPE, "application/json")],
            format!(r#"{{"status":{code}}}"#),
        )
            .into_response(),
        Reply::Body(content_type, bytes) => {
            ([(header::CONTENT_TYPE, content_type)], bytes).into_response()
        }
        Reply::Slow(ms) => {
            tokio::time::sleep(Duration::from_millis(ms)).await;
            (StatusCode::OK, r#"{"slow":true}"#).into_response()
        }
        Reply::AwsError(code, kind) => (
            StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST),
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::HeaderName::from_static("x-amzn-errortype"), kind),
            ],
            r#"{"message":"The provided model identifier is invalid."}"#,
        )
            .into_response(),
    }
}

/// A port nothing listens on: bound, then let go.
async fn closed_port() -> Result<SocketAddr, std::io::Error> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    listener.local_addr()
}

fn route(name: &str, kind: Kind, url: String, models: &[&str]) -> ProviderRoute {
    ProviderRoute {
        name: name.into(),
        kind,
        url,
        key: (kind != Kind::Bedrock).then(|| Secret::new(format!("{name}-provider-key"))),
        models: models.iter().map(|m| m.to_string()).collect(),
        ..ProviderRoute::default()
    }
}

fn aws() -> sigv4::Credentials {
    sigv4::Credentials {
        access_key_id: "AKIDEXAMPLE".into(),
        secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
        session_token: Some("session-token-example".into()),
    }
}

fn bedrock(url: String, models: &[(&str, &str)]) -> ProviderRoute {
    ProviderRoute {
        region: Some("us-east-1".into()),
        aws: Some(aws()),
        upstream_models: models
            .iter()
            .map(|(m, id)| (m.to_string(), id.to_string()))
            .collect(),
        ..route(
            "bedrock",
            Kind::Bedrock,
            url,
            &models.iter().map(|(m, _)| *m).collect::<Vec<_>>(),
        )
    }
}

struct Gateway {
    app: Router,
    log: PathBuf,
}

fn gateway_with(
    name: &str,
    providers: Vec<ProviderRoute>,
    timeouts: Timeouts,
) -> Result<Gateway, Box<dyn std::error::Error>> {
    let policy = Policy::new()
        .with_key(MAYA, "maya.cohen", "payments")
        .with_rule("everyone", Who::Any, Models::Any);
    gateway_for(name, providers, timeouts, policy)
}

fn gateway_for(
    name: &str,
    providers: Vec<ProviderRoute>,
    timeouts: Timeouts,
    policy: Policy,
) -> Result<Gateway, Box<dyn std::error::Error>> {
    let log = std::env::temp_dir().join(format!(
        "gantry-providers-{}-{name}.jsonl",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&log);
    let app = gantry_server::app(Config {
        providers,
        policy: Some(policy),
        audit: Some(Audit {
            log: Arc::new(AuditLog::open(&log)?),
            provider: String::new(),
            policy_sha256: sha256_hex(b"policy"),
            keys_sha256: sha256_hex(b"keys"),
        }),
        timeouts,
        ..Config::default()
    })?;
    Ok(Gateway { app, log })
}

fn gateway(
    name: &str,
    providers: Vec<ProviderRoute>,
) -> Result<Gateway, Box<dyn std::error::Error>> {
    gateway_with(name, providers, Timeouts::default())
}

async fn post(
    gw: &Gateway,
    path: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> Result<(StatusCode, HeaderMap, String), Box<dyn std::error::Error>> {
    let mut request = Request::post(path)
        .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
        .header(header::CONTENT_TYPE, "application/json");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = gw
        .app
        .clone()
        .oneshot(request.body(Body::from(body.to_string()))?)
        .await?;
    let (status, headers) = (response.status(), response.headers().clone());
    let text = String::from_utf8(response.into_body().collect().await?.to_bytes().to_vec())?;
    Ok((status, headers, text))
}

/// The records of the log. Waits a little for one of `event`, which is written after the answer has left.
async fn records(
    gw: &Gateway,
    event: Option<&str>,
) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    for _ in 0..50 {
        let all: Vec<Value> = std::fs::read_to_string(&gw.log)?
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        if event.is_none_or(|e| all.iter().any(|r| r["event"] == e)) {
            return Ok(all);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Err(format!("no {event:?} record was written").into())
}

const CHAT: &str = r#"{"model":"llama-4","messages":[{"role":"user","content":"Say hello."}]}"#;
const MESSAGE: &str = r#"{"model":"claude-sonnet-5-5","max_tokens":64,"stream":false,"messages":[{"role":"user","content":"Say hello."}]}"#;

// 1. Base URL with a path.

#[tokio::test]
async fn a_url_with_a_path_reaches_the_route_after_v1() -> TestResult {
    let (at, groq) = mock(vec![Reply::Status(200)]).await?;
    let gw = gateway(
        "path",
        vec![route(
            "groq",
            Kind::OpenAi,
            format!("http://{at}/openai/v1/"),
            &["llama-4"],
        )],
    )?;
    let (status, _, _) = post(&gw, "/v1/chat/completions", CHAT, &[]).await?;
    assert_eq!(status, StatusCode::OK);
    let (target, headers, _) = groq.first()?;
    assert_eq!(target, "/openai/v1/chat/completions");
    assert_eq!(headers[header::AUTHORIZATION], "Bearer groq-provider-key");
    Ok(())
}

#[tokio::test]
async fn serve_starts_on_a_file_check_accepts_with_a_path() -> TestResult {
    let dir = std::env::temp_dir().join(format!(
        "gantry-providers-{}-serve-path",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let policy = dir.join("gantry.policy.yaml");
    std::fs::write(
        &policy,
        "version: 1\nproviders:\n  - name: groq\n    kind: openai\n    url: https://api.groq.com/openai/v1\n    key_env: GROQ_API_KEY\n    models: [llama-4]\nrules:\n  - name: everyone\n    principals: { any: true }\n    models: [\"*\"]\n",
    )?;
    assert!(gantry_core::config::load(&policy, None).is_ok());
    let started = gantry_server::governed(&policy, None, &|_| Some("key".into()));
    assert!(started.is_ok(), "{:?}", started.err());
    Ok(())
}

// 2. Azure OpenAI.

#[tokio::test]
async fn azure_gets_its_deployment_path_api_version_and_api_key() -> TestResult {
    let (at, azure) = mock(vec![Reply::Status(200)]).await?;
    let gw = gateway(
        "azure",
        vec![ProviderRoute {
            api_version: Some("2024-10-21".into()),
            upstream_models: [("gpt-4o".to_string(), "prod-gpt-4o".to_string())].into(),
            ..route("azure", Kind::Azure, format!("http://{at}"), &["gpt-4o"])
        }],
    )?;
    let body = CHAT.replace("llama-4", "gpt-4o");
    let (status, _, _) = post(&gw, "/v1/chat/completions", &body, &[]).await?;
    assert_eq!(status, StatusCode::OK);
    let (target, headers, sent) = azure.first()?;
    assert_eq!(
        target,
        "/openai/deployments/prod-gpt-4o/chat/completions?api-version=2024-10-21"
    );
    assert_eq!(headers["api-key"], "azure-provider-key");
    assert!(headers.get(header::AUTHORIZATION).is_none());
    // The body goes as it came.
    assert_eq!(sent, body.as_bytes());
    Ok(())
}

// 3. Amazon Bedrock.

#[tokio::test]
async fn bedrock_gets_a_signed_invoke_with_the_body_bedrock_takes() -> TestResult {
    let message = json!({"id":"msg_1","type":"message","role":"assistant","model":"claude","content":[{"type":"text","text":"Hello."}],"stop_reason":"end_turn","usage":{"input_tokens":3,"output_tokens":2}});
    let (at, aws_mock) = mock(vec![Reply::Body(
        "application/json",
        message.to_string().into_bytes(),
    )])
    .await?;
    let gw = gateway(
        "bedrock",
        vec![bedrock(
            format!("http://{at}"),
            &[("claude-sonnet-5-5", "us.anthropic.claude-sonnet-5-5-v1:0")],
        )],
    )?;
    let (status, _, text) = post(
        &gw,
        "/v1/messages?beta=true",
        MESSAGE,
        &[
            ("anthropic-version", "2023-06-01"),
            (
                "anthropic-beta",
                "context-1m-2025-08-07, interleaved-thinking-2025-05-14",
            ),
        ],
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(serde_json::from_str::<Value>(&text)?, message);
    let (target, headers, sent) = aws_mock.first()?;
    assert_eq!(
        target,
        "/model/us.anthropic.claude-sonnet-5-5-v1%3A0/invoke"
    );
    let body: Value = serde_json::from_slice(&sent)?;
    assert_eq!(body["anthropic_version"], "bedrock-2023-05-31");
    assert_eq!(
        body["anthropic_beta"],
        json!(["context-1m-2025-08-07", "interleaved-thinking-2025-05-14"])
    );
    assert!(body.get("model").is_none() && body.get("stream").is_none());
    assert_eq!(body["max_tokens"], 64);
    assert!(headers.get("anthropic-beta").is_none());
    assert!(headers.get("x-api-key").is_none());
    // The signature is the one SigV4 gives for what arrived.
    let text = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
    };
    let host = text("host");
    assert_eq!(host, at.to_string());
    let expected = sigv4::sign(
        &aws(),
        "us-east-1",
        "bedrock",
        &sigv4::Request {
            method: "POST",
            path: "/model/us.anthropic.claude-sonnet-5-5-v1%3A0/invoke",
            query: "",
            headers: &[("host", host), ("content-type", "application/json")],
            payload: &sent,
        },
        text("x-amz-date"),
    );
    assert_eq!(text("authorization"), expected[0].1);
    assert!(text("authorization").starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"));
    assert!(
        text("authorization")
            .contains("SignedHeaders=content-type;host;x-amz-date;x-amz-security-token,")
    );
    assert_eq!(text("x-amz-security-token"), "session-token-example");
    Ok(())
}

fn bedrock_stream() -> Vec<u8> {
    [
        json!({"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude","content":[],"stop_reason":null,"usage":{"input_tokens":3,"output_tokens":0}}}),
        json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
        json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello."}}),
        json!({"type":"content_block_stop","index":0}),
        json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":2}}),
        json!({"type":"message_stop"}),
    ]
    .iter()
    .flat_map(eventstream::chunk)
    .collect()
}

#[tokio::test]
async fn a_bedrock_event_stream_reaches_the_caller_as_anthropic_events() -> TestResult {
    let (at, aws_mock) = mock(vec![Reply::Body(
        "application/vnd.amazon.eventstream",
        bedrock_stream(),
    )])
    .await?;
    let gw = gateway(
        "bedrock-stream",
        vec![bedrock(
            format!("http://{at}"),
            &[("claude-sonnet-5-5", "anthropic.claude-x")],
        )],
    )?;
    let body = MESSAGE.replace("\"stream\":false", "\"stream\":true");
    let (status, headers, text) = post(&gw, "/v1/messages", &body, &[]).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(headers[header::CONTENT_TYPE], "text/event-stream");
    let (target, _, _) = aws_mock.first()?;
    assert_eq!(
        target,
        "/model/anthropic.claude-x/invoke-with-response-stream"
    );
    assert!(
        text.starts_with("event: message_start\ndata: {\"type\":\"message_start\""),
        "{text}"
    );
    assert!(
        text.contains("event: content_block_delta\ndata: "),
        "{text}"
    );
    assert!(text.contains("\"text\":\"Hello.\""), "{text}");
    assert!(
        text.ends_with("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"),
        "{text}"
    );
    Ok(())
}

#[tokio::test]
async fn a_bedrock_error_reaches_the_caller_in_anthropic_shape() -> TestResult {
    let (at, _) = mock(vec![Reply::AwsError(
        400,
        "ValidationException:http://internal.amazon.com/",
    )])
    .await?;
    let gw = gateway(
        "bedrock-error",
        vec![bedrock(
            format!("http://{at}"),
            &[("claude-sonnet-5-5", "anthropic.claude-x")],
        )],
    )?;
    let (status, _, text) = post(&gw, "/v1/messages", MESSAGE, &[]).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: Value = serde_json::from_str(&text)?;
    assert_eq!(error["type"], "error");
    assert_eq!(error["error"]["type"], "invalid_request_error");
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("model identifier is invalid"),
        "{text}"
    );
    Ok(())
}

// 4. Retries and fallbacks.

#[tokio::test]
async fn a_5xx_is_retried_and_every_attempt_is_recorded() -> TestResult {
    let (at, groq) = mock(vec![
        Reply::Status(503),
        Reply::Status(429),
        Reply::Status(200),
    ])
    .await?;
    let gw = gateway(
        "retries",
        vec![ProviderRoute {
            retries: 2,
            ..route("groq", Kind::OpenAi, format!("http://{at}"), &["llama-4"])
        }],
    )?;
    let (status, headers, _) = post(&gw, "/v1/chat/completions", CHAT, &[]).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(groq.hits.load(Ordering::SeqCst), 3);
    let decision = headers["x-gantry-decision"].to_str()?.to_string();
    let all = records(&gw, Some("attempts")).await?;
    let attempts = all
        .iter()
        .find(|r| r["event"] == "attempts")
        .ok_or("no attempts record")?;
    assert_eq!(attempts["id"], decision.as_str());
    assert_eq!(
        attempts["attempts"],
        json!([
            {"provider":"groq","outcome":"503"},
            {"provider":"groq","outcome":"429"},
            {"provider":"groq","outcome":"200"}
        ])
    );
    // The request record came first, before anything was sent.
    assert_eq!(all[0]["id"], decision.as_str());
    assert_eq!(all[0]["verdict"], "allow");
    assert!(gantry_core::audit::verify(&gw.log).is_ok());
    Ok(())
}

#[tokio::test]
async fn retries_run_out_then_the_fallback_answers() -> TestResult {
    let (primary_at, primary) = mock(vec![Reply::Status(500)]).await?;
    let (fallback_at, fallback) = mock(vec![Reply::Status(200)]).await?;
    let gw = gateway(
        "fallback",
        vec![
            ProviderRoute {
                retries: 1,
                fallback: Some("backup".into()),
                ..route(
                    "primary",
                    Kind::OpenAi,
                    format!("http://{primary_at}"),
                    &["llama-4"],
                )
            },
            route(
                "backup",
                Kind::OpenAi,
                format!("http://{fallback_at}/v1"),
                &["other"],
            ),
        ],
    )?;
    let (status, _, _) = post(&gw, "/v1/chat/completions", CHAT, &[]).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(primary.hits.load(Ordering::SeqCst), 2);
    let (target, headers, _) = fallback.first()?;
    // The fallback's own URL rule and key.
    assert_eq!(target, "/v1/chat/completions");
    assert_eq!(headers[header::AUTHORIZATION], "Bearer backup-provider-key");
    let all = records(&gw, Some("attempts")).await?;
    let attempts = all
        .iter()
        .find(|r| r["event"] == "attempts")
        .ok_or("none")?;
    assert_eq!(
        attempts["attempts"],
        json!([
            {"provider":"primary","outcome":"500"},
            {"provider":"primary","outcome":"500"},
            {"provider":"backup","outcome":"200"}
        ])
    );
    Ok(())
}

#[tokio::test]
async fn an_unreachable_provider_falls_back_to_a_mapped_name() -> TestResult {
    let dead = closed_port().await?;
    let (at, azure) = mock(vec![Reply::Status(200)]).await?;
    let gw = gateway(
        "unreachable",
        vec![
            ProviderRoute {
                fallback: Some("azure".into()),
                ..route(
                    "openai",
                    Kind::OpenAi,
                    format!("http://{dead}"),
                    &["gpt-4o"],
                )
            },
            ProviderRoute {
                api_version: Some("2024-10-21".into()),
                upstream_models: [("gpt-4o".to_string(), "eu-gpt-4o".to_string())].into(),
                ..route("azure", Kind::Azure, format!("http://{at}"), &["gpt-4.1"])
            },
        ],
    )?;
    let (status, _, _) = post(
        &gw,
        "/v1/chat/completions",
        &CHAT.replace("llama-4", "gpt-4o"),
        &[],
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let (target, _, _) = azure.first()?;
    assert!(
        target.starts_with("/openai/deployments/eu-gpt-4o/"),
        "{target}"
    );
    let all = records(&gw, Some("attempts")).await?;
    let attempts = all
        .iter()
        .find(|r| r["event"] == "attempts")
        .ok_or("none")?;
    assert_eq!(attempts["attempts"][0]["outcome"], "upstream_unreachable");
    Ok(())
}

#[tokio::test]
async fn a_timeout_is_retried() -> TestResult {
    let (at, slow) = mock(vec![Reply::Slow(2000), Reply::Status(200)]).await?;
    let gw = gateway_with(
        "timeout",
        vec![ProviderRoute {
            retries: 1,
            ..route("slow", Kind::OpenAi, format!("http://{at}"), &["llama-4"])
        }],
        Timeouts {
            first_byte: Duration::from_millis(300),
            ..Timeouts::default()
        },
    )?;
    let (status, _, _) = post(&gw, "/v1/chat/completions", CHAT, &[]).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(slow.hits.load(Ordering::SeqCst), 2);
    let all = records(&gw, Some("attempts")).await?;
    let attempts = all
        .iter()
        .find(|r| r["event"] == "attempts")
        .ok_or("none")?;
    assert_eq!(attempts["attempts"][0]["outcome"], "upstream_timeout");
    Ok(())
}

#[tokio::test]
async fn a_callers_own_error_is_never_retried() -> TestResult {
    let (at, groq) = mock(vec![Reply::Status(400), Reply::Status(200)]).await?;
    let (fallback_at, fallback) = mock(vec![Reply::Status(200)]).await?;
    let gw = gateway(
        "no-retry",
        vec![
            ProviderRoute {
                retries: 3,
                fallback: Some("backup".into()),
                ..route("groq", Kind::OpenAi, format!("http://{at}"), &["llama-4"])
            },
            route(
                "backup",
                Kind::OpenAi,
                format!("http://{fallback_at}"),
                &["other"],
            ),
        ],
    )?;
    let (status, _, text) = post(&gw, "/v1/chat/completions", CHAT, &[]).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(text, r#"{"status":400}"#);
    assert_eq!(groq.hits.load(Ordering::SeqCst), 1);
    assert_eq!(fallback.hits.load(Ordering::SeqCst), 0);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !records(&gw, None)
            .await?
            .iter()
            .any(|r| r["event"] == "attempts")
    );
    Ok(())
}

#[tokio::test]
async fn once_the_answer_has_started_nothing_is_retried() -> TestResult {
    // A provider that starts a streamed answer, then drops the connection.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let at = listener.local_addr()?;
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = hits.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            let mut buffer = [0u8; 4096];
            let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut buffer).await;
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n6\r\ndata: \r\n")
                .await;
            drop(socket);
        }
    });
    let gw = gateway(
        "started",
        vec![ProviderRoute {
            retries: 3,
            ..route("cut", Kind::OpenAi, format!("http://{at}"), &["llama-4"])
        }],
    )?;
    let response = gw
        .app
        .clone()
        .oneshot(
            Request::post("/v1/chat/completions")
                .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
                .body(Body::from(CHAT))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    // The caller sees the answer break; the provider was asked once.
    assert!(response.into_body().collect().await.is_err());
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    Ok(())
}

// 5. Translation for chat completions callers.

fn anthropic_message() -> Value {
    json!({"id":"msg_01","type":"message","role":"assistant","model":"claude-sonnet-5-5","content":[{"type":"text","text":"Hello."}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":9,"output_tokens":2}})
}

#[tokio::test]
async fn a_chat_request_is_translated_for_a_provider_that_accepts_chat() -> TestResult {
    let (at, anthropic) = mock(vec![Reply::Body(
        "application/json",
        anthropic_message().to_string().into_bytes(),
    )])
    .await?;
    let gw = gateway(
        "translate",
        vec![ProviderRoute {
            accept_chat: true,
            ..route(
                "anthropic",
                Kind::Anthropic,
                format!("http://{at}"),
                &["claude-sonnet-5-5"],
            )
        }],
    )?;
    let chat = r#"{"model":"claude-sonnet-5-5","messages":[{"role":"system","content":"Be brief."},{"role":"user","content":"Say hello."}],"max_tokens":50}"#;
    let (status, _, text) = post(&gw, "/v1/chat/completions", chat, &[]).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let answer: Value = serde_json::from_str(&text)?;
    assert_eq!(answer["object"], "chat.completion");
    assert_eq!(answer["choices"][0]["message"]["content"], "Hello.");
    assert_eq!(answer["choices"][0]["finish_reason"], "stop");
    let (target, headers, sent) = anthropic.first()?;
    assert_eq!(target, "/v1/messages");
    assert_eq!(headers["x-api-key"], "anthropic-provider-key");
    assert_eq!(headers["anthropic-version"], "2023-06-01");
    let sent: Value = serde_json::from_slice(&sent)?;
    assert_eq!(sent["system"][0]["text"], "Be brief.");
    assert_eq!(sent["max_tokens"], 50);
    let all = records(&gw, None).await?;
    assert_eq!(all[0]["translated"], true);
    Ok(())
}

#[tokio::test]
async fn a_streamed_chat_request_through_bedrock_comes_back_as_chat_chunks() -> TestResult {
    let (at, aws_mock) = mock(vec![Reply::Body(
        "application/vnd.amazon.eventstream",
        bedrock_stream(),
    )])
    .await?;
    let gw = gateway(
        "translate-bedrock",
        vec![ProviderRoute {
            accept_chat: true,
            ..bedrock(
                format!("http://{at}"),
                &[("claude-sonnet-5-5", "anthropic.claude-x")],
            )
        }],
    )?;
    let chat = r#"{"model":"claude-sonnet-5-5","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"Say hello."}]}"#;
    let (status, _, text) = post(&gw, "/v1/chat/completions", chat, &[]).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, _, sent) = aws_mock.first()?;
    assert_eq!(
        target,
        "/model/anthropic.claude-x/invoke-with-response-stream"
    );
    let sent: Value = serde_json::from_slice(&sent)?;
    assert_eq!(sent["anthropic_version"], "bedrock-2023-05-31");
    assert!(
        text.contains("\"object\":\"chat.completion.chunk\""),
        "{text}"
    );
    assert!(text.contains("\"content\":\"Hello.\""), "{text}");
    assert!(text.contains("\"prompt_tokens\":3"), "{text}");
    assert!(text.trim_end().ends_with("data: [DONE]"), "{text}");
    Ok(())
}

#[tokio::test]
async fn an_untranslatable_field_is_refused_by_name_and_recorded() -> TestResult {
    let (at, anthropic) = mock(vec![Reply::Status(200)]).await?;
    let gw = gateway(
        "untranslatable",
        vec![ProviderRoute {
            accept_chat: true,
            ..route(
                "anthropic",
                Kind::Anthropic,
                format!("http://{at}"),
                &["claude-sonnet-5-5"],
            )
        }],
    )?;
    let chat = r#"{"model":"claude-sonnet-5-5","n":2,"messages":[{"role":"user","content":"Hi"}]}"#;
    let (status, _, text) = post(&gw, "/v1/chat/completions", chat, &[]).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error: Value = serde_json::from_str(&text)?;
    assert_eq!(error["error"]["code"], "untranslatable");
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("\"n\""),
        "{text}"
    );
    assert_eq!(anthropic.hits.load(Ordering::SeqCst), 0);
    let all = records(&gw, None).await?;
    assert_eq!(all[0]["verdict"], "refused");
    assert_eq!(all[0]["code"], "untranslatable");
    Ok(())
}

#[tokio::test]
async fn without_accept_chat_a_chat_request_is_still_the_wrong_route() -> TestResult {
    let (at, anthropic) = mock(vec![Reply::Status(200)]).await?;
    let gw = gateway(
        "no-accept",
        vec![route(
            "anthropic",
            Kind::Anthropic,
            format!("http://{at}"),
            &["claude-sonnet-5-5"],
        )],
    )?;
    let chat = r#"{"model":"claude-sonnet-5-5","messages":[{"role":"user","content":"Hi"}]}"#;
    let (status, _, text) = post(&gw, "/v1/chat/completions", chat, &[]).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        text.contains("wrong_route") && text.contains("accept_chat: true"),
        "{text}"
    );
    // UX11 n7: accept_chat translates chat only, so it is never offered for Responses or embeddings.
    for path in ["/v1/responses", "/v1/embeddings"] {
        let body = r#"{"model":"claude-sonnet-5-5","input":"Hi"}"#;
        let (status, _, text) = post(&gw, path, body, &[]).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
        assert!(
            text.contains("wrong_route")
                && text.contains("kind openai")
                && !text.contains("accept_chat"),
            "{path}: {text}"
        );
    }
    assert_eq!(anthropic.hits.load(Ordering::SeqCst), 0);
    Ok(())
}

// 6. Providers together with guardrails, spend and the cache.

/// The usage record of a decision, waiting for it: it is written as the answer ends.
async fn usage_of(gw: &Gateway, id: &str) -> Result<Value, Box<dyn std::error::Error>> {
    for _ in 0..100 {
        let all = records(gw, None).await?;
        if let Some(usage) = all.iter().find(|r| r["event"] == "usage" && r["id"] == id) {
            return Ok(usage.clone());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Err(format!("no usage record for {id}").into())
}

fn tokens(usage: &Value) -> (Option<&str>, Option<u64>, Option<u64>) {
    (
        usage["usage"].as_str(),
        usage["input_tokens"].as_u64(),
        usage["output_tokens"].as_u64(),
    )
}

#[tokio::test]
async fn translated_and_bedrock_answers_get_usage_records() -> TestResult {
    let (anthropic_at, _) = mock(vec![Reply::Body(
        "application/json",
        anthropic_message().to_string().into_bytes(),
    )])
    .await?;
    let gw = gateway(
        "usage-translated",
        vec![ProviderRoute {
            accept_chat: true,
            ..route(
                "anthropic",
                Kind::Anthropic,
                format!("http://{anthropic_at}"),
                &["claude-sonnet-5-5"],
            )
        }],
    )?;
    let chat =
        r#"{"model":"claude-sonnet-5-5","messages":[{"role":"user","content":"Say hello."}]}"#;
    let (status, headers, text) = post(&gw, "/v1/chat/completions", chat, &[]).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let usage = usage_of(&gw, headers["x-gantry-decision"].to_str()?).await?;
    assert_eq!(tokens(&usage), (Some("reported"), Some(9), Some(2)));
    assert_eq!(usage["provider"], "anthropic");

    // A Bedrock stream, translated for a chat client that did not ask for usage: usage is read before translation.
    let (bedrock_at, _) = mock(vec![Reply::Body(
        "application/vnd.amazon.eventstream",
        bedrock_stream(),
    )])
    .await?;
    let gw = gateway(
        "usage-bedrock",
        vec![ProviderRoute {
            accept_chat: true,
            ..bedrock(
                format!("http://{bedrock_at}"),
                &[("claude-sonnet-5-5", "anthropic.claude-x")],
            )
        }],
    )?;
    let chat = r#"{"model":"claude-sonnet-5-5","stream":true,"messages":[{"role":"user","content":"Say hello."}]}"#;
    let (status, headers, text) = post(&gw, "/v1/chat/completions", chat, &[]).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert!(!text.contains("prompt_tokens"), "{text}");
    let usage = usage_of(&gw, headers["x-gantry-decision"].to_str()?).await?;
    assert_eq!(tokens(&usage), (Some("reported"), Some(3), Some(2)));
    assert_eq!(usage["ended"], "complete");

    // And a Bedrock stream on the messages route.
    let body = MESSAGE.replace("\"stream\":false", "\"stream\":true");
    let (status, headers, _) = post(&gw, "/v1/messages", &body, &[]).await?;
    assert_eq!(status, StatusCode::OK);
    let usage = usage_of(&gw, headers["x-gantry-decision"].to_str()?).await?;
    assert_eq!(tokens(&usage), (Some("reported"), Some(3), Some(2)));
    assert!(gantry_core::audit::verify(&gw.log).is_ok());
    Ok(())
}

#[tokio::test]
async fn a_request_that_fell_back_has_an_attempts_record_and_a_usage_record() -> TestResult {
    let (primary_at, _) = mock(vec![Reply::Status(500)]).await?;
    let (fallback_at, _) = mock(vec![Reply::Body(
        "application/json",
        br#"{"usage":{"prompt_tokens":5,"completion_tokens":1}}"#.to_vec(),
    )])
    .await?;
    let gw = gateway(
        "attempts-usage",
        vec![
            ProviderRoute {
                retries: 1,
                fallback: Some("backup".into()),
                ..route(
                    "groq",
                    Kind::OpenAi,
                    format!("http://{primary_at}"),
                    &["llama-4"],
                )
            },
            route("backup", Kind::OpenAi, format!("http://{fallback_at}"), &[]),
        ],
    )?;
    let (status, headers, _) = post(&gw, "/v1/chat/completions", CHAT, &[]).await?;
    assert_eq!(status, StatusCode::OK);
    let decision = headers["x-gantry-decision"].to_str()?.to_string();
    let usage = usage_of(&gw, &decision).await?;
    assert_eq!(tokens(&usage), (Some("reported"), Some(5), Some(1)));
    // The provider that answered, not the one the request was first sent to.
    assert_eq!(usage["provider"], "backup");
    let all = records(&gw, Some("attempts")).await?;
    let of = |event: &str| {
        all.iter()
            .filter(|r| r["id"] == decision.as_str() && r["event"] == event)
            .count()
    };
    assert_eq!((of("attempts"), of("usage")), (1, 1));
    let summary = gantry_core::audit::verify_full(&gw.log, None)?;
    assert_eq!((summary.attempts, summary.usage), (1, 1));
    Ok(())
}

#[tokio::test]
async fn guardrails_run_before_the_cache_and_a_translated_hit_is_translated() -> TestResult {
    let (at, anthropic) = mock(vec![Reply::Body(
        "application/json",
        anthropic_message().to_string().into_bytes(),
    )])
    .await?;
    let policy = Policy::new()
        .with_key(MAYA, "maya.cohen", "payments")
        .with_rule("everyone", Who::Any, Models::Any)
        .with_guardrails(&[Guardrail {
            name: "no-secrets".into(),
            action: Action::Block,
            check: Check::Secrets,
            on: gantry_core::guard::On::REQUEST,
        }])
        .with_limits(Limits {
            cache_ttl_seconds: Some(60),
            ..Limits::default()
        });
    let gw = gateway_for(
        "guard-cache",
        vec![ProviderRoute {
            accept_chat: true,
            ..route(
                "anthropic",
                Kind::Anthropic,
                format!("http://{at}"),
                &["claude-sonnet-5-5"],
            )
        }],
        Timeouts::default(),
        policy,
    )?;
    let chat =
        r#"{"model":"claude-sonnet-5-5","messages":[{"role":"user","content":"Say hello."}]}"#;
    let (_, headers, first) = post(&gw, "/v1/chat/completions", chat, &[]).await?;
    // The answer is cached when it is settled, on the audit writer's thread after the caller has it: wait for that,
    // or a busy machine sends the second request first and it is a miss.
    usage_of(&gw, headers["x-gantry-decision"].to_str()?).await?;
    let (status, headers, second) = post(&gw, "/v1/chat/completions", chat, &[]).await?;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(headers["x-gantry-cache"], "hit");
    assert_eq!(anthropic.hits.load(Ordering::SeqCst), 1);
    // The cache keeps the provider's answer; a chat caller gets it as chat, the same as the first time.
    let hit: Value = serde_json::from_str(&second)?;
    assert_eq!(hit["object"], "chat.completion");
    assert_eq!(
        hit["choices"],
        serde_json::from_str::<Value>(&first)?["choices"]
    );
    // A native messages caller with the same translated bytes never gets a chat answer from the cache.
    let (_, _, native) = post(
        &gw,
        "/v1/messages",
        r#"{"model":"claude-sonnet-5-5","max_tokens":64,"messages":[{"role":"user","content":"Say hello."}]}"#,
        &[],
    )
    .await?;
    assert_eq!(serde_json::from_str::<Value>(&native)?["type"], "message");

    // A request the guardrail blocks is refused before the cache is read, and is never sent.
    let secret = r#"{"model":"claude-sonnet-5-5","messages":[{"role":"user","content":"key AKIAIOSFODNN7EXAMPLE"}]}"#;
    let sent = anthropic.hits.load(Ordering::SeqCst);
    for _ in 0..2 {
        let (status, headers, text) = post(&gw, "/v1/chat/completions", secret, &[]).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
        assert!(text.contains("guardrail_blocked"), "{text}");
        assert!(headers.get("x-gantry-cache").is_none());
    }
    assert_eq!(anthropic.hits.load(Ordering::SeqCst), sent);
    let all = records(&gw, None).await?;
    let blocked: Vec<&Value> = all
        .iter()
        .filter(|r| r["code"] == "guardrail_blocked")
        .collect();
    assert_eq!(blocked.len(), 2);
    assert!(blocked.iter().all(|r| r["cache"].is_null()));
    Ok(())
}
