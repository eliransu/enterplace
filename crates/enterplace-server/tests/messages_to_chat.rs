//! Claude Code to any provider: messages requests translated to chat completions (and on to Gemini) for a provider
//! with `accept_messages`, answers translated back, streamed or whole; and Claude on Vertex AI
//! (`vertex_anthropic`). Every provider here is a mock on 127.0.0.1.

use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Router,
    body::{Body, Bytes},
    http::{HeaderMap, Request, StatusCode, header},
    response::IntoResponse,
};
use enterplace_core::{
    audit::AuditLog,
    config::Kind,
    id::sha256_hex,
    policy::{Models, Policy, Who},
};
use enterplace_server::{Audit, Config, ProviderRoute, Secret};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Seen = Arc<Mutex<Vec<(String, HeaderMap, Bytes)>>>;

const MAYA: &str = "enterplace_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// A provider that records what it was sent and always gives the same answer.
async fn mock(
    content_type: &'static str,
    body: String,
) -> Result<(SocketAddr, Seen), Box<dyn std::error::Error>> {
    let seen: Seen = Arc::default();
    let log = seen.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = Router::new().fallback(move |request: Request<Body>| {
        let (log, body) = (log.clone(), body.clone());
        async move {
            let target = request
                .uri()
                .path_and_query()
                .map_or(String::new(), |pq| pq.as_str().to_string());
            let headers = request.headers().clone();
            let bytes = request
                .into_body()
                .collect()
                .await
                .map(|b| b.to_bytes())
                .unwrap_or_default();
            if let Ok(mut seen) = log.lock() {
                seen.push((target, headers, bytes));
            }
            ([(header::CONTENT_TYPE, content_type)], body).into_response()
        }
    });
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((addr, seen))
}

fn first(seen: &Seen) -> Result<(String, HeaderMap, Value), Box<dyn std::error::Error>> {
    let (target, headers, bytes) = seen
        .lock()
        .map_err(|_| "poisoned")?
        .first()
        .cloned()
        .ok_or("the provider was sent nothing")?;
    Ok((target, headers, serde_json::from_slice(&bytes)?))
}

fn provider(name: &str, kind: Kind, url: String, model: &str) -> ProviderRoute {
    ProviderRoute {
        name: name.into(),
        kind,
        url,
        key: Some(Secret::new(format!("{name}-provider-key"))),
        models: vec![model.into()],
        accept_messages: kind.api() == Kind::OpenAi,
        ..ProviderRoute::default()
    }
}

struct Gateway {
    app: Router,
    log: PathBuf,
}

fn gateway(
    name: &str,
    providers: Vec<ProviderRoute>,
) -> Result<Gateway, Box<dyn std::error::Error>> {
    let log = std::env::temp_dir().join(format!(
        "enterplace-messages-{}-{name}.jsonl",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&log);
    let policy = Policy::new()
        .with_key(MAYA, "maya.cohen", "payments")
        .with_rule("everyone", Who::Any, Models::Any);
    let app = enterplace_server::app(Config {
        providers,
        policy: Some(policy),
        audit: Some(Audit {
            log: Arc::new(AuditLog::open(&log)?),
            provider: String::new(),
            policy_sha256: sha256_hex(b"policy"),
            keys_sha256: sha256_hex(b"keys"),
        }),
        ..Config::default()
    })?;
    Ok(Gateway { app, log })
}

/// Sent as Claude Code sends it: the Enterplace key in x-api-key, with Anthropic's version and betas.
async fn claude_code(
    gw: &Gateway,
    path: &str,
    body: &Value,
) -> Result<(StatusCode, HeaderMap, String), Box<dyn std::error::Error>> {
    let request = Request::post(path)
        .header("x-api-key", MAYA)
        .header("anthropic-version", "2023-06-01")
        .header(
            "anthropic-beta",
            "claude-code-20250219,interleaved-thinking-2025-05-14",
        )
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))?;
    let response = gw.app.clone().oneshot(request).await?;
    let (status, headers) = (response.status(), response.headers().clone());
    let text = String::from_utf8(response.into_body().collect().await?.to_bytes().to_vec())?;
    Ok((status, headers, text))
}

async fn records(gw: &Gateway, event: &str) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    for _ in 0..50 {
        let all: Vec<Value> = std::fs::read_to_string(&gw.log)?
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        if all.iter().any(|r| r["event"] == event) {
            return Ok(all);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Err(format!("no {event} record was written").into())
}

fn message(model: &str, stream: bool) -> Value {
    json!({
        "model": model,
        "max_tokens": 1024,
        "stream": stream,
        "system": [{"type": "text", "text": "You are Claude Code.", "cache_control": {"type": "ephemeral"}}],
        "messages": [{"role": "user", "content": "List the files."}],
        "tools": [{"name": "Ls", "description": "Lists files", "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}}}],
        "metadata": {"user_id": "session-1"},
    })
}

fn completion() -> String {
    json!({
        "id": "chatcmpl-9", "object": "chat.completion", "created": 1, "model": "gpt-4o",
        "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {"role": "assistant", "content": "Looking.",
            "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "Ls", "arguments": "{\"path\":\".\"}"}}]}}],
        "usage": {"prompt_tokens": 40, "completion_tokens": 9, "total_tokens": 49},
    })
    .to_string()
}

/// Each event of an Anthropic stream as (event name, data).
fn events(sse: &str) -> Result<Vec<(String, Value)>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    for record in sse.split("\n\n").filter(|r| !r.trim().is_empty()) {
        let (name, data) = record.split_once('\n').ok_or("no data line")?;
        let name = name.strip_prefix("event: ").ok_or("no event line")?;
        out.push((
            name.to_string(),
            serde_json::from_str(data.strip_prefix("data: ").ok_or("no data")?)?,
        ));
    }
    Ok(out)
}

#[tokio::test]
async fn a_messages_request_reaches_a_chat_provider_and_comes_back_as_a_message() -> TestResult {
    let (at, seen) = mock("application/json", completion()).await?;
    let gw = gateway(
        "whole",
        vec![provider(
            "openai",
            Kind::OpenAi,
            format!("http://{at}"),
            "gpt-4o",
        )],
    )?;
    let (status, _, text) = claude_code(&gw, "/v1/messages", &message("gpt-4o", false)).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let answer: Value = serde_json::from_str(&text)?;
    assert_eq!(answer["type"], "message");
    assert_eq!(answer["stop_reason"], "tool_use");
    assert_eq!(
        answer["content"][0],
        json!({"type": "text", "text": "Looking."})
    );
    assert_eq!(
        answer["content"][1],
        json!({"type": "tool_use", "id": "call_1", "name": "Ls", "input": {"path": "."}})
    );
    assert_eq!(answer["usage"]["input_tokens"], 40);
    let (target, headers, body) = first(&seen)?;
    assert_eq!(target, "/v1/chat/completions");
    assert_eq!(body["max_completion_tokens"], 1024);
    assert_eq!(body["messages"][0]["role"], "system");
    assert_eq!(body["tools"][0]["function"]["name"], "Ls");
    assert_eq!(headers["authorization"], "Bearer openai-provider-key");
    for gone in ["x-api-key", "anthropic-version", "anthropic-beta"] {
        assert!(!headers.contains_key(gone), "{gone} reached the provider");
    }
    let all = records(&gw, "usage").await?;
    assert_eq!(all[0]["translated"], true);
    assert_eq!(all[0]["verdict"], "allow");
    let usage = all.iter().find(|r| r["event"] == "usage").ok_or("usage")?;
    assert_eq!(usage["input_tokens"], 40);
    Ok(())
}

#[tokio::test]
async fn a_streamed_chat_answer_reaches_claude_code_as_anthropic_events() -> TestResult {
    let sse = [
        json!({"id": "chatcmpl-s", "model": "gpt-4o", "choices": [{"index": 0, "delta": {"role": "assistant", "content": "Hi"}, "finish_reason": null}]}),
        json!({"id": "chatcmpl-s", "model": "gpt-4o", "choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "call_2", "type": "function", "function": {"name": "Ls", "arguments": "{}"}}]}, "finish_reason": null}]}),
        json!({"id": "chatcmpl-s", "model": "gpt-4o", "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}),
        json!({"id": "chatcmpl-s", "model": "gpt-4o", "choices": [], "usage": {"prompt_tokens": 12, "completion_tokens": 3, "total_tokens": 15}}),
    ]
    .iter()
    .map(|c| format!("data: {c}\n\n"))
    .collect::<String>()
        + "data: [DONE]\n\n";
    let (at, seen) = mock("text/event-stream", sse).await?;
    let gw = gateway(
        "stream",
        vec![provider(
            "openai",
            Kind::OpenAi,
            format!("http://{at}"),
            "gpt-4o",
        )],
    )?;
    let (status, headers, text) =
        claude_code(&gw, "/v1/messages", &message("gpt-4o", true)).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(headers[header::CONTENT_TYPE], "text/event-stream");
    let events = events(&text)?;
    let names: Vec<&str> = events.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        [
            "message_start",
            "content_block_start",
            "content_block_delta",
            "content_block_stop",
            "content_block_start",
            "content_block_delta",
            "content_block_stop",
            "message_delta",
            "message_stop"
        ]
    );
    assert_eq!(events[4].1["content_block"]["type"], "tool_use");
    assert_eq!(events[5].1["delta"]["type"], "input_json_delta");
    assert_eq!(events[7].1["delta"]["stop_reason"], "tool_use");
    assert_eq!(events[7].1["usage"]["output_tokens"], 3);
    let (_, _, body) = first(&seen)?;
    assert_eq!(body["stream_options"], json!({"include_usage": true}));
    let all = records(&gw, "usage").await?;
    let usage = all.iter().find(|r| r["event"] == "usage").ok_or("usage")?;
    assert_eq!(usage["output_tokens"], 3);
    Ok(())
}

#[tokio::test]
async fn a_messages_request_reaches_gemini_through_chat() -> TestResult {
    let gemini = json!({
        "candidates": [{"content": {"role": "model", "parts": [{"text": "Hello from Gemini."}]}, "finishReason": "STOP"}],
        "usageMetadata": {"promptTokenCount": 7, "candidatesTokenCount": 4, "totalTokenCount": 11},
        "modelVersion": "gemini-2.5-pro",
    });
    let (at, seen) = mock("application/json", gemini.to_string()).await?;
    let gw = gateway(
        "gemini",
        vec![provider(
            "gemini",
            Kind::Gemini,
            format!("http://{at}"),
            "gemini-2.5-pro",
        )],
    )?;
    let (status, _, text) =
        claude_code(&gw, "/v1/messages", &message("gemini-2.5-pro", false)).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let answer: Value = serde_json::from_str(&text)?;
    assert_eq!(answer["content"][0]["text"], "Hello from Gemini.");
    assert_eq!(answer["stop_reason"], "end_turn");
    assert!(answer["id"].as_str().is_some_and(|id| !id.is_empty()));
    let (target, _, body) = first(&seen)?;
    assert_eq!(target, "/v1beta/models/gemini-2.5-pro:generateContent");
    assert!(body["contents"].is_array() && body["systemInstruction"].is_object());
    Ok(())
}

#[tokio::test]
async fn untranslatable_fields_wrong_routes_and_errors_are_named() -> TestResult {
    let (at, _) = mock("application/json", completion()).await?;
    let mut plain = provider("plain", Kind::OpenAi, format!("http://{at}"), "gpt-4o-mini");
    plain.accept_messages = false;
    let gw = gateway(
        "refused",
        vec![
            provider("openai", Kind::OpenAi, format!("http://{at}"), "gpt-4o"),
            plain,
        ],
    )?;
    let mut thinking = message("gpt-4o", false);
    thinking["thinking"] = json!({"type": "sometimes"});
    let (status, _, text) = claude_code(&gw, "/v1/messages", &thinking).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        text.contains("untranslatable") && text.contains("Thinking"),
        "{text}"
    );
    let (status, _, text) =
        claude_code(&gw, "/v1/messages", &message("gpt-4o-mini", false)).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        text.contains("wrong_route") && text.contains("accept_messages: true"),
        "{text}"
    );
    // A chat provider has no count API: Enterplace answers with its own estimate, marked as one.
    let (status, _, text) =
        claude_code(&gw, "/v1/messages/count_tokens", &message("gpt-4o", false)).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(
        serde_json::from_str::<Value>(&text)?["estimated"],
        true,
        "{text}"
    );
    let all: Vec<Value> = std::fs::read_to_string(&gw.log)?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(all[0]["code"], "untranslatable");
    assert_eq!(all[1]["code"], "wrong_route");
    Ok(())
}

#[tokio::test]
async fn claude_code_sees_models_of_providers_that_accept_messages() -> TestResult {
    let (at, _) = mock("application/json", completion()).await?;
    let mut plain = provider("plain", Kind::OpenAi, format!("http://{at}"), "gpt-4o-mini");
    plain.accept_messages = false;
    let gw = gateway(
        "models",
        vec![
            provider("openai", Kind::OpenAi, format!("http://{at}"), "gpt-4o"),
            plain,
        ],
    )?;
    let request = Request::get("/v1/models")
        .header("x-api-key", MAYA)
        .header("anthropic-version", "2023-06-01")
        .body(Body::empty())?;
    let response = gw.app.clone().oneshot(request).await?;
    let list: Value = serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    let ids: Vec<&str> = list["data"]
        .as_array()
        .ok_or("data")?
        .iter()
        .filter_map(|m| m["id"].as_str())
        .collect();
    assert_eq!(ids, ["gpt-4o"]);
    Ok(())
}

#[tokio::test]
async fn claude_on_vertex_gets_raw_predict_with_the_vertex_body() -> TestResult {
    let reply = json!({"id": "msg_v", "type": "message", "role": "assistant", "model": "claude-sonnet-4-6",
        "content": [{"type": "text", "text": "From Vertex."}], "stop_reason": "end_turn", "stop_sequence": null,
        "usage": {"input_tokens": 5, "output_tokens": 3}});
    let (at, seen) = mock("application/json", reply.to_string()).await?;
    let base = format!("http://{at}/v1/projects/acme/locations/us-east5/publishers/anthropic");
    let gw = gateway(
        "vertex",
        vec![provider(
            "claude-vertex",
            Kind::VertexAnthropic,
            base,
            "claude-sonnet-4-6",
        )],
    )?;
    let (status, _, text) =
        claude_code(&gw, "/v1/messages", &message("claude-sonnet-4-6", false)).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(
        serde_json::from_str::<Value>(&text)?["content"][0]["text"],
        "From Vertex."
    );
    let (target, headers, body) = first(&seen)?;
    assert_eq!(
        target,
        "/v1/projects/acme/locations/us-east5/publishers/anthropic/models/claude-sonnet-4-6:rawPredict"
    );
    assert_eq!(
        headers["authorization"],
        "Bearer claude-vertex-provider-key"
    );
    assert!(!headers.contains_key("x-api-key"));
    assert_eq!(body["anthropic_version"], "vertex-2023-10-16");
    assert!(body.get("model").is_none());
    assert_eq!(body["system"][0]["cache_control"]["type"], "ephemeral");
    let (_, _, _) = claude_code(&gw, "/v1/messages", &message("claude-sonnet-4-6", true)).await?;
    let streamed = seen
        .lock()
        .map_err(|_| "poisoned")?
        .get(1)
        .cloned()
        .ok_or("second")?;
    assert!(
        streamed.0.ends_with("claude-sonnet-4-6:streamRawPredict"),
        "{}",
        streamed.0
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&streamed.2)?["stream"],
        true
    );
    // Vertex AI counts Claude's tokens at its count-tokens endpoint, with the model in the body.
    let (status, _, text) = claude_code(
        &gw,
        "/v1/messages/count_tokens",
        &message("claude-sonnet-4-6", false),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let counted = seen
        .lock()
        .map_err(|_| "poisoned")?
        .get(2)
        .cloned()
        .ok_or("third")?;
    assert!(
        counted.0.ends_with("/models/count-tokens:rawPredict"),
        "{}",
        counted.0
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&counted.2)?["model"],
        "claude-sonnet-4-6"
    );
    Ok(())
}

/// UX13 q7: a chat provider's error reaches Claude Code in Anthropic's shape, naming the provider, with the decision
/// ID and whether to send it again; the provider's own Retry-After passes through.
#[tokio::test]
async fn a_chat_providers_error_reaches_claude_code_named_and_with_retry_headers() -> TestResult {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let at = listener.local_addr()?;
    let app = Router::new().fallback(move |request: Request<Body>| async move {
        let bytes = request
            .into_body()
            .collect()
            .await
            .map(|b| b.to_bytes())
            .unwrap_or_default();
        let busy = String::from_utf8_lossy(&bytes).contains("providerbusy");
        if busy {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, "7")],
                json!({"error": {"message": "Rate limit reached.", "type": "requests"}}).to_string(),
            )
                .into_response();
        }
        (
            StatusCode::BAD_REQUEST,
            json!({"error": {"message": "This model's maximum context length is 128000 tokens.", "type": "invalid_request_error", "code": "context_length_exceeded"}}).to_string(),
        )
            .into_response()
    });
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let gw = gateway(
        "provider-errors",
        vec![provider(
            "openai",
            Kind::OpenAi,
            format!("http://{at}"),
            "gpt-4o",
        )],
    )?;
    let (status, headers, text) =
        claude_code(&gw, "/v1/messages", &message("gpt-4o", false)).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    let body: Value = serde_json::from_str(&text)?;
    let decision = headers
        .get("x-enterplace-decision")
        .and_then(|v| v.to_str().ok())
        .ok_or("no decision header")?;
    assert_eq!(body["type"], "error");
    assert_eq!(body["error"]["type"], "invalid_request_error");
    assert_eq!(body["decision"], decision);
    let said = body["error"]["message"].as_str().unwrap_or_default();
    assert_eq!(
        said,
        format!(
            "Provider \"openai\" answered 400: This model's maximum context length is 128000 tokens. Decision {decision}."
        )
    );
    assert_eq!(
        headers.get("x-should-retry").and_then(|v| v.to_str().ok()),
        Some("false")
    );

    let mut busy = message("gpt-4o", false);
    busy["messages"][0]["content"] = json!("providerbusy");
    let (status, headers, text) = claude_code(&gw, "/v1/messages", &busy).await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{text}");
    assert_eq!(
        headers.get("x-should-retry").and_then(|v| v.to_str().ok()),
        Some("true")
    );
    assert_eq!(
        headers
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok()),
        Some("7")
    );
    assert!(text.contains("rate_limit_error"), "{text}");
    Ok(())
}
