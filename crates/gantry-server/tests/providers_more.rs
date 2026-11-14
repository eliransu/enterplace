//! More providers and routes: Gemini and Vertex AI behind the chat route, OpenAI-compatible servers on a path or on
//! loopback without a key, and the Responses and embeddings routes. Every provider is a mock on 127.0.0.1, on a port
//! the system picks.

use std::{
    collections::VecDeque,
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
    guard::{Action, Check, Guardrail},
    id::sha256_hex,
    policy::{Limits, Models, Policy, Who},
    usage::{Price, PriceOverrides},
};
use gantry_server::{Audit, Config, ProviderRoute, Secret, Timeouts};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const MAYA: &str = "gantry_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[derive(Clone)]
enum Reply {
    Status(u16),
    Body(&'static str, String),
}

#[derive(Default)]
struct Mock {
    /// The port of 127.0.0.1 it listens on, picked by the system.
    port: u16,
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

/// A mock provider on a port of 127.0.0.1 the system picks. The last reply repeats.
async fn mock(replies: Vec<Reply>) -> Result<Arc<Mock>, Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let state = Arc::new(Mock {
        port: listener.local_addr()?.port(),
        replies: Mutex::new(replies.into()),
        ..Mock::default()
    });
    let mock = state.clone();
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
            answer(reply.unwrap_or(Reply::Status(200)))
        }
    });
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(state)
}

fn answer(reply: Reply) -> Response {
    match reply {
        Reply::Status(code) => (
            StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            [(header::CONTENT_TYPE, "application/json")],
            format!(r#"{{"status":{code}}}"#),
        )
            .into_response(),
        Reply::Body(content_type, body) => {
            ([(header::CONTENT_TYPE, content_type)], body).into_response()
        }
    }
}

fn route(name: &str, kind: Kind, url: String, models: &[&str]) -> ProviderRoute {
    ProviderRoute {
        name: name.into(),
        kind,
        url,
        key: Some(Secret::new(format!("{name}-provider-key"))),
        models: models.iter().map(|m| m.to_string()).collect(),
        ..ProviderRoute::default()
    }
}

struct Gateway {
    app: Router,
    log: std::path::PathBuf,
}

fn everyone() -> Policy {
    Policy::new()
        .with_key(MAYA, "maya.cohen", "payments")
        .with_rule("everyone", Who::Any, Models::Any)
}

fn gateway(
    name: &str,
    providers: Vec<ProviderRoute>,
    policy: Policy,
) -> Result<Gateway, Box<dyn std::error::Error>> {
    let log = std::env::temp_dir().join(format!(
        "gantry-providers-more-{}-{name}.jsonl",
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
        timeouts: Timeouts::default(),
        ..Config::default()
    })?;
    Ok(Gateway { app, log })
}

async fn call(
    gw: &Gateway,
    request: axum::http::request::Builder,
    body: &str,
) -> Result<(StatusCode, HeaderMap, String), Box<dyn std::error::Error>> {
    let response = gw
        .app
        .clone()
        .oneshot(request.body(Body::from(body.to_string()))?)
        .await?;
    let (status, headers) = (response.status(), response.headers().clone());
    let text = String::from_utf8(response.into_body().collect().await?.to_bytes().to_vec())?;
    Ok((status, headers, text))
}

async fn post(
    gw: &Gateway,
    path: &str,
    body: &str,
) -> Result<(StatusCode, HeaderMap, String), Box<dyn std::error::Error>> {
    let request = Request::post(path)
        .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
        .header(header::CONTENT_TYPE, "application/json");
    call(gw, request, body).await
}

fn all_records(gw: &Gateway) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    Ok(std::fs::read_to_string(&gw.log)?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?)
}

/// The decision record and the usage record of a request, waiting for the usage record: it follows the answer.
async fn records_of(
    gw: &Gateway,
    headers: &HeaderMap,
) -> Result<(Value, Value), Box<dyn std::error::Error>> {
    let id = headers["x-gantry-decision"].to_str()?.to_string();
    for _ in 0..100 {
        let all = all_records(gw)?;
        let decision = all
            .iter()
            .find(|r| r["id"] == id.as_str() && r["event"].is_null());
        let usage = all
            .iter()
            .find(|r| r["id"] == id.as_str() && r["event"] == "usage");
        if let (Some(d), Some(u)) = (decision, usage) {
            return Ok((d.clone(), u.clone()));
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Err(format!("no decision and usage record for {id}").into())
}

fn tokens(usage: &Value) -> (Option<&str>, Option<u64>, Option<u64>) {
    (
        usage["usage"].as_str(),
        usage["input_tokens"].as_u64(),
        usage["output_tokens"].as_u64(),
    )
}

fn price(input: f64, output: f64) -> Price {
    Price {
        input,
        output,
        cache_read: None,
        cache_write: None,
        cache_write_1h: None,
        long_context: None,
        max_output: None,
        max_context: None,
        per_image: None,
        ..Price::default()
    }
}

// 1. Gemini and Vertex AI behind the chat route.

fn gemini_answer() -> String {
    json!({
        "responseId": "resp-g1",
        "modelVersion": "gemini-2.5-flash",
        "candidates": [{"index": 0, "finishReason": "STOP", "content": {"role": "model", "parts": [
            {"text": "Checking."},
            {"functionCall": {"name": "weather", "args": {"city": "Haifa"}}}
        ]}}],
        "usageMetadata": {"promptTokenCount": 1000, "candidatesTokenCount": 400, "thoughtsTokenCount": 100, "totalTokenCount": 1500}
    })
    .to_string()
}

const GEMINI_CHAT: &str = r#"{"model":"gemini-2.5-flash","messages":[{"role":"system","content":"Be brief."},{"role":"user","content":"Weather in Haifa?"}],"tools":[{"type":"function","function":{"name":"weather","parameters":{"type":"object","properties":{"city":{"type":"string"}}}}}],"max_tokens":200}"#;

#[tokio::test]
async fn a_gemini_answer_without_an_id_gets_one_from_the_decision() -> TestResult {
    // PM11 MIN-3: Gemini may send no responseId, and a strict chat client refuses "id": null.
    let answer = gemini_answer().replace(r#""responseId":"resp-g1","#, "");
    let gemini = mock(vec![Reply::Body("application/json", answer)]).await?;
    let gw = gateway(
        "gemini-noid",
        vec![route(
            "gemini",
            Kind::Gemini,
            format!("http://127.0.0.1:{}/v1beta", gemini.port),
            &["gemini-2.5-flash"],
        )],
        everyone(),
    )?;
    let (status, headers, text) = post(&gw, "/v1/chat/completions", GEMINI_CHAT).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let decision = headers
        .get("x-gantry-decision")
        .and_then(|v| v.to_str().ok())
        .ok_or("no decision header")?;
    let chat: Value = serde_json::from_str(&text)?;
    assert_eq!(chat["id"], format!("chatcmpl-{decision}"), "{text}");
    Ok(())
}

#[tokio::test]
async fn a_chat_request_reaches_gemini_translated_and_comes_back_as_chat() -> TestResult {
    let gemini = mock(vec![Reply::Body("application/json", gemini_answer())]).await?;
    let mut prices = PriceOverrides::new();
    prices.insert("gemini-2.5-flash".into(), price(1.0, 2.0));
    let gw = gateway(
        "gemini",
        vec![route(
            "gemini",
            Kind::Gemini,
            format!("http://127.0.0.1:{}/v1beta", gemini.port),
            &["gemini-2.5-flash"],
        )],
        everyone().with_prices(prices),
    )?;
    let (status, headers, text) = post(&gw, "/v1/chat/completions", GEMINI_CHAT).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, sent_headers, body) = gemini.first()?;
    assert_eq!(target, "/v1beta/models/gemini-2.5-flash:generateContent");
    assert_eq!(sent_headers["x-goog-api-key"], "gemini-provider-key");
    assert!(sent_headers.get(header::AUTHORIZATION).is_none());
    let sent: Value = serde_json::from_slice(&body)?;
    assert_eq!(sent["systemInstruction"]["parts"][0]["text"], "Be brief.");
    assert_eq!(sent["contents"][0]["parts"][0]["text"], "Weather in Haifa?");
    assert_eq!(sent["generationConfig"]["maxOutputTokens"], 200);
    assert_eq!(
        sent["tools"][0]["functionDeclarations"][0]["name"],
        "weather"
    );
    assert!(sent.get("model").is_none() && sent.get("messages").is_none());

    let chat: Value = serde_json::from_str(&text)?;
    assert_eq!(chat["object"], "chat.completion");
    let choice = &chat["choices"][0];
    assert_eq!(choice["finish_reason"], "tool_calls");
    assert_eq!(choice["message"]["content"], "Checking.");
    assert_eq!(
        choice["message"]["tool_calls"][0]["function"]["arguments"],
        r#"{"city":"Haifa"}"#
    );
    assert_eq!(chat["usage"]["prompt_tokens"], 1000);

    let (decision, usage) = records_of(&gw, &headers).await?;
    assert_eq!(decision["translated"], true);
    assert_eq!(decision["provider"], "gemini");
    assert_eq!(tokens(&usage), (Some("reported"), Some(1000), Some(500)));
    // 1000 tokens at $1 and 500 at $2 per million.
    assert!(
        usage["cost_usd"]
            .as_f64()
            .is_some_and(|c| (c - 0.002).abs() < 1e-9),
        "{usage}"
    );
    Ok(())
}

#[tokio::test]
async fn a_streamed_chat_request_to_gemini_streams_back_as_chat_chunks() -> TestResult {
    let sse = "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Hel\"}]},\"index\":0}],\"usageMetadata\":{\"promptTokenCount\":7,\"candidatesTokenCount\":1},\"modelVersion\":\"gemini-2.5-flash\",\"responseId\":\"r9\"}\r\n\r\n\
data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"lo\"}]},\"finishReason\":\"STOP\",\"index\":0}],\"usageMetadata\":{\"promptTokenCount\":7,\"candidatesTokenCount\":2},\"modelVersion\":\"gemini-2.5-flash\",\"responseId\":\"r9\"}\r\n\r\n";
    let gemini = mock(vec![Reply::Body("text/event-stream", sse.into())]).await?;
    let gw = gateway(
        "gemini-stream",
        vec![route(
            "gemini",
            Kind::Gemini,
            // No path: the v1beta of the Gemini API is added.
            format!("http://127.0.0.1:{}", gemini.port),
            &["gemini-2.5-flash"],
        )],
        everyone(),
    )?;
    let body = r#"{"model":"gemini-2.5-flash","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"Hi"}]}"#;
    let (status, headers, text) = post(&gw, "/v1/chat/completions", body).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert!(
        headers[header::CONTENT_TYPE]
            .to_str()?
            .starts_with("text/event-stream")
    );
    let (target, _, _) = gemini.first()?;
    assert_eq!(
        target,
        "/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse"
    );
    let contents: String = text
        .split("\n\n")
        .filter_map(|e| e.strip_prefix("data: "))
        .filter(|e| *e != "[DONE]")
        .filter_map(|e| serde_json::from_str::<Value>(e).ok())
        .filter_map(|e| {
            e["choices"][0]["delta"]["content"]
                .as_str()
                .map(String::from)
        })
        .collect();
    assert_eq!(contents, "Hello");
    assert!(text.contains("\"completion_tokens\":2"), "{text}");
    assert!(text.ends_with("data: [DONE]\n\n"), "{text}");
    let (_, usage) = records_of(&gw, &headers).await?;
    assert_eq!(tokens(&usage), (Some("reported"), Some(7), Some(2)));
    assert_eq!(usage["ended"], "complete");
    Ok(())
}

#[tokio::test]
async fn vertex_gets_its_path_and_a_bearer_token() -> TestResult {
    let vertex = mock(vec![Reply::Body("application/json", gemini_answer())]).await?;
    let base = format!(
        "http://127.0.0.1:{}/v1/projects/acme/locations/us-central1/publishers/google",
        vertex.port
    );
    let gw = gateway(
        "vertex",
        vec![route("vertex", Kind::Vertex, base, &["gemini-2.5-flash"])],
        everyone(),
    )?;
    let (status, _, text) = post(&gw, "/v1/chat/completions", GEMINI_CHAT).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, headers, _) = vertex.first()?;
    assert_eq!(
        target,
        "/v1/projects/acme/locations/us-central1/publishers/google/models/gemini-2.5-flash:generateContent"
    );
    assert_eq!(headers[header::AUTHORIZATION], "Bearer vertex-provider-key");
    assert!(headers.get("x-goog-api-key").is_none());
    Ok(())
}

#[tokio::test]
async fn gemini_refusals_are_recorded_and_never_sent() -> TestResult {
    let gemini = mock(vec![Reply::Status(200)]).await?;
    let policy = everyone().with_guardrails(&[Guardrail {
        name: "no-secrets".into(),
        action: Action::Block,
        check: Check::Secrets,
        on: gantry_core::guard::On::REQUEST,
        shadow_until: None,
    }]);
    let gw = gateway(
        "gemini-refusals",
        vec![route(
            "gemini",
            Kind::Gemini,
            format!("http://127.0.0.1:{}/v1beta", gemini.port),
            &["gemini-2.5-flash"],
        )],
        policy,
    )?;
    // A field Gemini has no equivalent for is refused by name, as for the messages translation.
    let odd = r#"{"model":"gemini-2.5-flash","logprobs":true,"messages":[{"role":"user","content":"Hi"}]}"#;
    let (status, _, text) = post(&gw, "/v1/chat/completions", odd).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    assert!(
        text.contains("untranslatable") && text.contains(r#"\"logprobs\" set to true"#),
        "{text}"
    );
    // Guardrails read the chat body before it is translated.
    let secret = r#"{"model":"gemini-2.5-flash","messages":[{"role":"user","content":"key AKIAIOSFODNN7EXAMPLE"}]}"#;
    let (status, _, text) = post(&gw, "/v1/chat/completions", secret).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
    assert!(text.contains("guardrail_blocked"), "{text}");
    // Gemini takes chat requests only: the Responses and embeddings routes are for openai providers.
    for path in ["/v1/responses", "/v1/embeddings"] {
        let body = r#"{"model":"gemini-2.5-flash","input":"Hi"}"#;
        let (status, _, text) = post(&gw, path, body).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
        assert!(
            text.contains("wrong_route") && text.contains("kind openai"),
            "{text}"
        );
    }
    assert_eq!(gemini.hits.load(Ordering::SeqCst), 0);
    let codes: Vec<Value> = all_records(&gw)?
        .into_iter()
        .map(|r| r["code"].clone())
        .collect();
    assert_eq!(
        codes,
        [
            "untranslatable",
            "guardrail_blocked",
            "wrong_route",
            "wrong_route"
        ]
    );
    Ok(())
}

// 2. OpenAI-compatible servers.

#[tokio::test]
async fn an_openai_compatible_server_on_a_path_prefix_gets_the_route_after_v1() -> TestResult {
    // OpenRouter's base URL is https://openrouter.ai/api/v1.
    let server = mock(vec![Reply::Status(200)]).await?;
    let gw = gateway(
        "openrouter",
        vec![route(
            "openrouter",
            Kind::OpenAi,
            format!("http://127.0.0.1:{}/api/v1", server.port),
            &["meta-llama/llama-4"],
        )],
        everyone(),
    )?;
    let body = r#"{"model":"meta-llama/llama-4","messages":[{"role":"user","content":"Hi"}]}"#;
    let (status, _, _) = post(&gw, "/v1/chat/completions", body).await?;
    assert_eq!(status, StatusCode::OK);
    let (target, headers, sent) = server.first()?;
    assert_eq!(target, "/api/v1/chat/completions");
    assert_eq!(
        headers[header::AUTHORIZATION],
        "Bearer openrouter-provider-key"
    );
    assert_eq!(sent, body.as_bytes());
    Ok(())
}

#[tokio::test]
async fn a_local_server_without_a_key_is_served_from_a_policy_file() -> TestResult {
    let ollama = mock(vec![Reply::Status(200)]).await?;
    let dir = std::env::temp_dir().join(format!(
        "gantry-providers-more-{}-ollama",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let policy = dir.join("gantry.policy.yaml");
    std::fs::write(
        &policy,
        format!(
            "version: 1\nproviders:\n  - name: ollama\n    kind: openai\n    url: http://127.0.0.1:{}/v1\n    allow_private: true\n    models: [llama3.2]\nrules:\n  - name: everyone\n    principals: {{ any: true }}\n    models: [\"*\"]\n",
            ollama.port
        ),
    )?;
    let keys = dir.join("gantry.keys.yaml");
    std::fs::write(
        &keys,
        format!(
            "keys:\n  - name: maya.cohen\n    team: payments\n    sha256: {}\n",
            sha256_hex(MAYA.as_bytes())
        ),
    )?;
    // No environment variable is asked for.
    let started = gantry_server::governed(&policy, Some(&keys), &|_| None)?;
    let gw = Gateway {
        app: started.router,
        log: started.loaded.audit_path.clone(),
    };
    let body = r#"{"model":"llama3.2","messages":[{"role":"user","content":"Hi"}]}"#;
    let (status, _, text) = post(&gw, "/v1/chat/completions", body).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, headers, _) = ollama.first()?;
    assert_eq!(target, "/v1/chat/completions");
    // Neither a provider key nor the caller's Gantry key reaches it.
    assert!(headers.get(header::AUTHORIZATION).is_none());
    assert!(!format!("{headers:?}").contains(MAYA));
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// 3. The Responses API and the model list.

fn responses_answer() -> String {
    json!({
        "id": "resp_1", "object": "response", "status": "completed", "model": "gpt-5",
        "output": [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Hi."}]}],
        "usage": {"input_tokens": 50, "input_tokens_details": {"cached_tokens": 20}, "output_tokens": 5, "total_tokens": 55}
    })
    .to_string()
}

#[tokio::test]
async fn responses_go_to_openai_as_sent_with_retries_and_usage() -> TestResult {
    let openai = mock(vec![
        Reply::Status(503),
        Reply::Body("application/json", responses_answer()),
    ])
    .await?;
    let gw = gateway(
        "responses",
        vec![ProviderRoute {
            retries: 1,
            ..route(
                "openai",
                Kind::OpenAi,
                format!("http://127.0.0.1:{}", openai.port),
                &["gpt-5"],
            )
        }],
        everyone(),
    )?;
    let body = r#"{"model":"gpt-5","instructions":"Be brief.","input":[{"role":"user","content":[{"type":"input_text","text":"Hi"}]}],"store":false,"reasoning":{"effort":"low"}}"#;
    let (status, headers, text) = post(&gw, "/v1/responses", body).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(text, responses_answer());
    assert_eq!(openai.hits.load(Ordering::SeqCst), 2);
    let (target, sent_headers, sent) = openai.first()?;
    assert_eq!(target, "/v1/responses");
    assert_eq!(sent, body.as_bytes(), "original bytes");
    assert_eq!(
        sent_headers[header::AUTHORIZATION],
        "Bearer openai-provider-key"
    );
    let (decision, usage) = records_of(&gw, &headers).await?;
    assert_eq!(decision["path"], "/v1/responses");
    assert_eq!(decision["model"], "gpt-5");
    assert!(decision["translated"].is_null());
    // input_tokens includes the cached ones; each is counted once.
    assert_eq!(tokens(&usage), (Some("reported"), Some(30), Some(5)));
    assert_eq!(usage["cache_read_tokens"], 20);
    assert!(
        all_records(&gw)?.iter().any(|r| r["event"] == "attempts"),
        "the retry is recorded"
    );
    Ok(())
}

#[tokio::test]
async fn a_streamed_response_is_metered_from_its_completed_event() -> TestResult {
    let completed = json!({"type": "response.completed", "sequence_number": 3, "response": {"id": "resp_2", "object": "response", "status": "completed", "usage": {"input_tokens": 12, "input_tokens_details": {"cached_tokens": 0}, "output_tokens": 3, "total_tokens": 15}}});
    let sse = format!(
        "event: response.created\ndata: {}\n\nevent: response.output_text.delta\ndata: {}\n\nevent: response.completed\ndata: {completed}\n\n",
        json!({"type": "response.created", "sequence_number": 1, "response": {"id": "resp_2", "usage": null}}),
        json!({"type": "response.output_text.delta", "sequence_number": 2, "delta": "Hi"}),
    );
    let _openai = mock(vec![Reply::Body("text/event-stream", sse.clone())]).await?;
    let gw = gateway(
        "responses-stream",
        vec![route(
            "openai",
            Kind::OpenAi,
            format!("http://127.0.0.1:{}/v1", _openai.port),
            &["gpt-5"],
        )],
        everyone(),
    )?;
    let (status, headers, text) = post(
        &gw,
        "/v1/responses",
        r#"{"model":"gpt-5","input":"Hi","stream":true}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(text, sse, "the stream passes as sent");
    let (_, usage) = records_of(&gw, &headers).await?;
    assert_eq!(tokens(&usage), (Some("reported"), Some(12), Some(3)));
    assert_eq!(usage["ended"], "complete");
    Ok(())
}

#[tokio::test]
async fn responses_and_embeddings_are_governed_like_chat() -> TestResult {
    let openai = mock(vec![Reply::Status(200)]).await?;
    let policy = Policy::new()
        .with_key(MAYA, "maya.cohen", "payments")
        .with_rule(
            "payments",
            Who::Team("payments".into()),
            Models::Only(vec!["gpt-5".into()]),
        )
        .with_guardrails(&[Guardrail {
            name: "no-secrets".into(),
            action: Action::Block,
            check: Check::Secrets,
            on: gantry_core::guard::On::REQUEST,
            shadow_until: None,
        }]);
    let gw = gateway(
        "responses-governed",
        vec![route(
            "openai",
            Kind::OpenAi,
            format!("http://127.0.0.1:{}", openai.port),
            &["gpt-5", "text-embedding-3-small"],
        )],
        policy,
    )?;
    let (status, _, text) = post(
        &gw,
        "/v1/responses",
        r#"{"model":"gpt-5","input":"deploy with AKIAIOSFODNN7EXAMPLE"}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
    assert!(text.contains("guardrail_blocked"), "{text}");
    let (status, _, text) = post(
        &gw,
        "/v1/embeddings",
        r#"{"model":"gpt-5","input":["fine","AKIAIOSFODNN7EXAMPLE"]}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
    let (status, _, text) = post(
        &gw,
        "/v1/embeddings",
        r#"{"model":"text-embedding-3-small","input":"hello"}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
    assert!(text.contains("model_not_allowed"), "{text}");
    let (status, _, text) = post(&gw, "/v1/responses", r#"{"input":"no model"}"#).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    assert_eq!(openai.hits.load(Ordering::SeqCst), 0);
    assert_eq!(all_records(&gw)?.len(), 4);
    Ok(())
}

#[tokio::test]
async fn the_model_list_for_an_openai_caller_shows_only_allowed_chat_models() -> TestResult {
    // The list is Gantry's own: no provider is contacted, so the URLs name a port nothing listens on.
    let gw = gateway(
        "models-openai",
        vec![
            route(
                "openai",
                Kind::OpenAi,
                "http://127.0.0.1:9".into(),
                &["gpt-5", "gpt-4o-mini"],
            ),
            route(
                "gemini",
                Kind::Gemini,
                "http://127.0.0.1:9/v1beta".into(),
                &["gemini-2.5-flash"],
            ),
            route(
                "anthropic",
                Kind::Anthropic,
                "http://127.0.0.1:9".into(),
                &["claude-sonnet-5-5"],
            ),
        ],
        Policy::new()
            .with_key(MAYA, "maya.cohen", "payments")
            .with_rule(
                "payments",
                Who::Team("payments".into()),
                Models::Only(vec![
                    "gpt-5".into(),
                    "gemini-2.5-flash".into(),
                    "claude-sonnet-5-5".into(),
                ]),
            ),
    )?;
    let request =
        Request::get("/v1/models").header(header::AUTHORIZATION, format!("Bearer {MAYA}"));
    let (status, _, text) = call(&gw, request, "").await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let list: Value = serde_json::from_str(&text)?;
    assert_eq!(list["object"], "list");
    let mut ids: Vec<&str> = list["data"]
        .as_array()
        .ok_or("no data")?
        .iter()
        .filter_map(|m| m["id"].as_str())
        .collect();
    ids.sort_unstable();
    // gpt-4o-mini is served and not allowed; claude is allowed and on the messages API.
    assert_eq!(ids, ["gemini-2.5-flash", "gpt-5"]);
    assert_eq!(list["data"][0]["object"], "model");
    // An Anthropic client, which sends anthropic-version, still gets Anthropic's list.
    let request = Request::get("/v1/models")
        .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
        .header("anthropic-version", "2023-06-01");
    let (_, _, text) = call(&gw, request, "").await?;
    let list: Value = serde_json::from_str(&text)?;
    assert_eq!(list["data"][0]["id"], "claude-sonnet-5-5");
    assert_eq!(list["data"][0]["type"], "model");
    Ok(())
}

// 4. Embeddings.

#[tokio::test]
async fn embeddings_go_to_openai_as_sent_with_usage_and_the_cache() -> TestResult {
    let answer = r#"{"object":"list","data":[{"object":"embedding","embedding":[0.1,0.2],"index":0}],"model":"text-embedding-3-small","usage":{"prompt_tokens":8,"total_tokens":8}}"#;
    let openai = mock(vec![Reply::Body("application/json", answer.into())]).await?;
    let mut prices = PriceOverrides::new();
    prices.insert("text-embedding-3-small".into(), price(0.02, 0.0));
    let policy = everyone()
        .with_limits(Limits {
            cache_ttl_seconds: Some(60),
            ..Limits::default()
        })
        .with_prices(prices);
    let gw = gateway(
        "embeddings",
        vec![route(
            "openai",
            Kind::OpenAi,
            format!("http://127.0.0.1:{}", openai.port),
            &["text-embedding-3-small"],
        )],
        policy,
    )?;
    let body = r#"{"model":"text-embedding-3-small","input":"The food was delicious.","encoding_format":"float"}"#;
    let (status, headers, text) = post(&gw, "/v1/embeddings", body).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(text, answer);
    let (target, _, sent) = openai.first()?;
    assert_eq!(target, "/v1/embeddings");
    assert_eq!(sent, body.as_bytes());
    let (decision, usage) = records_of(&gw, &headers).await?;
    assert_eq!(decision["cache"], "miss");
    assert_eq!(tokens(&usage), (Some("reported"), Some(8), Some(0)));
    assert!(
        usage["cost_usd"].as_f64().is_some_and(|c| c > 0.0),
        "{usage}"
    );
    let (status, headers, again) = post(&gw, "/v1/embeddings", body).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["x-gantry-cache"], "hit");
    assert_eq!(again, answer);
    assert_eq!(openai.hits.load(Ordering::SeqCst), 1);
    assert!(gantry_core::audit::verify(&gw.log).is_ok());
    Ok(())
}
