//! Cloud providers and translation: Bedrock Converse for every model family, Bedrock embeddings and token counts,
//! Azure OpenAI with Entra ID, Responses and embeddings, Vertex AI embeddings, Model Garden, rerank and token counts,
//! Cohere and watsonx.ai, the Responses API served by providers that do not speak it, chat served by models that
//! speak only Responses, reasoning mapped across, and signed passthrough to Bedrock and Vertex AI. Every request goes
//! through the governed path: decided, guarded, budgeted, recorded. Every provider is a mock on 127.0.0.1.

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
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    response::{IntoResponse, Response},
};
use gantry_core::{
    audit::AuditLog,
    config::Kind,
    eventstream,
    guard::{Action, Check, Guardrail},
    id::sha256_hex,
    policy::{Models, Policy, Who},
    sigv4,
};
use gantry_server::{Audit, Config, ProviderRoute, Secret, Timeouts, cloud};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const MAYA: &str = "gantry_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[derive(Clone)]
enum Reply {
    Json(Value),
    Bytes(&'static str, Vec<u8>),
    Headed(Value, &'static str, &'static str),
    Status(u16),
}

#[derive(Default)]
struct Mock {
    port: u16,
    hits: AtomicUsize,
    seen: Mutex<Vec<(String, HeaderMap, Bytes)>>,
    replies: Mutex<VecDeque<Reply>>,
}

impl Mock {
    fn first(&self) -> Result<(String, HeaderMap, Bytes), &'static str> {
        self.nth(0)
    }

    fn nth(&self, n: usize) -> Result<(String, HeaderMap, Bytes), &'static str> {
        self.seen
            .lock()
            .map_err(|_| "poisoned")?
            .get(n)
            .cloned()
            .ok_or("the provider was sent nothing")
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }
}

/// A mock provider on a port the system picks. The last reply repeats.
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
            answer(reply.unwrap_or(Reply::Json(json!({}))))
        }
    });
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(state)
}

fn answer(reply: Reply) -> Response {
    match reply {
        Reply::Json(body) => (
            [(header::CONTENT_TYPE, "application/json")],
            body.to_string(),
        )
            .into_response(),
        Reply::Status(status) => StatusCode::from_u16(status)
            .unwrap_or(StatusCode::NOT_FOUND)
            .into_response(),
        Reply::Bytes(content_type, body) => {
            ([(header::CONTENT_TYPE, content_type)], body).into_response()
        }
        Reply::Headed(body, name, value) => (
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::HeaderName::from_static(name), value),
            ],
            body.to_string(),
        )
            .into_response(),
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

fn aws() -> sigv4::Credentials {
    sigv4::Credentials {
        access_key_id: "AKIDEXAMPLE".into(),
        secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
        session_token: None,
    }
}

fn converse(url: String, models: &[(&str, &str)]) -> ProviderRoute {
    ProviderRoute {
        key: None,
        region: Some("us-east-1".into()),
        aws: Some(aws().into()),
        upstream_models: models
            .iter()
            .map(|(m, id)| (m.to_string(), id.to_string()))
            .collect(),
        ..route(
            "bedrock",
            Kind::BedrockConverse,
            url,
            &models.iter().map(|(m, _)| *m).collect::<Vec<_>>(),
        )
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
        "gantry-providers-cloud-{}-{name}.jsonl",
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

async fn send(
    gw: &Gateway,
    request: Request<Body>,
) -> Result<(StatusCode, HeaderMap, String), Box<dyn std::error::Error>> {
    let response = gw.app.clone().oneshot(request).await?;
    let (status, headers) = (response.status(), response.headers().clone());
    let text =
        String::from_utf8_lossy(&response.into_body().collect().await?.to_bytes()).into_owned();
    Ok((status, headers, text))
}

async fn post(
    gw: &Gateway,
    path: &str,
    body: &Value,
) -> Result<(StatusCode, HeaderMap, String), Box<dyn std::error::Error>> {
    let request = Request::post(path)
        .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))?;
    send(gw, request).await
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

fn decision_of(gw: &Gateway, headers: &HeaderMap) -> Result<Value, Box<dyn std::error::Error>> {
    let id = headers["x-gantry-decision"].to_str()?.to_string();
    all_records(gw)?
        .into_iter()
        .find(|r| r["id"] == id.as_str() && r["event"].is_null())
        .ok_or_else(|| format!("no decision record for {id}").into())
}

fn tokens(usage: &Value) -> (Option<&str>, Option<u64>, Option<u64>) {
    (
        usage["usage"].as_str(),
        usage["input_tokens"].as_u64(),
        usage["output_tokens"].as_u64(),
    )
}

fn cost(usage: &Value) -> f64 {
    usage["cost_usd"].as_f64().unwrap_or(-1.0)
}

fn close(a: f64, b: f64) -> bool {
    (a - b).abs() < 1e-9
}

// 1. Bedrock Converse.

fn converse_answer() -> Value {
    json!({
        "output": {"message": {"role": "assistant", "content": [
            {"text": "Checking."},
            {"toolUse": {"toolUseId": "tu1", "name": "weather", "input": {"city": "Haifa"}}}
        ]}},
        "stopReason": "tool_use",
        "usage": {"inputTokens": 1000, "outputTokens": 500, "totalTokens": 1500},
        "metrics": {"latencyMs": 10}
    })
}

#[tokio::test]
async fn a_chat_request_reaches_bedrock_converse_signed_and_comes_back_as_chat_priced() -> TestResult
{
    let bedrock = mock(vec![Reply::Json(converse_answer())]).await?;
    let gw = gateway(
        "converse",
        vec![converse(
            bedrock.url(""),
            &[("nova-pro", "amazon.nova-pro-v1:0")],
        )],
        everyone(),
    )?;
    let chat = json!({"model": "nova-pro", "max_tokens": 300,
        "messages": [{"role": "system", "content": "Be brief."},
            {"role": "user", "content": [{"type": "text", "text": "Weather here?"}, {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0"}}]}],
        "tools": [{"type": "function", "function": {"name": "weather", "parameters": {"type": "object"}}}]});
    let (status, headers, text) = post(&gw, "/v1/chat/completions", &chat).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, sent, body) = bedrock.first()?;
    assert_eq!(target, "/model/amazon.nova-pro-v1%3A0/converse");
    assert!(
        sent[header::AUTHORIZATION]
            .to_str()?
            .starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/")
    );
    assert!(
        sent[header::AUTHORIZATION]
            .to_str()?
            .contains("/us-east-1/bedrock/aws4_request")
    );
    let body: Value = serde_json::from_slice(&body)?;
    assert_eq!(body["system"], json!([{"text": "Be brief."}]));
    assert_eq!(
        body["messages"][0]["content"][1]["image"]["source"]["bytes"],
        "iVBORw0"
    );
    assert_eq!(body["inferenceConfig"]["maxTokens"], 300);
    assert_eq!(
        body["toolConfig"]["tools"][0]["toolSpec"]["name"],
        "weather"
    );
    assert!(body.get("model").is_none());
    let chat: Value = serde_json::from_str(&text)?;
    assert_eq!(chat["choices"][0]["finish_reason"], "tool_calls");
    assert_eq!(
        chat["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"],
        r#"{"city":"Haifa"}"#
    );
    let (decision, usage) = records_of(&gw, &headers).await?;
    assert_eq!(decision["translated"], true);
    assert_eq!(tokens(&usage), (Some("reported"), Some(1000), Some(500)));
    // Priced as the Bedrock model ID it is called by (LiteLLM's table: $0.80 in, $3.20 out per million).
    assert!(close(cost(&usage), 0.0008 + 0.0016), "{usage}");
    Ok(())
}

#[tokio::test]
async fn every_converse_model_family_is_reached_on_its_model_id() -> TestResult {
    let families = [
        ("claude", "us.anthropic.claude-sonnet-5-5-v1:0"),
        ("llama", "meta.llama3-1-70b-instruct-v1:0"),
        ("mistral", "mistral.mistral-large-2407-v1:0"),
        ("command", "cohere.command-r-plus-v1:0"),
        ("nova", "amazon.nova-pro-v1:0"),
        ("jamba", "ai21.jamba-1-5-large-v1:0"),
        ("r1", "us.deepseek.r1-v1:0"),
        ("qwen", "qwen.qwen3-32b-v1:0"),
        ("oss", "openai.gpt-oss-120b-1:0"),
    ];
    let bedrock = mock(vec![Reply::Json(converse_answer())]).await?;
    let gw = gateway(
        "families",
        vec![converse(bedrock.url(""), &families)],
        everyone(),
    )?;
    for (n, (model, id)) in families.iter().enumerate() {
        let chat = json!({"model": model, "messages": [{"role": "user", "content": "hi"}]});
        let (status, _, text) = post(&gw, "/v1/chat/completions", &chat).await?;
        assert_eq!(status, StatusCode::OK, "{model}: {text}");
        let (target, _, _) = bedrock.nth(n)?;
        assert_eq!(
            target,
            format!("/model/{}/converse", sigv4::uri_encode(id, false))
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_converse_stream_comes_back_as_chat_chunks_with_usage_recorded() -> TestResult {
    let events = [
        ("messageStart", json!({"role": "assistant"})),
        (
            "contentBlockDelta",
            json!({"contentBlockIndex": 0, "delta": {"text": "Hel"}}),
        ),
        (
            "contentBlockDelta",
            json!({"contentBlockIndex": 0, "delta": {"text": "lo"}}),
        ),
        ("contentBlockStop", json!({"contentBlockIndex": 0})),
        ("messageStop", json!({"stopReason": "end_turn"})),
        (
            "metadata",
            json!({"usage": {"inputTokens": 7, "outputTokens": 2, "totalTokens": 9}, "metrics": {"latencyMs": 1}}),
        ),
    ];
    let stream: Vec<u8> = events
        .iter()
        .flat_map(|(name, payload)| eventstream::converse_event(name, payload))
        .collect();
    let bedrock = mock(vec![Reply::Bytes(
        "application/vnd.amazon.eventstream",
        stream,
    )])
    .await?;
    let gw = gateway(
        "converse-stream",
        vec![converse(
            bedrock.url(""),
            &[("llama", "meta.llama3-1-70b-instruct-v1:0")],
        )],
        everyone(),
    )?;
    let chat = json!({"model": "llama", "stream": true, "stream_options": {"include_usage": true}, "messages": [{"role": "user", "content": "hi"}]});
    let (status, headers, text) = post(&gw, "/v1/chat/completions", &chat).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(
        bedrock.first()?.0,
        "/model/meta.llama3-1-70b-instruct-v1%3A0/converse-stream"
    );
    let contents: String = text
        .split("\n\n")
        .filter_map(|e| e.strip_prefix("data: "))
        .filter_map(|e| serde_json::from_str::<Value>(e).ok())
        .filter_map(|e| {
            e["choices"][0]["delta"]["content"]
                .as_str()
                .map(String::from)
        })
        .collect();
    assert_eq!(contents, "Hello");
    assert!(
        text.contains("\"prompt_tokens\":7") && text.ends_with("data: [DONE]\n\n"),
        "{text}"
    );
    let (_, usage) = records_of(&gw, &headers).await?;
    assert_eq!(tokens(&usage), (Some("reported"), Some(7), Some(2)));
    assert_eq!(usage["ended"], "complete");
    Ok(())
}

#[tokio::test]
async fn claude_code_reaches_a_converse_model_and_gets_messages_back() -> TestResult {
    let bedrock = mock(vec![Reply::Json(converse_answer())]).await?;
    let mut provider = converse(
        bedrock.url(""),
        &[("mistral-large", "mistral.mistral-large-2407-v1:0")],
    );
    provider.accept_messages = true;
    let gw = gateway("converse-messages", vec![provider], everyone())?;
    let message = json!({"model": "mistral-large", "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}]});
    let request = Request::post("/v1/messages")
        .header("x-api-key", MAYA)
        .header("anthropic-version", "2023-06-01")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(message.to_string()))?;
    let (status, _, text) = send(&gw, request).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let answer: Value = serde_json::from_str(&text)?;
    assert_eq!(answer["type"], "message");
    assert_eq!(answer["stop_reason"], "tool_use");
    assert_eq!(answer["content"][1]["input"], json!({"city": "Haifa"}));
    let (_, sent, _) = bedrock.first()?;
    assert!(sent.get("anthropic-version").is_none());
    Ok(())
}

#[tokio::test]
async fn reasoning_effort_becomes_claudes_thinking_budget_on_converse() -> TestResult {
    let bedrock = mock(vec![Reply::Json(converse_answer())]).await?;
    let gw = gateway(
        "converse-reasoning",
        vec![converse(
            bedrock.url(""),
            &[
                ("claude", "us.anthropic.claude-sonnet-5-5-v1:0"),
                ("llama", "meta.llama3-1-70b-instruct-v1:0"),
            ],
        )],
        everyone(),
    )?;
    let chat = json!({"model": "claude", "reasoning_effort": "high", "max_tokens": 20000, "messages": [{"role": "user", "content": "hi"}]});
    let (status, _, text) = post(&gw, "/v1/chat/completions", &chat).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let body: Value = serde_json::from_slice(&bedrock.first()?.2)?;
    assert_eq!(
        body["additionalModelRequestFields"]["thinking"],
        json!({"type": "enabled", "budget_tokens": 16384})
    );
    // A family that takes no reasoning setting is refused by name and never sent.
    let chat = json!({"model": "llama", "reasoning_effort": "high", "messages": [{"role": "user", "content": "hi"}]});
    let (status, _, text) = post(&gw, "/v1/chat/completions", &chat).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    assert!(
        text.contains("untranslatable") && text.contains("reasoning_effort"),
        "{text}"
    );
    assert_eq!(bedrock.hits.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn bedrock_embeddings_reach_titan_and_cohere_and_come_back_priced() -> TestResult {
    let bedrock = mock(vec![
        Reply::Json(json!({"embedding": [0.1, 0.2, 0.3], "inputTextTokenCount": 4000})),
        Reply::Headed(
            json!({"id": "e1", "embeddings": [[0.5], [0.6]], "response_type": "embeddings_floats"}),
            "x-amzn-bedrock-input-token-count",
            "12",
        ),
    ])
    .await?;
    let gw = gateway(
        "bedrock-embed",
        vec![converse(
            bedrock.url(""),
            &[
                ("titan", "amazon.titan-embed-text-v2:0"),
                ("cohere-embed", "cohere.embed-english-v3"),
            ],
        )],
        everyone(),
    )?;
    let (status, headers, text) = post(
        &gw,
        "/v1/embeddings",
        &json!({"model": "titan", "input": "hello", "dimensions": 256}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, sent, body) = bedrock.first()?;
    assert_eq!(target, "/model/amazon.titan-embed-text-v2%3A0/invoke");
    assert!(
        sent[header::AUTHORIZATION]
            .to_str()?
            .starts_with("AWS4-HMAC-SHA256")
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&body)?,
        json!({"inputText": "hello", "dimensions": 256})
    );
    let answer: Value = serde_json::from_str(&text)?;
    assert_eq!(answer["data"][0]["embedding"], json!([0.1, 0.2, 0.3]));
    assert_eq!(answer["usage"]["prompt_tokens"], 4000);
    let (_, usage) = records_of(&gw, &headers).await?;
    assert_eq!(usage["input_tokens"], 4000);
    // $0.02 per million input tokens.
    assert!(close(cost(&usage), 0.00008), "{usage}");

    let (status, headers, text) = post(
        &gw,
        "/v1/embeddings",
        &json!({"model": "cohere-embed", "input": ["a", "b"], "input_type": "search_query"}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let body: Value = serde_json::from_slice(&bedrock.nth(1)?.2)?;
    assert_eq!(
        body,
        json!({"texts": ["a", "b"], "input_type": "search_query", "embedding_types": ["float"]})
    );
    let answer: Value = serde_json::from_str(&text)?;
    assert_eq!(answer["data"][1]["embedding"], json!([0.6]));
    let (_, usage) = records_of(&gw, &headers).await?;
    assert_eq!(usage["input_tokens"], 12);
    // A chat model is not an embeddings model: refused before anything is sent.
    let (status, _, text) = post(
        &gw,
        "/v1/embeddings",
        &json!({"model": "titan", "input": ["a", "b"]}),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    assert!(text.contains("one text per request"), "{text}");
    Ok(())
}

#[tokio::test]
async fn bedrock_counts_claudes_tokens() -> TestResult {
    let bedrock = mock(vec![Reply::Json(json!({"inputTokens": 42}))]).await?;
    let mut provider = route(
        "bedrock",
        Kind::Bedrock,
        bedrock.url(""),
        &["claude-sonnet-5-5"],
    );
    provider.key = None;
    provider.region = Some("us-east-1".into());
    provider.aws = Some(aws().into());
    provider.upstream_models = [(
        "claude-sonnet-5-5".to_string(),
        "us.anthropic.claude-sonnet-5-5-v1:0".to_string(),
    )]
    .into();
    let gw = gateway("bedrock-count", vec![provider], everyone())?;
    let message =
        json!({"model": "claude-sonnet-5-5", "messages": [{"role": "user", "content": "hi"}]});
    let request = Request::post("/v1/messages/count_tokens")
        .header("x-api-key", MAYA)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(message.to_string()))?;
    let (status, _, text) = send(&gw, request).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(
        serde_json::from_str::<Value>(&text)?,
        json!({"input_tokens": 42})
    );
    let (target, _, body) = bedrock.first()?;
    assert_eq!(
        target,
        "/model/us.anthropic.claude-sonnet-5-5-v1%3A0/count-tokens"
    );
    let body: Value = serde_json::from_slice(&body)?;
    let blob = body["input"]["invokeModel"]["body"]
        .as_str()
        .ok_or("no body blob")?;
    let decoded = eventstream::base64_decode(blob).ok_or("not base64")?;
    let inner: Value = serde_json::from_slice(&decoded)?;
    assert_eq!(inner["anthropic_version"], "bedrock-2023-05-31");
    Ok(())
}

// 2. Azure OpenAI.

fn azure(url: String) -> ProviderRoute {
    ProviderRoute {
        key: None,
        // An Entra ID token, as `cloud::entra` keeps it current.
        google: Some(cloud::Live::fixed(
            HeaderValue::from_static("Bearer entra-token"),
            "a test",
        )),
        api_version: Some("2025-04-01-preview".into()),
        upstream_models: [
            ("gpt-4o".to_string(), "prod-4o".to_string()),
            ("embed".to_string(), "prod-embed".to_string()),
        ]
        .into(),
        ..route("azure", Kind::Azure, url, &["gpt-4o", "embed"])
    }
}

const BOUNDARY: &str = "gantryboundary";

fn audio_form(model: &str) -> Vec<u8> {
    format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n{model}\r\n--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.wav\"\r\nContent-Type: audio/wav\r\n\r\nRIFF\r\n--{BOUNDARY}--\r\n"
    )
    .into_bytes()
}

async fn post_form(
    gw: &Gateway,
    path: &str,
    body: Vec<u8>,
) -> Result<(StatusCode, HeaderMap, String), Box<dyn std::error::Error>> {
    let request = Request::post(path)
        .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .body(Body::from(body))?;
    send(gw, request).await
}

fn azure_media(url: String) -> ProviderRoute {
    let mut azure = azure(url);
    for (model, deployment) in [
        ("gpt-image-1", "prod-image"),
        ("whisper-1", "prod-whisper"),
        ("tts-1", "prod-tts"),
    ] {
        azure.models.push(model.into());
        azure
            .upstream_models
            .insert(model.into(), deployment.into());
    }
    azure
}

#[tokio::test]
async fn azure_serves_images_transcription_and_speech_on_deployment_paths() -> TestResult {
    let mock_azure = mock(vec![
        Reply::Json(json!({"created": 1, "data": [{"b64_json": "AA=="}], "usage": {"input_tokens": 10, "output_tokens": 100}})),
        Reply::Json(json!({"text": "hello"})),
        Reply::Bytes("audio/mpeg", vec![1, 2, 3]),
    ])
    .await?;
    let gw = gateway(
        "azure-media",
        vec![azure_media(mock_azure.url(""))],
        everyone(),
    )?;
    let (status, _, text) = post(
        &gw,
        "/v1/images/generations",
        &json!({"model": "gpt-image-1", "prompt": "a lighthouse"}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(
        mock_azure.nth(0)?.0,
        "/openai/deployments/prod-image/images/generations?api-version=2025-04-01-preview"
    );
    let (status, headers, text) =
        post_form(&gw, "/v1/audio/transcriptions", audio_form("whisper-1")).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, sent, _) = mock_azure.nth(1)?;
    assert_eq!(
        target,
        "/openai/deployments/prod-whisper/audio/transcriptions?api-version=2025-04-01-preview"
    );
    assert_eq!(sent[header::AUTHORIZATION], "Bearer entra-token");
    assert_eq!(decision_of(&gw, &headers)?["model"], "whisper-1");
    let (status, _, _) = post(
        &gw,
        "/v1/audio/speech",
        &json!({"model": "tts-1", "input": "hi", "voice": "alloy"}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        mock_azure.nth(2)?.0,
        "/openai/deployments/prod-tts/audio/speech?api-version=2025-04-01-preview"
    );
    Ok(())
}

#[tokio::test]
async fn azure_v1_api_takes_openai_paths_with_the_deployment_as_model() -> TestResult {
    let mock_azure = mock(vec![
        Reply::Json(json!({"id": "c1", "object": "chat.completion", "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hi"}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 4, "completion_tokens": 1}})),
        Reply::Json(json!({"created": 1, "data": [{"b64_json": "AA=="}]})),
        Reply::Json(json!({"text": "hello"})),
    ])
    .await?;
    let mut v1 = azure_media(mock_azure.url("/openai/v1"));
    v1.api_version = None;
    let gw = gateway("azure-v1", vec![v1], everyone())?;
    let (status, headers, text) = post(
        &gw,
        "/v1/chat/completions",
        &json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, _, body) = mock_azure.nth(0)?;
    assert_eq!(target, "/openai/v1/chat/completions");
    assert_eq!(serde_json::from_slice::<Value>(&body)?["model"], "prod-4o");
    let (_, usage) = records_of(&gw, &headers).await?;
    assert_eq!(tokens(&usage), (Some("reported"), Some(4), Some(1)));
    let (status, _, text) = post(
        &gw,
        "/v1/images/generations",
        &json!({"model": "gpt-image-1", "prompt": "a lighthouse"}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, _, body) = mock_azure.nth(1)?;
    // Images and audio are in the v1 preview only.
    assert_eq!(target, "/openai/v1/images/generations?api-version=preview");
    assert_eq!(
        serde_json::from_slice::<Value>(&body)?["model"],
        "prod-image"
    );
    let (status, _, text) =
        post_form(&gw, "/v1/audio/transcriptions", audio_form("whisper-1")).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, _, body) = mock_azure.nth(2)?;
    assert_eq!(
        target,
        "/openai/v1/audio/transcriptions?api-version=preview"
    );
    assert!(String::from_utf8_lossy(&body).contains("\r\n\r\nprod-whisper\r\n"));
    Ok(())
}

#[tokio::test]
async fn azure_takes_entra_tokens_responses_and_embeddings_on_its_paths() -> TestResult {
    let openai_azure = mock(vec![
        Reply::Json(json!({"id": "resp_1", "object": "response", "status": "completed", "model": "prod-4o", "output": [], "usage": {"input_tokens": 5, "output_tokens": 1}})),
        Reply::Json(json!({"object": "list", "data": [{"object": "embedding", "index": 0, "embedding": [0.1]}], "usage": {"prompt_tokens": 3, "total_tokens": 3}})),
    ])
    .await?;
    let gw = gateway("azure", vec![azure(openai_azure.url(""))], everyone())?;
    let (status, headers, text) = post(
        &gw,
        "/v1/responses",
        &json!({"model": "gpt-4o", "input": "hi"}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, sent, body) = openai_azure.first()?;
    assert_eq!(target, "/openai/responses?api-version=2025-04-01-preview");
    assert_eq!(sent[header::AUTHORIZATION], "Bearer entra-token");
    assert!(sent.get("api-key").is_none());
    assert_eq!(serde_json::from_slice::<Value>(&body)?["model"], "prod-4o");
    let (_, usage) = records_of(&gw, &headers).await?;
    assert_eq!(tokens(&usage), (Some("reported"), Some(5), Some(1)));
    // The stored response is read back at Azure's own path, by its creator.
    let (status, _, text) = eventually(&gw, "/v1/responses/resp_1").await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(
        openai_azure.nth(1)?.0,
        "/openai/responses/resp_1?api-version=2025-04-01-preview"
    );
    let (status, _, text) = post(
        &gw,
        "/v1/embeddings",
        &json!({"model": "embed", "input": "hi"}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(
        openai_azure.nth(2)?.0,
        "/openai/deployments/prod-embed/embeddings?api-version=2025-04-01-preview"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn entra_id_tokens_come_from_client_credentials_workload_identity_and_managed_identity()
-> TestResult {
    let token = json!({"access_token": "entra-abc", "expires_in": 3600, "token_type": "Bearer"});
    let entra = mock(vec![Reply::Json(token)]).await?;
    let authority = entra.url("");
    let secret = cloud::entra("azure", &|name: &str| match name {
        "AZURE_TENANT_ID" => Some("tenant-1".into()),
        "AZURE_CLIENT_ID" => Some("app-1".into()),
        "AZURE_CLIENT_SECRET" => Some("s3cret".into()),
        "AZURE_AUTHORITY_HOST" => Some(authority.clone()),
        _ => None,
    })?;
    assert_eq!(secret.get(), "Bearer entra-abc");
    let (target, _, body) = entra.first()?;
    assert_eq!(target, "/tenant-1/oauth2/v2.0/token");
    let form = String::from_utf8(body.to_vec())?;
    assert!(
        form.contains("grant_type=client_credentials") && form.contains("client_secret=s3cret"),
        "{form}"
    );
    assert!(
        form.contains("scope=https%3A%2F%2Fcognitiveservices.azure.com%2F.default"),
        "{form}"
    );

    let file = std::env::temp_dir().join(format!("gantry-federated-{}", std::process::id()));
    std::fs::write(&file, "federated.jwt")?;
    let path = file.display().to_string();
    let workload = cloud::entra("azure", &|name: &str| match name {
        "AZURE_TENANT_ID" => Some("tenant-1".into()),
        "AZURE_CLIENT_ID" => Some("app-1".into()),
        "AZURE_FEDERATED_TOKEN_FILE" => Some(path.clone()),
        "AZURE_AUTHORITY_HOST" => Some(authority.clone()),
        _ => None,
    })?;
    assert_eq!(workload.get(), "Bearer entra-abc");
    let form = String::from_utf8(entra.nth(1)?.2.to_vec())?;
    assert!(form.contains("client_assertion=federated.jwt"), "{form}");

    let managed = cloud::entra("azure", &|name: &str| match name {
        "AZURE_POD_IDENTITY_AUTHORITY_HOST" => Some(authority.clone()),
        _ => None,
    })?;
    assert_eq!(managed.get(), "Bearer entra-abc");
    let (target, headers, _) = entra.nth(2)?;
    assert!(
        target.starts_with("/metadata/identity/oauth2/token?api-version=2018-02-01&resource="),
        "{target}"
    );
    assert_eq!(headers["metadata"], "true");
    let _ = std::fs::remove_file(&file);
    Ok(())
}

// 3. Vertex AI and the Gemini API.

fn vertex_base(mock: &Mock) -> String {
    mock.url("/v1/projects/acme/locations/us-central1/publishers/google")
}

#[tokio::test]
async fn vertex_counts_a_gemini_models_tokens_for_a_messages_request() -> TestResult {
    let vertex = mock(vec![Reply::Json(
        json!({"totalTokens": 31, "totalBillableCharacters": 96}),
    )])
    .await?;
    let gw = gateway(
        "vertex-count",
        vec![route(
            "vertex",
            Kind::Vertex,
            vertex_base(&vertex),
            &["gemini-2.5-flash"],
        )],
        everyone(),
    )?;
    let (status, headers, text) = post(
        &gw,
        "/v1/messages/count_tokens",
        &json!({"model": "gemini-2.5-flash", "system": "Be brief.",
            "messages": [{"role": "user", "content": "How many tokens is this?"}]}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(
        serde_json::from_str::<Value>(&text)?,
        json!({"input_tokens": 31})
    );
    let (target, sent, body) = vertex.first()?;
    assert!(
        target.ends_with("/models/gemini-2.5-flash:countTokens"),
        "{target}"
    );
    assert_eq!(sent[header::AUTHORIZATION], "Bearer vertex-provider-key");
    let body: Value = serde_json::from_slice(&body)?;
    assert_eq!(
        body["contents"][0]["parts"][0]["text"],
        "How many tokens is this?"
    );
    assert_eq!(body["systemInstruction"]["parts"][0]["text"], "Be brief.");
    assert!(body.get("generationConfig").is_none(), "{body}");
    assert_eq!(decision_of(&gw, &headers)?["model"], "gemini-2.5-flash");
    // Tools would be counted short, so they are refused by name.
    let (status, _, text) = post(
        &gw,
        "/v1/messages/count_tokens",
        &json!({"model": "gemini-2.5-flash", "messages": [{"role": "user", "content": "hi"}],
            "tools": [{"name": "t", "input_schema": {"type": "object"}}]}),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    assert!(text.contains("tools"), "{text}");
    Ok(())
}

#[tokio::test]
async fn vertex_embeds_ranks_and_reaches_model_garden() -> TestResult {
    let vertex = mock(vec![
        Reply::Json(json!({"predictions": [
            {"embeddings": {"values": [0.1, 0.2], "statistics": {"token_count": 6.0, "truncated": false}}},
            {"embeddings": {"values": [0.3, 0.4], "statistics": {"token_count": 4.0, "truncated": false}}}]})),
        Reply::Json(json!({"records": [{"id": "1", "score": 0.9}, {"id": "0", "score": 0.2}]})),
        Reply::Json(json!({"id": "c1", "object": "chat.completion", "model": "meta/llama-3.3-70b-instruct-maas",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hi"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 1}})),
    ])
    .await?;
    let gw = gateway(
        "vertex",
        vec![
            route(
                "vertex",
                Kind::Vertex,
                vertex_base(&vertex),
                &["text-embedding-005", "semantic-ranker-default-004"],
            ),
            route(
                "garden",
                Kind::VertexOpenAi,
                vertex.url("/v1/projects/acme/locations/us-central1/endpoints/openapi"),
                &["meta/llama-3.3-70b-instruct-maas"],
            ),
        ],
        everyone(),
    )?;
    let (status, headers, text) = post(&gw, "/v1/embeddings", &json!({"model": "text-embedding-005", "input": ["a", "b"], "input_type": "search_document"})).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, sent, body) = vertex.first()?;
    assert_eq!(
        target,
        "/v1/projects/acme/locations/us-central1/publishers/google/models/text-embedding-005:predict"
    );
    assert_eq!(sent[header::AUTHORIZATION], "Bearer vertex-provider-key");
    let body: Value = serde_json::from_slice(&body)?;
    assert_eq!(
        body["instances"][0],
        json!({"content": "a", "task_type": "RETRIEVAL_DOCUMENT"})
    );
    let answer: Value = serde_json::from_str(&text)?;
    assert_eq!(answer["data"][1]["embedding"], json!([0.3, 0.4]));
    let (_, usage) = records_of(&gw, &headers).await?;
    assert_eq!(usage["input_tokens"], 10);
    // $0.10 per million.
    assert!(close(cost(&usage), 0.000001), "{usage}");

    let (status, _, text) = post(&gw, "/v1/rerank", &json!({"model": "semantic-ranker-default-004", "query": "q", "documents": ["x", "y"], "top_n": 2})).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, _, body) = vertex.nth(1)?;
    assert_eq!(
        target,
        "/v1/projects/acme/locations/global/rankingConfigs/default_ranking_config:rank"
    );
    let body: Value = serde_json::from_slice(&body)?;
    assert_eq!(body["records"][1], json!({"id": "1", "content": "y"}));
    assert_eq!(body["topN"], 2);
    let answer: Value = serde_json::from_str(&text)?;
    assert_eq!(
        answer["results"][0],
        json!({"index": 1, "relevance_score": 0.9})
    );

    let chat = json!({"model": "meta/llama-3.3-70b-instruct-maas", "messages": [{"role": "user", "content": "hi"}]});
    let (status, _, text) = post(&gw, "/v1/chat/completions", &chat).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, sent, _) = vertex.nth(2)?;
    assert_eq!(
        target,
        "/v1/projects/acme/locations/us-central1/endpoints/openapi/chat/completions"
    );
    assert_eq!(sent[header::AUTHORIZATION], "Bearer garden-provider-key");
    Ok(())
}

#[tokio::test]
async fn gemini_embeds_with_batch_embed_contents() -> TestResult {
    let gemini = mock(vec![Reply::Json(
        json!({"embeddings": [{"values": [0.5]}, {"values": [0.6]}]}),
    )])
    .await?;
    let gw = gateway(
        "gemini-embed",
        vec![route(
            "gemini",
            Kind::Gemini,
            gemini.url("/v1beta"),
            &["gemini-embedding-001"],
        )],
        everyone(),
    )?;
    let (status, headers, text) = post(
        &gw,
        "/v1/embeddings",
        &json!({"model": "gemini-embedding-001", "input": ["abcd", "ef"]}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, sent, body) = gemini.first()?;
    assert_eq!(
        target,
        "/v1beta/models/gemini-embedding-001:batchEmbedContents"
    );
    assert_eq!(sent["x-goog-api-key"], "gemini-provider-key");
    let body: Value = serde_json::from_slice(&body)?;
    assert_eq!(body["requests"][1]["content"]["parts"][0]["text"], "ef");
    // The Gemini API counts no tokens: the texts' six bytes stand in, never under what was sent.
    let (_, usage) = records_of(&gw, &headers).await?;
    assert_eq!(usage["input_tokens"], 6);
    Ok(())
}

// 4. Cohere and watsonx.ai.

#[tokio::test]
async fn cohere_chats_embeds_and_reranks_on_its_own_api() -> TestResult {
    let cohere = mock(vec![
        Reply::Json(json!({"id": "c1", "finish_reason": "COMPLETE", "message": {"role": "assistant", "content": [{"type": "text", "text": "Hi"}]},
            "usage": {"billed_units": {"input_tokens": 1000, "output_tokens": 100}, "tokens": {"input_tokens": 1010, "output_tokens": 100}}})),
        Reply::Json(json!({"id": "e1", "embeddings": {"float": [[0.1]]}, "meta": {"billed_units": {"input_tokens": 2}}})),
        Reply::Json(json!({"id": "r1", "results": [{"index": 0, "relevance_score": 0.7}], "meta": {"billed_units": {"search_units": 1}}})),
    ])
    .await?;
    let gw = gateway(
        "cohere",
        vec![route(
            "cohere",
            Kind::Cohere,
            cohere.url("/v2"),
            &["command-a-03-2025", "embed-english-v3.0", "rerank-v3.5"],
        )],
        everyone(),
    )?;
    let chat = json!({"model": "command-a-03-2025", "top_p": 0.5, "messages": [{"role": "user", "content": "hi"}]});
    let (status, headers, text) = post(&gw, "/v1/chat/completions", &chat).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, sent, body) = cohere.first()?;
    assert_eq!(target, "/v2/chat");
    assert_eq!(sent[header::AUTHORIZATION], "Bearer cohere-provider-key");
    assert_eq!(serde_json::from_slice::<Value>(&body)?["p"], 0.5);
    assert_eq!(
        serde_json::from_str::<Value>(&text)?["choices"][0]["message"]["content"],
        "Hi"
    );
    let (_, usage) = records_of(&gw, &headers).await?;
    assert_eq!(tokens(&usage), (Some("reported"), Some(1000), Some(100)));
    // $2.50 in and $10 out per million, on what Cohere bills.
    assert!(close(cost(&usage), 0.0025 + 0.001), "{usage}");
    let (status, _, text) = post(
        &gw,
        "/v1/embeddings",
        &json!({"model": "embed-english-v3.0", "input": "hi"}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(cohere.nth(1)?.0, "/v2/embed");
    let (status, _, text) = post(
        &gw,
        "/v1/rerank",
        &json!({"model": "rerank-v3.5", "query": "q", "documents": ["x"]}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(cohere.nth(2)?.0, "/v2/rerank");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watsonx_chats_in_its_project_with_an_iam_token() -> TestResult {
    let watsonx = mock(vec![
        Reply::Json(json!({"access_token": "iam-xyz", "expires_in": 3600})),
        Reply::Json(json!({"id": "w1", "model_id": "ibm/granite-3-8b-instruct", "created": 1,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hi"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 9, "completion_tokens": 2, "total_tokens": 11}})),
    ])
    .await?;
    let iam = watsonx.url("");
    let token = cloud::ibm("watsonx", "ibm-api-key", &|name: &str| {
        (name == "IBM_CLOUD_IAM_URL").then(|| iam.clone())
    })?;
    assert_eq!(token.get(), "Bearer iam-xyz");
    let form = String::from_utf8(watsonx.first()?.2.to_vec())?;
    assert!(
        form.contains("apikey=ibm-api-key")
            && form.contains("grant_type=urn%3Aibm%3Aparams%3Aoauth%3Agrant-type%3Aapikey"),
        "{form}"
    );
    let provider = ProviderRoute {
        key: None,
        google: Some(token),
        project_id: Some("proj-1".into()),
        api_version: Some("2024-05-31".into()),
        ..route(
            "watsonx",
            Kind::Watsonx,
            watsonx.url("/ml/v1"),
            &["ibm/granite-3-8b-instruct"],
        )
    };
    let gw = gateway("watsonx", vec![provider], everyone())?;
    let chat = json!({"model": "ibm/granite-3-8b-instruct", "messages": [{"role": "user", "content": "hi"}]});
    let (status, headers, text) = post(&gw, "/v1/chat/completions", &chat).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, sent, body) = watsonx.nth(1)?;
    assert_eq!(target, "/ml/v1/text/chat?version=2024-05-31");
    assert_eq!(sent[header::AUTHORIZATION], "Bearer iam-xyz");
    let body: Value = serde_json::from_slice(&body)?;
    assert_eq!(
        (body["model_id"].as_str(), body["project_id"].as_str()),
        (Some("ibm/granite-3-8b-instruct"), Some("proj-1"))
    );
    let chat: Value = serde_json::from_str(&text)?;
    assert_eq!(chat["model"], "ibm/granite-3-8b-instruct");
    let (_, usage) = records_of(&gw, &headers).await?;
    assert_eq!(tokens(&usage), (Some("reported"), Some(9), Some(2)));
    Ok(())
}

// 5. The Responses API across providers.

fn anthropic_message() -> Value {
    json!({"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-sonnet-5-5",
        "content": [{"type": "thinking", "thinking": "Plan.", "signature": "s"}, {"type": "text", "text": "Listing."},
            {"type": "tool_use", "id": "tu_1", "name": "shell", "input": {"cmd": "ls"}}],
        "stop_reason": "tool_use", "usage": {"input_tokens": 100, "output_tokens": 20}})
}

#[tokio::test]
async fn codex_reaches_claude_through_the_responses_api() -> TestResult {
    let anthropic = mock(vec![Reply::Json(anthropic_message())]).await?;
    let gw = gateway(
        "responses-claude",
        vec![route(
            "anthropic",
            Kind::Anthropic,
            anthropic.url(""),
            &["claude-sonnet-5-5"],
        )],
        everyone(),
    )?;
    let request = json!({"model": "claude-sonnet-5-5", "instructions": "You are Codex.", "store": false,
        "reasoning": {"effort": "low"}, "max_output_tokens": 5000,
        "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": "List files"}]}],
        "tools": [{"type": "function", "name": "shell", "parameters": {"type": "object"}}]});
    let (status, headers, text) = post(&gw, "/v1/responses", &request).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, sent, body) = anthropic.first()?;
    assert_eq!(target, "/v1/messages");
    assert_eq!(sent["anthropic-version"], "2023-06-01");
    let body: Value = serde_json::from_slice(&body)?;
    assert_eq!(body["system"][0]["text"], "You are Codex.");
    assert_eq!(
        body["thinking"],
        json!({"type": "enabled", "budget_tokens": 1024})
    );
    assert_eq!(body["max_tokens"], 5000);
    assert_eq!(body["tools"][0]["name"], "shell");
    let response: Value = serde_json::from_str(&text)?;
    assert_eq!(response["object"], "response");
    assert_eq!(response["output"][0]["type"], "reasoning");
    assert_eq!(response["output"][1]["content"][0]["text"], "Listing.");
    assert_eq!(response["output"][2]["type"], "function_call");
    assert_eq!(response["output"][2]["arguments"], r#"{"cmd":"ls"}"#);
    let (decision, usage) = records_of(&gw, &headers).await?;
    assert_eq!(decision["translated"], true);
    assert_eq!(tokens(&usage), (Some("reported"), Some(100), Some(20)));
    // State the provider does not keep is refused by name and never sent.
    let stateful =
        json!({"model": "claude-sonnet-5-5", "input": "go on", "previous_response_id": "resp_9"});
    let (status, _, text) = post(&gw, "/v1/responses", &stateful).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    assert!(text.contains("previous_response_id"), "{text}");
    assert_eq!(anthropic.hits.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn a_streamed_responses_request_to_claude_streams_responses_events() -> TestResult {
    let events = [
        json!({"type": "message_start", "message": {"id": "m1", "model": "claude-sonnet-5-5", "usage": {"input_tokens": 9, "output_tokens": 1}}}),
        json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Hi"}}),
        json!({"type": "content_block_stop", "index": 0}),
        json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 3}}),
        json!({"type": "message_stop"}),
    ];
    let sse: String = events
        .iter()
        .map(|e| {
            format!(
                "event: {}\ndata: {e}\n\n",
                e["type"].as_str().unwrap_or_default()
            )
        })
        .collect();
    let anthropic = mock(vec![Reply::Bytes("text/event-stream", sse.into_bytes())]).await?;
    let gw = gateway(
        "responses-stream",
        vec![route(
            "anthropic",
            Kind::Anthropic,
            anthropic.url(""),
            &["claude-sonnet-5-5"],
        )],
        everyone(),
    )?;
    let request = json!({"model": "claude-sonnet-5-5", "stream": true, "input": "hi"});
    let (status, headers, text) = post(&gw, "/v1/responses", &request).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    for event in [
        "response.created",
        "response.output_item.added",
        "response.output_text.delta",
        "response.output_text.done",
        "response.completed",
    ] {
        assert!(
            text.contains(&format!("event: {event}\n")),
            "{event}: {text}"
        );
    }
    assert!(text.contains("\"output_tokens\":3"), "{text}");
    let (_, usage) = records_of(&gw, &headers).await?;
    assert_eq!(tokens(&usage), (Some("reported"), Some(9), Some(3)));
    Ok(())
}

#[tokio::test]
async fn responses_reach_gemini_and_bedrock_translated() -> TestResult {
    let gemini = mock(vec![Reply::Json(json!({"responseId": "g1", "modelVersion": "gemini-2.5-flash",
        "candidates": [{"index": 0, "finishReason": "STOP", "content": {"role": "model", "parts": [{"text": "Hello"}]}}],
        "usageMetadata": {"promptTokenCount": 4, "candidatesTokenCount": 1}}))]).await?;
    let bedrock = mock(vec![Reply::Json(converse_answer())]).await?;
    let gw = gateway(
        "responses-google-aws",
        vec![
            route(
                "gemini",
                Kind::Gemini,
                gemini.url("/v1beta"),
                &["gemini-2.5-flash"],
            ),
            converse(bedrock.url(""), &[("nova-pro", "amazon.nova-pro-v1:0")]),
        ],
        everyone(),
    )?;
    let (status, _, text) = post(
        &gw,
        "/v1/responses",
        &json!({"model": "gemini-2.5-flash", "input": "hi", "reasoning": {"effort": "medium"}}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, _, body) = gemini.first()?;
    assert_eq!(target, "/v1beta/models/gemini-2.5-flash:generateContent");
    let body: Value = serde_json::from_slice(&body)?;
    assert_eq!(
        body["generationConfig"]["thinkingConfig"],
        json!({"thinkingBudget": 4096})
    );
    let response: Value = serde_json::from_str(&text)?;
    assert_eq!(response["output"][0]["content"][0]["text"], "Hello");
    let (status, _, text) = post(
        &gw,
        "/v1/responses",
        &json!({"model": "nova-pro", "input": "hi"}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(bedrock.first()?.0, "/model/amazon.nova-pro-v1%3A0/converse");
    let response: Value = serde_json::from_str(&text)?;
    assert_eq!(response["output"][1]["name"], "weather");
    Ok(())
}

#[tokio::test]
async fn a_chat_request_reaches_a_responses_only_model() -> TestResult {
    let openai = mock(vec![Reply::Json(json!({"id": "resp_1", "object": "response", "created_at": 3, "model": "o3-pro", "status": "completed",
        "output": [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Deep."}]}],
        "usage": {"input_tokens": 11, "output_tokens": 2}}))]).await?;
    let mut provider = route("openai", Kind::OpenAi, openai.url(""), &["o3-pro"]);
    provider.chat_as_responses = true;
    let gw = gateway("chat-as-responses", vec![provider], everyone())?;
    let chat = json!({"model": "o3-pro", "max_tokens": 100, "messages": [{"role": "user", "content": "think"}]});
    let (status, headers, text) = post(&gw, "/v1/chat/completions", &chat).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, _, body) = openai.first()?;
    assert_eq!(target, "/v1/responses");
    let body: Value = serde_json::from_slice(&body)?;
    assert_eq!(body["max_output_tokens"], 100);
    assert_eq!(body["input"][0]["content"][0]["text"], "think");
    let chat: Value = serde_json::from_str(&text)?;
    assert_eq!(chat["choices"][0]["message"]["content"], "Deep.");
    let (_, usage) = records_of(&gw, &headers).await?;
    assert_eq!(tokens(&usage), (Some("reported"), Some(11), Some(2)));
    Ok(())
}

// 6. Governance on the translated routes.

#[tokio::test]
async fn guardrails_regions_and_rules_govern_translated_routes() -> TestResult {
    let anthropic = mock(vec![Reply::Json(anthropic_message())]).await?;
    let bedrock = mock(vec![Reply::Json(converse_answer())]).await?;
    let policy = Policy::new()
        .with_key(MAYA, "maya.cohen", "payments")
        .with_rule(
            "payments",
            Who::Team("payments".into()),
            Models::Only(vec!["claude-sonnet-5-5".into(), "titan".into()]),
        )
        .with_guardrails(&[Guardrail {
            name: "no-secrets".into(),
            action: Action::Block,
            check: Check::Secrets,
            on: gantry_core::guard::On::REQUEST,
            shadow_until: None,
        }]);
    let gw = gateway(
        "governed",
        vec![
            route(
                "anthropic",
                Kind::Anthropic,
                anthropic.url(""),
                &["claude-sonnet-5-5"],
            ),
            converse(
                bedrock.url(""),
                &[
                    ("titan", "amazon.titan-embed-text-v2:0"),
                    ("nova-pro", "amazon.nova-pro-v1:0"),
                ],
            ),
        ],
        policy,
    )?;
    // The guardrails read the Responses input before it is translated.
    let secret = json!({"model": "claude-sonnet-5-5", "input": "key AKIAIOSFODNN7EXAMPLE"});
    let (status, _, text) = post(&gw, "/v1/responses", &secret).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
    assert!(text.contains("guardrail_blocked"), "{text}");
    // And embeddings input before Titan sees it.
    let (status, _, text) = post(
        &gw,
        "/v1/embeddings",
        &json!({"model": "titan", "input": "key AKIAIOSFODNN7EXAMPLE"}),
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
    // A model the rule does not allow stays refused on every new route.
    let (status, headers, text) = post(
        &gw,
        "/v1/responses",
        &json!({"model": "nova-pro", "input": "hi"}),
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
    assert_eq!(decision_of(&gw, &headers)?["code"], "model_not_allowed");
    assert_eq!(
        anthropic.hits.load(Ordering::SeqCst) + bedrock.hits.load(Ordering::SeqCst),
        0
    );
    Ok(())
}

// 7. Signed passthrough.

#[tokio::test]
async fn bedrock_and_vertex_passthrough_are_signed_and_governed() -> TestResult {
    let bedrock = mock(vec![Reply::Json(converse_answer())]).await?;
    let vertex = mock(vec![Reply::Json(json!({"candidates": [], "usageMetadata": {"promptTokenCount": 2, "candidatesTokenCount": 1}}))]).await?;
    let policy = everyone().with_rule_change(|rule| {
        rule.passthrough = vec![
            gantry_core::policy::Passthrough {
                provider: "bedrock".into(),
                paths: vec!["/model".into()],
            },
            gantry_core::policy::Passthrough {
                provider: "vertex".into(),
                paths: vec!["/v1/projects/acme".into()],
            },
        ];
    });
    let gw = gateway(
        "signed-passthrough",
        vec![
            converse(bedrock.url(""), &[("nova-pro", "amazon.nova-pro-v1:0")]),
            route(
                "vertex",
                Kind::Vertex,
                vertex_base(&vertex),
                &["gemini-2.5-flash"],
            ),
        ],
        policy,
    )?;
    let native = json!({"messages": [{"role": "user", "content": [{"text": "hi"}]}]});
    let (status, headers, text) =
        post(&gw, "/bedrock/model/amazon.nova-pro-v1:0/converse", &native).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, sent, body) = bedrock.first()?;
    assert_eq!(target, "/model/amazon.nova-pro-v1%3A0/converse");
    assert!(
        sent[header::AUTHORIZATION]
            .to_str()?
            .starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/")
    );
    assert_eq!(serde_json::from_slice::<Value>(&body)?, native);
    let (decision, usage) = records_of(&gw, &headers).await?;
    assert_eq!(decision["provider"], "bedrock");
    // The model in the path is the one decided on, by the name the policy knows it by.
    assert_eq!(decision["model"], "nova-pro");
    assert_eq!(tokens(&usage), (Some("reported"), Some(1000), Some(500)));

    let path = "/vertex/v1/projects/acme/locations/us-central1/publishers/google/models/gemini-2.5-flash:generateContent";
    let (status, _, text) = post(&gw, path, &json!({"contents": []})).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, sent, _) = vertex.first()?;
    assert_eq!(
        target,
        "/v1/projects/acme/locations/us-central1/publishers/google/models/gemini-2.5-flash:generateContent"
    );
    assert_eq!(sent[header::AUTHORIZATION], "Bearer vertex-provider-key");

    // A path the rule does not list is refused and never sent.
    let (status, _, text) = post(
        &gw,
        "/vertex/v1/projects/other/locations/x/publishers/google/models/m:generateContent",
        &json!({}),
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
    assert!(text.contains("passthrough_not_allowed"), "{text}");
    assert_eq!(vertex.hits.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn a_bedrock_stream_through_signed_passthrough_is_charged_what_its_events_report()
-> TestResult {
    let mut converse_stream =
        eventstream::converse_event("messageStart", &json!({"role": "assistant"}));
    converse_stream.extend(eventstream::converse_event(
        "contentBlockDelta",
        &json!({"contentBlockIndex": 0, "delta": {"text": "Hi"}}),
    ));
    converse_stream.extend(eventstream::converse_event(
        "metadata",
        &json!({"usage": {"inputTokens": 1000, "outputTokens": 500, "totalTokens": 1500}, "metrics": {"latencyMs": 9}}),
    ));
    let mut invoke_stream = eventstream::chunk(
        &json!({"type": "message_start", "message": {"usage": {"input_tokens": 40, "output_tokens": 1}}}),
    );
    invoke_stream.extend(eventstream::chunk(&json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 7}})));
    invoke_stream.extend(eventstream::chunk(&json!({"type": "message_stop"})));
    let bedrock = mock(vec![
        Reply::Bytes("application/vnd.amazon.eventstream", converse_stream),
        Reply::Bytes("application/vnd.amazon.eventstream", invoke_stream),
    ])
    .await?;
    let policy = everyone().with_rule_change(|rule| {
        rule.passthrough = vec![gantry_core::policy::Passthrough {
            provider: "bedrock".into(),
            paths: vec!["/model".into()],
        }];
    });
    let gw = gateway(
        "signed-passthrough-stream",
        vec![converse(
            bedrock.url(""),
            &[
                ("nova-pro", "amazon.nova-pro-v1:0"),
                ("claude", "anthropic.claude-v9"),
            ],
        )],
        policy,
    )?;
    let native = json!({"messages": [{"role": "user", "content": [{"text": "hi"}]}]});
    let (status, headers, text) = post(
        &gw,
        "/bedrock/model/amazon.nova-pro-v1:0/converse-stream",
        &native,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (_, usage) = records_of(&gw, &headers).await?;
    assert_eq!(tokens(&usage), (Some("reported"), Some(1000), Some(500)));
    let (status, headers, text) = post(
        &gw,
        "/bedrock/model/anthropic.claude-v9/invoke-with-response-stream",
        &json!({"anthropic_version": "bedrock-2023-05-31", "max_tokens": 10, "messages": []}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (_, usage) = records_of(&gw, &headers).await?;
    assert_eq!(tokens(&usage), (Some("reported"), Some(40), Some(7)));
    Ok(())
}

// 8. Videos and containers.

const OMER: &str = "gantry_fedcba9876543210fedcba9876543210fedcba9876543210fedcba98765432";

async fn get(
    gw: &Gateway,
    path: &str,
    key: &str,
) -> Result<(StatusCode, HeaderMap, String), Box<dyn std::error::Error>> {
    let request = Request::get(path)
        .header(header::AUTHORIZATION, format!("Bearer {key}"))
        .body(Body::empty())?;
    send(gw, request).await
}

async fn usage_of(gw: &Gateway, headers: &HeaderMap) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(records_of(gw, headers).await?.1)
}

#[tokio::test]
async fn a_sora_video_is_guarded_owned_and_charged_for_its_seconds_when_done() -> TestResult {
    let openai = mock(vec![
        Reply::Json(json!({"id": "video_1", "object": "video", "model": "sora-2", "status": "queued", "seconds": "8", "size": "1280x720"})),
        Reply::Json(json!({"id": "video_1", "object": "video", "model": "sora-2", "status": "completed", "seconds": "8", "size": "1280x720"})),
    ])
    .await?;
    let policy = everyone()
        .with_key(OMER, "omer.levi", "payments")
        .with_guardrails(&[Guardrail {
            name: "no-secrets".into(),
            action: Action::Block,
            check: Check::Secrets,
            on: gantry_core::guard::On::REQUEST,
            shadow_until: None,
        }]);
    let gw = gateway(
        "sora",
        vec![route("openai", Kind::OpenAi, openai.url(""), &["sora-2"])],
        policy,
    )?;
    let secret = json!({"model": "sora-2", "prompt": "a sign reading AKIAIOSFODNN7EXAMPLE"});
    let (status, _, text) = post(&gw, "/v1/videos", &secret).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
    assert_eq!(openai.hits.load(Ordering::SeqCst), 0);
    let (status, created, text) = post(
        &gw,
        "/v1/videos",
        &json!({"model": "sora-2", "prompt": "a calm sea", "seconds": "8", "size": "1280x720"}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(openai.first()?.0, "/v1/videos");
    // Someone else is told it does not exist.
    let (status, _, _) = get(&gw, "/v1/videos/video_1", OMER).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, text) = get(&gw, "/v1/videos/video_1", MAYA).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let usage = usage_of(&gw, &created).await?;
    // Eight seconds at $0.10.
    assert!(close(cost(&usage), 0.8), "{usage}");
    assert_eq!(usage["model"], "sora-2");
    Ok(())
}

#[tokio::test]
async fn a_veo_video_goes_through_the_videos_route_and_comes_back_whole() -> TestResult {
    let operation = "projects/acme/locations/us-central1/publishers/google/models/veo-3.0-generate-001/operations/abc-123";
    let vertex = mock(vec![
        Reply::Json(json!({"name": operation})),
        Reply::Json(json!({"name": operation, "done": true, "response": {"videos": [{"bytesBase64Encoded": "AAEC", "mimeType": "video/mp4"}]}})),
    ])
    .await?;
    let gw = gateway(
        "veo",
        vec![route(
            "vertex",
            Kind::Vertex,
            vertex_base(&vertex),
            &["veo-3.0-generate-001"],
        )],
        everyone(),
    )?;
    let (status, created, text) = post(
        &gw,
        "/v1/videos",
        &json!({"model": "veo-3.0-generate-001", "prompt": "a calm sea", "size": "720x1280"}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let video: Value = serde_json::from_str(&text)?;
    assert_eq!(video["id"], "video_veo_abc-123");
    let (target, sent, body) = vertex.first()?;
    assert_eq!(
        target,
        "/v1/projects/acme/locations/us-central1/publishers/google/models/veo-3.0-generate-001:predictLongRunning"
    );
    assert_eq!(sent[header::AUTHORIZATION], "Bearer vertex-provider-key");
    let body: Value = serde_json::from_slice(&body)?;
    assert_eq!(
        body,
        json!({"instances": [{"prompt": "a calm sea"}], "parameters": {"sampleCount": 1, "durationSeconds": 8, "aspectRatio": "9:16"}})
    );
    let (status, _, text) = get(&gw, "/v1/videos/video_veo_abc-123/content", MAYA).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, _, body) = vertex.nth(1)?;
    assert!(
        target.ends_with("/models/veo-3.0-generate-001:fetchPredictOperation"),
        "{target}"
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&body)?["operationName"],
        operation
    );
    let usage = usage_of(&gw, &created).await?;
    // Eight seconds of Veo 3 at $0.40.
    assert!(close(cost(&usage), 3.2), "{usage}");
    Ok(())
}

#[tokio::test]
async fn a_container_is_allowed_by_its_size_charged_by_the_minute_and_reached_only_by_its_owner()
-> TestResult {
    let openai = mock(vec![
        Reply::Json(
            json!({"id": "cntr_1", "object": "container", "name": "work", "status": "running", "created_at": 1000}),
        ),
        Reply::Json(json!({"object": "list", "data": []})),
        Reply::Json(json!({"id": "cntr_1", "object": "container", "status": "expired", "created_at": 1000,
            "last_active_at": 1600, "expires_after": {"anchor": "last_active_at", "minutes": 20}})),
    ])
    .await?;
    let policy = Policy::new()
        .with_key(MAYA, "maya.cohen", "payments")
        .with_key(OMER, "omer.levi", "payments")
        .with_rule("payments", Who::Team("payments".into()), Models::Any)
        .with_rule_change(|r| r.limits.containers = vec!["1g".into(), "4g".into()]);
    let gw = gateway(
        "containers",
        vec![route("openai", Kind::OpenAi, openai.url(""), &["gpt-4o"])],
        policy,
    )?;
    let (status, _, text) = post(
        &gw,
        "/v1/containers",
        &json!({"name": "big", "memory_limit": "64g"}),
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
    assert!(
        text.contains("container_not_allowed") && text.contains("64g") && text.contains("1g, 4g"),
        "{text}"
    );
    assert_eq!(openai.hits.load(Ordering::SeqCst), 0);
    let (status, created, text) = post(&gw, "/v1/containers", &json!({"name": "work"})).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (status, _, _) = get(&gw, "/v1/containers/cntr_1/files", OMER).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, text) = get(&gw, "/v1/containers/cntr_1/files", MAYA).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(openai.nth(1)?.0, "/v1/containers/cntr_1/files");
    // Read when it expired: alive from 1000 to 20 minutes after its last use at 1600, 30 minutes at $0.03 per 20.
    let (status, _, text) = get(&gw, "/v1/containers/cntr_1", MAYA).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let usage = usage_of(&gw, &created).await?;
    assert!(close(cost(&usage), 0.045), "{usage}");
    assert_eq!(usage["model"], "container");
    assert_eq!(usage["container_size"], "1g");
    assert_eq!(usage["price"], "per_minute");
    Ok(())
}

#[tokio::test]
async fn a_rule_without_containers_allows_none_and_a_deleted_one_pays_the_minimum() -> TestResult {
    let openai = mock(vec![Reply::Json(
        json!({"id": "cntr_2", "object": "container", "status": "running"}),
    )])
    .await?;
    let gw = gateway(
        "containers-none",
        vec![route("openai", Kind::OpenAi, openai.url(""), &["gpt-4o"])],
        everyone(),
    )?;
    let (status, _, text) = post(&gw, "/v1/containers", &json!({"name": "work"})).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
    assert!(text.contains("containers: { sizes: [1g] }"), "{text}");
    let gw = gateway(
        "containers-delete",
        vec![route("openai", Kind::OpenAi, openai.url(""), &["gpt-4o"])],
        everyone().with_rule_change(|r| r.limits.containers = vec!["16g".into()]),
    )?;
    let (status, created, text) = post(
        &gw,
        "/v1/containers",
        &json!({"name": "work", "memory_limit": "16g"}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let request = Request::delete("/v1/containers/cntr_2")
        .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
        .body(Body::empty())?;
    let (status, _, text) = send(&gw, request).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    // Deleted at once: the 5-minute minimum of a $0.48 20-minute session.
    let usage = usage_of(&gw, &created).await?;
    assert!(close(cost(&usage), 0.12), "{usage}");
    Ok(())
}

// 9. Stored responses and async jobs.

async fn request(
    gw: &Gateway,
    method: &str,
    path: &str,
    key: &str,
) -> Result<(StatusCode, HeaderMap, String), Box<dyn std::error::Error>> {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {key}"))
        .body(Body::empty())?;
    send(gw, request).await
}

/// Asks until the answer is not a 404: a response is recorded as its creator's when its answer ends.
async fn eventually(
    gw: &Gateway,
    path: &str,
) -> Result<(StatusCode, HeaderMap, String), Box<dyn std::error::Error>> {
    for _ in 0..100 {
        let answer = get(gw, path, MAYA).await?;
        if answer.0 != StatusCode::NOT_FOUND {
            return Ok(answer);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Err(format!("{path} stayed 404").into())
}

#[tokio::test]
async fn a_stored_response_is_read_cancelled_and_deleted_by_its_creator_alone() -> TestResult {
    let response = json!({"id": "resp_9", "object": "response", "status": "completed", "model": "gpt-4o", "output": [], "usage": {"input_tokens": 5, "output_tokens": 1}});
    let openai = mock(vec![
        Reply::Json(response.clone()),
        Reply::Json(response.clone()),
        Reply::Json(json!({"object": "list", "data": []})),
        Reply::Json(response.clone()),
        Reply::Json(json!({"id": "resp_9", "object": "response.deleted", "deleted": true})),
    ])
    .await?;
    let gw = gateway(
        "responses-stored",
        vec![route("openai", Kind::OpenAi, openai.url(""), &["gpt-4o"])],
        everyone().with_key(OMER, "omer.levi", "payments"),
    )?;
    let (status, _, text) = post(
        &gw,
        "/v1/responses",
        &json!({"model": "gpt-4o", "input": "hi"}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (status, _, text) = eventually(&gw, "/v1/responses/resp_9").await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(openai.nth(1)?.0, "/v1/responses/resp_9");
    // Someone else is told it does not exist, and the provider is not asked.
    for (method, path) in [
        ("GET", "/v1/responses/resp_9"),
        ("DELETE", "/v1/responses/resp_9"),
        ("POST", "/v1/responses/resp_9/cancel"),
    ] {
        let (status, _, _) = request(&gw, method, path, OMER).await?;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}");
    }
    assert_eq!(openai.hits.load(Ordering::SeqCst), 2);
    let (status, _, _) = get(&gw, "/v1/responses/resp_9/input_items?limit=5", MAYA).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(openai.nth(2)?.0, "/v1/responses/resp_9/input_items?limit=5");
    let (status, _, _) = request(&gw, "POST", "/v1/responses/resp_9/cancel", MAYA).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(openai.nth(3)?.0, "/v1/responses/resp_9/cancel");
    let (status, headers, _) = request(&gw, "DELETE", "/v1/responses/resp_9", MAYA).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(decision_of(&gw, &headers)?["code"].is_null());
    let (status, _, _) = get(&gw, "/v1/responses/resp_9", MAYA).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn a_translated_response_is_kept_by_gantry_when_the_request_stores_it() -> TestResult {
    let anthropic = mock(vec![Reply::Json(anthropic_message())]).await?;
    let gw = gateway(
        "responses-kept",
        vec![route(
            "anthropic",
            Kind::Anthropic,
            anthropic.url(""),
            &["claude-sonnet-5-5"],
        )],
        everyone().with_key(OMER, "omer.levi", "payments"),
    )?;
    let (status, _, text) = post(
        &gw,
        "/v1/responses",
        &json!({"model": "claude-sonnet-5-5", "input": "List files", "store": true}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let made: Value = serde_json::from_str(&text)?;
    let id = made["id"].as_str().ok_or("no id")?.to_string();
    let path = format!("/v1/responses/{id}");
    let (status, _, text) = eventually(&gw, &path).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(serde_json::from_str::<Value>(&text)?, made);
    // Kept for its creator alone, never asked of the provider.
    let (status, _, _) = get(&gw, &path, OMER).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(anthropic.hits.load(Ordering::SeqCst), 1);
    let (status, _, text) = request(&gw, "POST", &format!("{path}/cancel"), MAYA).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    assert!(text.contains("not_background"), "{text}");
    let (status, _, text) = request(&gw, "DELETE", &path, MAYA).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(
        serde_json::from_str::<Value>(&text)?,
        json!({"id": id, "object": "response.deleted", "deleted": true})
    );
    let (status, _, _) = get(&gw, &path, MAYA).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // Not asked to store: the creator is told why there is nothing to read.
    let (_, _, text) = post(
        &gw,
        "/v1/responses",
        &json!({"model": "claude-sonnet-5-5", "input": "again"}),
    )
    .await?;
    let id = serde_json::from_str::<Value>(&text)?["id"]
        .as_str()
        .ok_or("no id")?
        .to_string();
    let mut answer = (StatusCode::OK, String::new());
    for _ in 0..100 {
        let (status, _, text) = get(&gw, &format!("/v1/responses/{id}"), MAYA).await?;
        answer = (status, text);
        if answer.1.contains("not_kept") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(answer.1.contains("not_kept"), "{answer:?}");
    Ok(())
}

#[tokio::test]
async fn an_async_job_runs_governed_and_its_answer_waits_for_its_submitter() -> TestResult {
    let openai = mock(vec![Reply::Json(json!({"id": "c1", "object": "chat.completion",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hi"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 4, "completion_tokens": 1}}))])
    .await?;
    let gw = gateway(
        "async",
        vec![route("openai", Kind::OpenAi, openai.url(""), &["gpt-4o"])],
        everyone().with_key(OMER, "omer.levi", "payments"),
    )?;
    let chat = json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]});
    let (status, _, text) = post(&gw, "/v1/async/chat/completions", &chat).await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{text}");
    let job: Value = serde_json::from_str(&text)?;
    assert_eq!(job["status"], "pending");
    let path = format!(
        "/v1/async/chat/completions/{}",
        job["id"].as_str().ok_or("no id")?
    );
    let mut done = Value::Null;
    for _ in 0..100 {
        let (status, _, text) = get(&gw, &path, MAYA).await?;
        if status == StatusCode::OK {
            done = serde_json::from_str(&text)?;
            break;
        }
        assert_eq!(status, StatusCode::ACCEPTED, "{text}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(done["result"]["choices"][0]["message"]["content"], "Hi");
    // The job was a request like any other: decided, recorded and metered under its own decision.
    let inner = all_records(&gw)?
        .into_iter()
        .find(|r| r["id"] == done["decision"] && r["event"] == "usage")
        .ok_or("no usage record for the job")?;
    assert_eq!(tokens(&inner), (Some("reported"), Some(4), Some(1)));
    let (status, _, _) = get(&gw, &path, OMER).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, text) = post(
        &gw,
        "/v1/async/chat/completions",
        &json!({"model": "gpt-4o", "stream": true, "messages": []}),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    assert!(text.contains("stream_not_async"), "{text}");
    // A model the rule does not allow fails inside the job, with the refusal held as its error.
    let gw = gateway(
        "async-refused",
        vec![route(
            "openai",
            Kind::OpenAi,
            openai.url(""),
            &["gpt-4o", "o3"],
        )],
        Policy::new()
            .with_key(MAYA, "maya.cohen", "payments")
            .with_rule("only-4o", Who::Any, Models::Only(vec!["gpt-4o".into()])),
    )?;
    let (_, _, text) = post(
        &gw,
        "/v1/async/chat/completions",
        &json!({"model": "o3", "messages": [{"role": "user", "content": "hi"}]}),
    )
    .await?;
    let path = format!(
        "/v1/async/chat/completions/{}",
        serde_json::from_str::<Value>(&text)?["id"]
            .as_str()
            .ok_or("no id")?
    );
    for _ in 0..100 {
        let (status, _, text) = get(&gw, &path, MAYA).await?;
        if status == StatusCode::OK {
            done = serde_json::from_str(&text)?;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(done["status"], "failed", "{done}");
    assert_eq!(done["status_code"], 403);
    assert!(
        done["error"].to_string().contains("model_not_allowed"),
        "{done}"
    );
    Ok(())
}

// 10. SageMaker and Replicate.

fn sagemaker(url: String) -> ProviderRoute {
    ProviderRoute {
        key: None,
        region: Some("us-east-1".into()),
        aws: Some(aws().into()),
        upstream_models: [("llama".to_string(), "my-llama-ep".to_string())].into(),
        ..route("sagemaker", Kind::Sagemaker, url, &["llama"])
    }
}

#[tokio::test]
async fn a_sagemaker_endpoint_is_signed_and_its_stream_comes_back_as_chat_events() -> TestResult {
    let chunk = |text: &str| {
        json!({"id": "c1", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"content": text}, "finish_reason": null}]})
            .to_string()
    };
    let lines = format!("{}\n{}\n", chunk("Hel"), chunk("lo"));
    // The container's output, cut in the middle of a line, as SageMaker may send it.
    let (first, second) = lines.split_at(30);
    let mut stream = eventstream::payload_part(first.as_bytes());
    stream.extend(eventstream::payload_part(second.as_bytes()));
    let endpoint = mock(vec![
        Reply::Json(json!({"id": "c1", "object": "chat.completion",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hi"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 12, "completion_tokens": 3, "total_tokens": 15}})),
        Reply::Bytes("application/vnd.amazon.eventstream", stream),
    ])
    .await?;
    let gw = gateway(
        "sagemaker",
        vec![sagemaker(endpoint.url("/endpoints"))],
        everyone(),
    )?;
    let chat = json!({"model": "llama", "messages": [{"role": "user", "content": "hi"}]});
    let (status, headers, text) = post(&gw, "/v1/chat/completions", &chat).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, sent, body) = endpoint.first()?;
    assert_eq!(target, "/endpoints/my-llama-ep/invocations");
    let auth = sent[header::AUTHORIZATION].to_str()?;
    assert!(auth.contains("/us-east-1/sagemaker/aws4_request"), "{auth}");
    assert_eq!(
        serde_json::from_slice::<Value>(&body)?["messages"][0]["content"],
        "hi"
    );
    let (_, usage) = records_of(&gw, &headers).await?;
    assert_eq!(tokens(&usage), (Some("reported"), Some(12), Some(3)));
    let mut streamed = chat.clone();
    streamed["stream"] = true.into();
    let (status, _, text) = post(&gw, "/v1/chat/completions", &streamed).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(
        endpoint.nth(1)?.0,
        "/endpoints/my-llama-ep/invocations-response-stream"
    );
    assert!(
        text.contains("\"content\":\"Hel\"") && text.contains("\"content\":\"lo\""),
        "{text}"
    );
    assert!(text.trim_end().ends_with("data: [DONE]"), "{text}");
    Ok(())
}

#[tokio::test]
async fn a_replicate_prediction_is_waited_for_and_answers_as_chat() -> TestResult {
    let model = "meta/meta-llama-3-70b-instruct";
    let done = json!({"id": "p1", "status": "succeeded", "output": ["Hel", "lo"],
        "metrics": {"input_token_count": 7, "output_token_count": 2, "predict_time": 0.4}});
    let replicate = mock(vec![]).await?;
    let sse = "event: output\nid: 1\ndata: Hel\n\nevent: output\nid: 2\ndata: lo\n\nevent: done\ndata: {}\n\n";
    replicate.replies.lock().map_err(|_| "poisoned")?.extend([
        Reply::Json(done.clone()),
        // A streaming prediction: created at once, its text read from its stream URL, its counts from its get URL.
        Reply::Json(json!({"id": "p2", "status": "starting", "urls": {
            "stream": replicate.url("/stream/p2"), "get": replicate.url("/v1/predictions/p2")}})),
        Reply::Bytes("text/event-stream", sse.as_bytes().to_vec()),
        Reply::Json(
            json!({"id": "p2", "status": "succeeded", "output": ["Hel", "lo"],
            "metrics": {"input_token_count": 9, "output_token_count": 2}}),
        ),
        Reply::Json(json!({"id": "p3", "status": "processing", "output": null})),
    ]);
    let gw = gateway(
        "replicate",
        vec![route(
            "replicate",
            Kind::Replicate,
            replicate.url("/v1"),
            &[model],
        )],
        everyone(),
    )?;
    let chat = json!({"model": model, "max_tokens": 64, "messages": [
        {"role": "system", "content": "Be brief."}, {"role": "user", "content": "hi"}]});
    let (status, headers, text) = post(&gw, "/v1/chat/completions", &chat).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let answer: Value = serde_json::from_str(&text)?;
    assert_eq!(answer["choices"][0]["message"]["content"], "Hello");
    let (target, sent, body) = replicate.first()?;
    assert_eq!(target, format!("/v1/models/{model}/predictions"));
    assert_eq!(sent["prefer"], "wait=60");
    assert_eq!(sent["cancel-after"], "60s");
    assert_eq!(sent[header::AUTHORIZATION], "Bearer replicate-provider-key");
    let body: Value = serde_json::from_slice(&body)?;
    assert_eq!(
        body,
        json!({"input": {"prompt": "User: hi\nAssistant:", "system_prompt": "Be brief.", "max_tokens": 64}})
    );
    let (_, usage) = records_of(&gw, &headers).await?;
    assert_eq!(tokens(&usage), (Some("reported"), Some(7), Some(2)));
    // Streamed: the tokens arrive as Replicate's stream sends them, and the usage is metered from the prediction
    // although the client did not ask to see it.
    let mut streamed = chat.clone();
    streamed["stream"] = true.into();
    let (status, headers, text) = post(&gw, "/v1/chat/completions", &streamed).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (_, sent, body) = replicate.nth(1)?;
    assert!(sent.get("prefer").is_none());
    assert_eq!(serde_json::from_slice::<Value>(&body)?["stream"], true);
    let (target, sent, _) = replicate.nth(2)?;
    assert_eq!(target, "/stream/p2");
    assert_eq!(sent[header::ACCEPT], "text/event-stream");
    assert_eq!(sent[header::AUTHORIZATION], "Bearer replicate-provider-key");
    assert_eq!(replicate.nth(3)?.0, "/v1/predictions/p2");
    assert!(
        text.contains("\"content\":\"Hel\"") && text.contains("\"content\":\"lo\""),
        "{text}"
    );
    assert!(text.contains("\"finish_reason\":\"stop\""), "{text}");
    assert!(!text.contains("\"usage\""), "{text}");
    assert!(text.ends_with("data: [DONE]\n\n"), "{text}");
    let (_, usage) = records_of(&gw, &headers).await?;
    assert_eq!(tokens(&usage), (Some("reported"), Some(9), Some(2)));
    // Not done after the wait: Replicate cancels it, and the caller is told why.
    let (status, _, text) = post(&gw, "/v1/chat/completions", &chat).await?;
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT, "{text}");
    assert!(text.contains("60 seconds"), "{text}");
    // A field a prediction has no place for is refused by name, never sent.
    let (status, _, text) = post(
        &gw,
        "/v1/chat/completions",
        &json!({"model": model, "messages": [{"role": "user", "content": "hi"}], "tools": []}),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    assert!(text.contains("tools"), "{text}");
    assert_eq!(replicate.hits.load(Ordering::SeqCst), 5);
    Ok(())
}

#[tokio::test]
async fn files_written_into_a_container_are_read_by_the_guardrails_both_ways() -> TestResult {
    let openai = mock(vec![
        Reply::Json(json!({"id": "cntr_7", "object": "container", "status": "running"})),
        Reply::Json(json!({"id": "cfile_1", "object": "container.file"})),
        Reply::Bytes(
            "text/plain",
            b"report: key AKIAIOSFODNN7EXAMPLE leaked".to_vec(),
        ),
        Reply::Bytes("application/octet-stream", vec![0, 159, 146, 150]),
    ])
    .await?;
    let policy = everyone()
        .with_rule_change(|r| r.limits.containers = vec!["1g".into()])
        .with_guardrails(&[Guardrail {
            name: "no-secrets".into(),
            action: Action::Block,
            check: Check::Secrets,
            on: gantry_core::guard::On {
                request: true,
                answer: true,
            },
            shadow_until: None,
        }]);
    let gw = gateway(
        "container-files",
        vec![route("openai", Kind::OpenAi, openai.url(""), &["gpt-4o"])],
        policy,
    )?;
    let (status, _, text) = post(&gw, "/v1/containers", &json!({"name": "work"})).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let file = |content: &str| {
        format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"notes.txt\"\r\nContent-Type: text/plain\r\n\r\n{content}\r\n--{BOUNDARY}--\r\n"
        )
        .into_bytes()
    };
    let (status, _, text) = post_form(
        &gw,
        "/v1/containers/cntr_7/files",
        file("aws key AKIAIOSFODNN7EXAMPLE"),
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
    assert_eq!(openai.hits.load(Ordering::SeqCst), 1);
    let (status, _, text) =
        post_form(&gw, "/v1/containers/cntr_7/files", file("plain notes")).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(openai.nth(1)?.0, "/v1/containers/cntr_7/files");
    // A file the code wrote, read back: the answer guardrails see it before the caller does.
    let (status, _, text) = get(&gw, "/v1/containers/cntr_7/files/cfile_1/content", MAYA).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
    assert!(!text.contains("AKIA"), "{text}");
    // Bytes that are not text cannot be read, and pass as they are.
    let (status, headers, _) =
        get(&gw, "/v1/containers/cntr_7/files/cfile_2/content", MAYA).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "application/octet-stream");
    Ok(())
}

fn video_form(model: &str, prompt: &str) -> Vec<u8> {
    let mut form = format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n{model}\r\n--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\n{prompt}\r\n--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"seconds\"\r\n\r\n4\r\n--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"input_reference\"; filename=\"ref.png\"\r\nContent-Type: image/png\r\n\r\n"
    )
    .into_bytes();
    form.extend_from_slice(b"\x89PNG\r\n\x1a\nIMG");
    form.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    form
}

#[tokio::test]
async fn a_video_takes_an_input_reference_image_with_its_prompt_guarded() -> TestResult {
    let openai = mock(vec![Reply::Json(json!({"id": "video_2", "object": "video", "model": "sora-2", "status": "queued", "seconds": "4"}))]).await?;
    let operation = "projects/acme/locations/us-central1/publishers/google/models/veo-3.0-generate-001/operations/op-9";
    let vertex = mock(vec![Reply::Json(json!({"name": operation}))]).await?;
    let policy = everyone().with_guardrails(&[Guardrail {
        name: "no-secrets".into(),
        action: Action::Block,
        check: Check::Secrets,
        on: gantry_core::guard::On::REQUEST,
        shadow_until: None,
    }]);
    let gw = gateway(
        "video-reference",
        vec![
            route("openai", Kind::OpenAi, openai.url(""), &["sora-2"]),
            route(
                "vertex",
                Kind::Vertex,
                vertex_base(&vertex),
                &["veo-3.0-generate-001"],
            ),
        ],
        policy,
    )?;
    let (status, _, text) = post_form(
        &gw,
        "/v1/videos",
        video_form("sora-2", "a sign reading AKIAIOSFODNN7EXAMPLE"),
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
    assert_eq!(openai.hits.load(Ordering::SeqCst), 0);
    let (status, _, text) =
        post_form(&gw, "/v1/videos", video_form("sora-2", "a calm sea")).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, sent, body) = openai.first()?;
    assert_eq!(target, "/v1/videos");
    assert!(
        sent[header::CONTENT_TYPE]
            .to_str()?
            .starts_with("multipart/form-data; boundary=")
    );
    let body = String::from_utf8_lossy(&body);
    assert!(
        body.contains("name=\"prompt\"\r\n\r\na calm sea\r\n"),
        "{body}"
    );
    assert!(
        body.contains(
            "name=\"input_reference\"; filename=\"input_reference\"\r\nContent-Type: image/png"
        ),
        "{body}"
    );
    assert!(body.contains("IMG"), "{body}");
    // Veo takes the image in its instance, base64.
    let (status, _, text) = post_form(
        &gw,
        "/v1/videos",
        video_form("veo-3.0-generate-001", "a calm sea"),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let body: Value = serde_json::from_slice(&vertex.first()?.2)?;
    assert_eq!(body["instances"][0]["prompt"], "a calm sea");
    assert_eq!(body["instances"][0]["image"]["mimeType"], "image/png");
    assert_eq!(
        body["instances"][0]["image"]["bytesBase64Encoded"],
        eventstream::base64_encode(b"\x89PNG\r\n\x1a\nIMG")
    );
    Ok(())
}

// 11. Background responses, OCI request signing and Triton's generate extension.

fn priced(input: f64, output: f64, max_output: u64) -> gantry_core::usage::Price {
    gantry_core::usage::Price {
        input,
        output,
        cache_read: None,
        cache_write: None,
        cache_write_1h: None,
        long_context: None,
        max_output: Some(max_output),
        max_context: None,
        ..Default::default()
    }
}

fn budgeted(policy: Policy, prices: &[(&str, gantry_core::usage::Price)]) -> Policy {
    let mut map = gantry_core::usage::PriceOverrides::new();
    for (model, price) in prices {
        map.insert((*model).into(), price.clone());
    }
    policy
        .with_rule_change(|rule| {
            rule.limits.budgets = vec![gantry_core::policy::Cap {
                budget: gantry_core::policy::Budget {
                    usd: 10.0,
                    per: gantry_core::policy::Period::Day,
                },
                models: Vec::new(),
                from: None,
                shadow_until: None,
            }];
        })
        .with_prices(map)
}

#[tokio::test]
async fn a_background_response_is_charged_its_usage_once_when_it_is_seen_done() -> TestResult {
    let queued = json!({"id": "resp_bg", "object": "response", "status": "queued", "background": true, "model": "gpt-4o", "output": []});
    let running = json!({"id": "resp_bg", "object": "response", "status": "in_progress", "background": true, "model": "gpt-4o", "output": []});
    let done = json!({"id": "resp_bg", "object": "response", "status": "completed", "background": true, "model": "gpt-4o",
        "output": [], "usage": {"input_tokens": 1000, "output_tokens": 100}});
    let openai = mock(vec![
        Reply::Json(queued),
        Reply::Json(running),
        Reply::Json(done),
    ])
    .await?;
    let gw = gateway(
        "responses-background",
        vec![route("openai", Kind::OpenAi, openai.url(""), &["gpt-4o"])],
        budgeted(everyone(), &[("gpt-4o", priced(2.0, 10.0, 1000))]),
    )?;
    let (status, headers, text) = post(
        &gw,
        "/v1/responses",
        &json!({"model": "gpt-4o", "input": "a long task", "background": true, "max_output_tokens": 500}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    // Queued: nothing used yet, so nothing charged; its reservation is held until it ends.
    let (_, usage) = records_of(&gw, &headers).await?;
    assert_eq!(usage["usage"], "background");
    assert_eq!(usage["charged_usd"], 0.0);
    let settled = |gw: &Gateway| -> Result<Vec<Value>, Box<dyn std::error::Error>> {
        Ok(all_records(gw)?
            .into_iter()
            .filter(|r| r["event"] == "usage" && r["response"] == "resp_bg")
            .collect())
    };
    let (status, _, text) = eventually(&gw, "/v1/responses/resp_bg").await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert!(text.contains("in_progress"), "{text}");
    assert!(settled(&gw)?.is_empty(), "charged before it ended");
    for _ in 0..2 {
        let (status, _, text) = get(&gw, "/v1/responses/resp_bg", MAYA).await?;
        assert_eq!(status, StatusCode::OK, "{text}");
    }
    let mut charged = Vec::new();
    for _ in 0..100 {
        charged = settled(&gw)?;
        if !charged.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(charged.len(), 1, "charged once: {charged:?}");
    assert_eq!(
        tokens(&charged[0]),
        (Some("reported"), Some(1000), Some(100))
    );
    // 1,000 input tokens at $2 and 100 output tokens at $10 per million.
    assert!(close(
        charged[0]["charged_usd"].as_f64().unwrap_or(-1.0),
        0.003
    ));
    Ok(())
}

/// A background response deleted before Gantry saw it end is charged once, when it is deleted: the usage the provider
/// last reported for it, read just before the delete, or, when it reported none, its reservation.
#[tokio::test]
async fn a_background_response_deleted_unfinished_is_charged_what_it_last_reported_or_its_reservation()
-> TestResult {
    let queued = json!({"id": "resp_del", "object": "response", "status": "queued", "background": true, "model": "gpt-4o", "output": []});
    let deleted = json!({"id": "resp_del", "object": "response.deleted", "deleted": true});
    let charged = |gw: &Gateway| -> Result<Vec<Value>, Box<dyn std::error::Error>> {
        Ok(all_records(gw)?
            .into_iter()
            .filter(|r| r["event"] == "usage" && r["response"] == "resp_del")
            .collect())
    };
    for (name, last, expected) in [
        // Running, with what it has used so far: 1,000 input tokens at $2 and 50 output tokens at $10 per million.
        (
            "responses-delete-usage",
            json!({"id": "resp_del", "object": "response", "status": "in_progress", "background": true, "model": "gpt-4o",
                "output": [], "usage": {"input_tokens": 1000, "output_tokens": 50}}),
            Some(0.0025),
        ),
        // Still queued, no usage: its reservation.
        ("responses-delete-reserved", queued.clone(), None),
    ] {
        let openai = mock(vec![
            Reply::Json(queued.clone()),
            Reply::Json(last),
            Reply::Json(deleted.clone()),
        ])
        .await?;
        let gw = gateway(
            name,
            vec![route("openai", Kind::OpenAi, openai.url(""), &["gpt-4o"])],
            budgeted(everyone(), &[("gpt-4o", priced(2.0, 10.0, 1000))]),
        )?;
        let (status, headers, text) = post(
            &gw,
            "/v1/responses",
            &json!({"model": "gpt-4o", "input": "a long task", "background": true, "max_output_tokens": 500}),
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{text}");
        let (_, held) = records_of(&gw, &headers).await?;
        assert_eq!(held["charged_usd"], 0.0);
        // The response is its creator's once its answer is recorded: until then a delete is refused here.
        let mut answer = (StatusCode::NOT_FOUND, HeaderMap::new(), String::new());
        for _ in 0..100 {
            answer = request(&gw, "DELETE", "/v1/responses/resp_del", MAYA).await?;
            if answer.0 != StatusCode::NOT_FOUND {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(answer.0, StatusCode::OK, "{}", answer.2);
        let mut found = Vec::new();
        for _ in 0..100 {
            found = charged(&gw)?;
            if !found.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(found.len(), 1, "charged once: {found:?}");
        let usd = found[0]["charged_usd"].as_f64().unwrap_or(-1.0);
        match expected {
            Some(usd_reported) => {
                assert_eq!(tokens(&found[0]), (Some("reported"), Some(1000), Some(50)));
                assert!(close(usd, usd_reported), "{usd}");
            }
            None => {
                // What it could have cost: its input estimate and its 500 output tokens at $10 per million.
                assert_ne!(found[0]["usage"], "reported", "{}", found[0]);
                assert!(usd >= 500.0 * 10.0 / 1e6, "{usd}");
            }
        }
        // The provider was asked for the response before it was deleted, and once deleted it is not charged again.
        assert_eq!(openai.hits.load(Ordering::SeqCst), 3);
        assert_eq!(openai.nth(1)?.0, "/v1/responses/resp_del");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(charged(&gw)?.len(), 1);
    }
    Ok(())
}

#[tokio::test]
async fn oci_requests_are_signed_with_the_api_signing_key() -> TestResult {
    use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaKeyPair, UnparsedPublicKey};
    let pem = include_str!("cloud/oci-test-key.pem");
    let oci = mock(vec![Reply::Json(json!({"id": "c1", "object": "chat.completion",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hi"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 3, "completion_tokens": 1}}))])
    .await?;
    let key_id = "ocid1.tenancy.oc1..aaaa/ocid1.user.oc1..bbbb/20:3b:97:13:55:1c:5b:0d:d3:37:d8:50:4e:c5:3a:34";
    let gw = gateway(
        "oci-signed",
        vec![ProviderRoute {
            key: None,
            oci: Some(Arc::new(gantry_server::oci::Signer::from_pem(key_id, pem)?)),
            ..route(
                "oci",
                Kind::OpenAi,
                oci.url("/20231130/actions/v1"),
                &["meta.llama-3.3-70b-instruct"],
            )
        }],
        everyone(),
    )?;
    let chat = json!({"model": "meta.llama-3.3-70b-instruct", "messages": [{"role": "user", "content": "hi"}]});
    let (status, _, text) = post(&gw, "/v1/chat/completions", &chat).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, sent, body) = oci.first()?;
    assert_eq!(target, "/20231130/actions/v1/chat/completions");
    let auth = sent[header::AUTHORIZATION].to_str()?;
    let field = |name: &str| -> Result<String, Box<dyn std::error::Error>> {
        Ok(auth
            .split(&format!("{name}=\""))
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .ok_or(format!("no {name} in {auth}"))?
            .to_string())
    };
    assert!(auth.starts_with("Signature version=\"1\","), "{auth}");
    assert_eq!(field("keyId")?, key_id);
    assert_eq!(field("algorithm")?, "rsa-sha256");
    let signed = field("headers")?;
    assert_eq!(
        signed,
        "date (request-target) host content-length content-type x-content-sha256"
    );
    // The signature covers what was sent: rebuilt from the request the provider got, it verifies with the public key.
    let lines: Vec<String> = signed
        .split(' ')
        .map(|name| -> Result<String, Box<dyn std::error::Error>> {
            Ok(match name {
                "(request-target)" => format!("(request-target): post {target}"),
                _ => format!("{name}: {}", sent[name].to_str()?),
            })
        })
        .collect::<Result<_, _>>()?;
    assert_eq!(sent["content-length"], body.len().to_string().as_str());
    let digest = ring::digest::digest(&ring::digest::SHA256, &body);
    assert_eq!(
        eventstream::base64_decode(sent["x-content-sha256"].to_str()?).as_deref(),
        Some(digest.as_ref())
    );
    let der: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let pair = RsaKeyPair::from_pkcs8(&eventstream::base64_decode(&der).ok_or("pem")?)
        .map_err(|_| "key")?;
    let signature = eventstream::base64_decode(&field("signature")?).ok_or("signature")?;
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, pair.public().as_ref())
        .verify(lines.join("\n").as_bytes(), &signature)
        .map_err(|_| "the signature does not verify")?;
    Ok(())
}

#[tokio::test]
async fn triton_generate_through_passthrough_is_metered_from_its_token_counts() -> TestResult {
    let stream = concat!(
        "data: {\"model_name\":\"llama\",\"text_output\":\"Hel\",\"num_input_tokens\":12,\"num_output_tokens\":1}\n\n",
        "data: {\"model_name\":\"llama\",\"text_output\":\"lo\",\"num_input_tokens\":12,\"num_output_tokens\":2}\n\n",
    );
    let triton = mock(vec![
        Reply::Json(json!({"model_name": "llama", "model_version": "1", "text_output": "Hi there", "num_input_tokens": 12, "num_output_tokens": 3})),
        Reply::Bytes("text/event-stream; charset=utf-8", stream.as_bytes().to_vec()),
    ])
    .await?;
    let policy = budgeted(
        everyone().with_rule_change(|rule| {
            rule.passthrough = vec![gantry_core::policy::Passthrough {
                provider: "triton".into(),
                paths: vec!["/v2/models".into()],
            }];
        }),
        &[("llama", priced(1.0, 2.0, 100))],
    );
    let gw = gateway(
        "triton-generate",
        vec![ProviderRoute {
            key: None,
            ..route("triton", Kind::OpenAi, triton.url(""), &["llama"])
        }],
        policy,
    )?;
    let generate = json!({"text_input": "hi", "parameters": {"max_tokens": 16, "return_num_input_tokens": true, "return_num_output_tokens": true}});
    let (status, headers, text) = post(
        &gw,
        "/passthrough/triton/v2/models/llama/generate",
        &generate,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(triton.first()?.0, "/v2/models/llama/generate");
    let (decision, usage) = records_of(&gw, &headers).await?;
    assert_eq!(decision["model"], "llama");
    assert_eq!(tokens(&usage), (Some("reported"), Some(12), Some(3)));
    assert!(close(cost(&usage), (12.0 + 6.0) / 1e6));
    let (status, headers, text) = post(
        &gw,
        "/passthrough/triton/v2/models/llama/generate_stream",
        &generate,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (_, usage) = records_of(&gw, &headers).await?;
    assert_eq!(
        tokens(&usage),
        (Some("reported"), Some(12), Some(3)),
        "{usage} {text}"
    );
    // A model without a price under a budget cannot be counted: refused, never sent.
    let (status, _, text) = post(
        &gw,
        "/passthrough/triton/v2/models/unpriced/generate",
        &generate,
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
    assert!(text.contains("no_price"), "{text}");
    assert_eq!(triton.hits.load(Ordering::SeqCst), 2);
    Ok(())
}

// 9. The provider long tail: images beyond OpenAI, Bedrock rerank, token counts everywhere, OCR, the api-key header.

fn with_price(model: &str, price: gantry_core::usage::Price) -> Policy {
    let mut map = gantry_core::usage::PriceOverrides::default();
    map.insert(model.to_string(), price);
    everyone().with_prices(map)
}

#[tokio::test]
async fn images_are_drawn_by_gemini_vertex_and_bedrock_and_priced_by_the_image() -> TestResult {
    let google = mock(vec![
        Reply::Json(
            json!({"predictions": [{"bytesBase64Encoded": "QQ==", "mimeType": "image/png"}, {"bytesBase64Encoded": "Qg=="}]}),
        ),
        Reply::Json(
            json!({"candidates": [{"content": {"parts": [{"inlineData": {"mimeType": "image/png", "data": "Qw=="}}]}}], "usageMetadata": {"promptTokenCount": 4, "candidatesTokenCount": 1290}}),
        ),
    ])
    .await?;
    let bedrock = mock(vec![
        Reply::Json(json!({"images": ["RA=="]})),
        Reply::Json(json!({"images": ["RQ=="], "finish_reasons": [null]})),
    ])
    .await?;
    let mut policy = with_price(
        "imagen-4.0-generate-001",
        gantry_core::usage::Price {
            per_image: Some(0.04),
            ..priced(0.0, 0.0, 0)
        },
    );
    policy = policy.with_rule("everyone", Who::Any, Models::Any);
    let gw = gateway(
        "images-tail",
        vec![
            route(
                "gemini",
                Kind::Gemini,
                google.url(""),
                &["imagen-4.0-generate-001", "gemini-2.5-flash-image"],
            ),
            converse(
                bedrock.url(""),
                &[
                    ("nova-canvas", "amazon.nova-canvas-v1:0"),
                    ("sd3", "stability.sd3-5-large-v1:0"),
                    ("nova-pro", "amazon.nova-pro-v1:0"),
                ],
            ),
        ],
        policy,
    )?;
    // Imagen: predict, two images, each charged.
    let (status, headers, text) = post(
        &gw,
        "/v1/images/generations",
        &json!({"model": "imagen-4.0-generate-001", "prompt": "a red kite", "n": 2, "size": "1024x1024"}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, sent, body) = google.first()?;
    assert_eq!(target, "/v1beta/models/imagen-4.0-generate-001:predict");
    assert_eq!(sent["x-goog-api-key"], "gemini-provider-key");
    assert_eq!(
        serde_json::from_slice::<Value>(&body)?,
        json!({"instances": [{"prompt": "a red kite"}], "parameters": {"sampleCount": 2, "aspectRatio": "1:1"}})
    );
    let answer: Value = serde_json::from_str(&text)?;
    assert_eq!(
        answer["data"],
        json!([{"b64_json": "QQ=="}, {"b64_json": "Qg=="}])
    );
    let (decision, usage) = records_of(&gw, &headers).await?;
    assert_eq!(decision["path"], "/v1/images/generations");
    assert!(close(cost(&usage), 0.08), "{usage}");

    // A Gemini model that writes images: generateContent.
    let (status, _, text) = post(
        &gw,
        "/v1/images/generations",
        &json!({"model": "gemini-2.5-flash-image", "prompt": "a blue kite"}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, _, body) = google.nth(1)?;
    assert_eq!(
        target,
        "/v1beta/models/gemini-2.5-flash-image:generateContent"
    );
    let body: Value = serde_json::from_slice(&body)?;
    assert_eq!(body["contents"][0]["parts"][0]["text"], "a blue kite");
    assert_eq!(
        body["generationConfig"]["responseModalities"],
        json!(["TEXT", "IMAGE"])
    );
    assert_eq!(
        serde_json::from_str::<Value>(&text)?["data"][0]["b64_json"],
        "Qw=="
    );

    // Nova Canvas and Stability AI on Bedrock: InvokeModel, signed.
    let (status, _, text) = post(
        &gw,
        "/v1/images/generations",
        &json!({"model": "nova-canvas", "prompt": "a kite", "size": "1280x720", "quality": "hd"}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, sent, body) = bedrock.first()?;
    assert_eq!(target, "/model/amazon.nova-canvas-v1%3A0/invoke");
    assert!(
        sent[header::AUTHORIZATION]
            .to_str()?
            .starts_with("AWS4-HMAC-SHA256")
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&body)?,
        json!({"taskType": "TEXT_IMAGE", "textToImageParams": {"text": "a kite"}, "imageGenerationConfig": {"numberOfImages": 1, "width": 1280, "height": 720, "quality": "premium"}})
    );
    assert_eq!(
        serde_json::from_str::<Value>(&text)?["data"][0]["b64_json"],
        "RA=="
    );
    let (status, _, text) = post(
        &gw,
        "/v1/images/generations",
        &json!({"model": "sd3", "prompt": "a kite", "size": "1024x1024"}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(
        serde_json::from_slice::<Value>(&bedrock.nth(1)?.2)?,
        json!({"prompt": "a kite", "output_format": "png", "aspect_ratio": "1:1"})
    );

    // A parameter with no equivalent, and a model that draws nothing, are refused before anything is sent.
    let before = (
        google.hits.load(Ordering::SeqCst),
        bedrock.hits.load(Ordering::SeqCst),
    );
    for (body, names) in [
        (
            json!({"model": "sd3", "prompt": "a kite", "n": 3}),
            "one image per request",
        ),
        (
            json!({"model": "nova-canvas", "prompt": "a kite", "style": "vivid"}),
            "\\\"style\\\"",
        ),
        (
            json!({"model": "imagen-4.0-generate-001", "prompt": "a kite", "response_format": "url"}),
            "response_format",
        ),
        (
            json!({"model": "nova-pro", "prompt": "a kite"}),
            "not an image model",
        ),
    ] {
        let (status, _, text) = post(&gw, "/v1/images/generations", &body).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
        assert!(text.contains(names), "{text}");
    }
    assert_eq!(
        before,
        (
            google.hits.load(Ordering::SeqCst),
            bedrock.hits.load(Ordering::SeqCst)
        )
    );
    Ok(())
}

#[tokio::test]
async fn bedrock_reranks_with_its_rerank_models() -> TestResult {
    let bedrock = mock(vec![Reply::Json(
        json!({"results": [{"index": 1, "relevance_score": 0.92}, {"index": 0, "relevance_score": 0.11}]}),
    )])
    .await?;
    let gw = gateway(
        "bedrock-rerank",
        vec![converse(
            bedrock.url(""),
            &[
                ("rerank", "cohere.rerank-v3-5:0"),
                ("amazon-rerank", "amazon.rerank-v1:0"),
            ],
        )],
        everyone(),
    )?;
    let ask = json!({"model": "rerank", "query": "capital of France", "documents": ["Berlin", "Paris"], "top_n": 2});
    let (status, headers, text) = post(&gw, "/v1/rerank", &ask).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, sent, body) = bedrock.first()?;
    assert_eq!(target, "/model/cohere.rerank-v3-5%3A0/invoke");
    assert!(
        sent[header::AUTHORIZATION]
            .to_str()?
            .starts_with("AWS4-HMAC-SHA256")
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&body)?,
        json!({"query": "capital of France", "documents": ["Berlin", "Paris"], "top_n": 2, "api_version": 2})
    );
    let answer: Value = serde_json::from_str(&text)?;
    assert_eq!(
        answer["results"][0],
        json!({"index": 1, "relevance_score": 0.92})
    );
    assert_eq!(answer["model"], "rerank");
    let decision = decision_of(&gw, &headers)?;
    assert_eq!(
        (decision["path"].as_str(), decision["provider"].as_str()),
        (Some("/v1/rerank"), Some("bedrock"))
    );
    // Amazon's model takes the same body without Cohere's version; a field with no equivalent is refused.
    let mut amazon = ask.clone();
    amazon["model"] = "amazon-rerank".into();
    let (status, _, text) = post(&gw, "/v1/rerank", &amazon).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert!(
        serde_json::from_slice::<Value>(&bedrock.nth(1)?.2)?
            .get("api_version")
            .is_none()
    );
    amazon["rank_fields"] = json!(["title"]);
    let (status, _, text) = post(&gw, "/v1/rerank", &amazon).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    assert!(text.contains("rank_fields"), "{text}");
    Ok(())
}

#[tokio::test]
async fn tokens_are_counted_by_every_provider_that_can_and_estimated_and_labelled_otherwise()
-> TestResult {
    let bedrock = mock(vec![Reply::Json(json!({"inputTokens": 17}))]).await?;
    let anthropic = mock(vec![Reply::Json(json!({"input_tokens": 23}))]).await?;
    let openai = mock(vec![Reply::Json(
        json!({"object": "response.input_tokens", "input_tokens": 31}),
    )])
    .await?;
    let groq = mock(vec![Reply::Status(404)]).await?;
    let mut chat = route("groq", Kind::OpenAi, groq.url("/openai/v1"), &["llama-4"]);
    chat.accept_messages = true;
    let mut converse = converse(bedrock.url(""), &[("nova", "amazon.nova-pro-v1:0")]);
    converse.accept_messages = true;
    let gw = gateway(
        "counts-tail",
        vec![
            converse,
            route(
                "anthropic",
                Kind::Anthropic,
                anthropic.url(""),
                &["claude-sonnet-5-5"],
            ),
            route("openai", Kind::OpenAi, openai.url(""), &["gpt-5"]),
            chat,
        ],
        everyone(),
    )?;
    let messages = |model: &str| json!({"model": model, "system": "Be brief.", "messages": [{"role": "user", "content": "How tall is the Eiffel Tower?"}]});
    // Bedrock Converse: Bedrock's CountTokens, with the request as a Converse body.
    let (status, _, text) = post(&gw, "/v1/messages/count_tokens", &messages("nova")).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(
        serde_json::from_str::<Value>(&text)?,
        json!({"input_tokens": 17})
    );
    let (target, _, body) = bedrock.first()?;
    assert_eq!(target, "/model/amazon.nova-pro-v1%3A0/count-tokens");
    let body: Value = serde_json::from_slice(&body)?;
    assert_eq!(
        body["input"]["converse"]["messages"][0]["content"][0]["text"],
        "How tall is the Eiffel Tower?"
    );
    assert_eq!(body["input"]["converse"]["system"][0]["text"], "Be brief.");

    // A chat provider has no count API: Gantry estimates, says so, and sends the provider nothing.
    let (status, headers, text) =
        post(&gw, "/v1/messages/count_tokens", &messages("llama-4")).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    // Every string of the request but its model, 42 characters, four to a token.
    assert_eq!(
        serde_json::from_str::<Value>(&text)?,
        json!({"input_tokens": 11, "estimated": true})
    );
    assert_eq!(headers["x-gantry-token-count"], "estimate");
    assert_eq!(groq.hits.load(Ordering::SeqCst), 0);
    let decision = decision_of(&gw, &headers)?;
    assert_eq!(
        (decision["verdict"].as_str(), decision["provider"].as_str()),
        (Some("allow"), Some("groq"))
    );

    // The Responses API's input token count: as sent to OpenAI, as a messages count to Claude, an estimate elsewhere.
    let responses = |model: &str| json!({"model": model, "instructions": "Be brief.", "input": "How tall is the Eiffel Tower?"});
    let (status, _, text) = post(&gw, "/v1/responses/input_tokens", &responses("gpt-5")).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(
        serde_json::from_str::<Value>(&text)?,
        json!({"object": "response.input_tokens", "input_tokens": 31})
    );
    let (target, _, body) = openai.first()?;
    assert_eq!(target, "/v1/responses/input_tokens");
    assert_eq!(
        serde_json::from_slice::<Value>(&body)?["input"],
        "How tall is the Eiffel Tower?"
    );
    let (status, _, text) = post(
        &gw,
        "/v1/responses/input_tokens",
        &responses("claude-sonnet-5-5"),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(
        serde_json::from_str::<Value>(&text)?,
        json!({"object": "response.input_tokens", "input_tokens": 23})
    );
    let (target, _, body) = anthropic.first()?;
    assert_eq!(target, "/v1/messages/count_tokens");
    let body: Value = serde_json::from_slice(&body)?;
    assert_eq!(body["system"][0]["text"], "Be brief.");
    assert!(
        body.get("max_tokens").is_none() && body.get("stream").is_none(),
        "{body}"
    );
    let (status, headers, text) =
        post(&gw, "/v1/responses/input_tokens", &responses("llama-4")).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let answer: Value = serde_json::from_str(&text)?;
    assert_eq!(
        (answer["object"].as_str(), answer["estimated"].as_bool()),
        (Some("response.input_tokens"), Some(true))
    );
    assert_eq!(headers["x-gantry-token-count"], "estimate");
    // A provider of kind openai was asked first, and has no such route.
    assert_eq!(groq.first()?.0, "/openai/v1/responses/input_tokens");
    // A model the rule does not allow is not counted either.
    let policy = Policy::new()
        .with_key(MAYA, "maya.cohen", "payments")
        .with_rule("some", Who::Any, Models::Only(vec!["nova".into()]));
    let strict = gateway(
        "counts-tail-strict",
        vec![route("openai", Kind::OpenAi, openai.url(""), &["gpt-5"])],
        policy,
    )?;
    let (status, _, text) =
        post(&strict, "/v1/responses/input_tokens", &responses("gpt-5")).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
    Ok(())
}

#[tokio::test]
async fn an_azure_sdks_api_key_header_carries_the_gantry_key_and_never_reaches_the_provider()
-> TestResult {
    let openai = mock(vec![Reply::Json(
        json!({"id": "c1", "object": "chat.completion", "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hi"}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4}}),
    )])
    .await?;
    let gw = gateway(
        "api-key-header",
        vec![route("openai", Kind::OpenAi, openai.url(""), &["gpt-5"])],
        everyone(),
    )?;
    let chat = json!({"model": "gpt-5", "messages": [{"role": "user", "content": "hi"}]});
    let with = |headers: &[(&str, &str)]| -> Result<Request<Body>, axum::http::Error> {
        let mut request =
            Request::post("/v1/chat/completions").header(header::CONTENT_TYPE, "application/json");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        request.body(Body::from(chat.to_string()))
    };
    let (status, headers, text) = send(&gw, with(&[("api-key", MAYA)])?).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(decision_of(&gw, &headers)?["person"], "maya.cohen");
    let (_, sent, _) = openai.first()?;
    assert!(
        sent.get("api-key").is_none(),
        "the Gantry key went to the provider"
    );
    assert_eq!(sent[header::AUTHORIZATION], "Bearer openai-provider-key");
    // Two different credentials are refused, as for the other headers; an unknown key is unknown.
    let (status, _, text) = send(
        &gw,
        with(&[("api-key", MAYA), ("x-api-key", "gantry_other")])?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    assert!(text.contains("ambiguous_key"), "{text}");
    let (status, _, text) = send(&gw, with(&[("api-key", "gantry_nobody")])?).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{text}");
    assert_eq!(openai.hits.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn a_document_is_read_by_mistrals_ocr_and_charged_by_the_page() -> TestResult {
    let mistral = mock(vec![Reply::Json(
        json!({"pages": [{"index": 0, "markdown": "# Invoice"}, {"index": 1, "markdown": "Total: 12"}], "model": "mistral-ocr-latest", "usage_info": {"pages_processed": 2, "doc_size_bytes": 4096}}),
    )])
    .await?;
    let policy = with_price(
        "mistral-ocr-latest",
        gantry_core::usage::Price {
            per_page: Some(0.001),
            ..priced(0.0, 0.0, 0)
        },
    );
    let gw = gateway(
        "ocr",
        vec![
            route(
                "mistral",
                Kind::OpenAi,
                mistral.url(""),
                &["mistral-ocr-latest"],
            ),
            route(
                "anthropic",
                Kind::Anthropic,
                mistral.url(""),
                &["claude-sonnet-5-5"],
            ),
        ],
        policy,
    )?;
    let ask = json!({"model": "mistral-ocr-latest", "document": {"type": "document_url", "document_url": "https://example.com/invoice.pdf"}});
    let (status, headers, text) = post(&gw, "/v1/ocr", &ask).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, sent, body) = mistral.first()?;
    assert_eq!(target, "/v1/ocr");
    assert_eq!(sent[header::AUTHORIZATION], "Bearer mistral-provider-key");
    assert_eq!(serde_json::from_slice::<Value>(&body)?, ask);
    assert_eq!(
        serde_json::from_str::<Value>(&text)?["pages"][1]["markdown"],
        "Total: 12"
    );
    let (decision, usage) = records_of(&gw, &headers).await?;
    assert_eq!(
        (decision["path"].as_str(), decision["model"].as_str()),
        (Some("/v1/ocr"), Some("mistral-ocr-latest"))
    );
    assert!(close(cost(&usage), 0.002), "{usage}");
    // A provider with no OCR API is named, and nothing is sent.
    let (status, _, text) = post(
        &gw,
        "/v1/ocr",
        &json!({"model": "claude-sonnet-5-5", "document": {}}),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    assert!(text.contains("wrong_route"), "{text}");
    assert_eq!(mistral.hits.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn an_aws_sdk_pointed_at_gantry_reaches_bedrock_with_a_gantry_key() -> TestResult {
    let bedrock = mock(vec![Reply::Json(converse_answer())]).await?;
    let policy = Policy::new()
        .with_key(MAYA, "maya.cohen", "payments")
        .with_rule("payments", Who::Any, Models::Only(vec!["nova-pro".into()]));
    let gw = gateway(
        "bedrock-sdk",
        vec![converse(
            bedrock.url(""),
            &[
                ("nova-pro", "amazon.nova-pro-v1:0"),
                ("nova-lite", "amazon.nova-lite-v1:0"),
            ],
        )],
        policy,
    )?;
    let native = json!({"messages": [{"role": "user", "content": [{"text": "hi"}]}]});
    let sdk = |path: &str, headers: &[(&str, &str)]| -> Result<Request<Body>, axum::http::Error> {
        let mut request = Request::post(path).header(header::CONTENT_TYPE, "application/json");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        request.body(Body::from(native.to_string()))
    };
    // As boto3 sends it: the model ID's colon escaped, the request signed with the caller's AWS credentials (which
    // Gantry cannot check and takes off), and the Gantry key in x-api-key.
    let signed = "AWS4-HMAC-SHA256 Credential=AKIACALLER/20261115/us-east-1/bedrock/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc";
    let (status, headers, text) = send(
        &gw,
        sdk(
            "/model/amazon.nova-pro-v1%3A0/converse",
            &[
                ("authorization", signed),
                ("x-amz-date", "20261115T000000Z"),
                ("x-amz-security-token", "caller-session"),
                ("x-api-key", MAYA),
            ],
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(
        serde_json::from_str::<Value>(&text)?["stopReason"],
        "tool_use"
    );
    let (target, sent, body) = bedrock.first()?;
    assert_eq!(target, "/model/amazon.nova-pro-v1%3A0/converse");
    // Signed by Gantry with the provider's credentials; nothing of the caller's signature or key went on.
    assert!(
        sent[header::AUTHORIZATION]
            .to_str()?
            .starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/")
    );
    assert!(sent.get("x-api-key").is_none() && sent.get("x-amz-security-token").is_none());
    assert_eq!(serde_json::from_slice::<Value>(&body)?, native);
    let (decision, usage) = records_of(&gw, &headers).await?;
    assert_eq!(
        (
            decision["person"].as_str(),
            decision["model"].as_str(),
            decision["provider"].as_str()
        ),
        (Some("maya.cohen"), Some("nova-pro"), Some("bedrock"))
    );
    assert_eq!(tokens(&usage), (Some("reported"), Some(1000), Some(500)));

    // An SDK given the Gantry key as its Bedrock API key sends it as a Bearer token; the policy's own name for the
    // model works in the path too.
    let bearer = format!("Bearer {MAYA}");
    let (status, _, text) = send(
        &gw,
        sdk("/model/nova-pro/converse", &[("authorization", &bearer)])?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(bedrock.nth(1)?.0, "/model/amazon.nova-pro-v1%3A0/converse");

    // A model the rule does not allow, and a request with no Gantry key, are refused in the shape the SDK reads,
    // and nothing is sent.
    let (status, headers, text) = send(
        &gw,
        sdk(
            "/model/amazon.nova-lite-v1%3A0/converse",
            &[("authorization", &bearer)],
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
    let refusal: Value = serde_json::from_str(&text)?;
    assert_eq!(headers["x-amzn-errortype"], "AccessDeniedException");
    assert_eq!(refusal["gantry_code"], "model_not_allowed");
    assert!(
        refusal["message"]
            .as_str()
            .unwrap_or_default()
            .contains("nova-lite"),
        "{text}"
    );
    let (status, headers, text) = send(
        &gw,
        sdk("/model/nova-pro/converse", &[("authorization", signed)])?,
    )
    .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{text}");
    assert_eq!(headers["x-amzn-errortype"], "AccessDeniedException");
    // Only the runtime's inference routes are served this way: anything else under /model is not a route.
    let (status, _, _) = send(
        &gw,
        sdk("/model/nova-pro/delete", &[("authorization", &bearer)])?,
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(bedrock.hits.load(Ordering::SeqCst), 2);
    Ok(())
}
