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
    let text = String::from_utf8(response.into_body().collect().await?.to_bytes().to_vec())?;
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
    let (status, _, text) = post(
        &gw,
        "/v1/embeddings",
        &json!({"model": "embed", "input": "hi"}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(
        openai_azure.nth(1)?.0,
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
