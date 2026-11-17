//! Google's own Gemini API through Enterplace, as Gemini CLI and Google's SDKs send it: `/v1beta/models/<model>:<method>`
//! with the Enterplace key in `x-goog-api-key` or `?key=`, governed like the chat route. Every provider is a mock on
//! 127.0.0.1, on a port the system picks.

use std::{
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
    response::IntoResponse,
};
use enterplace_core::{
    audit::AuditLog,
    config::{Alias, Deployment, Kind},
    guard::{Action, Check, Guardrail, On},
    id::sha256_hex,
    policy::{Limits, Models, Policy, Who},
    usage::{Price, PriceOverrides},
};
use enterplace_server::{Audit, Config, ProviderRoute, Secret, Timeouts};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const MAYA: &str = "enterplace_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const AGENT: &str = "GeminiCLI/0.68.0/gemini-2.5-flash (darwin; arm64)";

#[derive(Default)]
struct Mock {
    port: u16,
    hits: AtomicUsize,
    seen: Mutex<Vec<(String, HeaderMap, Bytes)>>,
    reply: (&'static str, String),
}

impl Mock {
    fn last(&self) -> Result<(String, HeaderMap, Bytes), &'static str> {
        self.seen
            .lock()
            .map_err(|_| "poisoned")?
            .last()
            .cloned()
            .ok_or("the provider was sent nothing")
    }
}

/// A mock provider that answers every request with `reply` (content type, body).
async fn mock(
    content_type: &'static str,
    body: String,
) -> Result<Arc<Mock>, Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let state = Arc::new(Mock {
        port: listener.local_addr()?.port(),
        reply: (content_type, body),
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
            ([(header::CONTENT_TYPE, mock.reply.0)], mock.reply.1.clone()).into_response()
        }
    });
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(state)
}

fn provider(name: &str, kind: Kind, url: String, models: &[&str]) -> ProviderRoute {
    ProviderRoute {
        name: name.into(),
        kind,
        url,
        key: Some(Secret::new(format!("{name}-provider-key"))),
        models: models.iter().map(|m| m.to_string()).collect(),
        ..ProviderRoute::default()
    }
}

fn gemini(mock: &Mock) -> ProviderRoute {
    provider(
        "gemini",
        Kind::Gemini,
        format!("http://127.0.0.1:{}", mock.port),
        &["gemini-2.5-flash", "gemini-2.5-pro", "gemini-embedding-001"],
    )
}

fn flash_only() -> Policy {
    Policy::new()
        .with_key(MAYA, "maya.cohen", "payments")
        .with_rule(
            "flash",
            Who::Any,
            Models::Only(vec![
                "gemini-2.5-flash".into(),
                "gemini-embedding-001".into(),
            ]),
        )
}

struct Gateway {
    app: Router,
    log: std::path::PathBuf,
}

fn gateway(
    name: &str,
    providers: Vec<ProviderRoute>,
    policy: Policy,
) -> Result<Gateway, Box<dyn std::error::Error>> {
    let log = std::env::temp_dir().join(format!(
        "enterplace-gemini-native-{}-{name}.jsonl",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&log);
    let app = enterplace_server::app(Config {
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

/// Sends a request as Gemini CLI does: its user agent, and the key in x-goog-api-key unless the path carries it.
async fn send(
    gw: &Gateway,
    method: &str,
    path: &str,
    body: &str,
) -> Result<(StatusCode, HeaderMap, String), Box<dyn std::error::Error>> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::USER_AGENT, AGENT)
        .header(header::CONTENT_TYPE, "application/json");
    if !path.contains("key=") {
        request = request.header("x-goog-api-key", MAYA);
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

fn records(gw: &Gateway) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
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
    let id = headers["x-enterplace-decision"].to_str()?.to_string();
    for _ in 0..100 {
        let all = records(gw)?;
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

fn answer(text: &str) -> String {
    json!({
        "candidates": [{"index": 0, "finishReason": "STOP", "content": {"role": "model", "parts": [{"text": text}]}}],
        "usageMetadata": {"promptTokenCount": 1000, "candidatesTokenCount": 400, "thoughtsTokenCount": 100, "totalTokenCount": 1500},
        "modelVersion": "gemini-2.5-flash"
    })
    .to_string()
}

fn sse(pieces: &[&str]) -> String {
    pieces
        .iter()
        .enumerate()
        .map(|(i, piece)| {
            format!(
                "data: {}\r\n\r\n",
                json!({
                    "candidates": [{"index": 0, "content": {"role": "model", "parts": [{"text": piece}]}}],
                    "usageMetadata": {"promptTokenCount": 7, "candidatesTokenCount": i + 1}
                })
            )
        })
        .collect()
}

// Gemini CLI sends this, with fields Enterplace does not know: they pass through untouched.
const BODY: &str = r#"{"contents":[{"role":"user","parts":[{"text":"Hi"}]}],"systemInstruction":{"parts":[{"text":"Be brief."}]},"generationConfig":{"temperature":0,"thinkingConfig":{"includeThoughts":true}},"futureField":{"x":1}}"#;

fn price() -> PriceOverrides {
    let mut prices = PriceOverrides::new();
    prices.insert(
        "gemini-2.5-flash".into(),
        Price {
            input: 1.0,
            output: 2.0,
            cache_read: None,
            cache_write: None,
            cache_write_1h: None,
            long_context: None,
            max_output: None,
            max_context: None,
            per_image: None,
            source: Default::default(),
            ..Price::default()
        },
    );
    prices
}

#[tokio::test]
async fn generate_content_with_the_key_in_x_goog_api_key_is_governed_and_recorded() -> TestResult {
    let upstream = mock("application/json", answer("Hello.")).await?;
    let gw = gateway(
        "header",
        vec![gemini(&upstream)],
        flash_only().with_prices(price()),
    )?;
    let (status, headers, text) = send(
        &gw,
        "POST",
        "/v1beta/models/gemini-2.5-flash:generateContent",
        BODY,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(
        serde_json::from_str::<Value>(&text)?["candidates"][0]["content"]["parts"][0]["text"],
        "Hello."
    );
    let (target, sent_headers, sent) = upstream.last()?;
    assert_eq!(target, "/v1beta/models/gemini-2.5-flash:generateContent");
    assert_eq!(sent_headers["x-goog-api-key"], "gemini-provider-key");
    assert!(sent_headers.get(header::AUTHORIZATION).is_none());
    // Unknown fields pass through as sent (AGENTS.md rule 7).
    assert_eq!(
        serde_json::from_slice::<Value>(&sent)?,
        serde_json::from_str::<Value>(BODY)?
    );
    let (decision, usage) = records_of(&gw, &headers).await?;
    assert_eq!(decision["verdict"], "allow", "{decision}");
    assert_eq!(decision["model"], "gemini-2.5-flash");
    assert_eq!(decision["user_agent"], AGENT);
    assert_eq!(decision["provider"], "gemini");
    assert_eq!(usage["input_tokens"], 1000, "{usage}");
    assert_eq!(usage["output_tokens"], 500, "{usage}");
    assert!(
        usage["cost_usd"]
            .as_f64()
            .is_some_and(|c| (c - 0.002).abs() < 1e-9),
        "{usage}"
    );
    Ok(())
}

#[tokio::test]
async fn the_key_in_the_query_works_and_never_reaches_the_provider_or_the_records() -> TestResult {
    let upstream = mock("text/event-stream", sse(&["Hel", "lo"])).await?;
    let gw = gateway("query", vec![gemini(&upstream)], flash_only())?;
    let path = format!("/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse&key={MAYA}");
    let (status, headers, text) = send(&gw, "POST", &path, BODY).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert!(
        headers[header::CONTENT_TYPE]
            .to_str()?
            .starts_with("text/event-stream")
    );
    assert!(text.contains("Hel") && text.contains("lo"), "{text}");
    let (target, sent_headers, _) = upstream.last()?;
    assert_eq!(
        target,
        "/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse"
    );
    assert!(sent_headers.values().all(|v| {
        !v.as_bytes()
            .windows(MAYA.len())
            .any(|w| w == MAYA.as_bytes())
    }));
    let (decision, usage) = records_of(&gw, &headers).await?;
    assert_eq!(decision["verdict"], "allow");
    assert_eq!(usage["output_tokens"], 2, "{usage}");
    let log = std::fs::read_to_string(&gw.log)?;
    assert!(!log.contains(MAYA) && !log.contains("key="), "{log}");
    Ok(())
}

#[tokio::test]
async fn a_stream_without_alt_sse_comes_back_as_a_json_array() -> TestResult {
    let upstream = mock("text/event-stream", sse(&["Hel", "lo"])).await?;
    let gw = gateway("array", vec![gemini(&upstream)], flash_only())?;
    let (status, headers, text) = send(
        &gw,
        "POST",
        "/v1beta/models/gemini-2.5-flash:streamGenerateContent",
        BODY,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert!(
        headers[header::CONTENT_TYPE]
            .to_str()?
            .starts_with("application/json")
    );
    let chunks: Vec<Value> = serde_json::from_str(&text)?;
    assert_eq!(chunks.len(), 2, "{text}");
    assert_eq!(
        chunks[1]["candidates"][0]["content"]["parts"][0]["text"],
        "lo"
    );
    // Enterplace reads the stream as events to meter and guard it.
    assert_eq!(
        upstream.last()?.0,
        "/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse"
    );
    let (_, usage) = records_of(&gw, &headers).await?;
    assert_eq!(usage["output_tokens"], 2, "{usage}");
    Ok(())
}

#[tokio::test]
async fn count_tokens_and_embeddings_reach_their_methods() -> TestResult {
    let upstream = mock("application/json", r#"{"totalTokens":3}"#.into()).await?;
    let gw = gateway("methods", vec![gemini(&upstream)], flash_only())?;
    for (path, body) in [
        (
            "/v1beta/models/gemini-2.5-flash:countTokens",
            r#"{"contents":[{"parts":[{"text":"Hi"}]}]}"#,
        ),
        (
            "/v1beta/models/gemini-embedding-001:embedContent",
            r#"{"content":{"parts":[{"text":"Hi"}]}}"#,
        ),
        (
            "/v1beta/models/gemini-embedding-001:batchEmbedContents",
            r#"{"requests":[{"model":"models/gemini-embedding-001","content":{"parts":[{"text":"Hi"}]}}]}"#,
        ),
        ("/v1/models/gemini-2.5-flash:generateContent", BODY),
    ] {
        let (status, _, text) = send(&gw, "POST", path, body).await?;
        assert_eq!(status, StatusCode::OK, "{path}: {text}");
        assert_eq!(upstream.last()?.0, path);
    }
    Ok(())
}

#[tokio::test]
async fn an_alias_in_a_count_tokens_body_is_sent_as_its_deployment() -> TestResult {
    let upstream = mock("application/json", r#"{"totalTokens":3}"#.into()).await?;
    let app = enterplace_server::app(Config {
        providers: vec![gemini(&upstream)],
        aliases: vec![Alias {
            name: "fast".into(),
            deployments: vec![Deployment {
                provider: "gemini".into(),
                model: "gemini-2.5-flash".into(),
                weight: 1,
                ..Deployment::default()
            }],
            ..Alias::default()
        }],
        policy: Some(
            Policy::new()
                .with_key(MAYA, "maya.cohen", "payments")
                .with_rule("fast", Who::Any, Models::Only(vec!["fast".into()])),
        ),
        timeouts: Timeouts::default(),
        ..Config::default()
    })?;
    let gw = Gateway {
        app,
        log: std::path::PathBuf::new(),
    };
    let (status, _, text) = send(
        &gw,
        "POST",
        "/v1beta/models/fast:countTokens",
        r#"{"generateContentRequest":{"model":"models/fast","contents":[{"parts":[{"text":"Hi"}]}]}}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, _, body) = upstream.last()?;
    assert_eq!(target, "/v1beta/models/gemini-2.5-flash:countTokens");
    let body: Value = serde_json::from_slice(&body)?;
    assert_eq!(
        body["generateContentRequest"]["model"], "models/gemini-2.5-flash",
        "the provider does not know the alias: {body}"
    );
    assert_eq!(
        body["generateContentRequest"]["contents"][0]["parts"][0]["text"],
        "Hi"
    );
    Ok(())
}

#[tokio::test]
async fn the_model_list_shows_only_what_the_rule_allows() -> TestResult {
    let upstream = mock("application/json", "{}".into()).await?;
    let gw = gateway("list", vec![gemini(&upstream)], flash_only())?;
    let (status, _, text) = send(&gw, "GET", "/v1beta/models", "").await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let list: Value = serde_json::from_str(&text)?;
    let names: Vec<&str> = list["models"]
        .as_array()
        .ok_or("no models")?
        .iter()
        .filter_map(|m| m["name"].as_str())
        .collect();
    assert_eq!(
        names,
        ["models/gemini-2.5-flash", "models/gemini-embedding-001"]
    );
    let (status, _, text) = send(&gw, "GET", "/v1beta/models/gemini-2.5-flash", "").await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(
        serde_json::from_str::<Value>(&text)?["name"],
        "models/gemini-2.5-flash"
    );
    let (status, _, text) = send(&gw, "GET", "/v1beta/models/gemini-2.5-pro", "").await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "{text}");
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn refusals_are_in_google_s_shape_recorded_and_never_sent() -> TestResult {
    let upstream = mock("application/json", answer("x")).await?;
    let policy = flash_only().with_guardrails(&[Guardrail {
        name: "no-secrets".into(),
        action: Action::Block,
        check: Check::Secrets,
        on: On::REQUEST,
        shadow_until: None,
    }]);
    let gw = gateway("refusals", vec![gemini(&upstream)], policy)?;
    // A model the rule does not allow.
    let (status, _, text) = send(
        &gw,
        "POST",
        "/v1beta/models/gemini-2.5-pro:generateContent",
        BODY,
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
    let error: Value = serde_json::from_str(&text)?;
    assert_eq!(error["error"]["code"], 403, "{text}");
    assert_eq!(error["error"]["status"], "PERMISSION_DENIED", "{text}");
    assert!(
        error["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("model_not_allowed")),
        "{text}"
    );
    // A secret in the prompt, or in a tool's result.
    for body in [
        r#"{"contents":[{"role":"user","parts":[{"text":"key AKIAIOSFODNN7EXAMPLE"}]}]}"#,
        r#"{"contents":[{"role":"user","parts":[{"functionResponse":{"name":"read","response":{"output":"AKIAIOSFODNN7EXAMPLE"}}}]}]}"#,
    ] {
        let (status, _, text) = send(
            &gw,
            "POST",
            "/v1beta/models/gemini-2.5-flash:generateContent",
            body,
        )
        .await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
        assert!(text.contains("guardrail_blocked"), "{text}");
    }
    // A body naming another model than the path.
    let (status, _, text) = send(
        &gw,
        "POST",
        "/v1beta/models/gemini-2.5-flash:countTokens",
        r#"{"generateContentRequest":{"model":"models/gemini-2.5-pro","contents":[]}}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    // No key at all.
    let request =
        Request::post("/v1beta/models/gemini-2.5-flash:generateContent").body(Body::from(BODY))?;
    let response = gw.app.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    // A key in the header and another in the query.
    let path = "/v1beta/models/gemini-2.5-flash:generateContent?key=enterplace_other";
    let request = Request::post(path)
        .header("x-goog-api-key", MAYA)
        .body(Body::from(BODY))?;
    let response = gw.app.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 0);
    let refused = records(&gw)?
        .iter()
        .filter(|r| r["verdict"] == "refused")
        .count();
    assert_eq!(refused, 6);
    Ok(())
}

#[tokio::test]
async fn a_streamed_answer_is_stopped_where_a_guardrail_blocks_it() -> TestResult {
    let mut pieces: Vec<String> = (0..10).map(|i| format!("Sentence {i} is fine. ")).collect();
    pieces.push("The key is AKIAIOSFODNN7EXAMPLE. ".into());
    pieces.push("After.".into());
    let pieces: Vec<&str> = pieces.iter().map(String::as_str).collect();
    let upstream = mock("text/event-stream", sse(&pieces)).await?;
    let policy = flash_only()
        .with_guardrails(&[Guardrail {
            name: "no-secrets".into(),
            action: Action::Block,
            check: Check::Secrets,
            on: On {
                request: true,
                answer: true,
            },
            shadow_until: None,
        }])
        .with_limits(Limits {
            check_stream_every: Some(40),
            ..Limits::default()
        });
    let gw = gateway("stream-guard", vec![gemini(&upstream)], policy)?;
    let (status, headers, text) = send(
        &gw,
        "POST",
        "/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse",
        BODY,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert!(
        !text.contains("AKIAIOSFODNN7EXAMPLE") && !text.contains("After."),
        "{text}"
    );
    assert!(
        text.contains("guardrail_blocked") || text.contains("stopped the model's answer"),
        "{text}"
    );
    let id = headers["x-enterplace-decision"].to_str()?.to_string();
    let mut blocked = false;
    for _ in 0..100 {
        blocked = records(&gw)?.iter().any(|r| {
            r["id"] == id.as_str() && r["event"] == "answer_guardrails" && r["verdict"] == "block"
        });
        if blocked {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(blocked);
    Ok(())
}

#[tokio::test]
async fn vertex_takes_the_native_body_with_its_bearer_token() -> TestResult {
    let upstream = mock("application/json", answer("Hi")).await?;
    let base = format!(
        "http://127.0.0.1:{}/v1/projects/acme/locations/us-central1/publishers/google",
        upstream.port
    );
    let gw = gateway(
        "vertex",
        vec![provider(
            "vertex",
            Kind::Vertex,
            base,
            &["gemini-2.5-flash"],
        )],
        flash_only(),
    )?;
    let (status, _, text) = send(
        &gw,
        "POST",
        "/v1beta/models/gemini-2.5-flash:generateContent",
        BODY,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (target, headers, body) = upstream.last()?;
    assert_eq!(
        target,
        "/v1/projects/acme/locations/us-central1/publishers/google/models/gemini-2.5-flash:generateContent"
    );
    assert_eq!(headers[header::AUTHORIZATION], "Bearer vertex-provider-key");
    assert_eq!(
        serde_json::from_slice::<Value>(&body)?,
        serde_json::from_str::<Value>(BODY)?
    );
    Ok(())
}

#[tokio::test]
async fn a_model_on_a_chat_provider_is_refused_on_the_native_route() -> TestResult {
    let upstream = mock("application/json", "{}".into()).await?;
    let openai = provider(
        "openai",
        Kind::OpenAi,
        format!("http://127.0.0.1:{}", upstream.port),
        &["gemini-2.5-flash"],
    );
    let gw = gateway("wrong", vec![openai], flash_only())?;
    let (status, _, text) = send(
        &gw,
        "POST",
        "/v1beta/models/gemini-2.5-flash:generateContent",
        BODY,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    assert!(text.contains("wrong_route"), "{text}");
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn a_budget_reads_the_output_limit_from_generation_config() -> TestResult {
    let upstream = mock("application/json", answer("Hi")).await?;
    let policy = flash_only()
        .with_prices(price())
        .with_key_change(MAYA, |p| {
            p.budget = Some(enterplace_core::policy::Budget {
                usd: 1.0,
                per: enterplace_core::policy::Period::Day,
            });
        });
    let gw = gateway("budget", vec![gemini(&upstream)], policy)?;
    let path = "/v1beta/models/gemini-2.5-flash:generateContent";
    // No output limit, and the price has no max_output: the most it could cost is unknown.
    let (status, _, text) = send(&gw, "POST", path, BODY).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    assert!(
        text.contains("max_tokens_needed") && text.contains("generationConfig.maxOutputTokens"),
        "{text}"
    );
    let limited = r#"{"contents":[{"role":"user","parts":[{"text":"Hi"}]}],"generationConfig":{"maxOutputTokens":100}}"#;
    let (status, _, text) = send(&gw, "POST", path, limited).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    // An output limit larger than the budget can pay for is refused before it is sent.
    let huge = r#"{"contents":[],"generationConfig":{"maxOutputTokens":1000000000}}"#;
    let (status, _, text) = send(&gw, "POST", path, huge).await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{text}");
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 1);
    Ok(())
}
