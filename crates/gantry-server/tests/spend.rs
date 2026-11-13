//! Acceptance tests for spend: usage records, budgets, rate limits and the cache.
//! Each test's mock provider listens on a port of 127.0.0.1 the system picks.

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
    routing::post,
};
use gantry_core::id::sha256_hex;
use gantry_server::{Governed, Reload, Trigger};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Error = Box<dyn std::error::Error>;

const PAT: &str = "gantry_pat_0123456789abcdef0123456789ab";
const RITA: &str = "gantry_rita_0123456789abcdef0123456789a";
const CARA: &str = "gantry_cara_0123456789abcdef0123456789a";
const OTTO: &str = "gantry_otto_0123456789abcdef0123456789a";
const CAP1: &str = "gantry_cap1_0123456789abcdef0123456789a";
const CAP2: &str = "gantry_cap2_0123456789abcdef0123456789a";

/// A stream whose events come from a channel, so a test can hold it open.
struct Feed(tokio::sync::mpsc::Receiver<Bytes>);

impl futures_core::Stream for Feed {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.0.poll_recv(cx).map(|item| item.map(Ok))
    }
}

fn has(body: &[u8], text: &str) -> bool {
    body.windows(text.len()).any(|w| w == text.as_bytes())
}

fn stream(events: Vec<&'static str>, hold: bool) -> axum::response::Response {
    slow(events, hold, "text/event-stream")
}

/// An answer sent in pieces; with `hold`, the provider waits 30 seconds after the first.
fn slow(events: Vec<&'static str>, hold: bool, content_type: &str) -> axum::response::Response {
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move {
        for (i, event) in events.into_iter().enumerate() {
            if hold && i == 1 {
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
            if tx.send(Bytes::from_static(event.as_bytes())).await.is_err() {
                return;
            }
        }
    });
    axum::response::Response::builder()
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from_stream(Feed(rx)))
        .unwrap_or_default()
}

/// A provider of both kinds, on a port the system picks. Every answer reports usage, except an OpenAI stream that
/// did not ask for it. Model `mo` writes 16384 output tokens whatever it is asked, as a model at its maximum does.
async fn provider() -> Result<(Arc<AtomicUsize>, u16), Error> {
    let hits = Arc::new(AtomicUsize::new(0));
    let (chat_hits, message_hits, count_hits) = (hits.clone(), hits.clone(), hits.clone());
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let app = Router::new()
        .route(
            "/v1/chat/completions",
            post(move |body: Bytes| async move {
                chat_hits.fetch_add(1, Ordering::SeqCst);
                if has(&body, "\"fail\"") {
                    return axum::response::Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(r#"{"error":{"message":"failed"}}"#))
                        .unwrap_or_default();
                }
                if has(&body, "\"stream\":true") {
                    let mut events = vec![
                        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n",
                    ];
                    if has(&body, "include_usage") {
                        events.push("data: {\"choices\":[],\"usage\":{\"prompt_tokens\":1000,\"completion_tokens\":1}}\n\n");
                    }
                    events.push("data: [DONE]\n\n");
                    return stream(events, has(&body, "\"hold\""));
                }
                if has(&body, "\"hold\"") {
                    return slow(
                        vec![r#"{"id":"slow","choices":[],"#, r#""usage":{"prompt_tokens":1,"completion_tokens":1}}"#],
                        true,
                        "application/json",
                    );
                }
                if has(&body, "\"delay\"") {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                let n = chat_hits.load(Ordering::SeqCst);
                let completion = if has(&body, "\"mo\"") { 16384 } else { 1 };
                axum::response::Response::builder()
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"id":"c{n}","choices":[],"usage":{{"prompt_tokens":1000,"completion_tokens":{completion}}}}}"#
                    )))
                    .unwrap_or_default()
            }),
        )
        .route(
            "/v1/messages",
            post(move |body: Bytes| async move {
                message_hits.fetch_add(1, Ordering::SeqCst);
                if !has(&body, "\"stream\":true") {
                    return axum::response::Response::builder()
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(r#"{"type":"message","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":5,"output_tokens":3}}"#))
                        .unwrap_or_default();
                }
                stream(
                    vec![
                        "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":100,\"cache_read_input_tokens\":1000,\"output_tokens\":1}}}\n\n",
                        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
                        "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":20}}\n\n",
                        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
                    ],
                    has(&body, "\"hold\""),
                )
            }),
        )
        // A Responses answer that replays a stored conversation of 200,000 tokens, as OpenAI reports one.
        .route(
            "/v1/responses",
            post(|| async {
                axum::response::Response::builder()
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"id":"resp_1","output":[],"usage":{"input_tokens":200000,"output_tokens":1}}"#))
                    .unwrap_or_default()
            }),
        )
        .route(
            "/v1/messages/count_tokens",
            post(move || async move {
                count_hits.fetch_add(1, Ordering::SeqCst);
                axum::response::Response::builder()
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"input_tokens":7}"#))
                    .unwrap_or_default()
            }),
        );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((hits, port))
}

fn policy(port: u16, budget: &str) -> String {
    format!(
        "version: 1
providers:
  - name: openai
    kind: openai
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: MOCK_KEY
    models: [gpt-4o-mini, m, mo, r, unpriced]
  - name: anthropic
    kind: anthropic
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: MOCK_KEY
    accept_chat: true
    models: [claude-sonnet-5-5, am]
aliases:
  - name: smart
    deployments: [{{ provider: openai, model: unpriced }}]
prices:
  m: {{ input: 0, output: 1000 }}
  am: {{ input: 0, output: 1000 }}
  mo: {{ input: 0, output: 1, max_output: 16384 }}
  r: {{ input: 1, output: 1, max_output: 100, max_context: 200000 }}
rules:
  - name: budgeted
    principals: {{ team: payments }}
    models: [m, am, r]
    budget: {{ usd: {budget}, per: day }}
  - name: capped
    principals: {{ team: cap }}
    models: [mo]
    budget: {{ usd: 0.04, per: day }}
  - name: limited
    principals: {{ name: rita }}
    models: [gpt-4o-mini, claude-sonnet-5-5]
    rate: {{ rpm: 2 }}
  - name: cached
    principals: {{ name: cara }}
    models: [gpt-4o-mini, claude-sonnet-5-5]
    cache: {{ ttl_seconds: 300 }}
  - name: everyone
    principals: {{ any: true }}
    models: [\"*\"]
"
    )
}

fn keys() -> String {
    let entry = |name: &str, team: &str, key: &str| {
        format!(
            "  - name: {name}\n    team: {team}\n    sha256: {}\n",
            sha256_hex(key.as_bytes())
        )
    };
    format!(
        "keys:\n{}{}{}{}{}{}",
        entry("pat", "payments", PAT),
        entry("rita", "ops", RITA),
        entry("cara", "ops", CARA),
        entry("otto", "ops", OTTO),
        entry("cap1", "cap", CAP1),
        entry("cap2", "cap", CAP2)
    )
}

struct Setup {
    port: u16,
    policy: PathBuf,
    audit: PathBuf,
    gw: Governed,
    hits: Arc<AtomicUsize>,
}

fn start(policy: &Path) -> Result<Governed, Error> {
    Ok(gantry_server::governed(policy, None, &|_| {
        Some("provider-secret".into())
    })?)
}

async fn setup(name: &str) -> Result<Setup, Error> {
    setup_with(name, "0.0025").await
}

async fn setup_with(name: &str, budget: &str) -> Result<Setup, Error> {
    let (hits, port) = provider().await?;
    let dir = std::env::temp_dir().join(format!("gantry-spend-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let policy = dir.join("gantry.policy.yaml");
    std::fs::write(&policy, self::policy(port, budget))?;
    std::fs::write(dir.join("gantry.keys.yaml"), keys())?;
    Ok(Setup {
        gw: start(&policy)?,
        port,
        policy,
        audit: dir.join("gantry-audit.jsonl"),
        hits,
    })
}

fn chat(key: &str, body: &str) -> Result<Request<Body>, axum::http::Error> {
    Request::post("/v1/chat/completions")
        .header(header::AUTHORIZATION, format!("Bearer {key}"))
        .body(Body::from(body.to_string()))
}

/// Status, headers and body text.
async fn answer(
    app: &Router,
    request: Request<Body>,
) -> Result<(StatusCode, axum::http::HeaderMap, String), Error> {
    let response = app.clone().oneshot(request).await?;
    let (status, headers) = (response.status(), response.headers().clone());
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, headers, String::from_utf8(body.to_vec())?))
}

fn records(path: &Path) -> Result<Vec<Value>, Error> {
    std::fs::read_to_string(path)?
        .lines()
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn decision(headers: &axum::http::HeaderMap) -> String {
    headers
        .get("x-gantry-decision")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

/// The usage record of a decision, waiting for it: it is written when the answer ends.
async fn usage_of(audit: &Path, id: &str) -> Result<Value, Error> {
    let start = Instant::now();
    loop {
        let found = records(audit)?
            .into_iter()
            .find(|r| r["event"] == "usage" && r["id"] == id);
        if let Some(record) = found {
            return Ok(record);
        }
        if start.elapsed() > Duration::from_secs(3) {
            return Err(format!("no usage record for {id}").into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn close(value: &Value, want: f64) -> bool {
    value.as_f64().is_some_and(|v| (v - want).abs() < 1e-12)
}

#[tokio::test(flavor = "multi_thread")]
async fn every_forwarded_request_gets_a_usage_record_after_its_decision() -> TestResult {
    let s = setup("usage").await?;
    let app = &s.gw.router;

    let (status, headers, _) =
        answer(app, chat(OTTO, r#"{"model":"gpt-4o-mini","messages":[]}"#)?).await?;
    assert_eq!(status, StatusCode::OK);
    let id = decision(&headers);
    let usage = usage_of(&s.audit, &id).await?;
    assert_eq!(usage["person"], "otto");
    assert_eq!(usage["team"], "ops");
    assert_eq!(usage["model"], "gpt-4o-mini");
    assert_eq!(usage["provider"], "openai");
    assert_eq!(usage["ended"], "complete");
    assert_eq!(usage["usage"], "reported");
    assert_eq!(
        (
            usage["input_tokens"].as_u64(),
            usage["output_tokens"].as_u64()
        ),
        (Some(1000), Some(1))
    );
    // gpt-4o-mini: 0.15 dollars per million input tokens, 0.60 per million output tokens.
    assert!(
        close(&usage["cost_usd"], 1000.0 * 0.15e-6 + 0.60e-6),
        "{usage}"
    );
    assert_eq!(usage["price_source"], "builtin");
    let all = records(&s.audit)?;
    let at = |want: &str| {
        all.iter().position(|r| {
            r["id"] == id && (r["event"] == want || (want == "decision" && r["event"].is_null()))
        })
    };
    assert!(
        at("decision") < at("usage"),
        "the usage record comes after the decision"
    );

    // An Anthropic stream: usage from message_start and message_delta, cache reads priced apart.
    let (status, headers, body) = answer(
        app,
        Request::post("/v1/messages")
            .header("x-api-key", OTTO)
            .body(Body::from(
                r#"{"model":"claude-sonnet-5-5","max_tokens":64,"stream":true,"messages":[]}"#,
            ))?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("message_stop"), "{body}");
    let usage = usage_of(&s.audit, &decision(&headers)).await?;
    assert_eq!(usage["cache_read_tokens"], 1000);
    assert_eq!(usage["output_tokens"], 20);
    assert!(
        close(
            &usage["cost_usd"],
            100.0 * 2.0e-6 + 20.0 * 10.0e-6 + 1000.0 * 0.10e-6
        ),
        "{usage}"
    );

    // An OpenAI stream that did not ask for usage, and a model with no price: recorded as such, never guessed.
    let (_, headers, _) = answer(
        app,
        chat(
            OTTO,
            r#"{"model":"gpt-4o-mini","stream":true,"messages":[]}"#,
        )?,
    )
    .await?;
    let usage = usage_of(&s.audit, &decision(&headers)).await?;
    // QA11-9: the stream finished, so its charge is estimated from its text; the counts stay unknown.
    assert_eq!(usage["usage"], "estimated");
    assert!(
        usage["cost_usd"].is_null() && usage["input_tokens"].is_null(),
        "{usage}"
    );
    let (_, headers, _) = answer(app, chat(OTTO, r#"{"model":"unpriced","messages":[]}"#)?).await?;
    let usage = usage_of(&s.audit, &decision(&headers)).await?;
    assert_eq!(
        (usage["usage"].as_str(), usage["price"].as_str()),
        (Some("reported"), Some("none"))
    );
    assert!(usage["cost_usd"].is_null(), "{usage}");
    assert!(usage["price_source"].is_null(), "{usage}");

    // A refused request was never forwarded, so it has no usage record.
    let (status, headers, _) = answer(app, chat(RITA, r#"{"model":"m","messages":[]}"#)?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let id = decision(&headers);
    assert!(
        !records(&s.audit)?
            .iter()
            .any(|r| r["event"] == "usage" && r["id"] == id)
    );
    let summary = gantry_core::audit::verify_full(&s.audit, None)?;
    assert_eq!((summary.requests, summary.usage), (5, 4));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_cut_off_by_the_caller_is_recorded_with_what_it_reported() -> TestResult {
    let s = setup("cut").await?;
    let response = s
        .gw
        .router
        .clone()
        .oneshot(
            Request::post("/v1/messages")
                .header("x-api-key", OTTO)
                .body(Body::from(r#"{"model":"claude-sonnet-5-5","max_tokens":64,"stream":true,"hold":1,"messages":[]}"#))?,
        )
        .await?;
    let id = decision(response.headers());
    let mut body = response.into_body();
    // The first event arrives while the provider is still holding the rest: no byte waits for the end.
    let first = tokio::time::timeout(Duration::from_secs(2), body.frame()).await?;
    assert!(first.is_some_and(|f| f.is_ok()));
    drop(body);
    let usage = usage_of(&s.audit, &id).await?;
    assert_eq!(usage["ended"], "cut_off");
    assert_eq!(
        (
            usage["input_tokens"].as_u64(),
            usage["output_tokens"].as_u64()
        ),
        (Some(100), Some(1))
    );
    // What it reported is only what was generated before the cut: the record says so, and the charge is the most
    // the request could have cost, not the 1 token reported so far.
    assert_eq!(usage["usage"], "partial", "{usage}");
    let (cost, charged) = (
        usage["cost_usd"].as_f64().ok_or("no cost")?,
        usage["charged_usd"].as_f64().ok_or("no charge")?,
    );
    assert!(charged > cost && charged >= 64.0 * 10.0e-6, "{usage}");
    Ok(())
}

/// Sends a request, reads its first frame, and closes the connection: a caller that stops reading.
async fn cut_after_first_frame(app: &Router, request: Request<Body>) -> Result<String, Error> {
    let response = app.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let id = decision(response.headers());
    let mut body = response.into_body();
    let first = tokio::time::timeout(Duration::from_secs(2), body.frame()).await?;
    assert!(first.is_some_and(|f| f.is_ok()));
    drop(body);
    Ok(id)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_cut_off_before_its_final_usage_is_charged_its_reservation_on_every_route()
-> TestResult {
    // QA10-1. Model am costs a tenth of a cent per output token, nothing per input token. Each request asks for 2
    // output tokens, so it reserves $0.002; the provider reports 1 output token in message_start, then holds.
    let s = setup_with("cut-budget", "0.0045").await?;
    let app = &s.gw.router;
    let native = Request::post("/v1/messages")
        .header("x-api-key", PAT)
        .body(Body::from(
            r#"{"model":"am","max_tokens":2,"stream":true,"hold":1,"messages":[]}"#,
        ))?;
    let translated = chat(
        PAT,
        // A chat request takes no unknown field, so the word that makes the mock hold is the message.
        r#"{"model":"am","max_tokens":2,"stream":true,"messages":[{"role":"user","content":"hold"}]}"#,
    )?;
    for (route, request) in [("messages", native), ("translated chat", translated)] {
        let id = cut_after_first_frame(app, request).await?;
        let usage = usage_of(&s.audit, &id).await?;
        assert_eq!(
            (usage["ended"].as_str(), usage["usage"].as_str()),
            (Some("cut_off"), Some("partial")),
            "{route}: {usage}"
        );
        assert!(close(&usage["cost_usd"], 0.001), "{route}: {usage}");
        assert!(
            close(&usage["reserved_usd"], 0.002) && close(&usage["charged_usd"], 0.002),
            "{route}: {usage}"
        );
    }
    // $0.004 is counted, so a request that could cost $0.001 more would pass $0.0045.
    let (status, _, body) = answer(
        app,
        chat(PAT, r#"{"model":"m","max_tokens":1,"messages":[]}"#)?,
    )
    .await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert!(body.contains("has spent $0.0040"), "{body}");

    // Without a budget the charge is still the most the request could cost: an OpenAI stream that reported
    // nothing before the cut, and a whole answer cut off half way.
    let streamed = chat(
        OTTO,
        r#"{"model":"gpt-4o-mini","max_tokens":10,"stream":true,"hold":1,"messages":[]}"#,
    )?;
    let whole = chat(
        OTTO,
        r#"{"model":"gpt-4o-mini","max_tokens":10,"hold":1,"messages":[]}"#,
    )?;
    for (what, request) in [("stream", streamed), ("whole answer", whole)] {
        let id = cut_after_first_frame(app, request).await?;
        let usage = usage_of(&s.audit, &id).await?;
        assert_eq!(usage["ended"], "cut_off", "{what}: {usage}");
        let charged = usage["charged_usd"].as_f64().ok_or("no charge")?;
        assert!(charged >= 10.0 * 0.60e-6, "{what}: {usage}");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_caller_who_hangs_up_after_forwarding_is_charged_its_reservation() -> TestResult {
    // QA14-1. The provider takes 2 s; the caller leaves after 0.3 s, before the answer starts. The provider has the
    // request and bills it, so the budget counts its reservation: 2 output tokens of m, $0.002.
    let s = setup("hang-up").await?;
    let app = &s.gw.router;
    let request = chat(
        PAT,
        r#"{"model":"m","max_tokens":2,"delay":1,"messages":[]}"#,
    )?;
    let gone = tokio::time::timeout(Duration::from_millis(300), app.clone().oneshot(request)).await;
    assert!(gone.is_err(), "the answer came before the caller left");
    assert_eq!(
        s.hits.load(Ordering::SeqCst),
        1,
        "the provider has the request"
    );
    let start = Instant::now();
    let usage = loop {
        if let Some(usage) = records(&s.audit)?
            .into_iter()
            .find(|r| r["event"] == "usage" && r["person"] == "pat")
        {
            break usage;
        }
        if start.elapsed() > Duration::from_secs(3) {
            return Err("no usage record for the request whose caller left".into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(
        (usage["usage"].as_str(), usage["ended"].as_str()),
        (Some("caller_left"), Some("cut_off")),
        "{usage}"
    );
    assert!(usage["status"].is_null(), "{usage}");
    assert!(close(&usage["charged_usd"], 0.002), "{usage}");
    // $0.002 is counted, so a request that could cost $0.001 more would pass $0.0025.
    let (status, _, body) = answer(
        app,
        chat(PAT, r#"{"model":"m","max_tokens":1,"messages":[]}"#)?,
    )
    .await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert!(body.contains("has spent $0.0020"), "{body}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn an_answer_that_reports_no_usage_is_never_free() -> TestResult {
    // QA10-5 P10: an OpenAI stream without include_usage must not be free. QA12-1: under a budget it is charged
    // its whole reservation, even though it finished.
    let s = setup("no-usage").await?;
    let (status, headers, body) = answer(
        &s.gw.router,
        chat(
            PAT,
            r#"{"model":"m","max_tokens":1,"stream":true,"messages":[]}"#,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let usage = usage_of(&s.audit, &decision(&headers)).await?;
    assert_eq!(
        (usage["ended"].as_str(), usage["usage"].as_str()),
        (Some("complete"), Some("not_reported"))
    );
    assert!(
        close(&usage["reserved_usd"], 0.001) && close(&usage["charged_usd"], 0.001),
        "{usage}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn the_estimate_is_the_most_a_request_could_cost_or_the_request_is_refused() -> TestResult {
    // QA10-2. Model m: $1000 per million output tokens, no max_output in its price.
    let s = setup_with("estimate", "1").await?;
    let app = &s.gw.router;
    for (body, code) in [
        (
            r#"{"model":"m","max_tokens":1,"max_tokens":1000000,"messages":[]}"#,
            "bad_limits",
        ),
        (
            r#"{"model":"m","max_tokens":"1000000","messages":[]}"#,
            "bad_limits",
        ),
        (
            r#"{"model":"m","max_tokens":-1,"messages":[]}"#,
            "bad_limits",
        ),
        (
            r#"{"model":"m","max_tokens":1,"messages":[],"messages":[]}"#,
            "bad_limits",
        ),
        // The larger of the two output fields is what the provider may run.
        (
            r#"{"model":"m","max_tokens":1,"max_completion_tokens":1000000,"messages":[]}"#,
            "budget_exceeded",
        ),
        (r#"{"model":"m","messages":[]}"#, "max_tokens_needed"),
    ] {
        let (status, headers, text) = answer(app, chat(PAT, body)?).await?;
        let error: Value = serde_json::from_str(&text)?;
        assert_eq!(error["error"]["code"], code, "{body}: {text}");
        let want = if code == "budget_exceeded" {
            StatusCode::TOO_MANY_REQUESTS
        } else {
            StatusCode::BAD_REQUEST
        };
        assert_eq!(status, want, "{body}: {text}");
        let record = records(&s.audit)?
            .into_iter()
            .find(|r| r["id"] == decision(&headers))
            .ok_or("no record")?;
        assert_eq!(record["code"], code);
    }
    assert_eq!(s.hits.load(Ordering::SeqCst), 0, "nothing was forwarded");
    // UX11 m18: with the budget untouched, the refusal says a smaller output limit could fit.
    let big = r#"{"model":"m","max_tokens":1000000,"messages":[]}"#;
    let (_, _, text) = answer(app, chat(PAT, big)?).await?;
    assert!(
        text.contains("budget_exceeded") && text.contains("smaller output token limit"),
        "{text}"
    );
    let (_, _, text) = answer(app, chat(PAT, r#"{"model":"m","messages":[]}"#)?).await?;
    assert!(
        text.contains("max_tokens") && text.contains("max_output"),
        "the refusal names both fixes: {text}"
    );
    // UX11 n5: only the budget that applies is named (pat's key has none), and on the Responses route the field
    // to send is that route's own.
    assert!(
        text.contains("budgeted")
            && text.contains("applies to this request")
            && !text.contains("the key of"),
        "{text}"
    );
    let responses = Request::post("/v1/responses")
        .header(header::AUTHORIZATION, format!("Bearer {PAT}"))
        .body(Body::from(r#"{"model":"m","input":"hi"}"#))?;
    let (_, _, text) = answer(app, responses).await?;
    assert!(text.contains("max_tokens_needed"), "{text}");
    assert!(
        text.contains("Send max_output_tokens") && !text.contains("max_completion_tokens"),
        "{text}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_requests_of_one_team_never_pass_its_budget() -> TestResult {
    // QA10-2's repro and QA10-5 P12. Team cap has $0.04 a day for model mo ($1 per million output tokens, at most
    // 16384 of them). No request says max_tokens and the provider writes all 16384 every time, so each costs
    // $0.016384: two fit, a third would pass the budget. Two members share it, ten requests at once.
    let s = setup("team-cap").await?;
    let mut tasks = Vec::new();
    for i in 0..10 {
        let app = s.gw.router.clone();
        let key = if i % 2 == 0 { CAP1 } else { CAP2 };
        tasks.push(tokio::spawn(async move {
            let request =
                chat(key, r#"{"model":"mo","messages":[]}"#).map_err(|e| e.to_string())?;
            answer(&app, request).await.map_err(|e| e.to_string())
        }));
    }
    let mut admitted = Vec::new();
    for task in tasks {
        let (status, headers, body) = task.await??;
        match status {
            StatusCode::OK => admitted.push(decision(&headers)),
            StatusCode::TOO_MANY_REQUESTS => assert!(body.contains("budget_exceeded"), "{body}"),
            other => return Err(format!("unexpected {other}: {body}").into()),
        }
    }
    assert_eq!(admitted.len(), 2, "two requests fit in the team's budget");
    let mut spent = 0.0;
    for id in &admitted {
        let usage = usage_of(&s.audit, id).await?;
        assert!(close(&usage["reserved_usd"], 0.016384), "{usage}");
        spent += usage["charged_usd"].as_f64().ok_or("no charge")?;
    }
    assert!(spent <= 0.04, "the team spent {spent} of 0.04");
    let (status, _, body) =
        answer(&s.gw.router, chat(CAP2, r#"{"model":"mo","messages":[]}"#)?).await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn the_cache_key_holds_the_route_and_the_headers_that_change_the_answer() -> TestResult {
    // QA10-3 and QA10-6. The same body on count_tokens and on messages must never answer for the other.
    let s = setup("cache-route").await?;
    let app = &s.gw.router;
    let body = r#"{"model":"claude-sonnet-5-5","max_tokens":64,"messages":[{"role":"user","content":"hi"}]}"#;
    let to = |path: &str, beta: Option<&str>| {
        let mut request = Request::post(path).header("x-api-key", CARA);
        if let Some(beta) = beta {
            request = request.header("anthropic-beta", beta);
        }
        request.body(Body::from(body))
    };
    let (_, _, counted) = answer(app, to("/v1/messages/count_tokens", None)?).await?;
    assert_eq!(counted, r#"{"input_tokens":7}"#);
    let (status, headers, message) = answer(app, to("/v1/messages", None)?).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(message.contains("\"type\":\"message\""), "{message}");
    assert_ne!(
        headers.get("x-gantry-cache").and_then(|v| v.to_str().ok()),
        Some("hit")
    );
    usage_of(&s.audit, &decision(&headers)).await?;
    // The messages answer is cached now: count_tokens still gets a count, from the provider.
    let (_, headers, counted) = answer(app, to("/v1/messages/count_tokens", None)?).await?;
    assert_eq!(counted, r#"{"input_tokens":7}"#);
    assert!(headers.get("x-gantry-cache").is_none());
    // The same request on the same route is a hit; with another anthropic-beta it is not.
    let (_, headers, again) = answer(app, to("/v1/messages", None)?).await?;
    assert_eq!(again, message);
    assert_eq!(
        headers.get("x-gantry-cache").and_then(|v| v.to_str().ok()),
        Some("hit")
    );
    let (_, headers, _) = answer(app, to("/v1/messages", Some("some-feature-2025"))?).await?;
    assert!(headers.get("x-gantry-cache").is_none());
    // Another query on the same path is another request too.
    let (status, headers, _) = answer(app, to("/v1/messages?beta=true", None)?).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(headers.get("x-gantry-cache").is_none());
    assert_eq!(s.hits.load(Ordering::SeqCst), 5);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_budget_refuses_what_would_pass_it_and_survives_a_restart_and_a_reload() -> TestResult {
    let s = setup("budget").await?;
    // Model m costs a tenth of a cent per output token. Each request reserves 1 output token and spends 1.
    let ask = || chat(PAT, r#"{"model":"m","max_tokens":1,"messages":[]}"#);
    for _ in 0..2 {
        let (status, headers, _) = answer(&s.gw.router, ask()?).await?;
        assert_eq!(status, StatusCode::OK);
        let usage = usage_of(&s.audit, &decision(&headers)).await?;
        assert!(
            close(&usage["cost_usd"], 0.001) && close(&usage["charged_usd"], 0.001),
            "{usage}"
        );
        assert!(close(&usage["reserved_usd"], 0.001), "{usage}");
    }
    let (status, headers, body) = answer(&s.gw.router, ask()?).await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(
        headers.get("x-should-retry").and_then(|v| v.to_str().ok()),
        Some("false")
    );
    assert!(headers.get(header::RETRY_AFTER).is_none());
    let error: Value = serde_json::from_str(&body)?;
    assert_eq!(error["error"]["code"], "budget_exceeded");
    let message = error["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("team \"payments\" has spent $0.0020 of its $0.0025 budget for this day")
            && message.contains("starts again at")
            && message.contains("UTC"),
        "{message}"
    );
    assert_eq!(
        s.hits.load(Ordering::SeqCst),
        2,
        "a refused request never reaches the provider"
    );
    let refused = records(&s.audit)?
        .into_iter()
        .find(|r| r["id"] == decision(&headers))
        .ok_or("no record")?;
    assert_eq!(refused["code"], "budget_exceeded");

    // A restart reads this day's spend back from the audit log.
    drop(s.gw);
    let gw = start(&s.policy)?;
    let (status, _, body) = answer(&gw.router, ask()?).await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");

    // A reload that raises the budget applies to the next request.
    std::fs::write(&s.policy, policy(s.port, "1"))?;
    assert!(matches!(gw.reloader.check(Trigger::Signal), Reload::Loaded));
    let (status, _, body) = answer(&gw.router, ask()?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rate_limit_refuses_with_the_seconds_to_wait() -> TestResult {
    let s = setup("rate").await?;
    let ask = || chat(RITA, r#"{"model":"gpt-4o-mini","messages":[]}"#);
    for _ in 0..2 {
        assert_eq!(answer(&s.gw.router, ask()?).await?.0, StatusCode::OK);
    }
    let (status, headers, body) = answer(&s.gw.router, ask()?).await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    let wait: u64 = headers
        .get(header::RETRY_AFTER)
        .ok_or("no Retry-After")?
        .to_str()?
        .parse()?;
    assert!((1..=60).contains(&wait), "{wait}");
    assert_eq!(
        headers.get("x-should-retry").and_then(|v| v.to_str().ok()),
        Some("true")
    );
    assert!(
        body.contains("\"rate_limited\"") && body.contains(&format!("again in {wait} seconds")),
        "{body}"
    );
    // Another person has a minute of their own.
    assert_eq!(
        answer(
            &s.gw.router,
            chat(OTTO, r#"{"model":"gpt-4o-mini","messages":[]}"#)?
        )
        .await?
        .0,
        StatusCode::OK
    );
    // Anthropic's clients see a rate_limit_error.
    let (status, _, body) = answer(
        &s.gw.router,
        Request::post("/v1/messages")
            .header("x-api-key", RITA)
            .body(Body::from(
                r#"{"model":"claude-sonnet-5-5","max_tokens":1,"messages":[]}"#,
            ))?,
    )
    .await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert!(body.contains("\"rate_limit_error\""), "{body}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn the_cache_answers_an_identical_request_without_the_provider() -> TestResult {
    let s = setup("cache").await?;
    let body = r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}"#;
    let (status, headers, first) = answer(&s.gw.router, chat(CARA, body)?).await?;
    assert_eq!(status, StatusCode::OK);
    let miss = decision(&headers);
    usage_of(&s.audit, &miss).await?;
    let (status, headers, second) = answer(&s.gw.router, chat(CARA, body)?).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first, second);
    assert_eq!(
        headers.get("x-gantry-cache").and_then(|v| v.to_str().ok()),
        Some("hit")
    );
    assert_eq!(s.hits.load(Ordering::SeqCst), 1);
    let hit = decision(&headers);
    let all = records(&s.audit)?;
    let of = |id: &str| {
        all.iter()
            .find(|r| r["id"] == id && r["event"].is_null())
            .cloned()
    };
    assert_eq!(of(&miss).ok_or("no record")?["cache"], "miss");
    let hit_record = of(&hit).ok_or("no record")?;
    assert_eq!(
        (hit_record["cache"].as_str(), hit_record["verdict"].as_str()),
        (Some("hit"), Some("allow"))
    );
    let usage = usage_of(&s.audit, &hit).await?;
    assert_eq!(
        (usage["cache"].as_str(), usage["cost_usd"].as_f64()),
        (Some("hit"), Some(0.0))
    );

    // Another body, no-store, a stream and an error answer all go to the provider, and none of them is kept.
    let other = r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}"#;
    answer(&s.gw.router, chat(CARA, other)?).await?;
    let no_store = Request::post("/v1/chat/completions")
        .header(header::AUTHORIZATION, format!("Bearer {CARA}"))
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(body))?;
    let (_, headers, _) = answer(&s.gw.router, no_store).await?;
    assert!(headers.get("x-gantry-cache").is_none());
    let streamed = r#"{"model":"gpt-4o-mini","stream":true,"messages":[]}"#;
    let failing = r#"{"model":"gpt-4o-mini","fail":1,"messages":[]}"#;
    for _ in 0..2 {
        answer(&s.gw.router, chat(CARA, streamed)?).await?;
        let (status, _, _) = answer(&s.gw.router, chat(CARA, failing)?).await?;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }
    assert_eq!(s.hits.load(Ordering::SeqCst), 7);
    // A rule without a cache never reads one: otto gets the provider's answer.
    answer(&s.gw.router, chat(OTTO, body)?).await?;
    assert_eq!(s.hits.load(Ordering::SeqCst), 8);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_budget_and_an_expired_key_are_refused_with_their_own_codes() -> TestResult {
    const KIM: &str = "gantry_kim_0123456789abcdef0123456789ab";
    const EXA: &str = "gantry_exa_0123456789abcdef0123456789ab";
    let Setup {
        policy, audit, gw, ..
    } = setup("key-limits").await?;
    // One server writes the log at a time.
    drop(gw);
    let keys_path = policy.with_file_name("gantry.keys.yaml");
    let with = |usd: &str| {
        format!(
            "{}  - name: kim\n    team: ops\n    sha256: {}\n    budget: {{ usd: {usd}, per: day }}\n  - name: exa\n    team: ops\n    sha256: {}\n    expires: 2020-01-01\n",
            keys(),
            sha256_hex(KIM.as_bytes()),
            sha256_hex(EXA.as_bytes())
        )
    };
    std::fs::write(&keys_path, with("0.0015"))?;
    let gw = start(&policy)?;
    let ask = |key: &str| chat(key, r#"{"model":"m","max_tokens":1,"messages":[]}"#);

    let (status, headers, body) = answer(&gw.router, ask(EXA)?).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    let error: Value = serde_json::from_str(&body)?;
    assert_eq!(error["error"]["code"], "key_expired");
    assert!(body.contains("expired at 2020-01-01"), "{body}");
    let refused = records(&audit)?
        .into_iter()
        .find(|r| r["id"] == decision(&headers))
        .ok_or("no record of the expired key")?;
    assert_eq!(refused["person"], "exa");
    assert_eq!(refused["code"], "key_expired");

    // UX13-1: a refusal names the alias the caller sent, with the deployment that lacks the price as detail.
    let (status, _, body) = answer(
        &gw.router,
        chat(KIM, r#"{"model":"smart","max_tokens":1,"messages":[]}"#)?,
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let error: Value = serde_json::from_str(&body)?;
    let message = error["error"]["message"].as_str().unwrap_or_default();
    assert_eq!(error["error"]["code"], "no_price");
    assert!(
        message.contains("alias \"smart\" (deployment \"unpriced\" on provider \"openai\")"),
        "{message}"
    );

    // The rule "everyone" has no budget: the key's own budget is what refuses.
    let (status, headers, body) = answer(&gw.router, ask(KIM)?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let kim8 = &sha256_hex(KIM.as_bytes())[..8];
    let usage = usage_of(&audit, &decision(&headers)).await?;
    assert_eq!(usage["key"], kim8);
    let allowed = records(&audit)?
        .into_iter()
        .find(|r| r["id"] == decision(&headers) && r["verdict"] == "allow")
        .ok_or("no decision record")?;
    assert_eq!(allowed["key"], kim8, "an allowed record names its key");
    let (status, headers, body) = answer(&gw.router, ask(KIM)?).await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(
        headers.get("x-should-retry").and_then(|v| v.to_str().ok()),
        Some("false")
    );
    let error: Value = serde_json::from_str(&body)?;
    assert_eq!(error["error"]["code"], "key_budget_exceeded");
    assert!(
        body.contains(&format!(
            "the key {kim8} of \\\"kim\\\" has spent $0.0010 of its $0.0015 budget for this day"
        )),
        "{body}"
    );

    // A restart reads the key's spend back from the audit log.
    drop(gw);
    let gw = start(&policy)?;
    let (status, _, body) = answer(&gw.router, ask(KIM)?).await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");

    // A reload that raises the key's budget applies to the next request.
    std::fs::write(&keys_path, with("1"))?;
    assert!(matches!(gw.reloader.check(Trigger::Signal), Reload::Loaded));
    let (status, _, body) = answer(&gw.router, ask(KIM)?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn metrics_count_decisions_upstream_answers_audit_writes_and_spend() -> TestResult {
    let s = setup("metrics").await?;
    let (status, headers, body) = answer(
        &s.gw.router,
        chat(PAT, r#"{"model":"m","max_tokens":1,"messages":[]}"#)?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    usage_of(&s.audit, &decision(&headers)).await?;
    let (status, _, _) =
        answer(&s.gw.router, chat("gantry_nobody_0123456789abcdef", "{}")?).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _, _) = answer(
        &s.gw.router,
        chat(PAT, r#"{"model":"gpt-4o","messages":[]}"#)?,
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, headers, text) =
        answer(&s.gw.metrics, Request::get("/metrics").body(Body::empty())?).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("text/plain; version=0.0.4"))
    );
    for line in [
        "gantry_requests_total{route=\"chat_completions\",verdict=\"allow\",code=\"\",provider=\"openai\"} 1",
        "gantry_requests_total{route=\"chat_completions\",verdict=\"refused\",code=\"unknown_key\",provider=\"\"} 1",
        "gantry_requests_total{route=\"chat_completions\",verdict=\"refused\",code=\"model_not_allowed\",provider=\"\"} 1",
        "gantry_upstream_responses_total{provider=\"openai\",outcome=\"200\"} 1",
        "gantry_upstream_seconds_count{provider=\"openai\"} 1",
        "gantry_overhead_seconds_count 1",
        "gantry_audit_queue_depth 0",
        "gantry_audit_broken 0",
        "gantry_spend_usd_total{team=\"payments\",model=\"m\"} 0.001",
    ] {
        assert!(text.contains(line), "{line} missing from:\n{text}");
    }
    assert!(text.contains("# TYPE gantry_audit_write_seconds histogram"));
    // The gateway's own router does not serve it: a caller with a Gantry key cannot read other teams' spend.
    let (status, _, _) =
        answer(&s.gw.router, Request::get("/metrics").body(Body::empty())?).await?;
    assert_ne!(status, StatusCode::OK);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn n_multiplies_the_reservation_and_concurrent_requests_stay_in_the_budget() -> TestResult {
    // QA11-1. n asks for n answers, each up to max_tokens: the provider bills all of them. Team cap has $0.04 a day
    // for model mo ($1 per million output tokens); each request asks for 4 answers of 4096 tokens, $0.016384, and
    // the provider writes all 16384. Ten at once from two members: two fit.
    let s = setup("n-cap").await?;
    let mut tasks = Vec::new();
    for i in 0..10 {
        let app = s.gw.router.clone();
        let key = if i % 2 == 0 { CAP1 } else { CAP2 };
        tasks.push(tokio::spawn(async move {
            let request = chat(
                key,
                r#"{"model":"mo","max_tokens":4096,"n":4,"messages":[]}"#,
            )
            .map_err(|e| e.to_string())?;
            answer(&app, request).await.map_err(|e| e.to_string())
        }));
    }
    let mut admitted = Vec::new();
    for task in tasks {
        let (status, headers, body) = task.await??;
        match status {
            StatusCode::OK => admitted.push(decision(&headers)),
            StatusCode::TOO_MANY_REQUESTS => assert!(body.contains("budget_exceeded"), "{body}"),
            other => return Err(format!("unexpected {other}: {body}").into()),
        }
    }
    assert_eq!(admitted.len(), 2, "two requests of four answers fit");
    let mut spent = 0.0;
    for id in &admitted {
        let usage = usage_of(&s.audit, id).await?;
        assert!(close(&usage["reserved_usd"], 0.016384), "{usage}");
        spent += usage["charged_usd"].as_f64().ok_or("no charge")?;
    }
    assert!(spent <= 0.04, "the team spent {spent} of 0.04");
    // n that is not a whole number from 1 to 16, or sent twice, is refused before anything is forwarded.
    let hits = s.hits.load(Ordering::SeqCst);
    for body in [
        r#"{"model":"mo","max_tokens":1,"n":128,"messages":[]}"#,
        r#"{"model":"mo","max_tokens":1,"n":0,"messages":[]}"#,
        r#"{"model":"mo","max_tokens":1,"n":"2","messages":[]}"#,
        r#"{"model":"mo","max_tokens":1,"n":1.5,"messages":[]}"#,
        r#"{"model":"mo","max_tokens":1,"n":1,"n":128,"messages":[]}"#,
    ] {
        let (status, _, text) = answer(&s.gw.router, chat(CAP1, body)?).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {text}");
        assert!(
            text.contains("bad_limits") && text.contains("n from 1 to 16"),
            "{body}: {text}"
        );
    }
    assert_eq!(s.hits.load(Ordering::SeqCst), hits, "nothing was forwarded");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_responses_request_naming_stored_context_is_never_answered_from_the_cache() -> TestResult
{
    // QA12-4 (a). A conversation, an earlier response and a stored prompt can change at the provider while the
    // body stays the same, so a cached answer would be stale. Rule `cached` (cara) caches without a budget.
    let s = setup("cache-stored").await?;
    let app = &s.gw.router;
    let responses = |body: &str| {
        Request::post("/v1/responses")
            .header(header::AUTHORIZATION, format!("Bearer {CARA}"))
            .body(Body::from(body.to_string()))
    };
    let hit = |headers: &axum::http::HeaderMap| {
        headers.get("x-gantry-cache").and_then(|v| v.to_str().ok()) == Some("hit")
    };
    for field in [
        r#""conversation":"conv_9""#,
        r#""previous_response_id":"resp_abc""#,
        r#""prompt":{"id":"pmpt_1"}"#,
    ] {
        let body =
            format!(r#"{{"model":"gpt-4o-mini","input":"next?","max_output_tokens":8,{field}}}"#);
        for _ in 0..2 {
            let (status, headers, text) = answer(app, responses(&body)?).await?;
            assert_eq!(status, StatusCode::OK, "{body}: {text}");
            assert!(!hit(&headers), "{body} was answered from the cache");
        }
    }
    // The same request without stored context is cached as before.
    let body = r#"{"model":"gpt-4o-mini","input":"next?","max_output_tokens":8}"#;
    let (_, headers, _) = answer(app, responses(body)?).await?;
    usage_of(&s.audit, &decision(&headers)).await?;
    let (_, headers, _) = answer(app, responses(body)?).await?;
    assert!(hit(&headers));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn stored_responses_context_is_refused_under_a_budget_unless_the_price_bounds_it()
-> TestResult {
    // QA11-2. previous_response_id, conversation and prompt make the provider add stored context the body does not
    // hold. Model m has no max_context: refused, nothing forwarded. Model r has max_context 200000: the request
    // reserves the whole context, and the provider's 200,000 input tokens fit in it.
    let s = setup_with("stored", "1").await?;
    let app = &s.gw.router;
    let responses = |body: &str| {
        Request::post("/v1/responses")
            .header(header::AUTHORIZATION, format!("Bearer {PAT}"))
            .body(Body::from(body.to_string()))
    };
    for field in [
        r#""previous_response_id":"resp_abc""#,
        r#""conversation":"conv_1""#,
        r#""prompt":{"id":"pmpt_1"}"#,
    ] {
        let body = format!(r#"{{"model":"m","input":"go on","max_output_tokens":1,{field}}}"#);
        let (status, _, text) = answer(app, responses(&body)?).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {text}");
        assert!(
            text.contains("stored_context") && text.contains("max_context"),
            "{body}: {text}"
        );
    }
    assert_eq!(s.hits.load(Ordering::SeqCst), 0, "nothing was forwarded");
    // Null is the same as absent, as the SDKs send it.
    let (status, _, text) = answer(
        app,
        responses(
            r#"{"model":"r","input":"hi","max_output_tokens":1,"previous_response_id":null}"#,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (status, headers, text) = answer(
        app,
        responses(r#"{"model":"r","input":"go on","max_output_tokens":1,"previous_response_id":"resp_abc"}"#)?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let usage = usage_of(&s.audit, &decision(&headers)).await?;
    let (reserved, charged) = (
        usage["reserved_usd"].as_f64().ok_or("no reservation")?,
        usage["charged_usd"].as_f64().ok_or("no charge")?,
    );
    assert!(reserved >= 0.200001 && charged <= reserved, "{usage}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_budgeted_stream_without_usage_is_charged_its_reservation() -> TestResult {
    // QA12-1. An OpenAI stream without include_usage reports no usage. A reasoning model's hidden reasoning tokens
    // are billed but never streamed, so under a budget an estimate from the streamed text would let them pass the
    // limit: the stream is charged its whole reservation. Without a budget the text estimate stays (see the
    // gpt-4o-mini stream in the test above). Model m costs $1000 per million output tokens.
    let s = setup_with("streamed-text", "1").await?;
    let (status, headers, body) = answer(
        &s.gw.router,
        chat(
            PAT,
            r#"{"model":"m","max_tokens":1000,"stream":true,"messages":[]}"#,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let usage = usage_of(&s.audit, &decision(&headers)).await?;
    assert_eq!(usage["usage"], "not_reported", "{usage}");
    assert!(close(&usage["reserved_usd"], 1.0), "{usage}");
    assert_eq!(usage["charged_usd"], usage["reserved_usd"], "{usage}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn tokens_held_by_requests_in_flight_count_for_a_person_a_team_and_a_key() -> TestResult {
    // QA14-16 (TP1 to TP3): 20 requests at once, each held 2 s at the provider. Only as many as fit in the limit
    // are admitted, because each holds its most tokens until its usage comes back.
    let (_, port) = provider().await?;
    let dir = std::env::temp_dir().join(format!("gantry-spend-{}-tpm-flight", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let policy = dir.join("gantry.policy.yaml");
    std::fs::write(
        &policy,
        format!(
            "version: 1
providers:
  - name: openai
    kind: openai
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: MOCK_KEY
    models: [m]
rules:
  - name: solo
    principals: {{ name: pat }}
    models: [m]
    rate: {{ tpm: 1000 }}
  - name: duo
    principals: {{ team: duo }}
    models: [m]
    rate: {{ tpm: 1000 }}
  - name: free
    principals: {{ any: true }}
    models: [m]
"
        ),
    )?;
    let entry = |name: &str, team: &str, key: &str, extra: &str| {
        format!(
            "  - name: {name}\n    team: {team}\n    sha256: {}\n{extra}",
            sha256_hex(key.as_bytes())
        )
    };
    std::fs::write(
        dir.join("gantry.keys.yaml"),
        format!(
            "keys:\n{}{}{}{}",
            entry("pat", "payments", PAT, ""),
            entry("cap1", "duo", CAP1, ""),
            entry("cap2", "duo", CAP2, ""),
            entry("otto", "ops", OTTO, "    tpm: 500\n")
        ),
    )?;
    let gw = start(&policy)?;
    let body = r#"{"model":"m","max_tokens":100,"delay":1,"messages":[]}"#;
    let most = body.len().div_ceil(3) + 100;
    let burst = |keys: Vec<&'static str>| {
        let app = gw.router.clone();
        async move {
            let sent: Vec<_> = keys
                .into_iter()
                .map(|key| {
                    let app = app.clone();
                    tokio::spawn(async move {
                        let request = chat(key, body).map_err(|e| e.to_string())?;
                        app.oneshot(request)
                            .await
                            .map(|r| r.status())
                            .map_err(|e| e.to_string())
                    })
                })
                .collect();
            let mut admitted = 0;
            for handle in sent {
                if handle.await?? == StatusCode::OK {
                    admitted += 1;
                }
            }
            Ok::<usize, Error>(admitted)
        }
    };
    assert_eq!(burst(vec![PAT; 20]).await?, 1000 / most, "a person");
    let duo: Vec<&'static str> = (0..20)
        .map(|i| if i % 2 == 0 { CAP1 } else { CAP2 })
        .collect();
    assert_eq!(
        burst(duo).await?,
        1000 / most,
        "a team of two shares one limit"
    );
    assert_eq!(burst(vec![OTTO; 20]).await?, 500 / most, "a key");
    Ok(())
}
