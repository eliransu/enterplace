//! Acceptance tests for caching: answer cache scopes, the semantic cache, answers a guardrail changed, and
//! automatic prompt caching with its savings. Each test's mock provider listens on a port the system picks.

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
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
use enterplace_core::id::sha256_hex;
use enterplace_server::Governed;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Error = Box<dyn std::error::Error>;

const CARA: &str = "enterplace_cara_0123456789abcdef0123456789a";
const OTTO: &str = "enterplace_otto_0123456789abcdef0123456789a";
const PAT: &str = "enterplace_pat_0123456789abcdef0123456789ab";
const PAM: &str = "enterplace_pam_0123456789abcdef0123456789ab";
const SAM: &str = "enterplace_sam_0123456789abcdef0123456789ab";
const GUS: &str = "enterplace_gus_0123456789abcdef0123456789ab";
const PIA: &str = "enterplace_pia_0123456789abcdef0123456789ab";
const AWS: &str = "AKIAIOSFODNN7EXAMPLE";

fn has(body: &[u8], text: &str) -> bool {
    body.windows(text.len()).any(|w| w == text.as_bytes())
}

/// What the mock provider saw.
#[derive(Default)]
struct Seen {
    chats: AtomicUsize,
    embeddings: AtomicUsize,
    messages: Mutex<Vec<Bytes>>,
}

fn json_response(body: String) -> axum::response::Response {
    axum::response::Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap_or_default()
}

/// Chat answers number themselves, so two answers are told apart. Embeddings place the two ways of asking for the
/// capital of France close together and everything else far from them.
async fn provider() -> Result<(Arc<Seen>, u16), Error> {
    let seen = Arc::new(Seen::default());
    let (chat, embed, messages) = (seen.clone(), seen.clone(), seen.clone());
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let app = Router::new()
        .route(
            "/v1/chat/completions",
            post(move |body: Bytes| async move {
                let n = chat.chats.fetch_add(1, Ordering::SeqCst) + 1;
                let text = if has(&body, "leak") {
                    format!("the key is {AWS}")
                } else {
                    format!("answer {n}")
                };
                json_response(
                    json!({
                        "id": format!("c{n}"),
                        "choices": [{"index": 0, "message": {"role": "assistant", "content": text}}],
                        "usage": {"prompt_tokens": 10, "completion_tokens": 2}
                    })
                    .to_string(),
                )
            }),
        )
        .route(
            "/v1/embeddings",
            post(move |body: Bytes| async move {
                embed.embeddings.fetch_add(1, Ordering::SeqCst);
                let vector = if has(&body, "capital of France") {
                    [1.0, 0.0, 0.0]
                } else if has(&body, "France's capital") {
                    [0.98, 0.2, 0.0]
                } else {
                    [0.0, 0.0, 1.0]
                };
                json_response(
                    json!({
                        "object": "list",
                        "data": [{"object": "embedding", "index": 0, "embedding": vector}],
                        "model": "emb",
                        "usage": {"prompt_tokens": 4, "total_tokens": 4}
                    })
                    .to_string(),
                )
            }),
        )
        .route(
            "/v1/messages",
            post(move |body: Bytes| async move {
                if let Ok(mut all) = messages.messages.lock() {
                    all.push(body);
                }
                json_response(
                    r#"{"type":"message","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":1000000,"cache_creation_input_tokens":0}}"#
                        .to_string(),
                )
            }),
        );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((seen, port))
}

fn policy(port: u16) -> String {
    format!(
        "version: 1
providers:
  - name: openai
    kind: openai
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: MOCK_KEY
    models: [gpt-4o-mini, emb]
  - name: anthropic
    kind: anthropic
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: MOCK_KEY
    models: [claude-sonnet-5-5]
prices:
  claude-sonnet-5-5: {{ input: 3, output: 15, cache_read: 0.3, cache_write: 3.75 }}
guardrails:
  - name: answer-secrets
    type: secrets
    action: mask
    on: [answer]
rules:
  - name: guarded
    principals: {{ name: gus }}
    models: [gpt-4o-mini, emb]
    guardrails: [answer-secrets]
    cache: {{ ttl_seconds: 300, semantic: {{ model: emb, threshold: 0.9 }} }}
  - name: prompts
    principals: {{ name: pia }}
    models: [claude-sonnet-5-5]
    prompt_cache: auto
  - name: per-person
    principals: {{ team: ops }}
    models: [gpt-4o-mini, emb]
    cache: {{ ttl_seconds: 300, semantic: {{ model: emb, threshold: 0.9 }} }}
  - name: per-team
    principals: {{ any: true }}
    models: [\"*\"]
    cache: {{ ttl_seconds: 300, scope: team, semantic: {{ model: emb, threshold: 0.9 }} }}
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
        "keys:\n{}{}{}{}{}{}{}",
        entry("cara", "ops", CARA),
        entry("otto", "ops", OTTO),
        entry("pat", "payments", PAT),
        entry("pam", "payments", PAM),
        entry("sam", "sales", SAM),
        entry("gus", "ops", GUS),
        entry("pia", "research", PIA),
    )
}

struct Setup {
    audit: PathBuf,
    gw: Governed,
    seen: Arc<Seen>,
}

async fn setup(name: &str) -> Result<Setup, Error> {
    let (seen, port) = provider().await?;
    let dir =
        std::env::temp_dir().join(format!("enterplace-caching-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let policy = dir.join("enterplace.policy.yaml");
    std::fs::write(&policy, self::policy(port))?;
    std::fs::write(dir.join("enterplace.keys.yaml"), keys())?;
    let gw = enterplace_server::governed(&policy, None, &|_| Some("provider-secret".into()))?;
    Ok(Setup {
        audit: dir.join("enterplace-audit.jsonl"),
        gw,
        seen,
    })
}

fn chat(key: &str, text: &str) -> Result<Request<Body>, axum::http::Error> {
    let body = json!({"model": "gpt-4o-mini", "messages": [{"role": "user", "content": text}]});
    Request::post("/v1/chat/completions")
        .header(header::AUTHORIZATION, format!("Bearer {key}"))
        .body(Body::from(body.to_string()))
}

fn messages(key: &str, body: &Value) -> Result<Request<Body>, axum::http::Error> {
    Request::post("/v1/messages")
        .header("x-api-key", key)
        .header("anthropic-version", "2023-06-01")
        .body(Body::from(body.to_string()))
}

struct Answer {
    status: StatusCode,
    cache: Option<String>,
    decision: String,
    body: String,
}

async fn send(app: &Router, request: Request<Body>) -> Result<Answer, Error> {
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let (cache, decision) = (
        header("x-enterplace-cache"),
        header("x-enterplace-decision"),
    );
    let body = response.into_body().collect().await?.to_bytes();
    Ok(Answer {
        status,
        cache,
        decision: decision.unwrap_or_default(),
        body: String::from_utf8(body.to_vec())?,
    })
}

fn records(path: &Path) -> Result<Vec<Value>, Error> {
    std::fs::read_to_string(path)?
        .lines()
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

/// The record of a decision (`event` absent) or of an event about it, waiting for it.
async fn record(audit: &Path, id: &str, event: Option<&str>) -> Result<Value, Error> {
    let start = Instant::now();
    loop {
        let found = records(audit)?
            .into_iter()
            .find(|r| r["id"] == id && r["event"].as_str() == event);
        if let Some(record) = found {
            return Ok(record);
        }
        if start.elapsed() > Duration::from_secs(3) {
            return Err(format!("no {event:?} record for {id}").into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Sends, and waits for the answer to be settled, so the next request can find it in the cache.
async fn settled(s: &Setup, request: Request<Body>) -> Result<Answer, Error> {
    let answer = send(&s.gw.router, request).await?;
    record(&s.audit, &answer.decision, Some("usage")).await?;
    Ok(answer)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_exact_cached_answer_stays_with_its_person_or_team() -> TestResult {
    let s = setup("exact-scope").await?;
    let first = settled(&s, chat(CARA, "hello there")?).await?;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);

    // Same rule, same team, same body: otto is another person, and the default scope is the person.
    let otto = settled(&s, chat(OTTO, "hello there")?).await?;
    assert_eq!(otto.cache.as_deref(), None);
    assert_ne!(otto.body, first.body);
    let again = send(&s.gw.router, chat(CARA, "hello there")?).await?;
    assert_eq!(
        (again.cache.as_deref(), &again.body),
        (Some("hit"), &first.body)
    );
    let hit = record(&s.audit, &again.decision, None).await?;
    assert_eq!(hit["cache"], "hit");
    assert_eq!(hit["cache_match"], "exact");
    assert_eq!(hit["cache_scope"], "person");
    assert_eq!(hit["cache_origin"], first.decision.as_str());

    // A team scope: a teammate shares the answer, another team never does, under the same rule.
    let pat = settled(&s, chat(PAT, "hello there")?).await?;
    let pam = send(&s.gw.router, chat(PAM, "hello there")?).await?;
    assert_eq!((pam.cache.as_deref(), &pam.body), (Some("hit"), &pat.body));
    assert_eq!(
        record(&s.audit, &pam.decision, None).await?["cache_scope"],
        "team"
    );
    let sam = send(&s.gw.router, chat(SAM, "hello there")?).await?;
    assert_eq!(sam.cache.as_deref(), None);
    assert_ne!(sam.body, pat.body);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn the_semantic_cache_serves_the_same_question_in_other_words_within_its_scope_only()
-> TestResult {
    let s = setup("semantic").await?;
    let first = settled(&s, chat(CARA, "What is the capital of France?")?).await?;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    let miss = record(&s.audit, &first.decision, None).await?;
    assert_eq!(miss["cache"], "miss");
    // The embedding is a request of its own: decided, recorded and charged as cara's, under her rule.
    let embedding = miss["cache_embedding"].as_str().ok_or("no embedding id")?;
    let embedded = record(&s.audit, embedding, None).await?;
    assert_eq!(
        (&embedded["path"], &embedded["person"], &embedded["verdict"]),
        (&json!("/v1/embeddings"), &json!("cara"), &json!("allow"))
    );
    record(&s.audit, embedding, Some("usage")).await?;

    let reworded = send(&s.gw.router, chat(CARA, "Tell me France's capital")?).await?;
    assert_eq!(
        (reworded.cache.as_deref(), &reworded.body),
        (Some("hit"), &first.body)
    );
    assert_eq!(s.seen.chats.load(Ordering::SeqCst), 1);
    let hit = record(&s.audit, &reworded.decision, None).await?;
    assert_eq!(hit["cache"], "hit");
    assert_eq!(hit["cache_match"], "semantic");
    assert_eq!(hit["cache_origin"], first.decision.as_str());
    let similarity = hit["cache_similarity"].as_f64().ok_or("no similarity")?;
    assert!((0.97..0.99).contains(&similarity), "{similarity}");
    let usage = record(&s.audit, &reworded.decision, Some("usage")).await?;
    assert_eq!(usage["cost_usd"].as_f64(), Some(0.0));

    // Another question is far from it.
    let other = settled(&s, chat(CARA, "Will it rain tomorrow?")?).await?;
    assert_eq!(other.cache.as_deref(), None);

    // Another person on the same rule and team never gets cara's answer, however close the question.
    let otto = settled(&s, chat(OTTO, "Tell me France's capital")?).await?;
    assert_eq!(otto.cache.as_deref(), None);
    assert_ne!(otto.body, first.body);

    // Team scope: a teammate gets it, another team under the same rule does not.
    let pat = settled(&s, chat(PAT, "What is the capital of France?")?).await?;
    let pam = send(&s.gw.router, chat(PAM, "Tell me France's capital")?).await?;
    assert_eq!((pam.cache.as_deref(), &pam.body), (Some("hit"), &pat.body));
    let sam = send(&s.gw.router, chat(SAM, "Tell me France's capital")?).await?;
    assert_eq!(sam.cache.as_deref(), None);
    assert_ne!(sam.body, pat.body);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn an_answer_a_guardrail_masked_is_never_cached() -> TestResult {
    let s = setup("guarded").await?;
    let first = settled(&s, chat(GUS, "leak it please")?).await?;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    assert!(!first.body.contains(AWS), "{}", first.body);
    assert_eq!(
        record(&s.audit, &first.decision, Some("answer_guardrails")).await?["verdict"],
        "mask"
    );
    let again = settled(&s, chat(GUS, "leak it please")?).await?;
    assert_eq!(again.cache.as_deref(), None);
    assert_eq!(s.seen.chats.load(Ordering::SeqCst), 2);

    // A clean answer under the same rule is cached as usual.
    settled(&s, chat(GUS, "hello there")?).await?;
    let hit = send(&s.gw.router, chat(GUS, "hello there")?).await?;
    assert_eq!(hit.cache.as_deref(), Some("hit"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn prompt_cache_auto_marks_the_stable_prefix_and_reports_the_savings() -> TestResult {
    let s = setup("prompt").await?;
    let body = json!({
        "model": "claude-sonnet-5-5",
        "max_tokens": 10,
        "system": "You are terse.",
        "tools": [
            {"name": "a", "input_schema": {"type": "object"}},
            {"name": "b", "input_schema": {"type": "object"}}
        ],
        "messages": [
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": "hello"},
            {"role": "user", "content": [{"type": "text", "text": "more"}]}
        ]
    });
    let answer = settled(&s, messages(PIA, &body)?).await?;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    let sent: Value = {
        let all = s.seen.messages.lock().map_err(|_| "poisoned")?;
        serde_json::from_slice(all.last().ok_or("nothing sent")?)?
    };
    let mark = json!({"type": "ephemeral"});
    assert_eq!(sent["tools"][1]["cache_control"], mark);
    assert!(sent["tools"][0].get("cache_control").is_none());
    assert_eq!(
        sent["system"],
        json!([{"type": "text", "text": "You are terse.", "cache_control": mark}])
    );
    assert_eq!(sent["messages"][2]["content"][0]["cache_control"], mark);
    assert_eq!(sent["messages"][0]["content"], "hi");
    // Nothing else changed.
    let mut unmarked = sent.clone();
    if let Some(tool) = unmarked["tools"][1].as_object_mut() {
        tool.remove("cache_control");
    }
    unmarked["system"] = json!("You are terse.");
    if let Some(block) = unmarked["messages"][2]["content"][0].as_object_mut() {
        block.remove("cache_control");
    }
    assert_eq!(unmarked, body);
    let decided = record(&s.audit, &answer.decision, None).await?;
    assert_eq!(
        decided["prompt_cache"],
        json!(["tools", "system", "messages"])
    );

    // 1,000,000 tokens read from the provider's cache at 0.3 instead of 3 dollars per million.
    let usage = record(&s.audit, &answer.decision, Some("usage")).await?;
    assert_eq!(usage["cache_read_tokens"], 1_000_000);
    let saved = usage["cache_saved_usd"].as_f64().ok_or("no savings")?;
    assert!((saved - 2.7).abs() < 1e-9, "{saved}");
    let metrics = send(&s.gw.metrics, Request::get("/metrics").body(Body::empty())?).await?;
    assert!(
        metrics
            .body
            .contains("enterplace_cache_saved_usd{team=\"research\",kind=\"prompt\"} 2.7"),
        "{}",
        metrics.body
    );

    // A request that places its own breakpoints is sent as it came.
    let mut own = body.clone();
    own["system"] = json!([{"type": "text", "text": "x", "cache_control": {"type": "ephemeral"}}]);
    let answer = settled(&s, messages(PIA, &own)?).await?;
    let sent: Value = {
        let all = s.seen.messages.lock().map_err(|_| "poisoned")?;
        serde_json::from_slice(all.last().ok_or("nothing sent")?)?
    };
    assert_eq!(sent, own);
    assert!(
        record(&s.audit, &answer.decision, None)
            .await?
            .get("prompt_cache")
            .is_none()
    );

    // A rule without prompt_cache never changes the body.
    settled(&s, messages(SAM, &body)?).await?;
    let sent: Value = {
        let all = s.seen.messages.lock().map_err(|_| "poisoned")?;
        serde_json::from_slice(all.last().ok_or("nothing sent")?)?
    };
    assert_eq!(sent, body);
    Ok(())
}
