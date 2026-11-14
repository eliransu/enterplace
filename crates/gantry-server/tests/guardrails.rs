//! Guardrails on the request path: built-in detectors and webhook guardrails, on both routes, with records.
//! Mock providers and mock guardrail vendors listen on ports of 127.0.0.1 the system picks, one set per test.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    http::{Request, StatusCode, header},
    routing::post,
};
use gantry_core::id::sha256_hex;
use gantry_server::{Governed, Reload, Trigger};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Error = Box<dyn std::error::Error>;

const MAYA: &str = "gantry_maya_0123456789abcdef0123456789";
const AWS: &str = "AKIAIOSFODNN7EXAMPLE";

/// A port of 127.0.0.1 nothing listens on: the vendor that is down. The system picked it free, and it is let go.
fn down_port() -> std::io::Result<u16> {
    Ok(std::net::TcpListener::bind(("127.0.0.1", 0))?
        .local_addr()?
        .port())
}

/// A provider that answers every request with the exact body it received, so a test sees what was forwarded.
/// Returns its port.
async fn provider() -> Result<u16, Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let echo = post(|body: Bytes| async move { body });
    let app = Router::new()
        .route("/v1/chat/completions", echo.clone())
        .route("/v1/messages", echo);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

type Seen = Arc<Mutex<Vec<Value>>>;

/// A guardrail vendor with one path per behaviour. It keeps every request it was sent. Returns them and its base URL.
async fn vendor() -> Result<(Seen, String), Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let base = format!("http://{}", listener.local_addr()?);
    let seen: Seen = Arc::default();
    let keep = |seen: &Seen, body: &Bytes| -> Value {
        let value: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        if let Ok(mut all) = seen.lock() {
            all.push(value.clone());
        }
        value
    };
    let app = Router::new()
        .route(
            "/allow",
            post(move |State(s): State<Seen>, body: Bytes| async move {
                keep(&s, &body);
                r#"{"action":"allow"}"#
            }),
        )
        .route(
            "/block",
            post(move |State(s): State<Seen>, body: Bytes| async move {
                keep(&s, &body);
                r#"{"action":"block","reason":"saw Maya Cohen","findings":[{"kind":"person_name","message":0}]}"#
            }),
        )
        .route(
            "/mask",
            post(move |State(s): State<Seen>, body: Bytes| async move {
                let sent = keep(&s, &body);
                let masked: Vec<Value> = sent["messages"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|m| json!(m["text"].as_str().unwrap_or("").replace("Maya Cohen", "[NAME]")))
                    .collect();
                json!({"action": "mask", "findings": [{"kind": "person_name"}], "masked_messages": masked})
                    .to_string()
            }),
        )
        .route(
            "/slow",
            post(move |State(s): State<Seen>, body: Bytes| async move {
                keep(&s, &body);
                tokio::time::sleep(Duration::from_secs(2)).await;
                r#"{"action":"allow"}"#
            }),
        )
        .route(
            "/malformed",
            post(move |State(s): State<Seen>, body: Bytes| async move {
                keep(&s, &body);
                r#"{"action":"deny"}"#
            }),
        )
        .route(
            "/error",
            post(move |State(s): State<Seen>, body: Bytes| async move {
                keep(&s, &body);
                (StatusCode::INTERNAL_SERVER_ERROR, r#"{"action":"allow"}"#)
            }),
        )
        .with_state(seen.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((seen, base))
}

fn policy(port: u16, guardrails: &str, names: &str) -> String {
    format!(
        "version: 1
providers:
  - name: mock-openai
    kind: openai
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: MOCK_KEY
    models: [model-a]
  - name: mock-anthropic
    kind: anthropic
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: MOCK_KEY
    models: [claude-a]
guardrails:
{guardrails}rules:
  - name: everyone
    principals: {{ any: true }}
    models: [\"*\"]
    guardrails: [{names}]
"
    )
}

fn hook(name: &str, url: &str, on_failure: &str, timeout_ms: u64) -> String {
    format!(
        "  - name: {name}\n    type: webhook\n    url: {url}\n    timeout_ms: {timeout_ms}\n    on_failure: {on_failure}\n"
    )
}

fn builtin(name: &str, kind: &str, action: &str) -> String {
    format!("  - name: {name}\n    type: {kind}\n    action: {action}\n")
}

struct Setup {
    policy: PathBuf,
    audit: PathBuf,
    gw: Governed,
}

fn setup(name: &str, policy: &str) -> Result<Setup, Error> {
    let dir = std::env::temp_dir().join(format!("gantry-guard-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("gantry.policy.yaml");
    std::fs::write(&path, policy)?;
    std::fs::write(
        dir.join("gantry.keys.yaml"),
        format!(
            "keys:\n  - name: maya.cohen\n    team: payments\n    sha256: {}\n",
            sha256_hex(MAYA.as_bytes())
        ),
    )?;
    let gw = gantry_server::governed(&path, None, &|_| Some("provider-secret".into()))?;
    Ok(Setup {
        policy: path,
        audit: dir.join("gantry-audit.jsonl"),
        gw,
    })
}

fn chat(text: &str) -> Result<Request<Body>, axum::http::Error> {
    let body = json!({"model": "model-a", "temperature": 0.5, "messages": [{"role": "user", "content": text}]});
    Request::post("/v1/chat/completions")
        .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
        .body(Body::from(body.to_string()))
}

fn messages(text: &str) -> Result<Request<Body>, axum::http::Error> {
    let body = json!({"model": "claude-a", "max_tokens": 64, "system": "be brief", "messages": [{"role": "user", "content": [{"type": "text", "text": text}]}]});
    Request::post("/v1/messages")
        .header("x-api-key", MAYA)
        .body(Body::from(body.to_string()))
}

struct Answer {
    status: StatusCode,
    retry: String,
    decision: String,
    body: String,
}

async fn send(gw: &Governed, request: Request<Body>) -> Result<Answer, Error> {
    let response = gw.router.clone().oneshot(request).await?;
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    let (status, retry, decision) = (
        response.status(),
        header("x-should-retry"),
        header("x-gantry-decision"),
    );
    let body = response.into_body().collect().await?.to_bytes();
    Ok(Answer {
        status,
        retry,
        decision,
        body: String::from_utf8(body.to_vec())?,
    })
}

/// The request records, newest last.
fn requests(s: &Setup) -> Result<Vec<Value>, Error> {
    std::fs::read_to_string(&s.audit)?
        .lines()
        .map(|line| Ok(serde_json::from_str::<Value>(line)?))
        .filter(|r| !matches!(r, Ok(v) if v.get("event").is_some()))
        .collect()
}

fn last(s: &Setup) -> Result<Value, Error> {
    requests(s)?.pop().ok_or_else(|| "no request record".into())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_blocking_guardrail_refuses_on_both_routes_and_records_without_the_text() -> TestResult {
    let port = provider().await?;
    let s = setup(
        "block",
        &policy(
            port,
            &builtin("no-secrets", "secrets", "block"),
            "no-secrets",
        ),
    )?;

    let refused = send(&s.gw, chat(&format!("deploy with {AWS}"))?).await?;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{}", refused.body);
    assert_eq!(refused.retry, "false");
    let body: Value = serde_json::from_str(&refused.body)?;
    assert_eq!(body["error"]["code"], "guardrail_blocked");
    let message = body["error"]["message"].as_str().unwrap_or("");
    assert!(
        message.contains("\"no-secrets\"") && message.contains("aws_access_key"),
        "{message}"
    );
    assert!(!refused.body.contains(AWS), "{}", refused.body);
    let record = last(&s)?;
    assert_eq!(record["verdict"], "refused");
    assert_eq!(record["code"], "guardrail_blocked");
    assert_eq!(record["id"], refused.decision);
    assert_eq!(
        record["guardrails"],
        json!([{"guardrail": "no-secrets", "detector": "secrets", "kind": "aws_access_key", "action": "block", "count": 1}])
    );
    assert!(!std::fs::read_to_string(&s.audit)?.contains(AWS));

    let refused = send(&s.gw, messages(&format!("deploy with {AWS}"))?).await?;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.retry, "false");
    let body: Value = serde_json::from_str(&refused.body)?;
    assert_eq!(body["type"], "error");
    assert_eq!(body["error"]["type"], "permission_error");
    assert_eq!(body["gantry_code"], "guardrail_blocked");
    assert!(!refused.body.contains(AWS));

    // A clean request goes through, and its record says the guardrails ran and found nothing.
    let clean = send(&s.gw, messages("hello")?).await?;
    assert_eq!(clean.status, StatusCode::OK, "{}", clean.body);
    let record = last(&s)?;
    assert_eq!(record["verdict"], "allow");
    assert_eq!(record["guardrails"], json!([]));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_masking_guardrail_forwards_the_masked_body_and_warn_forwards_it_unchanged() -> TestResult
{
    let port = provider().await?;
    let guards = format!(
        "{}{}",
        builtin("mask-pii", "pii", "mask"),
        builtin("watch-secrets", "secrets", "warn")
    );
    let s = setup("mask", &policy(port, &guards, "mask-pii, watch-secrets"))?;

    let sent = chat("mail maya@corp.example.com now")?;
    let answer = send(&s.gw, sent).await?;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    // Only the span changed: the other fields, their order and their numbers are as sent.
    assert_eq!(
        answer.body,
        r#"{"model":"model-a","temperature":0.5,"messages":[{"role":"user","content":"mail [MASKED email_address] now"}]}"#
    );
    let record = last(&s)?;
    assert_eq!(record["verdict"], "allow");
    assert_eq!(record["guardrails"][0]["action"], "mask");
    assert_eq!(record["guardrails"][0]["kind"], "email_address");

    let answer = send(&s.gw, messages("I am maya@corp.example.com")?).await?;
    let forwarded: Value = serde_json::from_str(&answer.body)?;
    assert_eq!(
        forwarded["messages"][0]["content"][0]["text"],
        "I am [MASKED email_address]"
    );

    // Warn: the exact bytes go on, and the finding is recorded.
    let text = format!("key {AWS}");
    let original = json!({"model": "model-a", "temperature": 0.5, "messages": [{"role": "user", "content": text}]}).to_string();
    let answer = send(&s.gw, chat(&text)?).await?;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.body, original);
    let record = last(&s)?;
    assert_eq!(record["guardrails"][0]["action"], "warn");
    assert_eq!(record["guardrails"][0]["kind"], "aws_access_key");
    assert!(!std::fs::read_to_string(&s.audit)?.contains(AWS));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_webhook_guardrail_gets_the_contract_and_its_answer_is_applied() -> TestResult {
    let port = provider().await?;
    let (seen, base) = vendor().await?;

    let s = setup(
        "hook-allow",
        &policy(
            port,
            &hook("vendor", &format!("{base}/allow"), "fail_closed", 1000),
            "vendor",
        ),
    )?;
    let answer = send(&s.gw, messages("I am Maya Cohen")?).await?;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    let sent = seen
        .lock()
        .map_err(|_| "lock")?
        .last()
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        sent,
        json!({
            "decision_id": answer.decision,
            "person": "maya.cohen",
            "team": "payments",
            "model": "claude-a",
            "route": "/v1/messages",
            "messages": [{"role": "system", "text": "be brief"}, {"role": "user", "text": "I am Maya Cohen"}]
        })
    );
    assert_eq!(last(&s)?["guardrails"], json!([]));

    let s = setup(
        "hook-block",
        &policy(
            port,
            &hook("vendor", &format!("{base}/block"), "fail_open", 1000),
            "vendor",
        ),
    )?;
    let answer = send(&s.gw, chat("I am Maya Cohen")?).await?;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert!(
        answer.body.contains("guardrail_blocked") && answer.body.contains("person_name"),
        "{}",
        answer.body
    );
    // The vendor's reason quotes the prompt, so it is neither shown nor recorded.
    assert!(!answer.body.contains("Maya Cohen"), "{}", answer.body);
    let record = last(&s)?;
    assert_eq!(record["code"], "guardrail_blocked");
    assert_eq!(
        record["guardrails"],
        json!([{"guardrail": "vendor", "detector": "webhook", "kind": "person_name", "action": "block", "count": 1}])
    );
    assert!(!std::fs::read_to_string(&s.audit)?.contains("Maya Cohen"));

    let s = setup(
        "hook-mask",
        &policy(
            port,
            &hook("vendor", &format!("{base}/mask"), "fail_closed", 1000),
            "vendor",
        ),
    )?;
    let answer = send(&s.gw, messages("I am Maya Cohen")?).await?;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    let forwarded: Value = serde_json::from_str(&answer.body)?;
    assert_eq!(
        forwarded["messages"][0]["content"][0]["text"],
        "I am [NAME]"
    );
    assert_eq!(forwarded["system"], "be brief");
    assert_eq!(last(&s)?["guardrails"][0]["action"], "mask");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_webhook_that_fails_follows_on_failure() -> TestResult {
    let port = provider().await?;
    let (_, base) = vendor().await?;
    let down = down_port()?;
    let failures = [
        ("slow", format!("{base}/slow")),
        ("down", format!("http://127.0.0.1:{down}/check")),
        ("malformed", format!("{base}/malformed")),
        ("error", format!("{base}/error")),
    ];
    for (what, url) in failures {
        for (mode, status, action) in [
            ("fail_closed", StatusCode::FORBIDDEN, "block"),
            ("fail_open", StatusCode::OK, "skipped"),
        ] {
            let s = setup(
                &format!("fail-{what}-{mode}"),
                &policy(port, &hook("vendor", &url, mode, 300), "vendor"),
            )?;
            let started = std::time::Instant::now();
            let answer = send(&s.gw, chat("hello")?).await?;
            assert_eq!(answer.status, status, "{what} {mode}: {}", answer.body);
            // The slow vendor answers after 2 s; the guardrail's 300 ms timeout must not wait for it.
            assert!(
                started.elapsed() < Duration::from_millis(1500),
                "{what} {mode}"
            );
            let record = last(&s)?;
            assert_eq!(
                record["guardrails"],
                json!([{"guardrail": "vendor", "detector": "webhook", "kind": "unavailable", "action": action, "count": 1}]),
                "{what} {mode}"
            );
            if mode == "fail_closed" {
                assert_eq!(answer.retry, "false");
                assert!(answer.body.contains("fail_closed"), "{}", answer.body);
                assert_eq!(record["code"], "guardrail_blocked");
            } else {
                assert_eq!(record["verdict"], "allow");
            }
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reload_that_changes_guardrails_applies_to_the_next_request() -> TestResult {
    let port = provider().await?;
    let (_, base) = vendor().await?;
    let warn = policy(port, &builtin("secrets", "secrets", "warn"), "secrets");
    let s = setup("reload", &warn)?;
    assert_eq!(send(&s.gw, chat(AWS)?).await?.status, StatusCode::OK);

    std::fs::write(&s.policy, warn.replace("action: warn", "action: block"))?;
    assert!(matches!(
        s.gw.reloader.check(Trigger::FileChange),
        Reload::Loaded
    ));
    assert_eq!(send(&s.gw, chat(AWS)?).await?.status, StatusCode::FORBIDDEN);

    // A webhook's URL may change without a restart.
    let at = |path: &str| {
        policy(
            port,
            &hook("vendor", &format!("{base}/{path}"), "fail_closed", 500),
            "vendor",
        )
    };
    std::fs::write(&s.policy, at("allow"))?;
    assert!(matches!(
        s.gw.reloader.check(Trigger::FileChange),
        Reload::Loaded
    ));
    assert_eq!(send(&s.gw, chat("hi")?).await?.status, StatusCode::OK);
    std::fs::write(&s.policy, at("block"))?;
    assert!(matches!(
        s.gw.reloader.check(Trigger::FileChange),
        Reload::Loaded
    ));
    assert_eq!(
        send(&s.gw, chat("hi")?).await?.status,
        StatusCode::FORBIDDEN
    );

    // A rule that names an undefined guardrail is rejected, and the version in use stays.
    std::fs::write(
        &s.policy,
        at("allow").replace("guardrails: [vendor]", "guardrails: [vendr]"),
    )?;
    assert!(matches!(
        s.gw.reloader.check(Trigger::FileChange),
        Reload::Rejected(_)
    ));
    assert_eq!(
        send(&s.gw, chat("hi")?).await?.status,
        StatusCode::FORBIDDEN
    );
    Ok(())
}

/// A hosted guardrail service wants a credential. It comes from an environment variable the policy names, and is never
/// in the policy or the audit log. The test reads CARGO_MANIFEST_DIR, which cargo sets, because setting a variable
/// needs `unsafe`.
#[tokio::test(flavor = "multi_thread")]
async fn a_webhook_sends_a_credential_from_the_environment_and_never_records_it() -> TestResult {
    let token = std::env::var("CARGO_MANIFEST_DIR")?;
    let port = provider().await?;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let auth = format!("http://{}/auth", listener.local_addr()?);
    let want = token.clone();
    let app = Router::new().route(
        "/auth",
        post(move |headers: axum::http::HeaderMap| async move {
            if headers.get("authorization").and_then(|v| v.to_str().ok()) == Some(want.as_str()) {
                (StatusCode::OK, r#"{"action":"allow"}"#)
            } else {
                (StatusCode::UNAUTHORIZED, r#"{"error":"no credential"}"#)
            }
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let guarded = |variable: &str| {
        policy(
            port,
            &format!(
                "{}    headers_env: {{ Authorization: {variable} }}\n",
                hook("vendor", &auth, "fail_closed", 1000)
            ),
            "vendor",
        )
    };
    let s = setup("hook-credential", &guarded("CARGO_MANIFEST_DIR"))?;
    let answer = send(&s.gw, chat("hello")?).await?;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    let log = std::fs::read_to_string(&s.audit)?;
    assert!(
        !log.contains(&token),
        "the credential reached the audit log"
    );
    assert!(!answer.body.contains(&token));

    // Without the variable, Gantry does not start, and a reload to such a policy is refused.
    let unset = "GANTRY_TEST_UNSET_GUARD_TOKEN";
    let path = s.policy.with_file_name("other.policy.yaml");
    std::fs::write(&path, guarded(unset))?;
    let err = gantry_server::governed(
        &path,
        s.policy
            .parent()
            .map(|d| d.join("gantry.keys.yaml"))
            .as_deref(),
        &|v| (v == "MOCK_KEY").then(|| "provider-secret".to_string()),
    )
    .err()
    .ok_or("Gantry started with the credential unset")?;
    assert!(err.contains(unset) && err.contains("is not set"), "{err}");
    std::fs::write(&s.policy, guarded(unset))?;
    let Reload::Rejected(problems) = s.gw.reloader.check(Trigger::Signal) else {
        return Err("a reload to a policy with an unset credential was applied".into());
    };
    assert!(problems.join("\n").contains(unset), "{problems:?}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_body_with_a_duplicated_key_is_refused_before_the_guardrails_read_it() -> TestResult {
    // QA10-8: the guardrail reads the last copy and a provider may act on the first, so neither copy is sent. The
    // provider is a port nothing listens on: a request that got through would be a 502, not a 400.
    let s = setup(
        "duplicate",
        &policy(
            down_port()?,
            &builtin("no-secrets", "secrets", "block"),
            "no-secrets",
        ),
    )?;
    let body = format!(
        r#"{{"model":"model-a","messages":[{{"role":"user","content":"deploy with {AWS}"}}],"messages":[{{"role":"user","content":"hi"}}]}}"#
    );
    let answer = send(
        &s.gw,
        Request::post("/v1/chat/completions")
            .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
            .body(Body::from(body))?,
    )
    .await?;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{}", answer.body);
    assert!(
        answer.body.contains("unreadable_request") && answer.body.contains("appears twice"),
        "{}",
        answer.body
    );
    let record = last(&s)?;
    assert_eq!(record["verdict"], "refused");
    assert_eq!(record["code"], "unreadable_request");
    assert!(!std::fs::read_to_string(&s.audit)?.contains(AWS));
    Ok(())
}

/// A provider that answers in each API's own shape, repeating the caller's last text: "You said: ...". A stream
/// when asked for one.
async fn parrot() -> Result<u16, Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let said = |body: &Bytes| -> String {
        let request: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        let last = &request["messages"][0]["content"];
        let text = last
            .as_str()
            .or_else(|| last[0]["text"].as_str())
            .unwrap_or("");
        format!("You said: {text}")
    };
    let app = Router::new()
        .route(
            "/v1/chat/completions",
            post(move |body: Bytes| async move {
                let text = said(&body);
                let stream = serde_json::from_slice::<Value>(&body).is_ok_and(|r| r["stream"] == true);
                if stream {
                    // In two pieces, so a secret is split across events as a model's tokens split it.
                    let (one, two) = halves(&text);
                    let chunk = |piece: &str, end: Value| json!({"id": "c", "model": "model-a", "choices": [{"index": 0, "delta": {"content": piece}, "finish_reason": end}]});
                    let usage = json!({"id": "c", "model": "model-a", "choices": [], "usage": {"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10}});
                    return (
                        [(header::CONTENT_TYPE, "text/event-stream")],
                        format!(
                            "data: {}\n\ndata: {}\n\ndata: {usage}\n\ndata: [DONE]\n\n",
                            chunk(one, Value::Null),
                            chunk(two, json!("stop"))
                        ),
                    );
                }
                (
                    [(header::CONTENT_TYPE, "application/json")],
                    json!({"id": "c", "object": "chat.completion", "created": 1, "model": "model-a",
                        "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": text}}],
                        "usage": {"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10}})
                    .to_string(),
                )
            }),
        )
        .route(
            "/v1/messages",
            post(move |body: Bytes| async move {
                if serde_json::from_slice::<Value>(&body).is_ok_and(|r| r["stream"] == true) {
                    let text = said(&body);
                    let (one, two) = halves(&text);
                    let delta = |piece: &str| json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": piece}});
                    let events = [
                        ("message_start", json!({"type": "message_start", "message": {"id": "m", "type": "message", "role": "assistant", "model": "claude-a", "content": [], "stop_reason": null, "usage": {"input_tokens": 5, "output_tokens": 0}}})),
                        ("content_block_start", json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}})),
                        ("content_block_delta", delta(one)),
                        ("content_block_delta", delta(two)),
                        ("content_block_stop", json!({"type": "content_block_stop", "index": 0})),
                        ("message_delta", json!({"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": null}, "usage": {"output_tokens": 5}})),
                        ("message_stop", json!({"type": "message_stop"})),
                    ];
                    let body: String = events
                        .iter()
                        .map(|(name, data)| format!("event: {name}\ndata: {data}\n\n"))
                        .collect();
                    return ([(header::CONTENT_TYPE, "text/event-stream")], body);
                }
                (
                    [(header::CONTENT_TYPE, "application/json")],
                    json!({"id": "m", "type": "message", "role": "assistant", "model": "claude-a",
                        "content": [{"type": "text", "text": said(&body)}], "stop_reason": "end_turn",
                        "stop_sequence": null, "usage": {"input_tokens": 5, "output_tokens": 5}})
                    .to_string(),
                )
            }),
        );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

/// A text cut in two at a character boundary near its middle.
fn halves(text: &str) -> (&str, &str) {
    let mut at = text.len() / 2;
    while !text.is_char_boundary(at) {
        at += 1;
    }
    text.split_at(at)
}

/// The answer_guardrails records, oldest first.
fn answer_records(s: &Setup) -> Result<Vec<Value>, Error> {
    Ok(std::fs::read_to_string(&s.audit)?
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|r| r["event"] == "answer_guardrails")
        .collect())
}

#[tokio::test(flavor = "multi_thread")]
async fn an_answer_guardrail_blocks_or_masks_the_answer_and_records_it() -> TestResult {
    let port = parrot().await?;
    let guards = format!(
        "{}    on: [answer]\n{}    on: [answer]\n",
        builtin("answer-secrets", "secrets", "block"),
        builtin("answer-pii", "pii", "mask")
    );
    let s = setup(
        "answer",
        &policy(port, &guards, "answer-secrets, answer-pii"),
    )?;

    // The request side does not run these, so the secret reaches the model and comes back in its answer.
    let blocked = send(&s.gw, chat(&format!("deploy with {AWS}"))?).await?;
    assert_eq!(blocked.status, StatusCode::FORBIDDEN, "{}", blocked.body);
    let body: Value = serde_json::from_str(&blocked.body)?;
    assert_eq!(body["error"]["code"], "guardrail_blocked");
    assert!(
        blocked.body.contains("withheld the model's answer") && !blocked.body.contains(AWS),
        "{}",
        blocked.body
    );
    let request = last(&s)?;
    assert_eq!(request["verdict"], "allow");
    assert!(request.get("guardrails").is_none(), "{request}");
    let answers = answer_records(&s)?;
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0]["id"], blocked.decision);
    assert_eq!(answers[0]["verdict"], "block");
    assert_eq!(answers[0]["guardrails"][0]["guardrail"], "answer-secrets");

    let masked = send(&s.gw, messages("write to maya.cohen@example.com")?).await?;
    assert_eq!(masked.status, StatusCode::OK, "{}", masked.body);
    let body: Value = serde_json::from_str(&masked.body)?;
    let text = body["content"][0]["text"].as_str().unwrap_or_default();
    assert!(
        text.starts_with("You said: write to ") && !text.contains("maya.cohen@example.com"),
        "{text}"
    );
    let answers = answer_records(&s)?;
    assert_eq!((answers.len(), &answers[1]["verdict"]), (2, &json!("mask")));
    assert_eq!(answers[1]["id"], masked.decision);

    let clean = send(&s.gw, chat("hello")?).await?;
    assert_eq!(clean.status, StatusCode::OK);
    assert_eq!(answer_records(&s)?[2]["verdict"], "pass");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_streamed_answer_is_not_checked_and_its_record_says_so() -> TestResult {
    let port = parrot().await?;
    let guards = format!(
        "{}    on: [request, answer]\n",
        builtin("both", "secrets", "block")
    );
    let s = setup("answer-stream", &policy(port, &guards, "both"))?;
    let body = json!({"model": "model-a", "stream": true, "messages": [{"role": "user", "content": "hi"}]});
    let request = Request::post("/v1/chat/completions")
        .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
        .body(Body::from(body.to_string()))?;
    let streamed = send(&s.gw, request).await?;
    assert_eq!(streamed.status, StatusCode::OK);
    assert_eq!(
        streamed_text(&streamed.body),
        "You said: hi",
        "{}",
        streamed.body
    );
    // Written after the answer has started; give it a moment.
    let mut records = Vec::new();
    for _ in 0..50 {
        records = answer_records(&s)?;
        if !records.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(records[0]["verdict"], "not_run");
    assert_eq!(records[0]["id"], streamed.decision);
    // On both sides: the request with the secret never reaches the model.
    let refused = send(&s.gw, chat(&format!("deploy with {AWS}"))?).await?;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert!(
        refused.body.contains("refused this request"),
        "{}",
        refused.body
    );
    Ok(())
}

/// The text a stream carries, chat chunks or messages text deltas, joined.
fn streamed_text(body: &str) -> String {
    body.lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .filter_map(|data| serde_json::from_str::<Value>(data).ok())
        .map(|event| {
            let chat = event["choices"][0]["delta"]["content"].as_str();
            let messages = event["delta"]["text"].as_str();
            chat.or(messages).unwrap_or_default().to_string()
        })
        .collect()
}

fn stream(path: &str, model: &str, text: &str) -> Result<Request<Body>, axum::http::Error> {
    let body = json!({"model": model, "max_tokens": 64, "stream": true, "messages": [{"role": "user", "content": text}]});
    Request::post(path)
        .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
        .header("x-api-key", MAYA)
        .body(Body::from(body.to_string()))
}

#[tokio::test(flavor = "multi_thread")]
async fn buffer_stream_checks_a_streamed_answer_then_replays_it() -> TestResult {
    let port = parrot().await?;
    let guards = format!(
        "{}    on: [answer]\n{}    on: [answer]\n",
        builtin("answer-secrets", "secrets", "block"),
        builtin("answer-pii", "pii", "mask")
    );
    // A third provider speaks chat and takes messages requests, translated both ways.
    let text = policy(port, &guards, "answer-secrets, answer-pii")
        .replace(
            "guardrails:\n",
            &format!("  - name: mock-chat\n    kind: openai\n    url: http://127.0.0.1:{port}\n    allow_private: true\n    key_env: MOCK_KEY\n    models: [model-m]\n    accept_messages: true\nguardrails:\n"),
        )
        .replace(
            "    guardrails: [answer-secrets, answer-pii]\n",
            "    guardrails: [answer-secrets, answer-pii]\n    buffer_stream: true\n",
        );
    let s = setup("answer-buffered", &text)?;

    // Allowed: the events go out as the provider sent them, and the record says the check passed.
    let clean = send(&s.gw, stream("/v1/chat/completions", "model-a", "hello")?).await?;
    assert_eq!(clean.status, StatusCode::OK, "{}", clean.body);
    assert_eq!(
        streamed_text(&clean.body),
        "You said: hello",
        "{}",
        clean.body
    );
    assert!(clean.body.ends_with("data: [DONE]\n\n"), "{}", clean.body);
    let records = answer_records(&s)?;
    assert_eq!((records.len(), &records[0]["verdict"]), (1, &json!("pass")));
    assert_eq!(records[0]["id"], clean.decision);

    // Blocked, though the key is split across two events: a refusal, nothing of the stream.
    for (path, model) in [
        ("/v1/chat/completions", "model-a"),
        ("/v1/messages", "claude-a"),
        ("/v1/messages", "model-m"),
    ] {
        let blocked = send(&s.gw, stream(path, model, &format!("deploy with {AWS}"))?).await?;
        assert_eq!(
            blocked.status,
            StatusCode::FORBIDDEN,
            "{model}: {}",
            blocked.body
        );
        assert!(
            blocked.body.contains("guardrail_blocked") && !blocked.body.contains(AWS),
            "{model}: {}",
            blocked.body
        );
        if path == "/v1/messages" {
            let body: Value = serde_json::from_str(&blocked.body)?;
            assert_eq!(body["type"], "error", "{model}: {}", blocked.body);
        }
        assert_eq!(
            answer_records(&s)?.last().map(|r| r["verdict"].clone()),
            Some(json!("block"))
        );
    }

    // Masked: still a stream, with the masked text in place of what the model wrote.
    for (path, model) in [
        ("/v1/chat/completions", "model-a"),
        ("/v1/messages", "claude-a"),
        ("/v1/messages", "model-m"),
    ] {
        let masked = send(
            &s.gw,
            stream(path, model, "write to maya.cohen@example.com")?,
        )
        .await?;
        assert_eq!(masked.status, StatusCode::OK, "{model}: {}", masked.body);
        let said = streamed_text(&masked.body);
        assert!(
            said.starts_with("You said: write to ")
                && !masked.body.contains("maya.cohen@example.com"),
            "{model}: {said}\n{}",
            masked.body
        );
        assert_eq!(
            answer_records(&s)?.last().map(|r| r["verdict"].clone()),
            Some(json!("mask"))
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn custom_detectors_block_or_shadow_and_the_admin_api_backtests_them() -> TestResult {
    let port = provider().await?;
    let guards = "  - name: tickets\n    type: regex\n    action: block\n    patterns:\n      ticket_id: 'TKT-[0-9]{6}'\n  - name: words\n    type: keywords\n    action: block\n    shadow_until: 2999-01-01\n    keywords:\n      codename: [Project Falcon]\n";
    // Maya, an admin key for the backtest call, and two roles: a backtest is a policy author's tool, so edit_policy
    // runs it and credentials alone does not.
    let admin = "gantry_admin_0123456789abcdef0123456789";
    let author = "gantry_author_0123456789abcdef012345678";
    let keeper = "gantry_keeper_0123456789abcdef012345678";
    let dir = std::env::temp_dir().join(format!("gantry-guard-{}-custom", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("gantry.policy.yaml");
    std::fs::write(
        &path,
        policy(port, guards, "tickets, words")
            + "roles:\n  - name: author\n    permissions: [edit_policy]\n  - name: keeper\n    permissions: [credentials]\n",
    )?;
    std::fs::write(
        dir.join("gantry.keys.yaml"),
        format!(
            "keys:\n  - name: maya.cohen\n    team: payments\n    sha256: {}\n  - name: ops\n    team: platform\n    admin: true\n    sha256: {}\n  - name: author\n    team: platform\n    role: author\n    sha256: {}\n  - name: keeper\n    team: platform\n    role: keeper\n    sha256: {}\n",
            sha256_hex(MAYA.as_bytes()),
            sha256_hex(admin.as_bytes()),
            sha256_hex(author.as_bytes()),
            sha256_hex(keeper.as_bytes())
        ),
    )?;
    let gw = gantry_server::governed(&path, None, &|_| Some("provider-secret".into()))?;
    let s = Setup {
        policy: path,
        audit: dir.join("gantry-audit.jsonl"),
        gw,
    };
    let gw = &s.gw;

    let answer = send(gw, chat("close TKT-123456 please")?).await?;
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{}", answer.body);
    assert!(answer.body.contains("ticket_id (1)") && !answer.body.contains("TKT-123456"));
    let record = last(&s)?;
    assert_eq!(record["guardrails"][0]["detector"], "regex");
    assert_eq!(record["guardrails"][0]["kind"], "ticket_id");

    // In its shadow period the keyword list blocks nothing and records `shadow`.
    let answer = send(gw, chat("how is project falcon going")?).await?;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    let record = last(&s)?;
    assert_eq!(record["guardrails"][0]["kind"], "codename");
    assert_eq!(record["guardrails"][0]["action"], "shadow");
    assert!(!std::fs::read_to_string(&s.audit)?.contains("falcon going"));

    let backtest = |body: Value, key: &str| {
        Request::post("/admin/guardrails/test")
            .header(header::AUTHORIZATION, format!("Bearer {key}"))
            .body(Body::from(body.to_string()))
    };
    let corpus = json!([
        {"text": "TKT-000001", "expect": true},
        {"text": "no ticket", "expect": false},
        {"text": "TKT-000002 again", "expect": false}
    ]);
    let answer = send(
        gw,
        backtest(json!({"guardrail": "tickets", "corpus": corpus}), admin)?,
    )
    .await?;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    let report: Value = serde_json::from_str(&answer.body)?;
    assert_eq!(
        (report["requests"].as_u64(), report["hits"].as_u64()),
        (Some(3), Some(2))
    );
    assert_eq!(report["labelled"]["precision"], 50.0);
    assert!(!answer.body.contains("TKT-000001"), "{}", answer.body);
    // A definition not in the policy yet can be tried too.
    let definition =
        json!({"name": "ids", "type": "regex", "action": "warn", "patterns": {"emp": "E[0-9]{7}"}});
    let answer = send(
        gw,
        backtest(
            json!({"guardrail": definition, "corpus": [{"text": "E1234567"}]}),
            admin,
        )?,
    )
    .await?;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    assert!(answer.body.contains("\"hits\":1"), "{}", answer.body);
    let answer = send(
        gw,
        backtest(json!({"guardrail": "tickets", "since": "7d"}), admin)?,
    )
    .await?;
    assert_eq!(answer.status, StatusCode::CONFLICT, "{}", answer.body);
    let answer = send(
        gw,
        backtest(json!({"guardrail": "nope", "corpus": corpus}), admin)?,
    )
    .await?;
    assert_eq!(answer.status, StatusCode::NOT_FOUND, "{}", answer.body);
    let answer = send(
        gw,
        backtest(json!({"guardrail": "tickets", "corpus": corpus}), MAYA)?,
    )
    .await?;
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{}", answer.body);
    let answer = send(
        gw,
        backtest(json!({"guardrail": "tickets", "corpus": corpus}), author)?,
    )
    .await?;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    let answer = send(
        gw,
        backtest(json!({"guardrail": "tickets", "corpus": corpus}), keeper)?,
    )
    .await?;
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{}", answer.body);
    assert!(
        answer.body.contains("edit_policy permission"),
        "{}",
        answer.body
    );
    Ok(())
}
