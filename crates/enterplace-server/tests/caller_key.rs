//! Caller-supplied provider keys: a rule may let a caller, identified by their Enterplace key as always, send their own
//! provider key in `x-enterplace-provider-key`, and Enterplace sends that key to the provider in place of its own. Everything
//! else still applies. Without the rule's opt-in the header is refused, never ignored and never forwarded, and it
//! never reaches a guardrail webhook or the audit log.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    routing::post,
};
use enterplace_core::id::sha256_hex;
use enterplace_server::Governed;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Error = Box<dyn std::error::Error>;

const MAYA: &str = "enterplace_maya_0123456789abcdef0123456789";
const DANA: &str = "enterplace_dana_0123456789abcdef0123456789";
const ENTERPLACES: &str = "enterplaces-own-provider-key-7d1e";
const CALLERS: &str = "sk-callers-own-key-5c2a9f0e81b4";
const HEADER: &str = "x-enterplace-provider-key";

/// Every request a mock received: its headers, as text, and its body.
type Seen = Arc<Mutex<Vec<(String, String)>>>;

fn keep(seen: &Seen, headers: &HeaderMap, body: &Bytes) {
    let headers: Vec<String> = headers
        .iter()
        .map(|(name, value)| format!("{name}: {}", String::from_utf8_lossy(value.as_bytes())))
        .collect();
    if let Ok(mut all) = seen.lock() {
        all.push((
            headers.join("\n"),
            String::from_utf8_lossy(body).into_owned(),
        ));
    }
}

/// A provider that keeps what it was sent and answers with a chat completion that used one token each way.
async fn provider() -> Result<(Seen, u16), Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let seen: Seen = Arc::default();
    let app = Router::new()
        .route(
            "/v1/chat/completions",
            post(
                |State(seen): State<Seen>, headers: HeaderMap, body: Bytes| async move {
                    keep(&seen, &headers, &body);
                    r#"{"id":"c","object":"chat.completion","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#
                },
            ),
        )
        .with_state(seen.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((seen, port))
}

/// A guardrail vendor that allows everything and keeps what it was sent.
async fn vendor() -> Result<(Seen, String), Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let base = format!("http://{}", listener.local_addr()?);
    let seen: Seen = Arc::default();
    let app = Router::new()
        .route(
            "/allow",
            post(
                |State(seen): State<Seen>, headers: HeaderMap, body: Bytes| async move {
                    keep(&seen, &headers, &body);
                    r#"{"action":"allow"}"#
                },
            ),
        )
        .with_state(seen.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((seen, base))
}

struct Setup {
    gw: Governed,
    audit: PathBuf,
}

fn setup(name: &str, port: u16, vendor: &str) -> Result<Setup, Error> {
    let dir = std::env::temp_dir().join(format!("enterplace-byok-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let policy = dir.join("enterplace.policy.yaml");
    std::fs::write(
        &policy,
        format!(
            "version: 1
providers:
  - name: mock
    kind: openai
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: MOCK_KEY
    models: [model-a]
prices:
  model-a: {{ input: 1, output: 1 }}
guardrails:
  - name: vendor
    type: webhook
    url: {vendor}/allow
    timeout_ms: 2000
    on_failure: fail_closed
rules:
  - name: bring-your-own
    principals: {{ team: payments }}
    models: [model-a]
    guardrails: [vendor]
    caller_provider_key: allowed
  - name: closed
    principals: {{ team: interns }}
    models: [model-a]
"
        ),
    )?;
    let entry = |name: &str, team: &str, key: &str| {
        format!(
            "  - name: {name}\n    team: {team}\n    sha256: {}\n",
            sha256_hex(key.as_bytes())
        )
    };
    std::fs::write(
        dir.join("enterplace.keys.yaml"),
        format!(
            "keys:\n{}{}",
            entry("maya.cohen", "payments", MAYA),
            entry("dana.levi", "interns", DANA)
        ),
    )?;
    let gw = enterplace_server::governed(&policy, None, &|_| Some(ENTERPLACES.into()))?;
    Ok(Setup {
        gw,
        audit: dir.join("enterplace-audit.jsonl"),
    })
}

fn chat(headers: &[(&str, &str)]) -> Result<Request<Body>, axum::http::Error> {
    let mut request = Request::post("/v1/chat/completions");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    request.body(Body::from(
        json!({"model": "model-a", "messages": [{"role": "user", "content": "hello"}]}).to_string(),
    ))
}

async fn send(gw: &Governed, request: Request<Body>) -> Result<(StatusCode, String), Error> {
    let response = gw.router.clone().oneshot(request).await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

fn records(s: &Setup) -> Result<Vec<Value>, Error> {
    Ok(std::fs::read_to_string(&s.audit)?
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect())
}

fn code(body: &str) -> String {
    serde_json::from_str::<Value>(body).unwrap_or_default()["error"]["code"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn an_allowed_rule_sends_the_callers_key_and_records_only_its_hash() -> TestResult {
    let (provider_saw, port) = provider().await?;
    let (vendor_saw, base) = vendor().await?;
    let s = setup("allowed", port, &base)?;
    let bearer = format!("Bearer {MAYA}");

    let (status, body) = send(
        &s.gw,
        chat(&[("authorization", &bearer), (HEADER, CALLERS)])?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!body.contains(CALLERS), "{body}");
    let (headers, _) = provider_saw
        .lock()
        .map_err(|_| "lock")?
        .last()
        .cloned()
        .ok_or("the provider was not called")?;
    assert!(
        headers.contains(&format!("authorization: Bearer {CALLERS}")),
        "the provider gets the caller's key: {headers}"
    );
    assert!(
        !headers.contains(ENTERPLACES) && !headers.contains(MAYA),
        "{headers}"
    );
    assert!(!headers.contains(HEADER), "{headers}");

    // Without the header, the same caller is sent with Enterplace's key.
    let (status, _) = send(&s.gw, chat(&[("authorization", &bearer)])?).await?;
    assert_eq!(status, StatusCode::OK);
    let (headers, _) = provider_saw
        .lock()
        .map_err(|_| "lock")?
        .last()
        .cloned()
        .unwrap_or_default();
    assert!(
        headers.contains(&format!("authorization: Bearer {ENTERPLACES}")),
        "{headers}"
    );

    // The guardrail ran, and never saw the caller's key.
    let webhook = vendor_saw.lock().map_err(|_| "lock")?.clone();
    assert_eq!(webhook.len(), 2, "the guardrail runs on both requests");
    for (headers, body) in &webhook {
        assert!(
            !headers.contains(CALLERS) && !body.contains(CALLERS),
            "{headers}\n{body}"
        );
        assert!(!headers.contains(HEADER), "{headers}");
    }

    let log = std::fs::read_to_string(&s.audit)?;
    assert!(!log.contains(CALLERS), "the audit log never holds the key");
    // Usage is recorded once each answer has ended, off the answer's path.
    let mut records = records(&s)?;
    for _ in 0..40 {
        if records.iter().filter(|r| r["event"] == "usage").count() >= 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        records = self::records(&s)?;
    }
    let decision = records
        .iter()
        .find(|r| r["caller_provider_key"] == json!(true))
        .ok_or("no decision record says the caller's key was used")?;
    assert_eq!(decision["verdict"], json!("allow"), "{decision}");
    assert_eq!(
        decision["caller_provider_key_sha256"],
        json!(&sha256_hex(CALLERS.as_bytes())[..8])
    );
    let usage: Vec<&Value> = records.iter().filter(|r| r["event"] == "usage").collect();
    assert_eq!(usage.len(), 2, "{usage:?}");
    assert_eq!(usage[0]["caller_paid"], json!(true), "{}", usage[0]);
    assert_eq!(usage[0]["budget"], json!("not_counted"), "{}", usage[0]);
    assert!(
        usage[0]["charged_usd"].as_f64().unwrap_or(0.0) > 0.0,
        "spend is still recorded"
    );
    assert_eq!(usage[1].get("caller_paid"), None, "{}", usage[1]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rule_without_the_opt_in_refuses_the_header_and_forwards_nothing() -> TestResult {
    let (provider_saw, port) = provider().await?;
    let (vendor_saw, base) = vendor().await?;
    let s = setup("refused", port, &base)?;

    let (status, body) = send(
        &s.gw,
        chat(&[
            ("authorization", &format!("Bearer {DANA}")),
            (HEADER, CALLERS),
        ])?,
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(code(&body), "caller_provider_key_not_allowed", "{body}");
    assert!(
        body.contains("caller_provider_key: allowed"),
        "the fix is named: {body}"
    );
    assert!(!body.contains(CALLERS), "{body}");
    assert!(provider_saw.lock().map_err(|_| "lock")?.is_empty());
    assert!(vendor_saw.lock().map_err(|_| "lock")?.is_empty());

    let log = std::fs::read_to_string(&s.audit)?;
    assert!(!log.contains(CALLERS));
    let last = records(&s)?.pop().ok_or("no record")?;
    assert_eq!(last["code"], "caller_provider_key_not_allowed");
    assert_eq!(last["caller_provider_key"], json!(true));

    // Sent twice, the header is ambiguous: refused, never one of the two picked.
    let (status, body) = send(
        &s.gw,
        chat(&[
            ("authorization", &format!("Bearer {MAYA}")),
            (HEADER, CALLERS),
            (HEADER, "sk-another"),
        ])?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(code(&body), "ambiguous_key", "{body}");
    assert!(provider_saw.lock().map_err(|_| "lock")?.is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_provider_key_never_stands_in_for_a_enterplace_key() -> TestResult {
    let (provider_saw, port) = provider().await?;
    let (_, base) = vendor().await?;
    let s = setup("no-enterplace-key", port, &base)?;

    let (status, body) = send(&s.gw, chat(&[(HEADER, CALLERS)])?).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(code(&body), "no_key", "{body}");

    // The provider key where the Enterplace key goes is an unknown Enterplace key.
    let (status, body) = send(
        &s.gw,
        chat(&[
            ("authorization", &format!("Bearer {CALLERS}")),
            (HEADER, CALLERS),
        ])?,
    )
    .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(code(&body), "unknown_key", "{body}");
    assert!(!body.contains(CALLERS), "{body}");
    assert!(provider_saw.lock().map_err(|_| "lock")?.is_empty());
    assert!(!std::fs::read_to_string(&s.audit)?.contains(CALLERS));
    Ok(())
}
