//! Subscription passthrough: a provider with `auth: passthrough` sends each caller's own Claude login (Claude Code's
//! subscription OAuth token) to Anthropic unchanged, and Gantry holds no key. The person is named by a Gantry person
//! token in x-gantry-user, or recorded as unknown on `identity: optional`. The login is never stored, logged or
//! recorded, never swapped for a key of Gantry's, and every rule, guardrail, kill switch and limit still applies.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, Request, StatusCode, header},
    response::IntoResponse,
    routing::post,
};
use gantry_core::id::sha256_hex;
use gantry_server::Governed;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Error = Box<dyn std::error::Error>;

const MAYA: &str = "gantry_u_maya0123456789abcdef0123456789abcdef";
const OMER_KEY: &str = "gantry_omer_0123456789abcdef0123456789";
const ADMIN: &str = "gantry_admin_0123456789abcdef012345678";
/// What Claude Code sends from a subscription login. A made-up value: the mock is all it ever reaches.
const LOGIN: &str = "Bearer sk-ant-oat01-FAKE-subscription-login-7c1d0e9f3a2b";
const BETA: &str = "claude-code-20250219,oauth-2025-04-20";
const GANTRYS: &str = "sk-ant-api03-gantrys-own-key-5e1f";

/// The headers and body of every request the mock Anthropic received.
type Seen = Arc<Mutex<Vec<(HeaderMap, String)>>>;

/// An Anthropic messages API that keeps what it was sent and answers with 8 tokens each way, streamed when asked.
async fn anthropic() -> Result<(Seen, u16), Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let seen: Seen = Arc::default();
    let app = Router::new()
        .route(
            "/v1/messages",
            post(
                |State(seen): State<Seen>, headers: HeaderMap, body: Bytes| async move {
                    let text = String::from_utf8_lossy(&body).into_owned();
                    let stream = text.contains("\"stream\":true");
                    if let Ok(mut all) = seen.lock() {
                        all.push((headers, text));
                    }
                    if stream {
                        let events = [
                            r#"{"type":"message_start","message":{"id":"m","type":"message","role":"assistant","model":"claude-sonnet-4-5","content":[],"usage":{"input_tokens":8,"output_tokens":1}}}"#,
                            r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
                            r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello there"}}"#,
                            r#"{"type":"content_block_stop","index":0}"#,
                            r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":8}}"#,
                            r#"{"type":"message_stop"}"#,
                        ];
                        let body: String = events
                            .iter()
                            .map(|e| {
                                let kind = serde_json::from_str::<Value>(e).unwrap_or_default()["type"]
                                    .as_str()
                                    .unwrap_or_default()
                                    .to_string();
                                format!("event: {kind}\ndata: {e}\n\n")
                            })
                            .collect();
                        return ([(header::CONTENT_TYPE, "text/event-stream")], body).into_response();
                    }
                    (
                        [(header::CONTENT_TYPE, "application/json")],
                        r#"{"id":"m","type":"message","role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"text","text":"hello there"}],"stop_reason":"end_turn","usage":{"input_tokens":8,"output_tokens":8}}"#,
                    )
                        .into_response()
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
                    if let Ok(mut all) = seen.lock() {
                        all.push((headers, String::from_utf8_lossy(&body).into_owned()));
                    }
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
    dir: PathBuf,
}

/// A gateway with a passthrough provider for claude-sonnet-4-5 (and a keyed one for the same model, which key
/// callers reach), and a keyed one for claude-haiku-4-5 only.
fn setup(name: &str, port: u16, vendor: &str, identity: &str, rate: &str) -> Result<Setup, Error> {
    let dir = std::env::temp_dir().join(format!("gantry-sub-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let policy = dir.join("gantry.policy.yaml");
    std::fs::write(
        &policy,
        format!(
            "version: 1
providers:
  - name: claude-subscriptions
    kind: anthropic
    url: http://127.0.0.1:{port}
    allow_private: true
    auth: passthrough
    identity: {identity}
    models: [claude-sonnet-4-5]
  - name: anthropic-api
    kind: anthropic
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: ANTHROPIC_PROVIDER_KEY
    models: [claude-sonnet-4-5, claude-haiku-4-5]
prices:
  claude-sonnet-4-5: {{ input: 3, output: 15 }}
  claude-haiku-4-5: {{ input: 1, output: 5 }}
guardrails:
  - name: vendor
    type: webhook
    url: {vendor}/allow
    timeout_ms: 2000
    on_failure: fail_closed
  - name: tickets
    type: regex
    action: block
    patterns:
      ticket_id: 'TKT-[0-9]{{6}}'
rules:
  - name: api-callers
    principals: {{ team: api }}
    models: [\"*\"]
  - name: everyone
    principals: {{ any: true }}
    models: [\"*\"]
    guardrails: [vendor, tickets]
    budget: {{ usd: 0.000001, per: day }}
{rate}"
        ),
    )?;
    let entry = |name: &str, team: &str, key: &str, admin: bool| {
        format!(
            "  - name: {name}\n    team: {team}\n    sha256: {}\n    admin: {admin}\n",
            sha256_hex(key.as_bytes())
        )
    };
    std::fs::write(
        dir.join("gantry.keys.yaml"),
        format!(
            "keys:\n{}{}{}",
            entry("maya.cohen", "payments", MAYA, false),
            entry("omer.levi", "api", OMER_KEY, false),
            entry("admin", "platform", ADMIN, true)
        ),
    )?;
    let gw = gantry_server::governed(&policy, None, &|_| Some(GANTRYS.into()))?;
    Ok(Setup { gw, dir })
}

fn messages(
    headers: &[(&str, &str)],
    model: &str,
    text: &str,
    stream: bool,
) -> Result<Request<Body>, Error> {
    let mut request = Request::post("/v1/messages?beta=true")
        .header("anthropic-version", "2023-06-01")
        .header(header::CONTENT_TYPE, "application/json");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    Ok(request.body(Body::from(
        json!({"model": model, "max_tokens": 64, "stream": stream, "messages": [{"role": "user", "content": text}]})
            .to_string(),
    ))?)
}

/// What Claude Code on a subscription login sends, with the person token from ANTHROPIC_CUSTOM_HEADERS.
fn claude_code(person: Option<&str>) -> Vec<(&str, &str)> {
    let mut headers = vec![
        ("authorization", LOGIN),
        ("anthropic-beta", BETA),
        ("x-app", "cli"),
        ("user-agent", "claude-cli/2.1.325 (external, cli)"),
        ("x-claude-code-session-id", "5b0c7a52-session"),
    ];
    if let Some(person) = person {
        headers.push(("x-gantry-user", person));
    }
    headers
}

async fn send(gw: &Governed, request: Request<Body>) -> Result<(StatusCode, String), Error> {
    let response = gw.router.clone().oneshot(request).await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

fn code(body: &str) -> String {
    serde_json::from_str::<Value>(body).unwrap_or_default()["gantry_code"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// The audit records, once at least `usage` usage records are written (they are written off the answer's path).
async fn records(dir: &Path, usage: usize) -> Result<Vec<Value>, Error> {
    for _ in 0..60 {
        let all: Vec<Value> = std::fs::read_to_string(dir.join("gantry-audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        if all.iter().filter(|r| r["event"] == "usage").count() >= usage {
            return Ok(all);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(format!("fewer than {usage} usage records were written").into())
}

/// Every file Gantry wrote under the setup's folder, as text: the audit log, the request index, the switches.
fn everything_written(dir: &Path) -> String {
    let mut text = String::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(at) = stack.pop() {
        for entry in std::fs::read_dir(&at).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                text += &String::from_utf8_lossy(&std::fs::read(&path).unwrap_or_default());
            }
        }
    }
    text
}

fn last(seen: &Seen) -> Result<(HeaderMap, String), Error> {
    seen.lock()
        .map_err(|_| "lock")?
        .last()
        .cloned()
        .ok_or_else(|| "the provider was not called".into())
}

#[tokio::test(flavor = "multi_thread")]
async fn the_callers_login_reaches_anthropic_unchanged_and_is_never_recorded() -> TestResult {
    let (provider_saw, port) = anthropic().await?;
    let (vendor_saw, base) = vendor().await?;
    let s = setup("named", port, &base, "required", "")?;

    let (status, body) = send(
        &s.gw,
        messages(
            &claude_code(Some(MAYA)),
            "claude-sonnet-4-5",
            "hello",
            false,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (headers, _) = last(&provider_saw)?;
    assert_eq!(
        headers.get("authorization").and_then(|v| v.to_str().ok()),
        Some(LOGIN),
        "the exact login goes on"
    );
    assert_eq!(
        headers.get("anthropic-beta").and_then(|v| v.to_str().ok()),
        Some(BETA)
    );
    assert!(headers.get("x-gantry-user").is_none(), "{headers:?}");
    assert!(
        headers.get("x-api-key").is_none(),
        "no key of Gantry's: {headers:?}"
    );
    let all = format!("{headers:?}");
    assert!(!all.contains(MAYA) && !all.contains(GANTRYS), "{all}");

    // The guardrail ran, and never saw the login or the person token.
    for (headers, body) in vendor_saw.lock().map_err(|_| "lock")?.iter() {
        let text = format!("{headers:?}{body}");
        assert!(
            !text.contains("sk-ant-oat01") && !text.contains(MAYA),
            "{text}"
        );
    }

    let records = records(&s.dir, 1).await?;
    let decision = records
        .iter()
        .find(|r| r["auth"] == "passthrough" && r["event"] != "usage")
        .ok_or("no decision record of the passthrough request")?;
    assert_eq!(decision["verdict"], "allow", "{decision}");
    assert_eq!(decision["person"], "maya.cohen", "{decision}");
    assert_eq!(decision["team"], "payments", "{decision}");
    assert_eq!(decision["identity"], "x-gantry-user", "{decision}");
    let usage = records
        .iter()
        .find(|r| r["event"] == "usage")
        .ok_or("no usage record")?;
    assert_eq!(usage["input_tokens"], 8, "{usage}");
    assert_eq!(usage["output_tokens"], 8, "{usage}");
    assert_eq!(usage["cost_basis"], "api_equivalent_estimate", "{usage}");
    assert_eq!(usage["budget"], "not_counted", "{usage}");
    assert!(
        usage["cost_usd"].as_f64().is_some_and(|c| c > 0.0),
        "{usage}"
    );

    // The budget above is far below one request: it would refuse a billed request, and a subscription's is not one.
    let (status, body) = send(
        &s.gw,
        messages(
            &claude_code(Some(MAYA)),
            "claude-sonnet-4-5",
            "again",
            false,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");

    let written = everything_written(&s.dir);
    assert!(
        !written.contains("sk-ant-oat01") && !written.contains("FAKE-subscription"),
        "no file Gantry wrote holds the login"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_passes_through_and_its_tokens_are_recorded() -> TestResult {
    let (_, port) = anthropic().await?;
    let (_, base) = vendor().await?;
    let s = setup("stream", port, &base, "required", "")?;
    let (status, body) = send(
        &s.gw,
        messages(&claude_code(Some(MAYA)), "claude-sonnet-4-5", "hello", true)?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.contains("hello there") && body.contains("message_stop"),
        "{body}"
    );
    let records = records(&s.dir, 1).await?;
    let usage = records
        .iter()
        .find(|r| r["event"] == "usage")
        .ok_or("no usage record")?;
    assert_eq!(usage["output_tokens"], 8, "{usage}");
    assert_eq!(usage["cost_basis"], "api_equivalent_estimate", "{usage}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_person_an_optional_identity_records_an_unknown_person_by_session() -> TestResult
{
    let (provider_saw, port) = anthropic().await?;
    let (_, base) = vendor().await?;
    let s = setup("unknown", port, &base, "optional", "")?;
    let (status, body) = send(
        &s.gw,
        messages(&claude_code(None), "claude-sonnet-4-5", "hello", false)?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (headers, _) = last(&provider_saw)?;
    assert_eq!(
        headers.get("authorization").and_then(|v| v.to_str().ok()),
        Some(LOGIN)
    );
    let records = records(&s.dir, 1).await?;
    let decision = records
        .iter()
        .find(|r| r["auth"] == "passthrough" && r["event"] != "usage")
        .ok_or("no decision record")?;
    assert_eq!(decision["person"], "unknown", "{decision}");
    assert_eq!(decision["identity"], "unknown", "{decision}");
    assert_eq!(
        decision["key"],
        json!(&sha256_hex(b"session\n5b0c7a52-session")[..8]),
        "told apart by its session: {decision}"
    );
    assert!(!everything_written(&s.dir).contains("sk-ant-oat01"));

    // A Gantry key is still read as one, and goes to the keyed provider with Gantry's key.
    let (status, body) = send(
        &s.gw,
        messages(
            &[("authorization", &format!("Bearer {OMER_KEY}"))],
            "claude-sonnet-4-5",
            "hello",
            false,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (headers, _) = last(&provider_saw)?;
    assert_eq!(
        headers.get("x-api-key").and_then(|v| v.to_str().ok()),
        Some(GANTRYS)
    );
    assert!(headers.get("authorization").is_none(), "{headers:?}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_login_and_a_key_never_stand_in_for_each_other() -> TestResult {
    let (provider_saw, port) = anthropic().await?;
    let (_, base) = vendor().await?;
    let s = setup("refusals", port, &base, "required", "")?;
    let calls = || provider_saw.lock().map(|all| all.len()).unwrap_or_default();

    // identity: required and no person.
    let (status, body) = send(
        &s.gw,
        messages(&claude_code(None), "claude-sonnet-4-5", "hello", false)?,
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(code(&body), "person_needed", "{body}");

    // A person token is not a key.
    let (status, body) = send(
        &s.gw,
        messages(
            &[("authorization", &format!("Bearer {MAYA}"))],
            "claude-sonnet-4-5",
            "hello",
            false,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(code(&body), "person_token_only", "{body}");

    // A login for a model only a keyed provider serves is refused, not sent with Gantry's key.
    let (status, body) = send(
        &s.gw,
        messages(&claude_code(Some(MAYA)), "claude-haiku-4-5", "hello", false)?,
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(code(&body), "login_not_accepted", "{body}");

    // A login beside a Gantry key is ambiguous.
    let mut both = claude_code(Some(MAYA));
    both.retain(|(n, _)| *n != "authorization");
    let bearer = format!("Bearer {OMER_KEY}");
    both.push(("authorization", &bearer));
    let (status, body) = send(&s.gw, messages(&both, "claude-sonnet-4-5", "hello", false)?).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(code(&body), "ambiguous_key", "{body}");

    // A person token Gantry does not know.
    let (status, body) = send(
        &s.gw,
        messages(
            &claude_code(Some("gantry_u_nobody0123456789abcdef0123456789")),
            "claude-sonnet-4-5",
            "hello",
            false,
        )?,
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "never a 401 on a login: {body}"
    );
    assert_eq!(code(&body), "unknown_key", "{body}");
    assert_eq!(calls(), 0, "nothing reached the provider");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn guardrails_and_kill_switches_apply_to_passthrough_traffic() -> TestResult {
    let (provider_saw, port) = anthropic().await?;
    let (_, base) = vendor().await?;
    let s = setup("governed", port, &base, "optional", "")?;

    let (status, body) = send(
        &s.gw,
        messages(
            &claude_code(Some(MAYA)),
            "claude-sonnet-4-5",
            "see TKT-123456",
            false,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(provider_saw.lock().map_err(|_| "lock")?.is_empty());

    let kill = |body: &str| -> Result<Request<Body>, Error> {
        Ok(Request::post("/admin/kills")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {ADMIN}"))
            .body(Body::from(body.to_string()))?)
    };
    let (status, body) = send(
        &s.gw,
        kill(r#"{"scope":"person","value":"maya.cohen","reason":"leaving"}"#)?,
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = send(
        &s.gw,
        messages(
            &claude_code(Some(MAYA)),
            "claude-sonnet-4-5",
            "hello",
            false,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(code(&body), "killed", "{body}");

    // Unknown people are stopped by name too.
    let (status, body) = send(
        &s.gw,
        kill(r#"{"scope":"person","value":"unknown","reason":"name yourselves"}"#)?,
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = send(
        &s.gw,
        messages(&claude_code(None), "claude-sonnet-4-5", "hello", false)?,
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(code(&body), "killed", "{body}");
    assert!(provider_saw.lock().map_err(|_| "lock")?.is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn tokens_per_day_and_requests_per_day_limit_subscription_traffic() -> TestResult {
    let (_, port) = anthropic().await?;
    let (_, base) = vendor().await?;
    // 16 tokens per answer: the first fits under 20, the second starts under it and passes it, the third is refused.
    let s = setup(
        "tpd",
        port,
        &base,
        "required",
        "    rate: { tpd: 20, rpd: 10 }\n",
    )?;
    for _ in 0..2 {
        let (status, body) = send(
            &s.gw,
            messages(
                &claude_code(Some(MAYA)),
                "claude-sonnet-4-5",
                "hello",
                false,
            )?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        // Tokens are counted once the usage is settled.
        records(&s.dir, 1).await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (status, body) = send(
        &s.gw,
        messages(
            &claude_code(Some(MAYA)),
            "claude-sonnet-4-5",
            "hello",
            false,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert!(body.contains("tokens were used today"), "{body}");
    Ok(())
}

/// What Codex sends from a ChatGPT login: an OAuth access token (a JWT) and the ChatGPT account. Made up.
const CHATGPT_LOGIN: &str = "Bearer eyJhbGciOiJSUzI1NiJ9.FAKE-chatgpt-login.c2ln";
const CHATGPT_ACCOUNT: &str = "6f1c2d3e-0000-4000-8000-acc0unt1d000";

/// ChatGPT's Codex backend (chatgpt.com/backend-api/codex): keeps what it was sent and answers with 8 tokens each way.
async fn chatgpt() -> Result<(Seen, u16), Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let seen: Seen = Arc::default();
    let app = Router::new()
        .route(
            "/backend-api/codex/responses",
            post(
                |State(seen): State<Seen>, headers: HeaderMap, body: Bytes| async move {
                    if let Ok(mut all) = seen.lock() {
                        all.push((headers, String::from_utf8_lossy(&body).into_owned()));
                    }
                    (
                        [(header::CONTENT_TYPE, "application/json")],
                        r#"{"id":"resp_1","object":"response","status":"completed","model":"gpt-5-codex","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hello there"}]}],"usage":{"input_tokens":8,"output_tokens":8,"total_tokens":16}}"#,
                    )
                },
            ),
        )
        .with_state(seen.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((seen, port))
}

fn codex_setup(name: &str, port: u16, identity: &str) -> Result<Setup, Error> {
    let dir = std::env::temp_dir().join(format!("gantry-sub-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let policy = dir.join("gantry.policy.yaml");
    std::fs::write(
        &policy,
        format!(
            "version: 1
providers:
  - name: chatgpt-subscriptions
    kind: openai
    url: http://127.0.0.1:{port}/backend-api/codex
    allow_private: true
    auth: passthrough
    identity: {identity}
    models: [gpt-5-codex]
prices:
  gpt-5-codex: {{ input: 1.25, output: 10 }}
rules:
  - name: everyone
    principals: {{ any: true }}
    models: [\"*\"]
"
        ),
    )?;
    std::fs::write(
        dir.join("gantry.keys.yaml"),
        format!(
            "keys:\n  - name: maya.cohen\n    team: payments\n    sha256: {}\n    admin: false\n",
            sha256_hex(MAYA.as_bytes())
        ),
    )?;
    let gw = gantry_server::governed(&policy, None, &|_| None)?;
    Ok(Setup { gw, dir })
}

/// What Codex on a ChatGPT login sends to a model provider with `requires_openai_auth = true` (Codex 0.166), with
/// the person token from the provider's `http_headers`.
fn codex(person: Option<&str>) -> Result<Request<Body>, Error> {
    let mut request = Request::post("/v1/responses")
        .header(header::CONTENT_TYPE, "application/json")
        .header("authorization", CHATGPT_LOGIN)
        .header("chatgpt-account-id", CHATGPT_ACCOUNT)
        .header("originator", "codex_cli_rs")
        .header("session-id", "01a1e44c-codex-session");
    if let Some(person) = person {
        request = request.header("x-gantry-user", person);
    }
    Ok(request.body(Body::from(
        json!({"model": "gpt-5-codex", "store": false, "stream": false, "instructions": "be brief", "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": "hello"}]}]})
            .to_string(),
    ))?)
}

#[tokio::test(flavor = "multi_thread")]
async fn codex_on_a_chatgpt_login_reaches_chatgpt_unchanged_and_is_never_recorded() -> TestResult {
    let (provider_saw, port) = chatgpt().await?;
    let s = codex_setup("codex", port, "required")?;

    let (status, body) = send(&s.gw, codex(Some(MAYA))?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (headers, _) = last(&provider_saw)?;
    let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    assert_eq!(
        get("authorization"),
        Some(CHATGPT_LOGIN),
        "the exact login goes on"
    );
    assert_eq!(get("chatgpt-account-id"), Some(CHATGPT_ACCOUNT));
    assert!(headers.get("x-gantry-user").is_none(), "{headers:?}");

    let records = records(&s.dir, 1).await?;
    let decision = records
        .iter()
        .find(|r| r["auth"] == "passthrough" && r["event"] != "usage")
        .ok_or("no decision record of the passthrough request")?;
    assert_eq!(decision["verdict"], "allow", "{decision}");
    assert_eq!(decision["person"], "maya.cohen", "{decision}");
    let usage = records
        .iter()
        .find(|r| r["event"] == "usage")
        .ok_or("no usage record")?;
    assert_eq!(usage["output_tokens"], 8, "{usage}");
    assert_eq!(usage["cost_basis"], "api_equivalent_estimate", "{usage}");
    assert!(!everything_written(&s.dir).contains("FAKE-chatgpt-login"));

    // Without a person, `identity: required` refuses it before anything is sent.
    let before = provider_saw.lock().map_err(|_| "lock")?.len();
    let (status, body) = send(&s.gw, codex(None)?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let code = serde_json::from_str::<Value>(&body).unwrap_or_default()["error"]["code"].clone();
    assert_eq!(code, "person_needed", "OpenAI's error shape: {body}");
    assert!(body.contains("http_headers"), "names Codex's fix: {body}");
    assert_eq!(provider_saw.lock().map_err(|_| "lock")?.len(), before);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn codex_without_a_person_is_told_apart_by_its_session() -> TestResult {
    let (_, port) = chatgpt().await?;
    let s = codex_setup("codex-unknown", port, "optional")?;
    let (status, body) = send(&s.gw, codex(None)?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let records = records(&s.dir, 1).await?;
    let decision = records
        .iter()
        .find(|r| r["auth"] == "passthrough" && r["event"] != "usage")
        .ok_or("no decision record")?;
    assert_eq!(decision["person"], "unknown", "{decision}");
    assert_eq!(
        decision["key"],
        json!(&sha256_hex(b"session\n01a1e44c-codex-session")[..8]),
        "told apart by Codex's session-id: {decision}"
    );
    Ok(())
}
