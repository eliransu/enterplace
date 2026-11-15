//! Built-in guardrail vendors through the gateway: each one asked in its own API, with its credential from the
//! environment, its answer turned into block, mask or allow, and the record naming the vendor and the kind only.
//! One mock on a port of 127.0.0.1 the system picks speaks every vendor's API. The credential is the value of
//! CARGO_MANIFEST_DIR, which cargo sets, because setting a variable needs `unsafe`.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    body::{Body, Bytes},
    http::{HeaderMap, Request, StatusCode, Uri, header},
    routing::post,
};
use gantry_core::id::sha256_hex;
use gantry_server::Governed;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Error = Box<dyn std::error::Error>;

const MAYA: &str = "gantry_maya_0123456789abcdef0123456789";
const KEY_ENV: &str = "CARGO_MANIFEST_DIR";
/// The word that makes every mock vendor find something.
const BAD: &str = "attack";

async fn provider() -> Result<u16, Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let app = Router::new().route(
        "/v1/chat/completions",
        post(|body: Bytes| async move { body }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

type Seen = Arc<Mutex<Vec<(String, HeaderMap, Value)>>>;

/// What each vendor answers, in its own format, for a request body. `None` is a 401 for a missing credential.
fn vendor_answer(path: &str, headers: &HeaderMap, body: &Value, key: &str) -> Option<Value> {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    };
    let bearer = header("authorization") == format!("Bearer {key}");
    let bad = body.to_string().contains(BAD);
    match path {
        "/v1/moderations" if bearer => {
            let results: Vec<Value> = body["input"]
                .as_array()?
                .iter()
                .map(|t| {
                    let hit = t.as_str().unwrap_or("").contains(BAD);
                    json!({"flagged": hit, "categories": {"violence": hit, "hate": false}})
                })
                .collect();
            Some(json!({"id": "modr-1", "model": "omni-moderation-latest", "results": results}))
        }
        "/v2/guard" if bearer => Some(json!({
            "flagged": bad,
            "breakdown": [{"detector_type": "prompt_attack", "detected": bad, "message_id": 0}]
        })),
        "/analyze" => {
            let text = body["text"].as_str().unwrap_or("");
            let at = text
                .find("maya@corp.com")
                .map(|b| text[..b].chars().count());
            Some(json!(at.map_or_else(Vec::new, |start| vec![
                json!({"entity_type": "EMAIL_ADDRESS", "start": start, "end": start + 13, "score": 1.0})
            ])))
        }
        "/anonymize" => {
            let text = body["text"].as_str().unwrap_or("");
            Some(
                json!({"text": text.replace("maya@corp.com", "[MASKED email_address]"), "items": []}),
            )
        }
        "/contentsafety/text:analyze" if header("ocp-apim-subscription-key") == key => {
            Some(json!({
                "blocklistsMatch": [],
                "categoriesAnalysis": [{"category": "Hate", "severity": 0}, {"category": "Violence", "severity": if bad { 6 } else { 0 }}]
            }))
        }
        "/contentsafety/text:shieldPrompt" if header("ocp-apim-subscription-key") == key => {
            Some(json!({
                "userPromptAnalysis": {"attackDetected": bad},
                "documentsAnalysis": []
            }))
        }
        "/v1/projects/p1/locations/us-central1/templates/t1:sanitizeUserPrompt" if bearer => {
            let state = if bad { "MATCH_FOUND" } else { "NO_MATCH_FOUND" };
            Some(json!({"sanitizationResult": {
                "filterMatchState": state,
                "invocationResult": "SUCCESS",
                "filterResults": {
                    "pi_and_jailbreak": {"piAndJailbreakFilterResult": {"matchState": state}},
                    "malicious_uris": {"maliciousUriFilterResult": {"matchState": "NO_MATCH_FOUND"}}
                }
            }}))
        }
        "/v1/text/guard" if bearer => Some(json!({"status": "Success", "result": {
            "blocked": bad, "transformed": false,
            "detectors": {"prompt_injection": {"detected": bad}}
        }})),
        "/nemo/v1/chat/completions" => Some(json!({
            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            "guardrails": {"config_id": "main", "log": {"activated_rails": [{"type": "input", "name": "self check input", "stop": bad}]}}
        })),
        "/lasso/classify" if header("lasso-api-key") == key => Some(json!({
            "violations_detected": bad,
            "deputies": {"jailbreak": bad},
            "findings": if bad { json!({"jailbreak": [{"name": "jailbreak", "category": "SAFETY", "action": "BLOCK"}]}) } else { json!({}) }
        })),
        "/guards/g1/validate" => Some(json!({
            "callId": "1", "validationPassed": !bad,
            "validationSummaries": [{"validatorName": "ToxicLanguage", "validatorStatus": if bad { "fail" } else { "pass" }}]
        })),
        "/aporia/validate" if header("x-aporia-api-key") == key => {
            Some(json!({"action": if bad { "block" } else { "passthrough" }}))
        }
        "/v1/scan/sync/request" if header("x-pan-token") == key => Some(json!({
            "action": if bad { "block" } else { "allow" }, "category": if bad { "malicious" } else { "benign" },
            "prompt_detected": {"injection": bad, "dlp": false}, "tr_id": body["tr_id"]
        })),
        "/guardrails/detect" if header("apikey") == key => Some(json!({
            // The detectors' own names hold the bad word: only the text decides.
            "summary": {"injection_attack": i32::from(body["text"].as_str().unwrap_or("").contains(BAD)), "toxicity": [], "nsfw": 0}, "details": {}
        })),
        "/cygnal/monitor" if header("grayswan-api-key") == key && body["policy_id"] == "pol1" => {
            Some(json!({
                "violation": if bad { 0.97 } else { 0.02 }, "violated_rules": if bad { json!([2]) } else { json!([]) },
                "ipi": false, "error": false
            }))
        }
        "/api/v1/inspect/chat" if header("x-cisco-ai-defense-api-key") == key => Some(json!({
            "is_safe": !bad, "classifications": if bad { json!(["SECURITY_VIOLATION"]) } else { json!([]) },
            "rules": if bad { json!([{"rule_name": "Prompt Injection"}]) } else { json!([]) }
        })),
        "/mistral/v1/chat/moderations" if bearer => Some(json!({
            "id": "m1", "model": "mistral-moderation-latest",
            "results": [{"categories": {"violence_and_threats": bad, "pii": false}}]
        })),
        "/v1/chat/completions" if bearer => Some(json!({
            "choices": [{"message": {"role": "assistant", "content": if bad { "unsafe\nS1" } else { "safe" }}}]
        })),
        _ => None,
    }
}

/// The mock vendor. Returns what it was sent and its base URL.
async fn vendor(key: String) -> Result<(Seen, String), Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let base = format!("http://{}", listener.local_addr()?);
    let seen: Seen = Arc::default();
    let kept = seen.clone();
    let app = Router::new().fallback(move |uri: Uri, headers: HeaderMap, body: Bytes| {
        let (seen, key) = (kept.clone(), key.clone());
        async move {
            let value: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let path = uri.path().to_string();
            let answer = vendor_answer(&path, &headers, &value, &key);
            if let Ok(mut all) = seen.lock() {
                all.push((path, headers, value));
            }
            match answer {
                Some(answer) => (StatusCode::OK, answer.to_string()),
                None => (
                    StatusCode::UNAUTHORIZED,
                    r#"{"error":"no credential"}"#.into(),
                ),
            }
        }
    });
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((seen, base))
}

fn policy(port: u16, guardrail: &str) -> String {
    format!(
        "version: 1
providers:
  - name: mock-openai
    kind: openai
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: MOCK_KEY
    models: [model-a]
guardrails:
{guardrail}rules:
  - name: everyone
    principals: {{ any: true }}
    models: [\"*\"]
    guardrails: [vendor]
"
    )
}

struct Setup {
    audit: PathBuf,
    gw: Governed,
}

fn setup(name: &str, policy: &str) -> Result<Setup, Error> {
    setup_with(name, policy, "")
}

/// `setup` with more entries in the keys file.
fn setup_with(name: &str, policy: &str, more_keys: &str) -> Result<Setup, Error> {
    let dir = std::env::temp_dir().join(format!("gantry-vendors-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("gantry.policy.yaml");
    std::fs::write(&path, policy)?;
    std::fs::write(
        dir.join("gantry.keys.yaml"),
        format!(
            "keys:\n  - name: maya.cohen\n    team: payments\n    sha256: {}\n{more_keys}",
            sha256_hex(MAYA.as_bytes())
        ),
    )?;
    let gw = gantry_server::governed(&path, None, &|v| {
        std::env::var(v).ok().or(Some("provider-secret".into()))
    })?;
    Ok(Setup {
        audit: dir.join("gantry-audit.jsonl"),
        gw,
    })
}

async fn chat(gw: &Governed, text: &str) -> Result<(StatusCode, String), Error> {
    let body = json!({"model": "model-a", "messages": [{"role": "system", "content": "be brief"}, {"role": "user", "content": text}]});
    let request = Request::post("/v1/chat/completions")
        .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
        .body(Body::from(body.to_string()))?;
    let response = gw.router.clone().oneshot(request).await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, String::from_utf8(body.to_vec())?))
}

fn last(s: &Setup) -> Result<Value, Error> {
    let text = std::fs::read_to_string(&s.audit)?;
    // QA14-9: the last decision record, not the last line: a usage record can be written after it.
    text.lines()
        .rev()
        .map(serde_json::from_str::<Value>)
        .find(|r| r.as_ref().is_ok_and(|r| r["event"].is_null()))
        .ok_or("no decision record")?
        .map_err(Into::into)
}

#[tokio::test(flavor = "multi_thread")]
async fn each_vendor_is_asked_in_its_own_api_and_blocks_or_allows() -> TestResult {
    let key = std::env::var(KEY_ENV)?;
    let port = provider().await?;
    let (seen, base) = vendor(key.clone()).await?;
    let common = "    on_failure: fail_closed\n    timeout_ms: 2000\n";
    let cases = [
        (
            "openai_moderation",
            format!("    url: {base}/v1\n    key_env: {KEY_ENV}\n"),
            "/v1/moderations",
            "violence",
        ),
        (
            "lakera",
            format!("    url: {base}\n    key_env: {KEY_ENV}\n    project_id: p1\n"),
            "/v2/guard",
            "prompt_attack",
        ),
        (
            "presidio",
            format!("    url: {base}\n    action: block\n"),
            "/analyze",
            "email_address",
        ),
        (
            "azure_content_safety",
            format!("    url: {base}\n    key_env: {KEY_ENV}\n"),
            "/contentsafety/text:analyze",
            "violence",
        ),
        (
            "azure_prompt_shield",
            format!("    url: {base}\n    key_env: {KEY_ENV}\n"),
            "/contentsafety/text:shieldPrompt",
            "prompt_injection",
        ),
        (
            "model_armor",
            format!(
                "    url: {base}\n    key_env: {KEY_ENV}\n    project_id: p1\n    region: us-central1\n    template_id: t1\n"
            ),
            "/v1/projects/p1/locations/us-central1/templates/t1:sanitizeUserPrompt",
            "pi_and_jailbreak",
        ),
        (
            "llama_guard",
            format!("    url: {base}/v1\n    key_env: {KEY_ENV}\n    model: llama-guard-3-8b\n"),
            "/v1/chat/completions",
            "s1",
        ),
        (
            "pangea",
            format!("    url: {base}\n    key_env: {KEY_ENV}\n"),
            "/v1/text/guard",
            "prompt_injection",
        ),
        (
            "nemo_guardrails",
            format!("    url: {base}/nemo\n    config_id: main\n"),
            "/nemo/v1/chat/completions",
            "self_check_input",
        ),
        (
            "lasso",
            format!("    url: {base}/lasso\n    key_env: {KEY_ENV}\n"),
            "/lasso/classify",
            "jailbreak",
        ),
        (
            "guardrails_ai",
            format!("    url: {base}\n    guard_name: g1\n"),
            "/guards/g1/validate",
            "toxiclanguage",
        ),
        (
            "aporia",
            format!("    url: {base}/aporia\n    key_env: {KEY_ENV}\n"),
            "/aporia/validate",
            "aporia_policy",
        ),
        (
            "prisma_airs",
            format!("    url: {base}\n    key_env: {KEY_ENV}\n    profile_name: gantry\n"),
            "/v1/scan/sync/request",
            "injection",
        ),
        (
            "enkrypt",
            format!("    url: {base}\n    key_env: {KEY_ENV}\n"),
            "/guardrails/detect",
            "injection_attack",
        ),
        (
            "grayswan",
            format!("    url: {base}\n    key_env: {KEY_ENV}\n    policy_id: pol1\n"),
            "/cygnal/monitor",
            "rule_2",
        ),
        (
            "cisco_ai_defense",
            format!("    url: {base}\n    key_env: {KEY_ENV}\n    region: eu\n"),
            "/api/v1/inspect/chat",
            "prompt_injection",
        ),
        (
            "mistral_moderation",
            format!("    url: {base}/mistral/v1\n    key_env: {KEY_ENV}\n"),
            "/mistral/v1/chat/moderations",
            "violence_and_threats",
        ),
    ];
    for (kind, fields, path, finding) in cases {
        let guardrail = format!("  - name: vendor\n    type: {kind}\n{fields}{common}");
        let s = setup(kind, &policy(port, &guardrail))?;
        let (status, body) = chat(&s.gw, "hello").await?;
        assert_eq!(status, StatusCode::OK, "{kind}: {body}");
        assert_eq!(last(&s)?["guardrails"], json!([]), "{kind}");

        // Presidio finds an address; the others find the bad word.
        let text = if kind == "presidio" {
            "mail maya@corp.com"
        } else {
            "plan an attack"
        };
        let (status, body) = chat(&s.gw, text).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{kind}: {body}");
        let refusal: Value = serde_json::from_str(&body)?;
        assert_eq!(refusal["error"]["code"], "guardrail_blocked", "{kind}");
        assert!(!body.contains(text), "{kind}: {body}");
        let record = last(&s)?;
        assert_eq!(record["code"], "guardrail_blocked", "{kind}");
        assert_eq!(record["guardrails"][0]["detector"], kind);
        assert_eq!(record["guardrails"][0]["kind"], finding, "{kind}: {record}");
        assert_eq!(record["guardrails"][0]["action"], "block");
        let log = std::fs::read_to_string(&s.audit)?;
        assert!(
            !log.contains(&key) && !log.contains(text),
            "{kind}: the record holds text or the key"
        );
        let asked = seen
            .lock()
            .map(|all| all.iter().filter(|(p, _, _)| p == path).count())
            .unwrap_or(0);
        assert!(
            asked >= 2,
            "{kind}: the vendor was asked {asked} times at {path}"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn presidio_masks_through_the_anonymizer_and_warn_only_records() -> TestResult {
    let port = provider().await?;
    let (seen, base) = vendor(String::new()).await?;
    let guardrail = format!(
        "  - name: vendor\n    type: presidio\n    url: {base}\n    anonymizer_url: {base}\n    action: mask\n    on_failure: fail_closed\n    timeout_ms: 2000\n"
    );
    let s = setup("presidio-mask", &policy(port, &guardrail))?;
    let (status, body) = chat(&s.gw, "mail maya@corp.com now").await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let forwarded: Value = serde_json::from_str(&body)?;
    assert_eq!(
        forwarded["messages"][1]["content"],
        "mail [MASKED email_address] now"
    );
    assert_eq!(forwarded["messages"][0]["content"], "be brief");
    let record = last(&s)?;
    assert_eq!(
        record["guardrails"],
        json!([{"guardrail": "vendor", "detector": "presidio", "kind": "email_address", "action": "mask", "count": 1}])
    );
    let paths: Vec<String> = seen
        .lock()
        .map(|a| a.iter().map(|(p, _, _)| p.clone()).collect())
        .unwrap_or_default();
    assert_eq!(paths, ["/analyze", "/anonymize"]);

    let warn = guardrail.replace("action: mask", "action: warn");
    let s = setup("presidio-warn", &policy(port, &warn))?;
    let (status, body) = chat(&s.gw, "mail maya@corp.com now").await?;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("maya@corp.com"));
    assert_eq!(last(&s)?["guardrails"][0]["action"], "warn");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_vendor_that_is_down_or_refuses_the_key_follows_on_failure() -> TestResult {
    let port = provider().await?;
    let down = std::net::TcpListener::bind(("127.0.0.1", 0))?
        .local_addr()?
        .port();
    // The mock wants a key the guardrail does not send: a 401.
    let (_, base) = vendor("another-key".into()).await?;
    for (url, why) in [(format!("http://127.0.0.1:{down}"), "down"), (base, "401")] {
        for (on_failure, status, action) in [
            ("fail_closed", StatusCode::FORBIDDEN, "block"),
            ("fail_open", StatusCode::OK, "skipped"),
        ] {
            let guardrail = format!(
                "  - name: vendor\n    type: lakera\n    url: {url}\n    key_env: {KEY_ENV}\n    on_failure: {on_failure}\n    timeout_ms: 500\n"
            );
            let s = setup(
                &format!("fail-{why}-{on_failure}"),
                &policy(port, &guardrail),
            )?;
            let (got, body) = chat(&s.gw, "hello").await?;
            assert_eq!(got, status, "{why} {on_failure}: {body}");
            let record = last(&s)?;
            assert_eq!(record["guardrails"][0]["kind"], "unavailable");
            assert_eq!(record["guardrails"][0]["action"], action);
        }
    }
    Ok(())
}

/// Bedrock signs with AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY from the environment. Setting them needs
/// `unsafe`, so the test runs itself again as a child process with them set.
#[tokio::test(flavor = "multi_thread")]
async fn bedrock_guardrail_signs_with_sigv4_from_the_environment() -> TestResult {
    const ID: &str = "AKIDEXAMPLE";
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    if std::env::var("AWS_ACCESS_KEY_ID").ok().as_deref() != Some(ID) {
        let status = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "bedrock_guardrail_signs_with_sigv4_from_the_environment",
                "--nocapture",
            ])
            .env("AWS_ACCESS_KEY_ID", ID)
            .env("AWS_SECRET_ACCESS_KEY", SECRET)
            .env_remove("AWS_SESSION_TOKEN")
            .status()?;
        assert!(status.success(), "the child run failed");
        return Ok(());
    }
    let port = provider().await?;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let host = listener.local_addr()?.to_string();
    let checked: Arc<Mutex<Vec<bool>>> = Arc::default();
    let kept = checked.clone();
    let app = Router::new().fallback(move |uri: Uri, headers: HeaderMap, body: Bytes| {
        let kept = kept.clone();
        async move {
            let get = |n: &str| headers.get(n).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
            // Signed again here with the same inputs: the signature must match exactly.
            let expected = gantry_core::sigv4::sign(
                &gantry_core::sigv4::Credentials {
                    access_key_id: ID.into(),
                    secret_access_key: SECRET.into(),
                    session_token: None,
                },
                "us-east-1",
                "bedrock",
                &gantry_core::sigv4::Request {
                    method: "POST",
                    path: uri.path(),
                    query: "",
                    headers: &[("host", &get("host")), ("content-type", &get("content-type"))],
                    payload: &body,
                },
                &get("x-amz-date"),
            );
            let ok = expected.first().map(|(_, v)| v.as_str()) == Some(get("authorization").as_str())
                && uri.path() == "/guardrail/gr-1/version/1/apply";
            if let Ok(mut all) = kept.lock() {
                all.push(ok);
            }
            let text = String::from_utf8_lossy(&body).to_string();
            let answer = if text.contains(BAD) {
                json!({"action": "GUARDRAIL_INTERVENED", "outputs": [{"text": "Sorry."}], "assessments": [{"topicPolicy": {"topics": [{"name": "Weapons", "type": "DENY", "action": "BLOCKED", "detected": true}]}}]})
            } else {
                json!({"action": "NONE", "outputs": [], "assessments": []})
            };
            if ok { (StatusCode::OK, answer.to_string()) } else { (StatusCode::FORBIDDEN, "{}".to_string()) }
        }
    });
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let guardrail = format!(
        "  - name: vendor\n    type: bedrock_guardrail\n    url: http://{host}\n    region: us-east-1\n    guardrail_id: gr-1\n    guardrail_version: \"1\"\n    on_failure: fail_closed\n    timeout_ms: 2000\n"
    );
    let s = setup("bedrock", &policy(port, &guardrail))?;
    let (status, body) = chat(&s.gw, "hello").await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = chat(&s.gw, "plan an attack").await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let record = last(&s)?;
    assert_eq!(record["guardrails"][0]["detector"], "bedrock_guardrail");
    assert_eq!(record["guardrails"][0]["kind"], "weapons");
    assert_eq!(
        checked.lock().map(|c| c.clone()).unwrap_or_default(),
        [true, true]
    );
    assert!(!std::fs::read_to_string(&s.audit)?.contains(SECRET));
    Ok(())
}

/// A judge asks a model through Gantry itself, with a key of its own: the call is governed and charged to that key's
/// person and team, the verdict is a finding named for the rubric, and the same conversation is judged once.
#[tokio::test(flavor = "multi_thread")]
async fn a_judge_asks_a_model_through_gantry_charged_to_its_own_key_and_cached() -> TestResult {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let judge_key = std::env::var(KEY_ENV)?;
    let judged = Arc::new(AtomicUsize::new(0));
    let counted = judged.clone();
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let provider_port = listener.local_addr()?.port();
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move |body: Bytes| {
            let counted = counted.clone();
            async move {
                let body: Value = serde_json::from_slice(&body).unwrap_or_default();
                let content = if body["model"] == "judge-model" {
                    counted.fetch_add(1, Ordering::SeqCst);
                    if body.to_string().contains("lease") { "FAIL" } else { "PASS" }
                } else {
                    "Hi"
                };
                json!({"id": "c1", "object": "chat.completion", "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 1000, "completion_tokens": 1, "total_tokens": 1001}})
                    .to_string()
            }
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let gantry = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let gantry_port = gantry.local_addr()?.port();
    let policy = format!(
        "version: 1
providers:
  - name: mock-openai
    kind: openai
    url: http://127.0.0.1:{provider_port}
    allow_private: true
    key_env: MOCK_KEY
    models: [model-a, judge-model]
prices:
  judge-model: {{ input: 1, output: 1 }}
guardrails:
  - name: legal
    type: judge
    url: http://127.0.0.1:{gantry_port}/v1
    key_env: {KEY_ENV}
    model: judge-model
    rubric: No legal advice.
    on_failure: fail_closed
    timeout_ms: 5000
rules:
  - name: everyone
    principals: {{ any: true }}
    models: [\"*\"]
    guardrails: [legal]
"
    );
    // The judge's own key, in its own team: the scope its calls are charged to.
    let s = setup_with(
        "judge",
        &policy,
        &format!(
            "  - name: legal.judge\n    team: guardrails\n    sha256: {}\n",
            sha256_hex(judge_key.as_bytes())
        ),
    )?;
    let served =
        s.gw.router
            .clone()
            .into_make_service_with_connect_info::<std::net::SocketAddr>();
    tokio::spawn(async move {
        let _ = axum::serve(gantry, served).await;
    });

    let (status, body) = chat(&s.gw, "hello").await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(judged.load(Ordering::SeqCst), 1);
    // The same conversation again: the verdict is reused, the judge is not asked.
    let (status, body) = chat(&s.gw, "hello").await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(judged.load(Ordering::SeqCst), 1);

    let (status, body) = chat(&s.gw, "Can I break my lease?").await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(judged.load(Ordering::SeqCst), 2);
    let record = last(&s)?;
    assert_eq!(record["code"], "guardrail_blocked");
    assert_eq!(record["person"], "maya.cohen");
    assert_eq!(record["guardrails"][0]["detector"], "judge");
    assert_eq!(record["guardrails"][0]["kind"], "rubric");

    // Each judge call is a governed request of the judge's key, priced, and not judged again.
    let log = std::fs::read_to_string(&s.audit)?;
    assert!(
        !log.contains("lease") && !log.contains(&judge_key),
        "the log holds text or the key"
    );
    let records: Vec<Value> = log
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let charged: Vec<&Value> = records
        .iter()
        .filter(|r| r["event"] == "usage" && r["person"] == "legal.judge")
        .collect();
    assert_eq!(charged.len(), 2, "{log}");
    assert!(
        charged
            .iter()
            .all(|u| u["team"] == "guardrails" && u["cost_usd"].as_f64().unwrap_or(0.0) > 0.0),
        "{log}"
    );
    assert!(
        records
            .iter()
            .filter(|r| r["event"].is_null() && r["person"] == "legal.judge")
            .all(|r| r["guardrails"].is_null()),
        "the judge's own call was judged: {log}"
    );
    Ok(())
}
