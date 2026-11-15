//! Acceptance tests for the governance smalls: required headers and body fields, default and per-key guardrails,
//! the app-facing guardrail check, key issue bounds, model groups, hourly and daily request limits, budget raises,
//! session budgets and the session on every record. The mock provider listens on a port the system picks.

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
    body::Body,
    http::{Request, StatusCode, header},
    routing::post,
};
use gantry_core::id::sha256_hex;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Error = Box<dyn std::error::Error>;

const ANA: &str = "gantry_ana0_0123456789abcdef0123456789a";
const BEN: &str = "gantry_ben0_0123456789abcdef0123456789a";
const LEAD: &str = "gantry_lead_0123456789abcdef0123456789a";
const ROOT: &str = "gantry_root_0123456789abcdef0123456789a";
const AWS: &str = "AKIAIOSFODNN7EXAMPLE";

/// Every answer used 1 output token, a tenth of a cent on the priced models. Counts the requests it got.
async fn provider() -> Result<(u16, Arc<AtomicUsize>), Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move || {
            let seen = seen.clone();
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                axum::response::Response::builder()
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"id":"c","choices":[],"usage":{"prompt_tokens":0,"completion_tokens":1}}"#,
                    ))
                    .unwrap_or_default()
            }
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((port, calls))
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
    models: [m, n, big, free]
prices:
  m: {{ input: 0, output: 1000 }}
  n: {{ input: 0, output: 1000 }}
  big: {{ input: 0, output: 1000 }}
guardrails:
  - name: no-secrets
    type: secrets
    action: block
  - name: mask-pii
    type: pii
    action: mask
  - name: answers-clean
    type: secrets
    action: block
    on: [answer]
default_guardrails: [no-secrets]
model_groups:
  small: [m, n]
key_bounds:
  max_days: 365
roles:
  - name: lead
    permissions: [see_keys, issue_keys, see_spend]
    key_bounds:
      max_days: 30
      max_budget: {{ usd: 10, per: month }}
      models: [\"group:small\"]
rules:
  - name: tenants
    principals: {{ team: tenants }}
    models: [free]
    require: {{ headers: [X-Tenant-ID], body: [metadata.ticket] }}
  - name: counted
    principals: {{ team: counted }}
    models: [free]
    rate: {{ rph: 2, rpd: 3 }}
  - name: sessions
    principals: {{ team: sessions }}
    models: [big]
    budget: {{ usd: 0.002, per: session }}
    rate: {{ session_requests: 3 }}
  - name: groups
    principals: {{ team: groups }}
    models: [\"group:small\", big]
  - name: raised
    principals: {{ team: raised }}
    models: [big]
    budget: {{ usd: 0.001, per: day }}
    guardrails: [answers-clean]
  - name: admins
    principals: {{ any: true }}
    models: [free]
limits:
  - {{ model_group: small, budget: {{ usd: 0.002, per: day }} }}
"
    )
}

fn keys() -> String {
    let entry = |name: &str, team: &str, key: &str, extra: &str| {
        format!(
            "  - name: {name}\n    team: {team}\n    sha256: {}\n{extra}",
            sha256_hex(key.as_bytes())
        )
    };
    format!(
        "keys:\n{}{}{}{}",
        entry("ana", "TEAM", ANA, ""),
        entry("ben", "TEAM", BEN, "    guardrails: [mask-pii]\n"),
        entry("lead", "ops", LEAD, "    role: lead\n"),
        entry("root", "ops", ROOT, "    admin: true\n"),
    )
}

struct Setup {
    gw: gantry_server::Governed,
    audit: PathBuf,
    calls: Arc<AtomicUsize>,
}

/// A gateway whose two callers, ana and ben, are in `team`.
async fn setup(name: &str, team: &str) -> Result<Setup, Error> {
    let (port, calls) = provider().await?;
    let dir = std::env::temp_dir().join(format!("gantry-gov-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let policy = dir.join("gantry.policy.yaml");
    std::fs::write(&policy, self::policy(port))?;
    std::fs::write(dir.join("gantry.keys.yaml"), keys().replace("TEAM", team))?;
    Ok(Setup {
        gw: gantry_server::governed(&policy, None, &|_| Some("provider-secret".into()))?,
        audit: dir.join("gantry-audit.jsonl"),
        calls,
    })
}

fn call(
    method: &str,
    path: &str,
    key: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> Result<Request<Body>, axum::http::Error> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {key}"));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    request.body(Body::from(body.to_string()))
}

fn chat(
    key: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> Result<Request<Body>, axum::http::Error> {
    call("POST", "/v1/chat/completions", key, body, headers)
}

async fn answer(app: &Router, request: Request<Body>) -> Result<(StatusCode, Value), Error> {
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, serde_json::from_slice(&body).unwrap_or(Value::Null)))
}

fn code(body: &Value) -> &str {
    body["error"]["code"].as_str().unwrap_or_default()
}

fn records(path: &Path) -> Result<Vec<Value>, Error> {
    std::fs::read_to_string(path)?
        .lines()
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

/// Waits until `n` usage records are written: a request's cost is counted when its answer ends.
async fn usage(audit: &Path, n: usize) -> Result<Vec<Value>, Error> {
    let start = Instant::now();
    loop {
        let usage: Vec<Value> = records(audit)?
            .into_iter()
            .filter(|r| r["event"] == "usage")
            .collect();
        if usage.len() >= n {
            return Ok(usage);
        }
        if start.elapsed() > Duration::from_secs(3) {
            return Err(format!("{} usage records, not {n}", usage.len()).into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

const FREE: &str = r#"{"model":"free","messages":[{"role":"user","content":"hello"}]}"#;

#[tokio::test(flavor = "multi_thread")]
async fn a_rule_refuses_a_request_without_its_required_header_or_body_field() -> TestResult {
    let s = setup("require", "tenants").await?;
    let app = &s.gw.router;
    let with_ticket = r#"{"model":"free","messages":[],"metadata":{"ticket":"OPS-12"}}"#;
    let (status, body) = answer(app, chat(ANA, FREE, &[("x-tenant-id", "acme")])?).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(code(&body), "required_missing");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(message.contains("body field metadata.ticket"), "{message}");
    assert!(!message.contains("lacks header"), "{message}");

    let (status, body) = answer(app, chat(ANA, with_ticket, &[])?).await?;
    assert_eq!(code(&body), "required_missing", "{status} {body}");
    // An empty value is not a value.
    let (_, body) = answer(app, chat(ANA, with_ticket, &[("x-tenant-id", " ")])?).await?;
    assert_eq!(code(&body), "required_missing", "{body}");
    assert_eq!(s.calls.load(Ordering::SeqCst), 0);

    let (status, body) = answer(app, chat(ANA, with_ticket, &[("X-Tenant-ID", "acme")])?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let refused = records(&s.audit)?
        .into_iter()
        .find(|r| r["code"] == "required_missing")
        .ok_or("no refusal record")?;
    assert_eq!(refused["required_missing"][0], "body field metadata.ticket");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn default_guardrails_run_on_every_rule_and_a_key_adds_its_own() -> TestResult {
    let s = setup("guards", "counted").await?;
    let app = &s.gw.router;
    // Rule "counted" lists no guardrail: the policy's default one still blocks.
    let secret =
        format!(r#"{{"model":"free","messages":[{{"role":"user","content":"key {AWS}"}}]}}"#);
    let (status, body) = answer(app, chat(ANA, &secret, &[])?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(code(&body), "guardrail_blocked");

    // Ben's key adds mask-pii to the rule's guardrails; ana's does not.
    let mail =
        r#"{"model":"free","messages":[{"role":"user","content":"mail maya@corp.example.com"}]}"#;
    for key in [ANA, BEN] {
        let (status, body) = answer(app, chat(key, mail, &[])?).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let all = records(&s.audit)?;
    let guards_of = |person: &str| -> Vec<String> {
        all.iter()
            .filter(|r| r["person"] == person && r["verdict"] == "allow")
            .flat_map(|r| r["guardrails"].as_array().cloned().unwrap_or_default())
            .filter_map(|g| g["guardrail"].as_str().map(str::to_string))
            .collect()
    };
    assert!(
        guards_of("ben").contains(&"mask-pii".to_string()),
        "{all:?}"
    );
    assert!(!guards_of("ana").contains(&"mask-pii".to_string()));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn an_app_checks_text_against_its_rule_s_guardrails_without_a_model_call() -> TestResult {
    let s = setup("check", "raised").await?;
    let app = &s.gw.router;
    let check =
        |key: &'static str, body: String| call("POST", "/v1/guardrails/check", key, &body, &[]);
    let (status, body) = answer(
        app,
        check(BEN, r#"{"text":"write to maya@corp.example.com"}"#.into())?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["blocked"], false);
    let masked = body["text"][0].as_str().unwrap_or_default();
    assert!(
        !masked.contains("maya@corp.example.com") && masked.starts_with("write to "),
        "{body}"
    );
    assert!(
        body["findings"].as_array().is_some_and(|f| !f.is_empty()),
        "{body}"
    );

    let (status, body) = answer(
        app,
        check(ANA, format!(r#"{{"text":["fine","key {AWS}"]}}"#))?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["blocked"], true, "{body}");
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|m| m.contains("no-secrets")),
        "{body}"
    );

    // The answer side runs the guardrails the rule runs on answers: only answers-clean here.
    let (_, body) = answer(
        app,
        check(ANA, format!(r#"{{"text":"key {AWS}","on":"answer"}}"#))?,
    )
    .await?;
    assert_eq!(body["blocked"], true, "{body}");
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|m| m.contains("answers-clean")),
        "{body}"
    );

    let (status, body) = answer(app, check(ANA, r#"{"texts":"x"}"#.into())?).await?;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::BAD_REQUEST, "invalid_request")
    );

    // No model was called, nothing was charged, and each check is on the record.
    assert_eq!(s.calls.load(Ordering::SeqCst), 0);
    let all = records(&s.audit)?;
    let checks: Vec<&Value> = all
        .iter()
        .filter(|r| r["path"] == "/v1/guardrails/check")
        .collect();
    assert_eq!(checks.len(), 4);
    assert_eq!(checks[0]["guardrail_check"], "request");
    assert_eq!(checks[0]["cost_usd"], 0);
    assert_eq!(checks[2]["guardrail_check"], "answer");
    assert!(all.iter().all(|r| r["event"] != "usage"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_role_grants_no_more_than_its_key_bounds_allow() -> TestResult {
    let s = setup("bounds", "counted").await?;
    let app = &s.gw.router;
    let issue = |key: &'static str, body: &'static str| call("POST", "/admin/keys", key, body, &[]);
    // Left unset, each bounded field takes its bound.
    let (status, body) = answer(app, issue(LEAD, r#"{"name":"new1","team":"counted"}"#)?).await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let prefix = body["sha256_prefix"]
        .as_str()
        .ok_or("no prefix")?
        .to_string();
    let (_, info) = answer(app, call("GET", "/admin/keys", ROOT, "", &[])?).await?;
    let made = info["keys"]
        .as_array()
        .and_then(|keys| keys.iter().find(|k| k["sha256_prefix"] == prefix.as_str()))
        .ok_or("the key is not listed")?;
    assert_eq!(made["budget"]["usd"], 10.0, "{made}");
    assert_eq!(made["models"], serde_json::json!(["m", "n"]));
    assert!(made["expires"].is_string(), "{made}");

    for (body, word) in [
        (
            r#"{"name":"new2","team":"counted","expires":"2099-01-01"}"#,
            "at most 30 days",
        ),
        (
            r#"{"name":"new2","team":"counted","budget":{"usd":11,"per":"month"}}"#,
            "at most $10 a month",
        ),
        // $1 a day spends faster than $10 a month.
        (
            r#"{"name":"new2","team":"counted","budget":{"usd":1,"per":"day"}}"#,
            "at most $10 a month",
        ),
        (
            r#"{"name":"new2","team":"counted","models":["big"]}"#,
            "only m, n",
        ),
    ] {
        let (status, refused) = answer(app, issue(LEAD, body)?).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
        assert_eq!(code(&refused), "key_bounds_exceeded");
        let message = refused["error"]["message"].as_str().unwrap_or_default();
        assert!(message.contains(word), "{message}");
    }
    let (status, body) = answer(
        app,
        issue(
            LEAD,
            r#"{"name":"new3","team":"counted","budget":{"usd":0.2,"per":"day"},"models":["m"]}"#,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    // The admin has no bounds of its own: the policy's apply (a year), and nothing else.
    let (status, body) = answer(
        app,
        issue(ROOT, r#"{"name":"new4","team":"counted","budget":{"usd":5000,"per":"month"},"models":["big"]}"#)?,
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = answer(
        app,
        issue(
            ROOT,
            r#"{"name":"new5","team":"counted","expires":"2099-01-01"}"#,
        )?,
    )
    .await?;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::FORBIDDEN, "key_bounds_exceeded"),
        "{body}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_model_group_is_allowed_by_name_and_budgeted_as_one() -> TestResult {
    let s = setup("groups", "groups").await?;
    let app = &s.gw.router;
    let ask = |model: &str| format!(r#"{{"model":"{model}","max_tokens":1,"messages":[]}}"#);
    // m and n share the group's $0.002 a day: two requests fit, whichever model each names.
    for (i, model) in ["m", "n"].iter().enumerate() {
        let (status, body) = answer(app, chat(ANA, &ask(model), &[])?).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        usage(&s.audit, i + 1).await?;
    }
    let (status, body) = answer(app, chat(ANA, &ask("m"), &[])?).await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(code(&body), "budget_exceeded");
    assert!(
        body["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("model group \"small\"")),
        "{body}"
    );
    // big is in no group: it does not count against the group's budget.
    let (status, body) = answer(app, chat(ANA, &ask("big"), &[])?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, explained) = answer(
        app,
        call("GET", "/admin/explain?key=ana&model=n", ROOT, "", &[])?,
    )
    .await?;
    assert!(
        explained["limits"].as_array().is_some_and(|l| l
            .iter()
            .any(|a| a["of"] == "model_group" && a["scope"] == "model_group:small")),
        "{explained}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn requests_are_limited_by_the_hour_and_by_the_day() -> TestResult {
    let s = setup("rpd", "counted").await?;
    let app = &s.gw.router;
    for _ in 0..2 {
        let (status, body) = answer(app, chat(ANA, FREE, &[])?).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let response = app.clone().oneshot(chat(ANA, FREE, &[])?).await?;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let wait: u64 = response
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .ok_or("no Retry-After")?;
    assert!((1..=3600).contains(&wait), "{wait}");
    let body: Value = serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    assert_eq!(code(&body), "rate_limited");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(message.contains("2 requests this hour"), "{message}");
    // Each person has their own count.
    let (status, body) = answer(app, chat(BEN, FREE, &[])?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let refused = records(&s.audit)?
        .into_iter()
        .find(|r| r["code"] == "rate_limited")
        .ok_or("no refusal record")?;
    assert_eq!(refused["limit"]["kind"], "rph");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_raise_is_asked_for_approved_and_ends_by_itself() -> TestResult {
    let s = setup("raise", "raised").await?;
    let app = &s.gw.router;
    let one = r#"{"model":"big","max_tokens":1,"messages":[]}"#;
    let (status, body) = answer(app, chat(ANA, one, &[])?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    usage(&s.audit, 1).await?;
    let (status, body) = answer(app, chat(ANA, one, &[])?).await?;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::TOO_MANY_REQUESTS, "budget_exceeded"),
        "{body}"
    );

    // Ana asks; nothing changes until an admin decides.
    let asked = r#"{"usd":0.001,"until":"2099-01-01","reason":"quarter-end backfill"}"#;
    let (status, raise) = answer(app, call("POST", "/v1/budget/raises", ANA, asked, &[])?).await?;
    assert_eq!(status, StatusCode::CREATED, "{raise}");
    assert_eq!(raise["state"], "pending");
    assert_eq!(raise["scope"], "team:raised");
    let id = raise["id"].as_str().ok_or("no id")?.to_string();
    let (_, body) = answer(app, chat(ANA, one, &[])?).await?;
    assert_eq!(code(&body), "budget_exceeded");
    let (status, body) = answer(
        app,
        call("POST", "/v1/budget/raises", ANA, r#"{"usd":5}"#, &[])?,
    )
    .await?;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::BAD_REQUEST, "invalid_request"),
        "{body}"
    );

    let (_, listed) = answer(app, call("GET", "/admin/budget/raises", ROOT, "", &[])?).await?;
    assert_eq!(listed["raises"][0]["id"], id.as_str(), "{listed}");
    // A caller who is no admin cannot approve their own raise.
    let approve = format!("/admin/budget/raises/{id}/approve");
    let (status, _) = answer(app, call("POST", &approve, ANA, "", &[])?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, approved) =
        answer(app, call("POST", &approve, ROOT, r#"{"usd":0.002}"#, &[])?).await?;
    assert_eq!(status, StatusCode::OK, "{approved}");
    assert_eq!(approved["state"], "approved");
    assert_eq!(approved["usd"], 0.002);
    assert_eq!(approved["decided_by"], "root");
    let (status, body) = answer(app, call("POST", &approve, ROOT, "", &[])?).await?;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::CONFLICT, "raise_decided")
    );

    // $0.001 of budget and $0.002 of raise: two more requests fit, a fourth does not.
    for n in 2..=3 {
        let (status, body) = answer(app, chat(BEN, one, &[])?).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        usage(&s.audit, n).await?;
    }
    let (_, body) = answer(app, chat(ANA, one, &[])?).await?;
    assert_eq!(code(&body), "budget_exceeded");
    assert!(
        body["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("$0.0030 budget")),
        "{body}"
    );
    let (_, explained) = answer(
        app,
        call("GET", "/admin/explain?key=ana&model=big", ROOT, "", &[])?,
    )
    .await?;
    let budget = explained["limits"]
        .as_array()
        .and_then(|l| l.iter().find(|a| a["limit"] == "budget"))
        .ok_or("no budget in the explanation")?;
    assert!(
        budget["source"].as_str().is_some_and(|s| s.contains(&id)),
        "{budget}"
    );

    // An admin's own raise is approved at once, and one whose time has passed counts for nothing.
    let (status, body) = answer(
        app,
        call(
            "POST",
            "/admin/budget/raises",
            ROOT,
            r#"{"scope":"team:raised","usd":1,"until":"2020-01-01","reason":"old"}"#,
            &[],
        )?,
    )
    .await?;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::BAD_REQUEST, "invalid_request"),
        "{body}"
    );
    let (_, mine) = answer(app, call("GET", "/v1/budget/raises", ANA, "", &[])?).await?;
    assert_eq!(mine["raises"].as_array().map(Vec::len), Some(1), "{mine}");

    let all = records(&s.audit)?;
    assert!(
        all.iter().any(|r| r["budget_raise"]["id"] == id.as_str()),
        "the request is recorded"
    );
    assert!(
        all.iter().any(|r| r["action"] == "approve_budget_raise"
            && r["target"]["id"] == id.as_str()
            && r["verdict"] == "allow"),
        "the approval is recorded"
    );
    // Kept beside the keys file, so a restart keeps it.
    let kept = std::fs::read_to_string(s.audit.with_file_name("gantry-raises.json"))?;
    assert!(kept.contains(&id), "{kept}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_has_its_own_budget_and_request_count() -> TestResult {
    let s = setup("session", "sessions").await?;
    let app = &s.gw.router;
    let one = r#"{"model":"big","max_tokens":1,"messages":[{"role":"user","content":"go"}]}"#;
    // $0.002 a session: two requests of a tenth of a cent fit, a third would pass it.
    for n in 1..=2 {
        let (status, body) = answer(app, chat(ANA, one, &[("x-gantry-session", "a")])?).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        usage(&s.audit, n).await?;
    }
    let (status, body) = answer(app, chat(ANA, one, &[("x-gantry-session", "a")])?).await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(code(&body), "session_budget_exceeded");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("session \"ses_") && message.contains("new session"),
        "{message}"
    );

    // Another session of the same person starts from zero, and so does the same session id of another person.
    let (status, body) = answer(app, chat(ANA, one, &[("x-gantry-session", "b")])?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = answer(app, chat(BEN, one, &[("x-gantry-session", "a")])?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");

    // session_requests: 3. Session b has sent one; a request refused for its budget in session a counted too.
    for _ in 0..2 {
        let (status, body) = answer(app, chat(ANA, one, &[("x-gantry-session", "b")])?).await?;
        assert!(
            status == StatusCode::OK || code(&body) == "session_budget_exceeded",
            "{body}"
        );
    }
    let (status, body) = answer(app, chat(ANA, one, &[("x-gantry-session", "b")])?).await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(code(&body), "session_requests_exceeded", "{body}");
    let (_, explained) = answer(
        app,
        call("GET", "/admin/explain?key=ana&model=big", ROOT, "", &[])?,
    )
    .await?;
    let of_session: Vec<&Value> = explained["limits"]
        .as_array()
        .map(|l| l.iter().filter(|a| a["of"] == "session").collect())
        .unwrap_or_default();
    assert_eq!(of_session.len(), 2, "{explained}");
    assert_eq!(of_session[0]["per"], "session");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn every_request_record_names_its_session_with_no_events_guardrail() -> TestResult {
    let s = setup("records", "counted").await?;
    let app = &s.gw.router;
    // Named by a header, by Claude Code's metadata, and by nothing at all: the first message then.
    let (status, body) = answer(app, chat(ANA, FREE, &[("x-session-id", "s1")])?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let claude = r#"{"model":"free","messages":[{"role":"user","content":"hi"}],"metadata":{"user_id":"user_1_account_2_session_abc"}}"#;
    answer(app, chat(BEN, claude, &[])?).await?;
    answer(app, chat(BEN, FREE, &[])?).await?;
    answer(app, chat(BEN, FREE, &[])?).await?;
    let all = usage(&s.audit, 2).await?;
    let decisions: Vec<Value> = records(&s.audit)?
        .into_iter()
        .filter(|r| r["path"] == "/v1/chat/completions" && r["event"] != "usage")
        .collect();
    let session = |i: usize| {
        decisions[i]["session"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    };
    assert!(
        decisions
            .iter()
            .all(|r| r["session"].as_str().is_some_and(|s| s.starts_with("ses_"))),
        "{decisions:?}"
    );
    assert!(decisions.iter().all(|r| r.get("turn").is_none()));
    // The same resolution an events guardrail uses.
    let markers = gantry_core::events::Markers {
        session: Some("s1".into()),
        ..Default::default()
    };
    let key = &sha256_hex(ANA.as_bytes())[..8];
    assert_eq!(
        session(0),
        gantry_core::events::session_id("ana", key, &markers, &Value::Null, "").0
    );
    assert_ne!(session(1), session(2));
    assert_eq!(
        session(2),
        session(3),
        "the same first message from the same key is one session"
    );
    // The usage record carries it too, so spend sums by session.
    assert!(
        all.iter().any(|r| r["session"] == session(0).as_str()),
        "{all:?}"
    );
    Ok(())
}
