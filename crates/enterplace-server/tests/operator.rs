//! Acceptance tests for the operator visibility package: where a request's time went (the `Server-Timing` header,
//! `stages_ms` on the usage record and the stage histograms), the metrics an operator was missing (unpriced
//! requests, reserved budget, a deployment's rate headroom), each deployment's health at `GET /admin/deployments`,
//! a provider's connection test, a caller's own budget at `GET /v1/enterplace/me` with the budget headers a rule turns
//! on, and usage as a FOCUS cost file.

use std::time::{Duration, Instant};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::{get, post},
};
use enterplace_core::id::sha256_hex;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

type Error = Box<dyn std::error::Error>;
type TestResult = Result<(), Error>;

const MAYA: &str = "enterplace_maya_0123456789abcdef0123456789ab";
const ADMIN: &str = "enterplace_admin_0123456789abcdef0123456789";

/// A provider that answers chat completions with usage and its rate-limit headers, and lists its models to the
/// right key only.
async fn provider() -> Result<u16, Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let app = Router::new()
        .route(
            "/v1/chat/completions",
            post(|| async {
                axum::response::Response::builder()
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("x-ratelimit-limit-requests", "100")
                    .header("x-ratelimit-remaining-requests", "25")
                    .body(Body::from(
                        r#"{"id":"c","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1000,"completion_tokens":500}}"#,
                    ))
                    .unwrap_or_default()
            }),
        )
        .route(
            "/v1/models",
            get(|request: Request<Body>| async move {
                let key = request
                    .headers()
                    .get(header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                if key == "Bearer secret" {
                    (
                        StatusCode::OK,
                        r#"{"object":"list","data":[{"id":"m"},{"id":"u"}]}"#,
                    )
                } else {
                    (
                        StatusCode::UNAUTHORIZED,
                        r#"{"error":{"message":"bad key"}}"#,
                    )
                }
            }),
        );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

struct Answer {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: String,
}

impl Answer {
    fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
    }

    fn json(&self) -> Result<Value, Error> {
        Ok(serde_json::from_str(&self.body)?)
    }
}

async fn send(app: &Router, request: Request<Body>) -> Result<Answer, Error> {
    let response = app.clone().oneshot(request).await?;
    let (status, headers) = (response.status(), response.headers().clone());
    let body = response.into_body().collect().await?.to_bytes();
    Ok(Answer {
        status,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

fn chat(model: &str, text: &str) -> Result<Request<Body>, axum::http::Error> {
    Request::post("/v1/chat/completions")
        .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
        .body(Body::from(
            serde_json::json!({"model": model, "max_tokens": 5, "messages": [{"role": "user", "content": text}]}).to_string(),
        ))
}

fn admin(method: &str, path: &str) -> Result<Request<Body>, axum::http::Error> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {ADMIN}"))
        .body(Body::empty())
}

struct Gateway {
    gw: enterplace_server::Governed,
    audit: std::path::PathBuf,
}

/// A gateway on its own folder: provider `mock` (models m, priced, and u, with no price), provider `gone` (nothing
/// listens there), the alias `smart` over both, a PII guardrail, and a team budget with the budget headers on.
async fn gateway(name: &str) -> Result<Gateway, Error> {
    let port = provider().await?;
    let dead = {
        let l = std::net::TcpListener::bind(("127.0.0.1", 0))?;
        l.local_addr()?.port()
    };
    let dir =
        std::env::temp_dir().join(format!("enterplace-operator-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        dir.join("enterplace.keys.yaml"),
        format!(
            "keys:\n  - name: maya.cohen\n    team: payments\n    sha256: {}\n  - name: root\n    team: platform\n    admin: true\n    sha256: {}\n",
            sha256_hex(MAYA.as_bytes()),
            sha256_hex(ADMIN.as_bytes())
        ),
    )?;
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
    models: [m, u]
  - name: gone
    kind: openai
    url: http://127.0.0.1:{dead}
    allow_private: true
    key_env: WRONG_KEY
    models: [g]
  - name: wrong
    kind: openai
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: WRONG_KEY
    models: [w]
prices:
  m: {{ input: 1, output: 2 }}
  g: {{ input: 1, output: 2 }}
aliases:
  - name: smart
    cooldown_seconds: 60
    deployments:
      - {{ provider: gone, model: g }}
      - {{ provider: mock, model: m, rpm: 100 }}
guardrails:
  - name: mask-pii
    type: pii
    action: mask
limits:
  - {{ team: payments, budget: {{ usd: 10, per: month }} }}
rules:
  - name: payments
    principals: {{ team: payments }}
    models: [m, u, smart]
    guardrails: [mask-pii]
    budget_headers: true
  - name: admins
    principals: {{ team: platform }}
    models: [m, u]
"
        ),
    )?;
    let gw = enterplace_server::governed(&policy, None, &|v| match v {
        "MOCK_KEY" => Some("secret".into()),
        "WRONG_KEY" => Some("not-the-key".into()),
        _ => None,
    })?;
    Ok(Gateway {
        gw,
        audit: dir.join("enterplace-audit.jsonl"),
    })
}

impl Gateway {
    /// Waits for `n` usage records, then returns every record of the audit log.
    async fn settled(&self, n: usize) -> Result<Vec<Value>, Error> {
        let start = Instant::now();
        loop {
            let text = std::fs::read_to_string(&self.audit)?;
            if text.matches("\"event\":\"usage\"").count() >= n {
                return Ok(text
                    .lines()
                    .filter_map(|line| serde_json::from_str(line).ok())
                    .collect());
            }
            if start.elapsed() > Duration::from_secs(30) {
                return Err(format!("{n} usage records never came").into());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_requests_time_is_split_by_stage_in_the_header_the_record_and_the_histograms()
-> TestResult {
    let g = gateway("stages").await?;
    let answer = send(&g.gw.router, chat("m", "write to dana@example.com")?).await?;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    let timing = answer.header("server-timing");
    assert!(timing.starts_with("enterplace;dur="), "{timing}");
    for stage in [
        "auth",
        "read",
        "policy",
        "guardrails",
        "cache",
        "audit",
        "connect",
        "first-byte",
    ] {
        assert!(
            timing.contains(&format!("enterplace-{stage};dur=")),
            "{stage} missing from {timing}"
        );
    }
    let records = g.settled(1).await?;
    let usage = records
        .iter()
        .find(|r| r["event"] == "usage")
        .ok_or("no usage record")?;
    for stage in [
        "auth",
        "read",
        "policy",
        "guardrails",
        "cache",
        "audit",
        "connect",
        "first_byte",
        "stream",
    ] {
        assert!(
            usage["stages_ms"][stage].is_number(),
            "{stage} missing from {usage}"
        );
    }
    assert!(usage["guardrail_ms"]["builtin"].is_number(), "{usage}");
    // The stages are parts of the request's time, not more than it.
    let total: f64 = usage["stages_ms"]
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(name, _)| *name != "connect")
        .filter_map(|(_, v)| v.as_f64())
        .sum();
    assert!(total < 30_000.0);

    let metrics = send(&g.gw.metrics, Request::get("/metrics").body(Body::empty())?).await?;
    for line in [
        "enterplace_stage_seconds_count{stage=\"auth\"} 1",
        "enterplace_stage_seconds_count{stage=\"first_byte\"} 1",
        "enterplace_stage_seconds_count{stage=\"stream\"} 1",
        "enterplace_guardrail_seconds_count{guardrail=\"builtin\"} 1",
    ] {
        assert!(
            metrics.body.contains(line),
            "{line} missing from:\n{}",
            metrics.body
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn metrics_count_unpriced_requests_reserved_budget_and_a_deployments_rate_headroom()
-> TestResult {
    let g = gateway("metrics").await?;
    // A model with no price is served, and counted as such. The team budget refuses it, so the admin's rule asks.
    let unpriced = Request::post("/v1/chat/completions")
        .header(header::AUTHORIZATION, format!("Bearer {ADMIN}"))
        .body(Body::from(
            r#"{"model":"u","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}"#,
        ))?;
    assert_eq!(send(&g.gw.router, unpriced).await?.status, StatusCode::OK);
    let answer = send(&g.gw.router, chat("smart", "hello")?).await?;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    g.settled(2).await?;
    let metrics = send(&g.gw.metrics, Request::get("/metrics").body(Body::empty())?).await?;
    for line in [
        "enterplace_unpriced_requests_total{model=\"u\"} 1",
        "enterplace_budget_reserved_usd{scope=\"team\",name=\"payments\",per=\"month\"} 0",
        "enterplace_deployment_rate_headroom_ratio{deployment=\"mock/m\"} 0.25",
        "# TYPE enterplace_mcp_calls_total counter",
    ] {
        assert!(
            metrics.body.contains(line),
            "{line} missing from:\n{}",
            metrics.body
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn the_admin_api_shows_each_deployments_health_and_tests_a_providers_connection() -> TestResult
{
    let g = gateway("deployments").await?;
    let answer = send(&g.gw.router, chat("smart", "hello")?).await?;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    g.settled(1).await?;

    let view = send(&g.gw.router, admin("GET", "/admin/deployments")?).await?;
    assert_eq!(view.status, StatusCode::OK, "{}", view.body);
    let view = view.json()?;
    assert_eq!(view["counted_by"], "this gateway");
    let of = |name: &str| -> Result<Value, Error> {
        view["deployments"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|d| d["deployment"] == name)
            .cloned()
            .ok_or_else(|| format!("{name} missing from {view}").into())
    };
    let gone = of("gone/g")?;
    assert_eq!(gone["state"], "cooling", "{gone}");
    assert_eq!(gone["cooldowns"], 1);
    assert!(
        gone["cooling_seconds"]
            .as_u64()
            .is_some_and(|s| s > 0 && s <= 60)
    );
    assert_eq!(gone["aliases"], serde_json::json!(["smart"]));
    assert!(gone["error_rate"].as_f64().is_some_and(|e| e > 0.0));
    let mock = of("mock/m")?;
    assert_eq!(mock["state"], "up", "{mock}");
    assert_eq!(mock["limits"]["rpm"], 100);
    assert_eq!(mock["requests_this_minute"], 1);
    assert_eq!(mock["rate_headroom"], 0.25);
    assert!(mock["latency_p50_ms"].is_number() && mock["latency_p90_ms"].is_number());
    assert_eq!(mock["error_rate"], 0.0);
    assert!(view["providers"].as_array().is_some_and(|p| {
        p.iter()
            .any(|p| p["name"] == "mock" && p["kind"] == "openai")
    }));

    // The test asks for the model list: the cheapest call, which bills nothing.
    let ok = send(&g.gw.router, admin("POST", "/admin/providers/mock/test")?).await?;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.body);
    let ok = ok.json()?;
    assert_eq!(ok["ok"], true, "{ok}");
    assert_eq!(ok["status"], 200);
    assert_eq!(ok["models_listed"], 2);
    assert_eq!(ok["call"], "GET /v1/models");
    let refused = send(&g.gw.router, admin("POST", "/admin/providers/wrong/test")?)
        .await?
        .json()?;
    assert_eq!(refused["ok"], false);
    assert_eq!(refused["status"], 401);
    assert!(
        refused["detail"]
            .as_str()
            .is_some_and(|d| d.contains("refused the key")),
        "{refused}"
    );
    let unreachable = send(&g.gw.router, admin("POST", "/admin/providers/gone/test")?)
        .await?
        .json()?;
    assert_eq!(unreachable["ok"], false);
    assert_eq!(unreachable["outcome"], "upstream_unreachable");
    let missing = send(&g.gw.router, admin("POST", "/admin/providers/nope/test")?).await?;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    // A key that is not an admin's is refused.
    let stranger = Request::get("/admin/deployments")
        .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
        .body(Body::empty())?;
    assert_eq!(
        send(&g.gw.router, stranger).await?.status,
        StatusCode::FORBIDDEN
    );

    // Each test is in the audit log with its outcome, and the provider's key is in none of them.
    let log = std::fs::read_to_string(&g.audit)?;
    let tests: Vec<Value> = log
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|r| r["action"] == "test_provider")
        .collect();
    assert_eq!(tests.len(), 4, "{tests:?}");
    assert!(tests.iter().any(|r| r["target"]["ok"] == true));
    assert!(tests.iter().any(|r| r["target"]["status"] == 401));
    assert!(!log.contains("not-the-key") && !log.contains("\"secret\""));
    Ok(())
}

const HOST: &str = "enterplace.test";

/// Signs in to the console with the admin key and returns the session cookie.
async fn sign_in(app: &Router) -> Result<String, Error> {
    let response = app
        .clone()
        .oneshot(
            Request::post("/console/sign-in")
                .header(header::HOST, HOST)
                .header(header::ORIGIN, format!("http://{HOST}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("key={ADMIN}")))?,
        )
        .await?;
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .ok_or("the console set no session cookie")?;
    Ok(cookie.to_string())
}

#[tokio::test(flavor = "multi_thread")]
async fn the_console_shows_deployments_tests_a_provider_and_a_requests_time_by_stage() -> TestResult
{
    let g = gateway("console").await?;
    let answer = send(&g.gw.router, chat("smart", "hello dana@example.com")?).await?;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    let decision = answer.header("x-enterplace-decision").to_string();
    g.settled(1).await?;
    let cookie = sign_in(&g.gw.router).await?;
    let page = |path: &str| {
        Request::get(path)
            .header(header::HOST, HOST)
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
    };

    let deployments = send(&g.gw.router, page("/console/deployments")?).await?;
    assert_eq!(deployments.status, StatusCode::OK);
    for wanted in [
        "gone/g",
        "mock/m",
        "cooling",
        "rpm 100",
        "Test connection",
        "this gateway",
    ] {
        assert!(
            deployments.body.contains(wanted),
            "{wanted} missing from the Deployments page"
        );
    }
    let test = |provider: &str| {
        Request::post("/console/deployments")
            .header(header::HOST, HOST)
            .header(header::ORIGIN, format!("http://{HOST}"))
            .header(header::COOKIE, &cookie)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!("provider={provider}")))
    };
    let tested = send(&g.gw.router, test("mock")?).await?;
    assert_eq!(tested.status, StatusCode::OK);
    assert!(tested.body.contains("connected"), "the result is shown");
    let failed = send(&g.gw.router, test("wrong")?).await?;
    assert!(
        failed.body.contains("failed") && failed.body.contains("refused the key"),
        "a refused key is shown with what to check"
    );
    // A form from another site tests nothing.
    let foreign = Request::post("/console/deployments")
        .header(header::HOST, HOST)
        .header(header::ORIGIN, "http://elsewhere.test")
        .header(header::COOKIE, &cookie)
        .body(Body::from("provider=mock"))?;
    assert_ne!(send(&g.gw.router, foreign).await?.status, StatusCode::OK);
    let log = std::fs::read_to_string(&g.audit)?;
    let tests = log
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|r| r["action"] == "test_provider" && r["via"] == "console")
        .count();
    assert_eq!(tests, 2, "each console test is recorded once");

    // The request's record sheet, as the console app reads it, says where its time went.
    let row = send(
        &g.gw.router,
        page(&format!("/console/api/requests/{decision}"))?,
    )
    .await?;
    assert_eq!(row.status, StatusCode::OK);
    for wanted in ["Time by stage", "first byte", "guardrail builtin"] {
        assert!(row.body.contains(wanted), "{wanted} missing from the row");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_caller_reads_its_own_budget_and_a_rule_can_put_it_on_every_answer() -> TestResult {
    let g = gateway("budget").await?;
    let me = |key: &str| {
        Request::get("/v1/enterplace/me")
            .header(header::AUTHORIZATION, format!("Bearer {key}"))
            .body(Body::empty())
    };
    let before = send(&g.gw.router, me(MAYA)?).await?;
    assert_eq!(before.status, StatusCode::OK, "{}", before.body);
    let before = before.json()?;
    assert_eq!(before["name"], "maya.cohen");
    assert_eq!(before["team"], "payments");
    assert_eq!(before["rule"], "payments");
    assert_eq!(before["remaining_usd"], 10.0);
    assert_eq!(before["budgets"][0]["usd"], 10.0);
    assert_eq!(before["budgets"][0]["per"], "month");
    assert!(
        before["resets"]
            .as_str()
            .is_some_and(|r| r.ends_with("00:00 UTC")),
        "{before}"
    );

    // The rule has budget_headers: each answer says what the tightest budget has left, and when it resets.
    let answer = send(&g.gw.router, chat("m", "hello")?).await?;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    let left: f64 = answer.header("x-enterplace-budget-remaining-usd").parse()?;
    assert!(left < 10.0 && left > 9.0, "{left}");
    assert_eq!(
        Some(answer.header("x-enterplace-budget-reset")),
        before["resets"].as_str()
    );
    g.settled(1).await?;
    let after = send(&g.gw.router, me(MAYA)?).await?.json()?;
    // 1,000 tokens in at $1 and 500 out at $2 a million.
    assert_eq!(after["budgets"][0]["spent_usd"], 0.002);
    assert_eq!(after["remaining_usd"], 9.998);

    // A rule without budget_headers adds none, and its caller has no budget to show.
    let plain = Request::post("/v1/chat/completions")
        .header(header::AUTHORIZATION, format!("Bearer {ADMIN}"))
        .body(Body::from(
            r#"{"model":"m","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}"#,
        ))?;
    let plain = send(&g.gw.router, plain).await?;
    assert_eq!(plain.status, StatusCode::OK);
    assert!(
        !plain
            .headers
            .contains_key("x-enterplace-budget-remaining-usd")
    );
    let admin_me = send(&g.gw.router, me(ADMIN)?).await?.json()?;
    assert!(admin_me["remaining_usd"].is_null() && admin_me["budgets"] == serde_json::json!([]));

    // A key Enterplace does not know learns nothing, and asking writes no audit record.
    let stranger = send(&g.gw.router, me("enterplace_nobody_0123456789")?).await?;
    assert_eq!(stranger.status, StatusCode::UNAUTHORIZED);
    g.settled(2).await?;
    assert!(!std::fs::read_to_string(&g.audit)?.contains("/v1/enterplace/me"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn usage_is_exported_as_a_focus_cost_file() -> TestResult {
    let g = gateway("focus").await?;
    for _ in 0..2 {
        let answer = send(&g.gw.router, chat("m", "hello")?).await?;
        assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    }
    // A refused request reached no provider: it is no line.
    assert_eq!(
        send(&g.gw.router, chat("nope", "hello")?).await?.status,
        StatusCode::FORBIDDEN
    );
    g.settled(2).await?;
    let file = send(&g.gw.router, admin("GET", "/admin/usage?format=focus")?).await?;
    assert_eq!(file.status, StatusCode::OK, "{}", file.body);
    assert!(file.header("content-type").starts_with("text/csv"));
    assert!(
        file.header("content-disposition")
            .contains("enterplace-focus.csv")
    );
    let mut lines = file.body.lines();
    let header: Vec<&str> = lines.next().ok_or("no header")?.split(',').collect();
    for column in [
        "BilledCost",
        "BillingAccountId",
        "BillingCurrency",
        "BillingPeriodStart",
        "BillingPeriodEnd",
        "ChargeCategory",
        "ChargePeriodStart",
        "ChargePeriodEnd",
        "EffectiveCost",
        "ListCost",
        "ContractedCost",
        "ProviderName",
        "PublisherName",
        "InvoiceIssuerName",
        "ServiceCategory",
        "ServiceName",
        "SkuId",
        "SubAccountId",
        "ConsumedQuantity",
        "ConsumedUnit",
        "Tags",
    ] {
        assert!(header.contains(&column), "{column} missing from the header");
    }
    let rows: Vec<&str> = lines.collect();
    assert_eq!(
        rows.len(),
        1,
        "one line per day, team, provider and model: {rows:?}"
    );
    let row = rows[0];
    let today = &enterplace_core::audit::timestamp()[..10];
    // Two requests of 1,000 tokens in and 500 out: $0.004, 3,000 tokens.
    assert!(
        row.starts_with("0.004,\"default\",\"default\",USD,"),
        "{row}"
    );
    assert!(
        row.contains(&format!("Usage-Based,{today}T00:00:00Z,")),
        "{row}"
    );
    assert!(
        row.contains(",3000,Tokens,0.004,0.004,\"mock\",0.004,Standard,"),
        "{row}"
    );
    assert!(
        row.contains("\"AI and Machine Learning\",\"mock\",\"m\",\"payments\",\"payments\","),
        "{row}"
    );
    assert!(row.ends_with(",2,2000,1000"), "{row}");
    // A filter narrows it as it narrows the JSON answer.
    let none = send(
        &g.gw.router,
        admin("GET", "/admin/usage?format=focus&team=nobody")?,
    )
    .await?;
    assert_eq!(none.body.lines().count(), 1, "the header alone");
    Ok(())
}
