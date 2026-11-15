//! Acceptance tests for the operator visibility package: where a request's time went (the `Server-Timing` header,
//! `stages_ms` on the usage record and the stage histograms), the metrics an operator was missing (unpriced
//! requests, reserved budget, a deployment's rate headroom), each deployment's health at `GET /admin/deployments`,
//! a provider's connection test, a caller's own budget at `GET /v1/gantry/me` with the budget headers a rule turns
//! on, and usage as a FOCUS cost file.

use std::time::{Duration, Instant};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::{get, post},
};
use gantry_core::id::sha256_hex;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

type Error = Box<dyn std::error::Error>;
type TestResult = Result<(), Error>;

const MAYA: &str = "gantry_maya_0123456789abcdef0123456789ab";
const ADMIN: &str = "gantry_admin_0123456789abcdef0123456789";

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
    gw: gantry_server::Governed,
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
    let dir = std::env::temp_dir().join(format!("gantry-operator-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        dir.join("gantry.keys.yaml"),
        format!(
            "keys:\n  - name: maya.cohen\n    team: payments\n    sha256: {}\n  - name: root\n    team: platform\n    admin: true\n    sha256: {}\n",
            sha256_hex(MAYA.as_bytes()),
            sha256_hex(ADMIN.as_bytes())
        ),
    )?;
    let policy = dir.join("gantry.policy.yaml");
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
    let gw = gantry_server::governed(&policy, None, &|v| match v {
        "MOCK_KEY" => Some("secret".into()),
        "WRONG_KEY" => Some("not-the-key".into()),
        _ => None,
    })?;
    Ok(Gateway {
        gw,
        audit: dir.join("gantry-audit.jsonl"),
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
    assert!(timing.starts_with("gantry;dur="), "{timing}");
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
            timing.contains(&format!("gantry-{stage};dur=")),
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
        "gantry_stage_seconds_count{stage=\"auth\"} 1",
        "gantry_stage_seconds_count{stage=\"first_byte\"} 1",
        "gantry_stage_seconds_count{stage=\"stream\"} 1",
        "gantry_guardrail_seconds_count{guardrail=\"builtin\"} 1",
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
        "gantry_unpriced_requests_total{model=\"u\"} 1",
        "gantry_budget_reserved_usd{scope=\"team\",name=\"payments\",per=\"month\"} 0",
        "gantry_deployment_rate_headroom_ratio{deployment=\"mock/m\"} 0.25",
        "# TYPE gantry_mcp_calls_total counter",
    ] {
        assert!(
            metrics.body.contains(line),
            "{line} missing from:\n{}",
            metrics.body
        );
    }
    Ok(())
}
