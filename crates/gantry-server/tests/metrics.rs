//! `/metrics` covers what an operator watches: tokens by kind, request and first byte latency, refusals by code,
//! guardrail findings, answer cache lookups, deployment health and cooldowns, budget remaining per scope and store
//! health, with labels taken from the policy only, so their number stays bounded.

use std::time::{Duration, Instant};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::post,
};
use gantry_core::id::sha256_hex;
use http_body_util::BodyExt;
use tower::ServiceExt;

type Error = Box<dyn std::error::Error>;
type TestResult = Result<(), Error>;

const MAYA: &str = "gantry_maya_0123456789abcdef0123456789ab";

async fn provider() -> Result<u16, Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let app = Router::new().route(
        "/v1/chat/completions",
        post(|| async {
            axum::response::Response::builder()
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"id":"c","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}"#,
                ))
                .unwrap_or_default()
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

async fn send(app: &Router, request: Request<Body>) -> Result<(StatusCode, String), Error> {
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

fn chat(model: &str, text: &str) -> Result<Request<Body>, axum::http::Error> {
    Request::post("/v1/chat/completions")
        .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
        .body(Body::from(
            serde_json::json!({"model": model, "max_tokens": 5, "messages": [{"role": "user", "content": text}]}).to_string(),
        ))
}

#[tokio::test(flavor = "multi_thread")]
async fn metrics_cover_tokens_latency_refusals_findings_cache_deployments_and_budgets() -> TestResult
{
    let port = provider().await?;
    let dead = {
        let l = std::net::TcpListener::bind(("127.0.0.1", 0))?;
        l.local_addr()?.port()
    };
    let dir = std::env::temp_dir().join(format!("gantry-metrics-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        dir.join("gantry.keys.yaml"),
        format!(
            "keys:\n  - name: maya.cohen\n    team: payments\n    sha256: {}\n",
            sha256_hex(MAYA.as_bytes())
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
    models: [m]
  - name: gone
    kind: openai
    url: http://127.0.0.1:{dead}
    allow_private: true
    key_env: MOCK_KEY
    models: [g]
prices:
  m: {{ input: 1, output: 2 }}
  g: {{ input: 1, output: 2 }}
aliases:
  - name: smart
    cooldown_seconds: 60
    deployments:
      - {{ provider: gone, model: g }}
      - {{ provider: mock, model: m }}
guardrails:
  - name: mask-pii
    type: pii
    action: mask
limits:
  - {{ team: payments, budget: {{ usd: 10, per: month }} }}
  - {{ person: maya.cohen, budget: {{ usd: 5, per: month }} }}
rules:
  - name: payments
    principals: {{ team: payments }}
    models: [m, smart]
    guardrails: [mask-pii]
    cache: {{ ttl_seconds: 300 }}
"
        ),
    )?;
    let gw = gantry_server::governed(&policy, None, &|v| {
        (v == "MOCK_KEY").then(|| "secret".into())
    })?;
    let audit = dir.join("gantry-audit.jsonl");
    // Usage is recorded, and an answer kept in the cache, on the audit writer once each answer ends. Each request
    // waits for the one before it to be settled: sent at once, the second could miss the first's cache entry.
    let settled = |n: usize| {
        let audit = audit.clone();
        async move {
            let start = Instant::now();
            while std::fs::read_to_string(&audit)?
                .matches("\"event\":\"usage\"")
                .count()
                < n
            {
                if start.elapsed() > Duration::from_secs(30) {
                    return Err::<(), Error>(format!("{n} usage records never came").into());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Ok(())
        }
    };

    let (status, body) = send(&gw.router, chat("m", "write to dana@example.com")?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    settled(1).await?;
    let (status, _) = send(&gw.router, chat("m", "write to dana@example.com")?).await?;
    assert_eq!(status, StatusCode::OK);
    settled(2).await?;
    let (status, body) = send(&gw.router, chat("smart", "hello")?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = send(&gw.router, chat("nope", "hello")?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    settled(3).await?;

    let (status, text) = send(&gw.metrics, Request::get("/metrics").body(Body::empty())?).await?;
    assert_eq!(status, StatusCode::OK);
    for line in [
        "gantry_tokens_total{team=\"payments\",model=\"m\",kind=\"input\"} 20",
        "gantry_tokens_total{team=\"payments\",model=\"m\",kind=\"output\"} 10",
        "gantry_refusals_total{code=\"model_not_allowed\"} 1",
        "gantry_guardrail_findings_total{kind=\"email_address\"} 2",
        "gantry_cache_lookups_total{outcome=\"hit\"} 1",
        "gantry_cache_lookups_total{outcome=\"miss\"} 2",
        "gantry_first_byte_seconds_count{provider=\"mock\"} 2",
        "gantry_deployment_up{deployment=\"gone/g\"} 0",
        "gantry_deployment_cooldowns_total{deployment=\"gone/g\"} 1",
        "gantry_budget_limit_usd{scope=\"team\",name=\"payments\",per=\"month\"} 10",
    ] {
        assert!(text.contains(line), "{line} missing from:\n{text}");
    }
    assert!(
        text.contains("gantry_request_seconds_count{model=\"m\"} 3"),
        "{text}"
    );
    assert!(
        text.contains(
            "gantry_budget_remaining_usd{scope=\"team\",name=\"payments\",per=\"month\"} 9.99"
        ),
        "{text}"
    );
    // A person's budget is a series per person: left out unless GANTRY_METRICS_BUDGET_SCOPES asks for it.
    assert!(!text.contains("name=\"maya.cohen\""), "{text}");
    // Every metric has its help and type.
    for name in text
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split(['{', ' ']).next())
    {
        let base = name
            .trim_end_matches("_bucket")
            .trim_end_matches("_sum")
            .trim_end_matches("_count");
        assert!(
            text.contains(&format!("# TYPE {base} ")) || text.contains(&format!("# TYPE {name} ")),
            "{name} has no TYPE"
        );
    }
    Ok(())
}
