//! Coding agent controls at the gateway: `coding_agents: { browser: block }` refuses a request that offers the model
//! browser tools (Claude in Chrome and the like), names the tool and the fix, and records it; a rule's own value
//! overrides the policy's, and `tool_action: strip` takes the tools out instead. Bypass and auto mode leave no
//! reliable trace in a request, so they are enforced on the device (enterprise/src/device.rs), not here.

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

const MAYA: &str = "enterplace_maya_0123456789abcdef0123456789";
const NOA: &str = "enterplace_noa_0123456789abcdef01234567890";
const CHROME: &str = "mcp__claude-in-chrome__navigate";

/// Answers with the tool names it was sent, so a test sees what reached the provider.
async fn provider() -> Result<u16, Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let app = Router::new().route(
        "/v1/messages",
        post(|body: Bytes| async move {
            let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let seen: Vec<Value> = request["tools"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|t| t["name"].clone())
                .collect();
            (
                [(header::CONTENT_TYPE, "application/json")],
                json!({"id": "m", "type": "message", "role": "assistant", "model": "claude-a",
                    "content": [{"type": "text", "text": Value::Array(seen).to_string()}],
                    "stop_reason": "end_turn", "usage": {"input_tokens": 5, "output_tokens": 5}})
                .to_string(),
            )
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

fn policy(port: u16, top: &str, rules: &str) -> String {
    format!(
        "version: 1
providers:
  - name: mock-anthropic
    kind: anthropic
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: MOCK_KEY
    models: [claude-a]
{top}rules:
{rules}  - name: everyone
    principals: {{ any: true }}
    models: [\"*\"]
"
    )
}

struct Setup {
    audit: std::path::PathBuf,
    gw: Governed,
}

fn setup(name: &str, policy: &str) -> Result<Setup, Error> {
    let dir = std::env::temp_dir().join(format!(
        "enterplace-coding-agents-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("enterplace.policy.yaml");
    std::fs::write(&path, policy)?;
    std::fs::write(
        dir.join("enterplace.keys.yaml"),
        format!(
            "keys:\n  - name: maya.cohen\n    team: payments\n    sha256: {}\n  - name: noa.levi\n    team: research\n    sha256: {}\n",
            sha256_hex(MAYA.as_bytes()),
            sha256_hex(NOA.as_bytes())
        ),
    )?;
    let gw = enterplace_server::governed(&path, None, &|_| Some("provider-secret".into()))?;
    Ok(Setup {
        audit: dir.join("enterplace-audit.jsonl"),
        gw,
    })
}

/// A Claude Code request: its own tools, and the browser's when Chrome is on.
fn messages(key: &str, tools: &[&str]) -> Result<Request<Body>, axum::http::Error> {
    let tools: Vec<Value> = tools
        .iter()
        .map(|n| json!({"name": n, "input_schema": {"type": "object"}}))
        .collect();
    let body = json!({"model": "claude-a", "max_tokens": 64,
        "messages": [{"role": "user", "content": "open the dashboard"}], "tools": tools});
    Request::post("/v1/messages")
        .header("x-api-key", key)
        .header(header::USER_AGENT, "claude-cli/2.1.300 (external, cli)")
        .body(Body::from(body.to_string()))
}

async fn send(gw: &Governed, request: Request<Body>) -> Result<(StatusCode, Value), Error> {
    let response = gw.router.clone().oneshot(request).await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, serde_json::from_slice(&body)?))
}

fn last_record(s: &Setup) -> Result<Value, Error> {
    let text = std::fs::read_to_string(&s.audit)?;
    let line = text.lines().last().ok_or("no record")?;
    Ok(serde_json::from_str(line)?)
}

fn code(body: &Value) -> &Value {
    if body["enterplace_code"].is_string() {
        &body["enterplace_code"]
    } else {
        &body["error"]["code"]
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn browser_tools_are_refused_org_wide_and_recorded() -> TestResult {
    let top = "coding_agents:\n  browser: block\n";
    let s = setup("block", &policy(provider().await?, top, ""))?;
    let (status, body) = send(&s.gw, messages(MAYA, &["Read", "Bash", CHROME])?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(code(&body), "browser_not_allowed", "{body}");
    let text = body.to_string();
    // The cause (the tool, the rule) and the fix (turn Chrome off, or the admin's setting).
    assert!(text.contains(CHROME), "{text}");
    assert!(text.contains("everyone"), "{text}");
    assert!(text.contains("--chrome"), "{text}");
    assert!(text.contains("coding_agents"), "{text}");
    let record = last_record(&s)?;
    assert_eq!(record["code"], "browser_not_allowed");
    assert_eq!(
        record["guardrails"][0],
        json!({"guardrail": "coding_agents", "detector": "browser", "kind": CHROME, "action": "block", "count": 1})
    );
    // Without browser tools the same person goes through.
    let (status, body) = send(&s.gw, messages(MAYA, &["Read", "Bash"])?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Other browser servers count too; a tool that only mentions a browser does not.
    let (status, _) = send(&s.gw, messages(MAYA, &["mcp__playwright__browser_click"])?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = send(&s.gw, messages(MAYA, &["mcp__docs__open_in_chrome"])?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rule_overrides_the_org_wide_setting_for_its_team() -> TestResult {
    let top = "coding_agents:\n  browser: block\n";
    let rules = "  - name: research
    principals: { team: research }
    models: [\"*\"]
    coding_agents: { browser: allow }
";
    let s = setup("override", &policy(provider().await?, top, rules))?;
    let (status, body) = send(&s.gw, messages(NOA, &["Read", CHROME])?).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "research may use the browser: {body}"
    );
    let (status, body) = send(&s.gw, messages(MAYA, &["Read", CHROME])?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn with_strip_the_browser_tools_are_taken_out_and_the_rest_sent() -> TestResult {
    let rules = "  - name: payments
    principals: { team: payments }
    models: [\"*\"]
    tool_action: strip
    coding_agents: { browser: block }
";
    let s = setup("strip", &policy(provider().await?, "", rules))?;
    let (status, body) = send(&s.gw, messages(MAYA, &["Read", CHROME])?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["content"][0]["text"], json!(["Read"]).to_string());
    let record = last_record(&s)?;
    assert_eq!(record["guardrails"][0]["detector"], "browser");
    assert_eq!(record["guardrails"][0]["action"], "strip");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_policy_that_does_not_say_leaves_browser_tools_alone() -> TestResult {
    let s = setup("unset", &policy(provider().await?, "", ""))?;
    let (status, body) = send(&s.gw, messages(MAYA, &["Read", CHROME])?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_misspelled_setting_is_refused_with_the_words_it_takes() -> TestResult {
    let port = provider().await?;
    for (top, expect) in [
        ("coding_agents:\n  browser: deny\n", "allow or block"),
        ("coding_agents:\n  chrome: block\n", "chrome"),
    ] {
        let dir = std::env::temp_dir().join(format!(
            "enterplace-coding-agents-{}-bad",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("enterplace.policy.yaml");
        std::fs::write(&path, policy(port, top, ""))?;
        let Err(e) = enterplace_server::governed(&path, None, &|_| Some("x".into())) else {
            return Err(format!("{top} was taken").into());
        };
        assert!(e.to_string().contains(expect), "{e}");
    }
    Ok(())
}
