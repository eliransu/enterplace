//! Function tools: a rule's `tools:` list decides the function tools a request declares and the tool calls in the
//! answer (refused, or stripped with `tool_action: strip`), and answer guardrails read tool call arguments.
//! The mock provider calls the tool the user's text names, with the tools it was sent and the text as arguments.

use axum::{
    Router,
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
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
const AWS: &str = "AKIAIOSFODNN7EXAMPLE";

fn tool_names(request: &Value) -> Vec<Value> {
    request["tools"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|t| t["function"]["name"].as_str().or(t["name"].as_str()))
        .map(Value::from)
        .collect()
}

fn user_text(request: &Value) -> String {
    let content = &request["messages"][0]["content"];
    content
        .as_str()
        .or_else(|| content[0]["text"].as_str())
        .unwrap_or("")
        .to_string()
}

async fn provider() -> Result<u16, Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let app = Router::new()
        .route(
            "/v1/chat/completions",
            post(|body: Bytes| async move {
                let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                let text = user_text(&request);
                let name = text.split(' ').next().unwrap_or("").to_string();
                let arguments = json!({"seen": tool_names(&request), "text": text}).to_string();
                (
                    [(header::CONTENT_TYPE, "application/json")],
                    json!({"id": "c", "object": "chat.completion", "created": 1, "model": "model-a",
                        "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {"role": "assistant", "content": null,
                            "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": name, "arguments": arguments}}]}}],
                        "usage": {"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10}})
                    .to_string(),
                )
            }),
        )
        .route(
            "/v1/messages",
            post(|body: Bytes| async move {
                let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                let text = user_text(&request);
                let name = text.split(' ').next().unwrap_or("").to_string();
                (
                    [(header::CONTENT_TYPE, "application/json")],
                    json!({"id": "m", "type": "message", "role": "assistant", "model": "claude-a",
                        "content": [{"type": "tool_use", "id": "t1", "name": name, "input": {"seen": tool_names(&request), "text": text}}],
                        "stop_reason": "tool_use", "usage": {"input_tokens": 5, "output_tokens": 5}})
                    .to_string(),
                )
            }),
        );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

fn policy(port: u16, rule_extra: &str) -> String {
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
  - name: answer-secrets
    type: secrets
    action: block
    on: [answer]
  - name: answer-pii
    type: pii
    action: mask
    on: [answer]
rules:
  - name: everyone
    principals: {{ any: true }}
    models: [\"*\"]
    guardrails: [answer-secrets, answer-pii]
    tools: [function.get_weather, \"!function.run_shell\"]
{rule_extra}"
    )
}

struct Setup {
    audit: std::path::PathBuf,
    gw: Governed,
}

fn setup(name: &str, policy: &str) -> Result<Setup, Error> {
    let dir = std::env::temp_dir().join(format!("gantry-fntools-{}-{name}", std::process::id()));
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
        audit: dir.join("gantry-audit.jsonl"),
        gw,
    })
}

fn chat(text: &str, tools: &[&str]) -> Result<Request<Body>, axum::http::Error> {
    let tools: Vec<Value> = tools
        .iter()
        .map(|n| json!({"type": "function", "function": {"name": n, "parameters": {"type": "object"}}}))
        .collect();
    let body = json!({"model": "model-a", "messages": [{"role": "user", "content": text}], "tools": tools});
    Request::post("/v1/chat/completions")
        .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
        .body(Body::from(body.to_string()))
}

fn messages(text: &str, tools: &[&str]) -> Result<Request<Body>, axum::http::Error> {
    let tools: Vec<Value> = tools
        .iter()
        .map(|n| json!({"name": n, "input_schema": {"type": "object"}}))
        .collect();
    let body = json!({"model": "claude-a", "max_tokens": 64, "messages": [{"role": "user", "content": text}], "tools": tools});
    Request::post("/v1/messages")
        .header("x-api-key", MAYA)
        .body(Body::from(body.to_string()))
}

async fn send(gw: &Governed, request: Request<Body>) -> Result<(StatusCode, Value), Error> {
    let response = gw.router.clone().oneshot(request).await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, serde_json::from_slice(&body)?))
}

fn records(s: &Setup) -> Result<Vec<Value>, Error> {
    std::fs::read_to_string(&s.audit)?
        .lines()
        .map(|line| Ok(serde_json::from_str::<Value>(line)?))
        .collect()
}

fn code(body: &Value) -> &Value {
    if body["gantry_code"].is_string() {
        &body["gantry_code"]
    } else {
        &body["error"]["code"]
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_disallowed_declared_tool_is_refused_and_recorded_on_both_routes() -> TestResult {
    let s = setup("block", &policy(provider().await?, ""))?;
    for request in [
        chat("get_weather now", &["get_weather", "run_shell"])?,
        messages("get_weather now", &["get_weather", "run_shell"])?,
    ] {
        let (status, body) = send(&s.gw, request).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(code(&body), "tool_not_allowed", "{body}");
        assert!(body.to_string().contains("run_shell"), "{body}");
        let record = records(&s)?.pop().ok_or("no record")?;
        assert_eq!(record["code"], "tool_not_allowed");
        assert_eq!(
            record["guardrails"][0],
            json!({"guardrail": "tools", "detector": "function_tools", "kind": "run_shell", "action": "block", "count": 1})
        );
    }
    // An allowed tool goes through; the model calling an undeclared, disallowed tool has its answer withheld.
    let (status, body) = send(&s.gw, chat("get_weather now", &["get_weather"])?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = send(&s.gw, chat("run_shell rm", &["get_weather"])?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(code(&body), "tool_not_allowed");
    let answer = records(&s)?
        .into_iter()
        .rfind(|r| r["event"] == "answer_guardrails")
        .ok_or("no answer record")?;
    assert_eq!(answer["verdict"], "block");
    assert_eq!(answer["guardrails"][0]["kind"], "run_shell");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn strip_takes_the_tool_out_of_the_request_and_the_call_out_of_the_answer() -> TestResult {
    let s = setup(
        "strip",
        &policy(provider().await?, "    tool_action: strip\n"),
    )?;
    let (status, body) = send(
        &s.gw,
        chat("get_weather now", &["get_weather", "run_shell"])?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let arguments: Value = serde_json::from_str(
        body["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap_or("{}"),
    )?;
    assert_eq!(arguments["seen"], json!(["get_weather"]));
    let record = records(&s)?
        .into_iter()
        .rfind(|r| r.get("event").is_none())
        .ok_or("no record")?;
    assert_eq!(record["guardrails"][0]["action"], "strip");

    let (status, body) = send(&s.gw, messages("run_shell rm", &["get_weather"])?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["content"], json!([]));
    assert_eq!(body["stop_reason"], "end_turn");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn answer_guardrails_read_tool_call_arguments() -> TestResult {
    let s = setup("arguments", &policy(provider().await?, ""))?;
    for request in [
        chat(&format!("get_weather {AWS}"), &["get_weather"])?,
        messages(&format!("get_weather {AWS}"), &["get_weather"])?,
    ] {
        let (status, body) = send(&s.gw, request).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(code(&body), "guardrail_blocked");
        assert!(!body.to_string().contains(AWS));
    }
    // Masked inside an object input, which stays an object.
    let (status, body) = send(
        &s.gw,
        messages("get_weather maya@corp.example.com", &["get_weather"])?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["content"][0]["input"]["text"],
        "get_weather [MASKED email_address]"
    );
    Ok(())
}
