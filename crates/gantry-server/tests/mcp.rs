//! Package 6.2, the MCP gateway: tools from two servers, limited by policy, each call audited.
//!
//! Two mock MCP servers on loopback: `github` answers with JSON, pages its tool list and wants a credential from the
//! environment; `docs` answers every request as a server-sent event stream with a progress notification first.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    body::{Body, Bytes},
    http::{HeaderMap, Request, StatusCode, header},
    response::Response,
    routing::post,
};
use gantry_core::id::sha256_hex;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Error = Box<dyn std::error::Error>;
type Calls = Arc<Mutex<Vec<String>>>;

const MAYA: &str = "gantry_maya_0123456789abcdef0123456789";
const OMER: &str = "gantry_omer_0123456789abcdef0123456789";

fn reply(sse: bool, status: StatusCode, session: Option<&str>, message: &Value) -> Response {
    let mut response = Response::builder().status(status);
    if let Some(session) = session {
        response = response.header("mcp-session-id", session);
    }
    let response = if sse {
        let progress = json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progressToken": 1, "progress": 1}});
        response
            .header(header::CONTENT_TYPE, "text/event-stream")
            .body(Body::from(format!(
                "event: message\ndata: {progress}\n\nevent: message\ndata: {message}\n\n"
            )))
    } else {
        response
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(message.to_string()))
    };
    response.unwrap_or_default()
}

/// A mock MCP server. Every tool it runs is added to `calls` as `<server>:<tool>`.
async fn server(
    name: &'static str,
    sse: bool,
    credential: Option<&'static str>,
    calls: Calls,
) -> Result<u16, Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let session = format!("session-{name}");
    let app = Router::new().route(
        "/mcp",
        post(move |headers: HeaderMap, body: Bytes| {
            let (calls, session) = (calls.clone(), session.clone());
            async move {
                let given = |h: &str| headers.get(h).and_then(|v| v.to_str().ok()).map(str::to_string);
                if credential.is_some() && given("authorization").as_deref() != credential {
                    return reply(false, StatusCode::UNAUTHORIZED, None, &json!({}));
                }
                let Ok(message) = serde_json::from_slice::<Value>(&body) else {
                    return reply(false, StatusCode::BAD_REQUEST, None, &json!({}));
                };
                let id = message["id"].clone();
                let method = message["method"].as_str().unwrap_or_default();
                if method == "initialize" {
                    let result = json!({"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": name, "version": "1"}});
                    return reply(sse, StatusCode::OK, Some(&session), &json!({"jsonrpc": "2.0", "id": id, "result": result}));
                }
                if given("mcp-session-id").as_deref() != Some(session.as_str()) {
                    return reply(false, StatusCode::BAD_REQUEST, None, &json!({}));
                }
                if id.is_null() {
                    return reply(false, StatusCode::ACCEPTED, None, &Value::Null)
                        .map(|_| Body::empty());
                }
                let tool = |n: &str| json!({"name": n, "description": format!("{name} {n}"), "inputSchema": {"type": "object"}});
                let result = match (name, method, message["params"]["cursor"].as_str()) {
                    ("github", "tools/list", None) => json!({"tools": [tool("create_issue"), tool("delete_repo")], "nextCursor": "page-2"}),
                    ("github", "tools/list", Some(_)) => json!({"tools": [tool("list_issues")]}),
                    (_, "tools/list", _) => json!({"tools": [tool("search"), tool("read")]}),
                    (_, "tools/call", _) => {
                        let called = message["params"]["name"].as_str().unwrap_or_default().to_string();
                        if let Ok(mut calls) = calls.lock() {
                            calls.push(format!("{name}:{called}"));
                        }
                        json!({"content": [{"type": "text", "text": format!("{name} ran {called}")}], "isError": false})
                    }
                    _ => return reply(sse, StatusCode::OK, None, &json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "no such method"}})),
                };
                reply(sse, StatusCode::OK, None, &json!({"jsonrpc": "2.0", "id": id, "result": result}))
            }
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

fn entry(name: &str, team: &str, key: &str) -> String {
    format!(
        "  - name: {name}\n    team: {team}\n    sha256: {}\n",
        sha256_hex(key.as_bytes())
    )
}

/// A policy with the two servers, maya's team allowed some tools from each, and no rule for omer's team.
async fn setup(name: &str, calls: &Calls) -> Result<PathBuf, Error> {
    let github = server("github", false, Some("Bearer gh-secret"), calls.clone()).await?;
    let docs = server("docs", true, None, calls.clone()).await?;
    let dir = std::env::temp_dir().join(format!("gantry-mcp-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        dir.join("gantry.policy.yaml"),
        format!(
            "version: 1
providers:
  - name: mock
    kind: openai
    url: http://127.0.0.1:1
    allow_private: true
    key_env: MOCK_PROVIDER_KEY
    models: [model-a]
mcp:
  - name: github
    url: http://127.0.0.1:{github}/mcp
    allow_private: true
    headers_env: {{ Authorization: GITHUB_MCP_TOKEN }}
  - name: docs
    url: http://127.0.0.1:{docs}/mcp
    allow_private: true
rules:
  - name: payments-team
    principals: {{ team: payments }}
    models: [model-a]
    tools: [github.create_issue, github.list_issues, docs.*]
"
        ),
    )?;
    std::fs::write(
        dir.join("gantry.keys.yaml"),
        format!(
            "keys:\n{}{}",
            entry("maya.cohen", "payments", MAYA),
            entry("omer.katz", "support", OMER)
        ),
    )?;
    Ok(dir)
}

fn gateway(dir: &std::path::Path) -> Result<Router, Error> {
    let env = |variable: &str| match variable {
        "GITHUB_MCP_TOKEN" => Some("Bearer gh-secret".to_string()),
        _ => Some("provider-secret".to_string()),
    };
    Ok(gantry_server::governed(&dir.join("gantry.policy.yaml"), None, &env)?.router)
}

async fn rpc(app: &Router, key: &str, message: Value) -> Result<(StatusCode, Value), Error> {
    let request = Request::post("/mcp")
        .header(header::AUTHORIZATION, format!("Bearer {key}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .body(Body::from(message.to_string()))?;
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, serde_json::from_slice(&body).unwrap_or(Value::Null)))
}

fn call(id: i64, tool: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": {"title": "secret-title-text"}}})
}

fn ran(calls: &Calls) -> Vec<String> {
    calls.lock().map(|c| c.clone()).unwrap_or_default()
}

fn records(dir: &std::path::Path) -> Result<Vec<Value>, Error> {
    Ok(std::fs::read_to_string(dir.join("gantry-audit.jsonl"))?
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect())
}

#[tokio::test(flavor = "multi_thread")]
async fn tools_from_two_servers_limited_by_policy_each_call_audited() -> TestResult {
    let calls = Calls::default();
    let dir = setup("accept", &calls).await?;
    let app = gateway(&dir)?;

    let (status, init) = rpc(&app, MAYA, json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}})).await?;
    assert_eq!(status, StatusCode::OK, "{init}");
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    assert!(
        init["result"]["capabilities"]["tools"].is_object(),
        "{init}"
    );
    assert_eq!(init["result"]["serverInfo"]["name"], "gantry");
    let (status, _) = rpc(
        &app,
        MAYA,
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await?;
    assert_eq!(status, StatusCode::ACCEPTED);

    // Exactly the allowed tools of both servers, the second page of github's list included.
    let (_, list) = rpc(
        &app,
        MAYA,
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
    )
    .await?;
    let mut names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .ok_or_else(|| format!("no tools: {list}"))?
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "docs.read",
            "docs.search",
            "github.create_issue",
            "github.list_issues"
        ]
    );

    // An allowed call reaches the right server, and the caller's id comes back.
    let (_, created) = rpc(&app, MAYA, call(7, "github.create_issue")).await?;
    assert_eq!(created["id"], 7, "{created}");
    assert_eq!(
        created["result"]["content"][0]["text"],
        "github ran create_issue"
    );
    assert_eq!(ran(&calls), ["github:create_issue"]);
    // The docs server answers as an event stream: its answer is the one for this call.
    let (_, found) = rpc(&app, MAYA, call(8, "docs.search")).await?;
    assert_eq!(found["id"], 8, "{found}");
    assert_eq!(found["result"]["content"][0]["text"], "docs ran search");
    assert_eq!(ran(&calls), ["github:create_issue", "docs:search"]);

    // A tool the rule does not allow is refused and never reaches the server.
    let (status, refused) = rpc(&app, MAYA, call(9, "github.delete_repo")).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(refused["id"], 9);
    let message = refused["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("tool_not_allowed")
            && message.contains("payments-team")
            && message.contains("Ask a Gantry admin"),
        "{refused}"
    );
    assert_eq!(refused["error"]["data"]["gantry_code"], "tool_not_allowed");
    // A key no rule names gets no tools at all.
    let (_, none) = rpc(&app, OMER, call(10, "docs.search")).await?;
    assert_eq!(none["error"]["data"]["gantry_code"], "no_rule", "{none}");
    let (_, none) = rpc(
        &app,
        OMER,
        json!({"jsonrpc": "2.0", "id": 11, "method": "tools/list"}),
    )
    .await?;
    assert_eq!(none["error"]["data"]["gantry_code"], "no_rule", "{none}");
    assert_eq!(ran(&calls), ["github:create_issue", "docs:search"]);

    // Every call is on record, allowed and refused, without its arguments or its result.
    let log = records(&dir)?;
    let decided: Vec<(&str, &str, &str, &str)> = log
        .iter()
        .filter(|r| r["path"] == "/mcp" && r["mcp_method"] == "tools/call")
        .map(|r| {
            let text = |f: &str| r[f].as_str().unwrap_or("-");
            (text("person"), text("tool"), text("verdict"), text("code"))
        })
        .collect();
    assert_eq!(
        decided,
        [
            ("maya.cohen", "create_issue", "allow", "-"),
            ("maya.cohen", "search", "allow", "-"),
            ("maya.cohen", "delete_repo", "refused", "tool_not_allowed"),
            ("omer.katz", "search", "refused", "no_rule"),
        ]
    );
    let allowed = log
        .iter()
        .find(|r| r["tool"] == "create_issue" && r["verdict"] == "allow")
        .ok_or("no record of the allowed call")?;
    assert_eq!(allowed["server"], "github");
    assert_eq!(allowed["team"], "payments");
    assert_eq!(allowed["rule"], "payments-team");
    assert_eq!(allowed["key"], &sha256_hex(MAYA.as_bytes())[..8]);
    let results: Vec<&Value> = log.iter().filter(|r| r["event"] == "mcp_result").collect();
    assert_eq!(results.len(), 2);
    for result in results {
        assert!(result["duration_ms"].is_u64(), "{result}");
        assert_eq!(result["outcome"], "ok", "{result}");
        assert!(
            log.iter()
                .any(|r| r["id"] == result["id"] && r["verdict"] == "allow")
        );
    }
    let text = std::fs::read_to_string(dir.join("gantry-audit.jsonl"))?;
    assert!(
        !text.contains("secret-title-text") && !text.contains(" ran "),
        "{text}"
    );
    gantry_core::audit::verify(&dir.join("gantry-audit.jsonl"))?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_killed_person_and_an_unknown_key_call_no_tool() -> TestResult {
    let calls = Calls::default();
    let dir = setup("killed", &calls).await?;
    std::fs::write(
        dir.join("gantry.kills.json"),
        r#"{"kills":[{"scope":"person","value":"maya.cohen","reason":"leaked laptop","by":"ops.admin","at":"2026-11-13T09:00:00.000Z"}]}"#,
    )?;
    let app = gateway(&dir)?;
    let (_, killed) = rpc(&app, MAYA, call(1, "github.create_issue")).await?;
    assert_eq!(killed["error"]["data"]["gantry_code"], "killed", "{killed}");
    assert!(
        killed["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("leaked laptop")),
        "{killed}"
    );
    let (status, stranger) = rpc(
        &app,
        "gantry_nobody_0123456789abcdef",
        call(2, "docs.search"),
    )
    .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        stranger["error"]["data"]["gantry_code"], "unknown_key",
        "{stranger}"
    );
    assert!(ran(&calls).is_empty());
    let log = records(&dir)?;
    assert!(
        log.iter()
            .any(|r| r["code"] == "killed" && r["tool"] == "create_issue")
    );
    assert!(
        log.iter()
            .any(|r| r["code"] == "unknown_key" && r["path"] == "/mcp")
    );
    gantry_core::audit::verify(&dir.join("gantry-audit.jsonl"))?;
    Ok(())
}
