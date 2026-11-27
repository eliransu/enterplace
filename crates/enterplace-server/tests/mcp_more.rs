//! The MCP gateway's long tail: servers changed without a restart, the older HTTP+SSE transport and stdio servers,
//! priced tools, token exchange to upstream servers, the sessions list and the allowlist of client applications.
//!
//! Every upstream is a mock on loopback, or a shell script for stdio.

use std::{
    convert::Infallible,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, Request, StatusCode, header},
    response::Response,
    routing::{get, post},
};
use enterplace_core::id::sha256_hex;
use enterplace_server::{Governed, Reload, Trigger};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Error = Box<dyn std::error::Error>;

const MAYA: &str = "enterplace_maya_0123456789abcdef0123456789";
const ADMIN: &str = "enterplace_admin_0123456789abcdef0123456789";

/// What a mock server saw: how often it was initialized, and the `Authorization` of each tool call.
#[derive(Default)]
struct Seen {
    initialized: AtomicUsize,
    auth: Mutex<Vec<String>>,
}

/// The answer of a mock MCP server named `name` to one JSON-RPC message, `None` for a notification.
fn mcp_answer(name: &str, seen: &Seen, headers: &HeaderMap, message: &Value) -> Option<Value> {
    let id = message.get("id")?.clone();
    let result = match message["method"].as_str().unwrap_or_default() {
        "initialize" => {
            seen.initialized.fetch_add(1, Ordering::SeqCst);
            json!({"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": name, "version": "1"}})
        }
        "tools/list" => json!({"tools": [
            {"name": "echo", "description": "says it back", "inputSchema": {"type": "object"}},
            {"name": "search", "description": "looks it up", "inputSchema": {"type": "object"}},
        ]}),
        "tools/call" => {
            if let Ok(mut auth) = seen.auth.lock() {
                auth.push(
                    headers
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_string(),
                );
            }
            json!({"content": [{"type": "text", "text": format!("{name} ran {}", message["params"]["name"].as_str().unwrap_or_default())}], "isError": false})
        }
        _ => {
            return Some(
                json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "no such method"}}),
            );
        }
    };
    Some(json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

async fn listen(app: Router) -> Result<u16, Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

/// A Streamable HTTP mock at `/mcp`. With `wants`, it refuses any other `Authorization`.
async fn streamable(
    name: &'static str,
    wants: Option<&'static str>,
) -> Result<(u16, Arc<Seen>), Error> {
    let seen = Arc::new(Seen::default());
    let state = seen.clone();
    let app = Router::new().route(
        "/mcp",
        post(move |headers: HeaderMap, body: Bytes| {
            let seen = state.clone();
            async move {
                let given = headers.get("authorization").and_then(|v| v.to_str().ok());
                if wants.is_some() && given != wants {
                    return Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body(Body::empty())
                        .unwrap_or_default();
                }
                let message: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                match mcp_answer(name, &seen, &headers, &message) {
                    Some(answer) => Response::builder()
                        .header(header::CONTENT_TYPE, "application/json")
                        .header("mcp-session-id", "s-1")
                        .body(Body::from(answer.to_string()))
                        .unwrap_or_default(),
                    None => Response::builder()
                        .status(StatusCode::ACCEPTED)
                        .body(Body::empty())
                        .unwrap_or_default(),
                }
            }
        }),
    );
    Ok((listen(app).await?, seen))
}

/// An event stream that stays open: what a legacy server answers on.
struct Stream(tokio::sync::mpsc::UnboundedReceiver<Bytes>);

impl http_body::Body for Stream {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Infallible>>> {
        self.0
            .poll_recv(cx)
            .map(|event| event.map(|bytes| Ok(http_body::Frame::data(bytes))))
    }
}

#[cfg(unix)]
type Legacy = Arc<(
    Seen,
    Mutex<Option<tokio::sync::mpsc::UnboundedSender<Bytes>>>,
)>;

/// A mock of the older HTTP+SSE transport: `GET /sse` opens the stream and names `/messages`, where each message is
/// posted; its answer comes on the stream.
#[cfg(unix)]
async fn legacy_sse() -> Result<(u16, Legacy), Error> {
    let state: Legacy = Arc::default();
    let app = Router::new()
        .route(
            "/sse",
            get(|State(state): State<Legacy>| async move {
                let (tell, heard) = tokio::sync::mpsc::unbounded_channel();
                let _ = tell.send(Bytes::from(
                    "event: endpoint\ndata: /messages?session=7\n\n",
                ));
                if let Ok(mut slot) = state.1.lock() {
                    *slot = Some(tell);
                }
                Response::builder()
                    .header(header::CONTENT_TYPE, "text/event-stream")
                    .body(Body::new(Stream(heard)))
                    .unwrap_or_default()
            }),
        )
        .route(
            "/messages",
            post(
                |State(state): State<Legacy>, headers: HeaderMap, body: Bytes| async move {
                    let message: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                    if let Some(answer) = mcp_answer("old", &state.0, &headers, &message)
                        && let Ok(slot) = state.1.lock()
                        && let Some(tell) = slot.as_ref()
                    {
                        let _ =
                            tell.send(Bytes::from(format!("event: message\ndata: {answer}\n\n")));
                    }
                    StatusCode::ACCEPTED
                },
            ),
        )
        .with_state(state.clone());
    Ok((listen(app).await?, state))
}

fn entry(name: &str, team: &str, key: &str) -> String {
    format!(
        "  - name: {name}\n    team: {team}\n    sha256: {}\n",
        sha256_hex(key.as_bytes())
    )
}

fn dir_for(name: &str) -> Result<PathBuf, Error> {
    let dir =
        std::env::temp_dir().join(format!("enterplace-mcp-more-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        dir.join("enterplace.keys.yaml"),
        format!(
            "keys:\n{}{}    admin: true\n",
            entry("maya.cohen", "payments", MAYA),
            entry("ops.admin", "ops", ADMIN)
        ),
    )?;
    Ok(dir)
}

const HEAD: &str = "version: 1
providers:
  - name: mock
    kind: openai
    url: http://127.0.0.1:1
    allow_private: true
    key_env: MOCK_PROVIDER_KEY
    models: [model-a]
prices:
  model-a: { input: 1, output: 2 }
";

fn write_policy(dir: &Path, rest: &str) -> Result<(), Error> {
    Ok(std::fs::write(
        dir.join("enterplace.policy.yaml"),
        format!("{HEAD}{rest}"),
    )?)
}

fn governed(
    dir: &Path,
    extra: &'static [(&'static str, &'static str)],
) -> Result<Governed, String> {
    let env = move |variable: &str| match extra.iter().find(|(name, _)| *name == variable) {
        Some((_, value)) => Some((*value).to_string()),
        None if variable.starts_with("ENTERPLACE_") => None,
        None => Some("provider-secret".to_string()),
    };
    enterplace_server::governed(&dir.join("enterplace.policy.yaml"), None, &env)
}

/// One HTTP exchange with the gateway: the status and the body.
async fn http(
    app: &Router,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: String,
) -> Result<(StatusCode, HeaderMap, String), Error> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "enterplace.test")
        .header(header::ORIGIN, "http://enterplace.test");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = app.clone().oneshot(request.body(Body::from(body))?).await?;
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await?.to_bytes();
    Ok((
        parts.status,
        parts.headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    ))
}

/// One JSON-RPC message to `/mcp` with maya's key and these headers besides: the answer and the response headers.
async fn rpc(
    app: &Router,
    headers: &[(&str, &str)],
    message: Value,
) -> Result<(Value, HeaderMap), Error> {
    let auth = format!("Bearer {MAYA}");
    let mut all = vec![
        ("authorization", auth.as_str()),
        ("content-type", "application/json"),
        ("accept", "application/json"),
    ];
    all.extend_from_slice(headers);
    let (_, response_headers, body) = http(app, "POST", "/mcp", &all, message.to_string()).await?;
    Ok((
        serde_json::from_str(&body).unwrap_or(Value::Null),
        response_headers,
    ))
}

fn call(tool: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": tool, "arguments": {}}})
}

fn list() -> Value {
    json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
}

fn tools(answer: &Value) -> Vec<String> {
    let mut names: Vec<String> = answer["result"]["tools"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|t| t["name"].as_str().map(String::from))
        .collect();
    names.sort_unstable();
    names
}

fn code(answer: &Value) -> &str {
    answer["error"]["data"]["enterplace_code"]
        .as_str()
        .unwrap_or("-")
}

fn text(answer: &Value) -> &str {
    answer["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("-")
}

fn records(dir: &Path) -> Result<Vec<Value>, Error> {
    Ok(std::fs::read_to_string(dir.join("enterplace-audit.jsonl"))?
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect())
}

const RULE: &str = "rules:
  - name: payments-team
    principals: { team: payments }
    models: [model-a]
";

#[tokio::test(flavor = "multi_thread")]
async fn servers_are_added_changed_and_removed_without_a_restart_and_sessions_are_kept()
-> TestResult {
    let (first, first_seen) = streamable("first", None).await?;
    let (second, _) = streamable("second", None).await?;
    let (third, _) = streamable("third", None).await?;
    let dir = dir_for("reload")?;
    // No server at start: /mcp is served, and lists nothing.
    write_policy(&dir, &format!("{RULE}    tools: []\n"))?;
    let gw = governed(&dir, &[])?;
    let (answer, _) = rpc(&gw.router, &[], list()).await?;
    assert_eq!(tools(&answer), Vec::<String>::new(), "{answer}");

    // A reload adds one.
    let one = format!(
        "mcp:\n  - name: first\n    url: http://127.0.0.1:{first}/mcp\n    allow_private: true\n"
    );
    write_policy(&dir, &format!("{one}{RULE}    tools: ['*']\n"))?;
    assert!(matches!(
        gw.reloader.check(Trigger::FileChange),
        Reload::Loaded
    ));
    let (answer, _) = rpc(&gw.router, &[], list()).await?;
    assert_eq!(tools(&answer), ["first.echo", "first.search"], "{answer}");
    let (answer, _) = rpc(&gw.router, &[], call("first.echo")).await?;
    assert_eq!(text(&answer), "first ran echo", "{answer}");
    assert_eq!(first_seen.initialized.load(Ordering::SeqCst), 1);

    // A second one is added; the first keeps the session Enterplace opened at it. (The management API's
    // PUT /admin/mcp/<name> makes the same new policy version when the policy is kept in the store.)
    let two = format!(
        "{one}  - name: second\n    url: http://127.0.0.1:{second}/mcp\n    allow_private: true\n"
    );
    write_policy(&dir, &format!("{two}{RULE}    tools: ['*']\n"))?;
    assert!(matches!(
        gw.reloader.check(Trigger::FileChange),
        Reload::Loaded
    ));
    let (answer, _) = rpc(&gw.router, &[], call("second.echo")).await?;
    assert_eq!(text(&answer), "second ran echo", "{answer}");
    let (answer, _) = rpc(&gw.router, &[], call("first.echo")).await?;
    assert_eq!(text(&answer), "first ran echo", "{answer}");
    assert_eq!(
        first_seen.initialized.load(Ordering::SeqCst),
        1,
        "the first server's session was kept"
    );

    // A server whose address changes is reached at the new one, and a removed one serves nothing.
    let moved = format!(
        "mcp:\n  - name: first\n    url: http://127.0.0.1:{third}/mcp\n    allow_private: true\n"
    );
    write_policy(&dir, &format!("{moved}{RULE}    tools: ['*']\n"))?;
    assert!(matches!(
        gw.reloader.check(Trigger::FileChange),
        Reload::Loaded
    ));
    let (answer, _) = rpc(&gw.router, &[], call("first.echo")).await?;
    assert_eq!(text(&answer), "third ran echo", "{answer}");
    let (answer, _) = rpc(&gw.router, &[], call("second.echo")).await?;
    assert_eq!(code(&answer), "unknown_tool", "{answer}");
    let (answer, _) = rpc(&gw.router, &[], list()).await?;
    assert_eq!(tools(&answer), ["first.echo", "first.search"], "{answer}");
    Ok(())
}

// The stdio server is a /bin/sh script, so this test runs where there is one.
#[cfg(unix)]
const SCRIPT: &str = r#"while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  case "$line" in
    *'"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"sh","version":"1"}}}\n' "$id";;
    *'"tools/list"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"whoami","description":"says what it was given","inputSchema":{"type":"object"}}]}}\n' "$id";;
    *'"tools/call"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"token=%s secret=%s"}],"isError":false}}\n' "$id" "$TOOL_TOKEN" "${MOCK_PROVIDER_KEY:-unset}";;
  esac
done
"#;

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_legacy_sse_server_and_a_stdio_server_serve_tools_beside_streamable_http() -> TestResult {
    let (new, _) = streamable("new", None).await?;
    let (old, old_seen) = legacy_sse().await?;
    let dir = dir_for("transports")?;
    let script = dir.join("server.sh");
    std::fs::write(&script, SCRIPT)?;
    let policy = format!(
        "mcp:
  - name: new
    url: http://127.0.0.1:{new}/mcp
    allow_private: true
  - name: old
    url: http://127.0.0.1:{old}/sse
    transport: sse
    allow_private: true
    headers_env: {{ Authorization: OLD_TOKEN }}
  - name: local
    transport: stdio
    command: /bin/sh
    args: ['{}']
    env: {{ TOOL_TOKEN: LOCAL_TOKEN }}
{RULE}    tools: ['*']
",
        script.display()
    );
    write_policy(&dir, &policy)?;
    // The policy cannot choose what the gateway runs: without the allowlist in its environment it does not start.
    let Err(refused) = governed(
        &dir,
        &[("OLD_TOKEN", "Bearer old"), ("LOCAL_TOKEN", "t-local")],
    ) else {
        return Err("a stdio server started without ENTERPLACE_MCP_STDIO_ALLOW".into());
    };
    assert!(
        refused.contains("ENTERPLACE_MCP_STDIO_ALLOW") && refused.contains("/bin/sh"),
        "{refused}"
    );
    let Err(refused) = governed(
        &dir,
        &[
            ("OLD_TOKEN", "Bearer old"),
            ("LOCAL_TOKEN", "t-local"),
            ("ENTERPLACE_MCP_STDIO_ALLOW", "/usr/bin/true"),
        ],
    ) else {
        return Err("a stdio server started with a command the allowlist does not hold".into());
    };
    assert!(refused.contains("ENTERPLACE_MCP_STDIO_ALLOW"), "{refused}");
    let gw = governed(
        &dir,
        &[
            ("OLD_TOKEN", "Bearer old"),
            ("LOCAL_TOKEN", "t-local"),
            ("ENTERPLACE_MCP_STDIO_ALLOW", "/usr/bin/true, /bin/sh"),
        ],
    )?;
    let (answer, _) = rpc(&gw.router, &[], list()).await?;
    assert_eq!(
        tools(&answer),
        [
            "local.whoami",
            "new.echo",
            "new.search",
            "old.echo",
            "old.search"
        ],
        "{answer}"
    );
    let (answer, _) = rpc(&gw.router, &[], call("old.echo")).await?;
    assert_eq!(text(&answer), "old ran echo", "{answer}");
    // The legacy server got the shared credential on the POST, in one session for both requests.
    assert_eq!(
        old_seen
            .0
            .auth
            .lock()
            .map(|a| a.clone())
            .unwrap_or_default(),
        ["Bearer old"]
    );
    assert_eq!(old_seen.0.initialized.load(Ordering::SeqCst), 1);
    // The process got the variable the policy names and nothing else of the gateway's environment.
    let (answer, _) = rpc(&gw.router, &[], call("local.whoami")).await?;
    assert_eq!(text(&answer), "token=t-local secret=unset", "{answer}");
    let (answer, _) = rpc(&gw.router, &[], call("new.echo")).await?;
    assert_eq!(text(&answer), "new ran echo", "{answer}");
    // Each call is on record with its server, whatever the transport.
    let servers: Vec<String> = records(&dir)?
        .iter()
        .filter(|r| r["event"] == "mcp_result" && r["outcome"] == "ok")
        .filter_map(|r| r["server"].as_str().map(String::from))
        .collect();
    assert_eq!(servers, ["old", "local", "new"]);

    // A command that is not an absolute path, and stdio with a url, are named by enterplace check.
    write_policy(
        &dir,
        &format!("mcp:\n  - name: local\n    transport: stdio\n    command: sh\n{RULE}"),
    )?;
    let Err(refused) = governed(&dir, &[]) else {
        return Err("a relative command loaded".into());
    };
    assert!(refused.contains("absolute path"), "{refused}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_priced_tool_is_charged_to_budgets_and_refused_once_the_budget_is_spent() -> TestResult {
    let (port, _) = streamable("paid", None).await?;
    let dir = dir_for("prices")?;
    write_policy(
        &dir,
        &format!(
            "mcp:
  - name: paid
    url: http://127.0.0.1:{port}/mcp
    allow_private: true
    call_price_usd: 0.25
    tool_prices: {{ search: 1.0 }}
{RULE}    tools: ['*']
    budget: {{ usd: 1.2, per: day }}
"
        ),
    )?;
    let gw = governed(&dir, &[])?;
    let (answer, _) = rpc(&gw.router, &[], call("paid.echo")).await?;
    assert_eq!(text(&answer), "paid ran echo", "{answer}");
    let (answer, _) = rpc(&gw.router, &[], call("paid.search")).await?;
    assert_eq!(text(&answer), "paid ran search", "{answer}");
    // 1.25 of 1.20 is spent: the next priced call is refused before it reaches the server.
    let (answer, _) = rpc(&gw.router, &[], call("paid.echo")).await?;
    assert_eq!(code(&answer), "budget_exceeded", "{answer}");
    let all = records(&dir)?;
    let usage: Vec<(String, f64)> = all
        .iter()
        .filter(|r| r["event"] == "usage")
        .map(|r| {
            (
                r["model"].as_str().unwrap_or_default().to_string(),
                r["charged_usd"].as_f64().unwrap_or(0.0),
            )
        })
        .collect();
    assert_eq!(
        usage,
        [
            ("paid.echo".to_string(), 0.25),
            ("paid.search".to_string(), 1.0)
        ]
    );
    assert!(
        all.iter()
            .filter(|r| r["event"] == "usage")
            .all(|r| r["provider"] == "mcp" && r["person"] == "maya.cohen")
    );
    let charged: Vec<f64> = all
        .iter()
        .filter(|r| r["event"] == "mcp_result")
        .filter_map(|r| r["charged_usd"].as_f64())
        .collect();
    assert_eq!(charged, [0.25, 1.0]);
    // The spend is what the admin API's usage sums by model.
    let auth = format!("Bearer {ADMIN}");
    let (status, _, body) = http(
        &gw.router,
        "GET",
        "/admin/usage?group_by=model",
        &[("authorization", &auth)],
        String::new(),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let summed: Value = serde_json::from_str(&body)?;
    assert_eq!(summed["totals"]["spend_usd"], 1.25, "{body}");
    assert!(body.contains("paid.search"), "{body}");
    Ok(())
}

/// A mock identity provider's token endpoint: trades `user-jwt` for a token, and counts the trades.
async fn idp(forms: Arc<Mutex<Vec<String>>>) -> Result<u16, Error> {
    let app = Router::new().route(
        "/token",
        post(move |body: String| {
            let forms = forms.clone();
            async move {
                if let Ok(mut forms) = forms.lock() {
                    forms.push(body.clone());
                }
                let obo = body.contains("requested_token_use=on_behalf_of") && body.contains("assertion=user-jwt");
                let exchange = body.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange")
                    && body.contains("subject_token=user-jwt")
                    && body.contains("audience=api%3A%2F%2Ftickets");
                if !(obo || exchange) || !body.contains("client_secret=idp-secret") {
                    return (StatusCode::BAD_REQUEST, json!({"error": "invalid_grant", "error_description": "the subject token is not one of ours"}).to_string());
                }
                let token = if obo { "obo-token" } else { "exchanged-token" };
                (StatusCode::OK, json!({"access_token": token, "token_type": "Bearer", "expires_in": 600}).to_string())
            }
        }),
    );
    listen(app).await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_callers_token_is_exchanged_for_the_servers_and_each_call_runs_with_it() -> TestResult {
    let forms: Arc<Mutex<Vec<String>>> = Arc::default();
    let idp = idp(forms.clone()).await?;
    let (tickets, tickets_seen) = streamable("tickets", Some("Bearer exchanged-token")).await?;
    let (graph, _) = streamable("graph", Some("Bearer obo-token")).await?;
    let dir = dir_for("exchange")?;
    write_policy(
        &dir,
        &format!(
            "mcp:
  - name: tickets
    url: http://127.0.0.1:{tickets}/mcp
    allow_private: true
    user_auth: token_exchange
    token_url: http://127.0.0.1:{idp}/token
    oauth_client_id: enterplace
    oauth_client_secret_env: IDP_SECRET
    audience: api://tickets
    oauth_scopes: [tickets.read]
  - name: graph
    url: http://127.0.0.1:{graph}/mcp
    allow_private: true
    user_auth: on_behalf_of
    token_url: http://127.0.0.1:{idp}/token
    oauth_client_id: enterplace
    oauth_client_secret_env: IDP_SECRET
    oauth_scopes: [api://graph/.default]
{RULE}    tools: ['*']
"
        ),
    )?;
    let gw = governed(&dir, &[("IDP_SECRET", "idp-secret")])?;
    // Without the caller's own token there is nothing to trade.
    let (answer, _) = rpc(&gw.router, &[], call("tickets.echo")).await?;
    assert_eq!(code(&answer), "credential_needed", "{answer}");
    assert!(
        answer["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("x-enterplace-subject-token"),
        "{answer}"
    );
    // A token the identity provider does not know is not traded, and the refusal says so.
    let (answer, _) = rpc(
        &gw.router,
        &[("x-enterplace-subject-token", "stolen")],
        call("tickets.echo"),
    )
    .await?;
    assert_eq!(code(&answer), "credential_needed", "{answer}");
    assert!(
        answer["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("not one of ours"),
        "{answer}"
    );
    let subject = [("x-enterplace-subject-token", "user-jwt")];
    let (answer, _) = rpc(&gw.router, &subject, call("tickets.echo")).await?;
    assert_eq!(text(&answer), "tickets ran echo", "{answer}");
    let (answer, _) = rpc(&gw.router, &subject, call("tickets.search")).await?;
    assert_eq!(text(&answer), "tickets ran search", "{answer}");
    assert_eq!(
        tickets_seen
            .auth
            .lock()
            .map(|a| a.clone())
            .unwrap_or_default(),
        ["Bearer exchanged-token", "Bearer exchanged-token"]
    );
    let (answer, _) = rpc(&gw.router, &subject, call("graph.echo")).await?;
    assert_eq!(text(&answer), "graph ran echo", "{answer}");
    // One trade per server for the two tokens used: the traded token is kept until it expires.
    let forms = forms.lock().map(|f| f.clone()).unwrap_or_default();
    assert_eq!(
        forms
            .iter()
            .filter(|f| f.contains("subject_token=user-jwt"))
            .count(),
        1,
        "{forms:?}"
    );
    assert_eq!(
        forms
            .iter()
            .filter(|f| f.contains("assertion=user-jwt"))
            .count(),
        1,
        "{forms:?}"
    );
    assert!(
        forms.iter().any(|f| f.contains("scope=tickets.read")),
        "{forms:?}"
    );
    // The record says how the call was authorized upstream, and holds neither token.
    let log = std::fs::read_to_string(dir.join("enterplace-audit.jsonl"))?;
    assert!(
        !log.contains("user-jwt") && !log.contains("exchanged-token") && !log.contains("obo-token")
    );
    let auths: Vec<String> = records(&dir)?
        .iter()
        .filter(|r| r["verdict"] == "allow")
        .filter_map(|r| r["upstream_auth"].as_str().map(String::from))
        .collect();
    assert_eq!(auths, ["token_exchange", "token_exchange", "on_behalf_of"]);
    Ok(())
}

fn initialize(client: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": client, "version": "2.1"}}})
}

fn session_of(headers: &HeaderMap) -> String {
    headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn sessions_are_listed_and_ended_and_a_rule_names_the_clients_that_may_connect() -> TestResult
{
    let (port, seen) = streamable("docs", None).await?;
    let dir = dir_for("sessions")?;
    write_policy(
        &dir,
        &format!(
            "mcp:
  - name: docs
    url: http://127.0.0.1:{port}/mcp
    allow_private: true
{RULE}    tools: ['*']
    mcp_clients: [claude-code, cursor*]
"
        ),
    )?;
    let gw = governed(&dir, &[])?;
    let (_, headers) = rpc(&gw.router, &[], initialize("claude-code")).await?;
    let good = session_of(&headers);
    let (_, headers) = rpc(&gw.router, &[], initialize("Cursor-Nightly")).await?;
    let cursor = session_of(&headers);
    let (_, headers) = rpc(&gw.router, &[], initialize("shadow-agent")).await?;
    let other = session_of(&headers);
    assert!(good.len() >= 12 && cursor.len() >= 12 && other.len() >= 12);

    // A client the rule names lists and calls; one it does not is refused by name, before any server is asked.
    let (answer, _) = rpc(&gw.router, &[("mcp-session-id", &good)], call("docs.echo")).await?;
    assert_eq!(text(&answer), "docs ran echo", "{answer}");
    let (answer, _) = rpc(&gw.router, &[("mcp-session-id", &cursor)], list()).await?;
    assert_eq!(tools(&answer), ["docs.echo", "docs.search"], "{answer}");
    let (answer, _) = rpc(&gw.router, &[("mcp-session-id", &other)], call("docs.echo")).await?;
    assert_eq!(code(&answer), "mcp_client_not_allowed", "{answer}");
    assert!(
        answer["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("shadow-agent"),
        "{answer}"
    );
    let (answer, _) = rpc(&gw.router, &[("mcp-session-id", &other)], list()).await?;
    assert_eq!(code(&answer), "mcp_client_not_allowed", "{answer}");
    // No session and a user agent the rule does not name: refused too. A named user agent passes.
    let (answer, _) = rpc(&gw.router, &[("user-agent", "curl/8.1")], call("docs.echo")).await?;
    assert_eq!(code(&answer), "mcp_client_not_allowed", "{answer}");
    let (answer, _) = rpc(
        &gw.router,
        &[("user-agent", "claude-code/2.1 (cli)")],
        call("docs.echo"),
    )
    .await?;
    assert_eq!(text(&answer), "docs ran echo", "{answer}");
    assert_eq!(
        seen.auth.lock().map(|a| a.len()).unwrap_or(0),
        2,
        "refused calls reached no server"
    );
    let refused: Vec<Value> = records(&dir)?
        .into_iter()
        .filter(|r| r["code"] == "mcp_client_not_allowed")
        .collect();
    assert_eq!(refused.len(), 3);
    assert_eq!(refused[0]["mcp_client"], "shadow-agent", "{}", refused[0]);

    // The admin API lists the sessions with who and what opened them.
    let auth = format!("Bearer {ADMIN}");
    let (status, _, body) = http(
        &gw.router,
        "GET",
        "/admin/mcp/sessions",
        &[("authorization", &auth)],
        String::new(),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed: Value = serde_json::from_str(&body)?;
    let mut clients: Vec<&str> = listed["sessions"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s["client"].as_str())
        .collect();
    clients.sort_unstable();
    assert_eq!(
        clients,
        ["Cursor-Nightly", "claude-code", "shadow-agent"],
        "{body}"
    );
    let ours = listed["sessions"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|s| s["client"] == "claude-code")
        .ok_or("the session is not listed")?;
    assert_eq!(
        (ours["person"].as_str(), ours["team"].as_str()),
        (Some("maya.cohen"), Some("payments"))
    );
    assert_eq!(ours["client_version"], "2.1");
    // The list shows the start of the id only: the whole id stays the client's.
    let id = ours["id"].as_str().unwrap_or_default().to_string();
    assert!(good.starts_with(&id) && id.len() < good.len(), "{id}");
    // A key that is no admin's reads none of it.
    let maya = format!("Bearer {MAYA}");
    let (status, _, _) = http(
        &gw.router,
        "GET",
        "/admin/mcp/sessions",
        &[("authorization", &maya)],
        String::new(),
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Ending a session refuses the next request in it, and is on record.
    let (status, _, body) = http(
        &gw.router,
        "DELETE",
        &format!("/admin/mcp/sessions/{id}"),
        &[("authorization", &auth)],
        String::new(),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (answer, _) = rpc(&gw.router, &[("mcp-session-id", &good)], call("docs.echo")).await?;
    assert_eq!(code(&answer), "session_revoked", "{answer}");
    let (status, _, body) = http(
        &gw.router,
        "DELETE",
        &format!("/admin/mcp/sessions/{id}"),
        &[("authorization", &auth)],
        String::new(),
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(
        records(&dir)?
            .iter()
            .any(|r| r["action"] == "end_mcp_session")
    );

    // The console's page lists what is left, with a button to end each.
    let (_, headers, _) = http(
        &gw.router,
        "POST",
        "/console/sign-in",
        &[("content-type", "application/x-www-form-urlencoded")],
        format!("key={ADMIN}"),
    )
    .await?;
    let cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|c| c.split(';').next())
        .ok_or("no console cookie")?
        .to_string();
    let (status, _, body) = http(
        &gw.router,
        "GET",
        "/console/api/mcp-sessions",
        &[("cookie", &cookie)],
        String::new(),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let page: Value = serde_json::from_str(&body)?;
    let shown: Vec<&str> = page["sessions"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s["client"].as_str())
        .collect();
    assert!(
        page["editable"] == true
            && shown.iter().any(|c| c.starts_with("Cursor-Nightly"))
            && !shown.iter().any(|c| c.starts_with("claude-code")),
        "{body}"
    );
    // Ending one from the console refuses its next request too, and is on record.
    let cursor = page["sessions"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|s| {
            s["client"]
                .as_str()
                .is_some_and(|c| c.starts_with("Cursor-Nightly"))
        })
        .and_then(|s| s["id"].as_str())
        .ok_or("Cursor-Nightly is not listed")?
        .to_string();
    let ended = |dir| -> Result<usize, Error> {
        Ok(records(dir)?
            .iter()
            .filter(|r| r["action"] == "end_mcp_session")
            .count())
    };
    let before = ended(&dir)?;
    let (status, _, body) = http(
        &gw.router,
        "POST",
        "/console/api/mcp-sessions",
        &[("cookie", &cookie), ("content-type", "application/json")],
        json!({ "id": cursor }).to_string(),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _, body) = http(
        &gw.router,
        "POST",
        "/console/api/mcp-sessions",
        &[("cookie", &cookie), ("content-type", "application/json")],
        json!({ "id": cursor }).to_string(),
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    // Both tries are on record: a session is recorded as ended before it is.
    assert_eq!(ended(&dir)?, before + 2);
    Ok(())
}

const OMER: &str = "enterplace_omer_0123456789abcdef0123456789";

/// One JSON-RPC message to `/mcp` with `key`: the answer.
async fn rpc_as(app: &Router, key: &str, message: Value) -> Result<Value, Error> {
    let auth = format!("Bearer {key}");
    let headers = [
        ("authorization", auth.as_str()),
        ("content-type", "application/json"),
        ("accept", "application/json"),
    ];
    let (_, _, body) = http(app, "POST", "/mcp", &headers, message.to_string()).await?;
    Ok(serde_json::from_str(&body).unwrap_or(Value::Null))
}

/// The console's JSON API, signed in as the admin.
struct ConsoleApi<'a> {
    app: &'a Router,
    cookie: String,
}

impl ConsoleApi<'_> {
    async fn sign_in(app: &Router) -> Result<ConsoleApi<'_>, Error> {
        let (_, headers, _) = http(
            app,
            "POST",
            "/console/sign-in",
            &[("content-type", "application/x-www-form-urlencoded")],
            format!("key={ADMIN}"),
        )
        .await?;
        let cookie = headers
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .and_then(|c| c.split(';').next())
            .ok_or("no console cookie")?
            .to_string();
        Ok(ConsoleApi { app, cookie })
    }

    async fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<(StatusCode, Value), Error> {
        let (status, _, text) = http(
            self.app,
            method,
            path,
            &[
                ("cookie", self.cookie.as_str()),
                ("content-type", "application/json"),
            ],
            body.map(|b| b.to_string()).unwrap_or_default(),
        )
        .await?;
        Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null)))
    }
}

/// Three servers (`docs` with `search` switched off, `open`, and `gone`, which never answers), one rule that allows
/// every tool to everyone, and keys for maya (payments), omer (support) and an admin.
async fn catalog_setup(name: &str) -> Result<(PathBuf, String), Error> {
    let (docs, _) = streamable("docs", None).await?;
    let (open, _) = streamable("open", None).await?;
    let dir = dir_for(name)?;
    std::fs::write(
        dir.join("enterplace.keys.yaml"),
        format!(
            "keys:\n{}{}{}    admin: true\n",
            entry("maya.cohen", "payments", MAYA),
            entry("omer.katz", "support", OMER),
            entry("ops.admin", "ops", ADMIN)
        ),
    )?;
    let servers = format!(
        "mcp:
  - name: docs
    url: http://127.0.0.1:{docs}/mcp
    allow_private: true
    disabled_tools: [search]
  - name: open
    url: http://127.0.0.1:{open}/mcp
    allow_private: true
  - name: gone
    url: http://127.0.0.1:1/mcp
    allow_private: true
rules:
  - name: everyone
    principals: {{ any: true }}
    models: [model-a]
    tools: ['*']
"
    );
    write_policy(&dir, &servers)?;
    Ok((dir, servers))
}

fn reloaded(gw: &Governed) -> Result<(), Error> {
    match gw.reloader.check(Trigger::FileChange) {
        Reload::Loaded => Ok(()),
        _ => Err("the policy the console saved did not load".into()),
    }
}

fn actions(dir: &Path) -> Result<Vec<String>, Error> {
    Ok(records(dir)?
        .iter()
        .filter_map(|r| r["action"].as_str().map(String::from))
        .collect())
}

#[tokio::test(flavor = "multi_thread")]
async fn the_console_lists_a_servers_tools_and_a_tool_switched_off_is_refused_to_everyone()
-> TestResult {
    let (dir, servers) = catalog_setup("catalog").await?;
    let bad = servers.replacen("disabled_tools: [search]", "disabled_tools: ['docs.*']", 1);
    write_policy(&dir, &bad)?;
    let Err(err) = governed(&dir, &[]) else {
        return Err("loaded with a pattern in disabled_tools".into());
    };
    assert!(err.contains("disabled_tools"), "{err}");
    write_policy(&dir, &servers)?;
    let gw = governed(&dir, &[])?;

    // A switched off tool is listed to no one and refused to everyone; the rest of the server is as before.
    let answer = rpc_as(&gw.router, MAYA, list()).await?;
    assert_eq!(
        tools(&answer),
        ["docs.echo", "open.echo", "open.search"],
        "{answer}"
    );
    let answer = rpc_as(&gw.router, MAYA, call("docs.search")).await?;
    assert_eq!(code(&answer), "tool_disabled", "{answer}");
    let answer = rpc_as(&gw.router, OMER, call("docs.echo")).await?;
    assert_eq!(text(&answer), "docs ran echo", "{answer}");

    // Test lists the server's tools now, with their descriptions and which are switched off.
    let console = ConsoleApi::sign_in(&gw.router).await?;
    let (status, tested) = console
        .call(
            "POST",
            "/console/api/mcp-catalog",
            Some(json!({"server": "docs"})),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{tested}");
    assert_eq!(
        tested["tools"],
        json!([
            {"name": "echo", "description": "says it back", "enabled": true},
            {"name": "search", "description": "looks it up", "enabled": false},
        ]),
        "{tested}"
    );
    let (status, catalog) = console
        .call("GET", "/console/api/mcp-catalog", None)
        .await?;
    assert_eq!(status, StatusCode::OK, "{catalog}");
    assert_eq!(catalog["servers"][0]["name"], "docs", "{catalog}");
    assert_eq!(catalog["servers"][0]["tools"], tested["tools"], "{catalog}");

    // Switched back on from the console: recorded, saved through the policy, and served after the reload.
    let (status, answer) = console
        .call(
            "PUT",
            "/console/api/mcp/docs/catalog",
            Some(json!({"disabled": []})),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{answer}");
    reloaded(&gw)?;
    let answer = rpc_as(&gw.router, MAYA, call("docs.search")).await?;
    assert_eq!(text(&answer), "docs ran search", "{answer}");
    let (status, answer) = console
        .call(
            "PUT",
            "/console/api/mcp/docs/catalog",
            Some(json!({"disabled": ["echo"]})),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{answer}");
    reloaded(&gw)?;
    let answer = rpc_as(&gw.router, MAYA, call("docs.echo")).await?;
    assert_eq!(code(&answer), "tool_disabled", "{answer}");
    assert!(actions(&dir)?.iter().any(|a| a == "change_mcp_catalog"));
    Ok(())
}
