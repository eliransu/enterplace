//! The MCP gateway: `/mcp`, MCP's Streamable HTTP transport, in front of the upstream MCP servers a policy names.
//!
//! A caller sends its Gantry key as on the model routes. Gantry answers `initialize` itself, gathers `tools/list`
//! from every server and shows only the tools the caller's rule allows, named `<server>.<tool>`, and checks every
//! `tools/call` against the rule before it forwards it. Each call is recorded before it is forwarded, and its outcome
//! after; arguments and results never are.
//!
//! Gantry is one MCP client to each upstream server: it opens one session per server and shares it among callers.
//! Gantry asks callers nothing, so requests an upstream server sends inside an event stream are not relayed.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderName, HeaderValue, Method, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
    routing::any,
};
use gantry_core::{
    audit::Entry,
    id,
    mcp::tool_allowed,
    policy::{Principal, Rule},
};
use http_body_util::BodyExt;
use serde_json::{Map, Value, json};

use crate::{
    AppState, ClientAddr, ConfigError, DECISION, MAX_BODY_BYTES, Refusal, Secret, Snapshot,
    caller_key, checked_upstream, killed, read_body,
};

/// The MCP protocol versions Gantry speaks to callers, newest first. Gantry relays tools only, which every one of
/// these carries the same way.
const VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26"];
/// The version Gantry asks each upstream server for.
const UPSTREAM_VERSION: &str = "2025-06-18";
/// Pages of one server's tool list Gantry reads, so a server that always answers with a next cursor cannot hold a
/// `tools/list` forever.
const MAX_PAGES: usize = 100;
/// JSON-RPC error code of a Gantry refusal, in the range JSON-RPC leaves to servers.
const REFUSED: i64 = -32001;

/// An upstream MCP server as `governed` hands it over: its endpoint and its credentials, read from the environment.
#[derive(Clone, Debug)]
pub struct McpRoute {
    pub name: String,
    /// The server's MCP endpoint, for example `https://mcp.example.com/mcp`.
    pub url: String,
    /// Headers sent with every request to it, such as `Authorization`.
    pub headers: Vec<(String, Secret)>,
}

struct Upstream {
    name: String,
    url: String,
    headers: Vec<(HeaderName, HeaderValue)>,
    session: Mutex<Option<Session>>,
}

#[derive(Clone)]
struct Session {
    id: Option<String>,
    version: String,
}

#[derive(Clone)]
struct McpState {
    app: AppState,
    servers: Arc<Vec<Upstream>>,
    // Each request to an upstream server gets its own id: callers share a session, so their ids could collide.
    next: Arc<AtomicU64>,
}

/// The `/mcp` route, when the policy names MCP servers.
pub(crate) fn router(app: &AppState, routes: Vec<McpRoute>) -> Result<Option<Router>, ConfigError> {
    if routes.is_empty() {
        return Ok(None);
    }
    let mut servers = Vec::new();
    for route in routes {
        let mut headers = Vec::new();
        for (name, secret) in &route.headers {
            let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                ConfigError(format!(
                    "MCP server \"{}\": \"{name}\" cannot be an HTTP header name. Name a header such as Authorization.",
                    route.name
                ))
            })?;
            let mut value = HeaderValue::from_str(&secret.0).map_err(|_| {
                ConfigError(format!(
                    "MCP server \"{}\": the value of header {name} holds a character that cannot go in an HTTP header. Check its variable for a stray newline or quote.",
                    route.name
                ))
            })?;
            value.set_sensitive(true);
            headers.push((name, value));
        }
        servers.push(Upstream {
            url: checked_upstream(&route.url)?,
            name: route.name,
            headers,
            session: Mutex::new(None),
        });
    }
    let state = McpState {
        app: app.clone(),
        servers: Arc::new(servers),
        next: Arc::default(),
    };
    Ok(Some(
        Router::new().route("/mcp", any(serve)).with_state(state),
    ))
}

async fn serve(State(mcp): State<McpState>, request: Request) -> Response {
    let decision = id::decision_id();
    let mut response = if request.method() == Method::POST {
        let version = mcp.app.version();
        post(&mcp, &version, request, &decision).await
    } else {
        // No stream of Gantry's own to listen to, and no session to end: MCP clients take 405 for both.
        let mut response = (
            StatusCode::METHOD_NOT_ALLOWED,
            "Gantry's MCP endpoint takes POST only: it opens no stream of its own and keeps no session to end.",
        )
            .into_response();
        response
            .headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("POST"));
        response
    };
    if let Ok(value) = HeaderValue::from_str(&decision) {
        response.headers_mut().insert(DECISION, value);
    }
    response
}

/// What was learned about one message while it was checked. It becomes the audit record.
#[derive(Default)]
struct Asked<'a> {
    client: Option<String>,
    person: Option<&'a Principal>,
    key: Option<String>,
    rule: Option<&'a Rule>,
    /// Set once the body is read as a JSON-RPC message. Before that a refusal is an HTTP error.
    method: Option<String>,
    id: Option<Value>,
    server: Option<String>,
    tool: Option<String>,
}

async fn post(mcp: &McpState, version: &Snapshot, request: Request, decision: &str) -> Response {
    let (parts, body) = request.into_parts();
    let mut asked = Asked {
        client: parts
            .extensions
            .get::<ClientAddr>()
            .map(|addr| addr.0.ip().to_string()),
        ..Asked::default()
    };
    match answer(mcp, version, parts, body, decision, &mut asked).await {
        Ok(response) => response,
        Err(refusal) => match record(mcp, version, decision, &asked, Some(&refusal)).await {
            Ok(()) => refused(&refusal, &asked, decision),
            Err(unavailable) => refused(&unavailable, &asked, decision),
        },
    }
}

fn json_response(status: StatusCode, body: &Value) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

fn result(id: &Value, result: Value) -> Response {
    json_response(
        StatusCode::OK,
        &json!({"jsonrpc": "2.0", "id": id, "result": result}),
    )
}

/// A refusal as a JSON-RPC error. Before the message was read it goes with the refusal's HTTP status (a missing or
/// unknown key); after, with 200, so the client shows its message as the answer to that call.
fn refused(refusal: &Refusal, asked: &Asked<'_>, decision: &str) -> Response {
    let message = match refusal.message.strip_prefix("Refused: ") {
        Some(rest) => format!("Refused ({}): {rest} Decision {decision}.", refusal.code),
        None => format!("{} Decision {decision}.", refusal.message),
    };
    let code = if refusal.code == "unreadable_request" {
        -32600
    } else {
        REFUSED
    };
    let status = if asked.method.is_some() {
        StatusCode::OK
    } else {
        refusal.status
    };
    json_response(
        status,
        &json!({
            "jsonrpc": "2.0",
            "id": asked.id.clone().unwrap_or(Value::Null),
            "error": {"code": code, "message": message, "data": {"gantry_code": refusal.code, "decision": decision}},
        }),
    )
}

fn unreadable(why: &str) -> Refusal {
    Refusal::new(
        StatusCode::BAD_REQUEST,
        "unreadable_request",
        format!("Refused: {why}"),
    )
}

/// Checks one message and answers it. Every error is a refusal, recorded by the caller.
async fn answer<'a>(
    mcp: &McpState,
    version: &'a Snapshot,
    parts: Parts,
    body: Body,
    decision: &str,
    asked: &mut Asked<'a>,
) -> Result<Response, Refusal> {
    let Some(policy) = &version.policy else {
        return Err(Refusal::new(
            StatusCode::NOT_FOUND,
            "unknown_route",
            "Refused: this Gantry runs without a policy, so it serves no MCP tools. Start it with a policy file that lists servers under mcp.",
        ));
    };
    let key = caller_key(&parts.headers)?;
    let Some(person) = policy.identify(key) else {
        asked.key = Some(id::sha256_hex(key.as_bytes())[..8].to_string());
        return Err(Refusal::new(
            StatusCode::UNAUTHORIZED,
            "unknown_key",
            "Refused: Gantry does not know this key. It was never issued or it has been removed. Put your Gantry key in the MCP client's headers, as `Authorization: Bearer <key>`, or ask a Gantry admin for one.",
        ));
    };
    asked.person = Some(person);
    asked.key = Some(person.key.clone());
    if person.expired(&gantry_core::audit::timestamp()) {
        return Err(Refusal::new(
            StatusCode::UNAUTHORIZED,
            "key_expired",
            format!(
                "Refused: the key {} of \"{}\" expired at {} (UTC). Ask a Gantry admin for a new key, or run gantry login again, and put it in the MCP client's headers.",
                person.key,
                person.name,
                person.expires.as_deref().unwrap_or_default()
            ),
        ));
    }
    let (bytes, _held) = read_body(Some(&person.name), &mcp.app, &parts.headers, body).await?;
    let Ok(Value::Object(message)) = serde_json::from_slice::<Value>(&bytes) else {
        return Err(unreadable(
            "the body must be one JSON-RPC 2.0 message, a JSON object. Batches are not accepted: send one message per POST.",
        ));
    };
    let Some(method) = message.get("method").and_then(Value::as_str) else {
        // A response to a request: Gantry sends callers none, so there is nothing to match it with.
        return Ok(StatusCode::ACCEPTED.into_response());
    };
    asked.method = Some(method.to_string());
    let Some(call_id) = message.get("id").cloned() else {
        // A notification, such as notifications/initialized: nothing to answer.
        return Ok(StatusCode::ACCEPTED.into_response());
    };
    asked.id = Some(call_id.clone());
    let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
    let name = if method == "tools/call" {
        let name = params.get("name").and_then(Value::as_str).ok_or_else(|| {
            unreadable("tools/call needs params.name, the tool to call, as tools/list names it.")
        })?;
        match name.split_once('.') {
            Some((server, tool)) => {
                asked.server = Some(server.to_string());
                asked.tool = Some(tool.to_string());
            }
            None => asked.tool = Some(name.to_string()),
        }
        Some(name)
    } else {
        None
    };
    // A switch on a person, team or key stops their tools as it stops their models. A switch on a model named like a
    // tool (`gantry kill --model github.delete_repo`) stops that one tool for everyone.
    let key_sha256 = id::sha256_hex(key.as_bytes());
    killed(&mcp.app, person, &key_sha256, name)?;
    let rule = match method {
        "tools/list" | "tools/call" => {
            let rule = policy.rule_for(person).ok_or_else(|| {
                Refusal::new(
                    StatusCode::FORBIDDEN,
                    "no_rule",
                    format!(
                        "Refused: no rule in the policy names \"{}\" or team \"{}\", so no MCP tool is allowed. Ask a Gantry admin to add a rule with the tools you need.",
                        person.name, person.team
                    ),
                )
            })?;
            asked.rule = Some(rule);
            rule
        }
        "initialize" => {
            let asked_for = params.get("protocolVersion").and_then(Value::as_str);
            let protocol = VERSIONS
                .iter()
                .find(|v| Some(**v) == asked_for)
                .unwrap_or(&VERSIONS[0]);
            return Ok(result(
                &call_id,
                json!({
                    "protocolVersion": protocol,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": "gantry", "version": gantry_core::VERSION},
                    "instructions": "Tools of the MCP servers behind this Gantry, named <server>.<tool>. Only the tools your policy rule allows are listed.",
                }),
            ));
        }
        "ping" => return Ok(result(&call_id, json!({}))),
        _ => {
            return Ok(json_response(
                StatusCode::OK,
                &json!({"jsonrpc": "2.0", "id": call_id, "error": {"code": -32601, "message": format!("Gantry's MCP endpoint serves initialize, ping, tools/list and tools/call; \"{method}\" is not one of them.")}}),
            ));
        }
    };
    let Some(name) = name else {
        return Ok(result(&call_id, json!({"tools": mcp.tools(rule).await})));
    };
    if !tool_allowed(&rule.tools, name) {
        let allowed = if rule.tools.is_empty() {
            "It allows no MCP tools.".to_string()
        } else {
            format!("It allows: {}.", rule.tools.join(", "))
        };
        return Err(Refusal::new(
            StatusCode::FORBIDDEN,
            "tool_not_allowed",
            format!(
                "Refused: rule \"{}\" does not allow tool \"{name}\" for \"{}\" of team \"{}\". {allowed} Ask a Gantry admin to add it to the rule's tools if you need it.",
                rule.name, person.name, person.team
            ),
        ));
    }
    let server = asked
        .server
        .as_deref()
        .and_then(|s| mcp.servers.iter().find(|u| u.name == s))
        .ok_or_else(|| {
            let names: Vec<&str> = mcp.servers.iter().map(|s| s.name.as_str()).collect();
            Refusal::new(
                StatusCode::NOT_FOUND,
                "unknown_tool",
                format!(
                    "Refused: \"{name}\" is on no MCP server of this Gantry. Tools are named <server>.<tool>, and the servers are: {}. Run tools/list for the names.",
                    names.join(", ")
                ),
            )
        })?;
    // The call is on record before it is forwarded. A call that cannot be recorded does not happen.
    if let Err(unavailable) = record(mcp, version, decision, asked, None).await {
        return Ok(refused(&unavailable, asked, decision));
    }
    let mut forwarded = params;
    if let Some(params) = forwarded.as_object_mut() {
        params.insert("name".into(), asked.tool.clone().unwrap_or_default().into());
    }
    let started = Instant::now();
    let upstream = mcp.ask(server, "tools/call", forwarded).await;
    let mut outcome = Map::new();
    outcome.insert(
        "duration_ms".into(),
        u64::try_from(started.elapsed().as_millis())
            .unwrap_or(u64::MAX)
            .into(),
    );
    let response = match upstream {
        Ok(mut answer) => {
            if let Some(error) = answer.get("error") {
                outcome.insert("outcome".into(), "rpc_error".into());
                outcome.insert("upstream_code".into(), error["code"].clone());
            } else {
                let failed = answer["result"]["isError"].as_bool() == Some(true);
                outcome.insert(
                    "outcome".into(),
                    if failed { "tool_error" } else { "ok" }.into(),
                );
            }
            if let Some(answer) = answer.as_object_mut() {
                answer.insert("id".into(), call_id.clone());
            }
            json_response(StatusCode::OK, &answer)
        }
        Err(failure) => {
            outcome.insert("outcome".into(), failure.outcome.into());
            json_response(
                StatusCode::OK,
                &json!({
                    "jsonrpc": "2.0",
                    "id": call_id,
                    "error": {
                        "code": -32603,
                        "message": format!("Gantry got no answer from MCP server \"{}\": {}. The tool may or may not have run there. Try again, and tell your Gantry admin if it keeps failing. Decision {decision}.", server.name, failure.detail),
                        "data": {"gantry_code": format!("upstream_{}", failure.outcome), "decision": decision},
                    },
                }),
            )
        }
    };
    record_outcome(mcp, decision, asked, outcome).await;
    Ok(response)
}

/// The decision record of one message, as model requests have, with the MCP method, server and tool.
async fn record(
    mcp: &McpState,
    version: &Snapshot,
    decision: &str,
    asked: &Asked<'_>,
    refusal: Option<&Refusal>,
) -> Result<(), Refusal> {
    let Some(audit) = &mcp.app.audit else {
        return Ok(());
    };
    let entry = Entry {
        id: decision,
        person: asked.person.map(|p| p.name.as_str()),
        team: asked.person.map(|p| p.team.as_str()),
        client: asked.client.as_deref(),
        key: asked.key.as_deref(),
        method: "POST",
        path: "/mcp",
        allowed: refusal.is_none(),
        code: refusal.map(|r| r.code),
        rule: asked.rule.map(|r| r.name.as_str()),
        rule_line: asked.rule.map(|r| r.line).filter(|line| *line > 0),
        policy_sha256: &version.policy_sha256,
        keys_sha256: &version.keys_sha256,
        ..Entry::default()
    };
    let mut record = gantry_core::audit::record(&entry);
    for (field, value) in [
        ("mcp_method", &asked.method),
        ("server", &asked.server),
        ("tool", &asked.tool),
    ] {
        if let Some(value) = value {
            // Cut like every caller-chosen string on a record, so a caller cannot choose a record's size.
            record.insert(
                field.into(),
                value.chars().take(200).collect::<String>().into(),
            );
        }
    }
    let (tell, written) = tokio::sync::oneshot::channel();
    audit.log.append_record_then(&record, move |result| {
        let _ = tell.send(result);
    });
    if matches!(written.await, Ok(Ok(()))) {
        return Ok(());
    }
    eprintln!("gantry: the audit log could not be written, so decision {decision} was refused");
    Err(Refusal::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "audit_unavailable",
        "Refused: Gantry could not write this call to its audit log, and it does not forward what it cannot record. Tell your Gantry admin.",
    ))
}

/// How a forwarded call ended, after its decision record. The tool has run by now, so a failure to write this is
/// reported and the answer still goes back.
async fn record_outcome(
    mcp: &McpState,
    decision: &str,
    asked: &Asked<'_>,
    outcome: Map<String, Value>,
) {
    let Some(audit) = &mcp.app.audit else {
        return;
    };
    let mut record = Map::new();
    record.insert("event".into(), "mcp_result".into());
    record.insert("id".into(), decision.into());
    record.insert("time".into(), gantry_core::audit::timestamp().into());
    record.insert(
        "person".into(),
        asked.person.map(|p| p.name.as_str()).into(),
    );
    record.insert("team".into(), asked.person.map(|p| p.team.as_str()).into());
    record.insert("key".into(), asked.key.as_deref().into());
    record.insert("server".into(), asked.server.as_deref().into());
    record.insert(
        "tool".into(),
        asked
            .tool
            .as_deref()
            .map(|t| t.chars().take(200).collect::<String>())
            .into(),
    );
    record.extend(outcome);
    let (tell, written) = tokio::sync::oneshot::channel();
    audit.log.append_record_then(&record, move |result| {
        let _ = tell.send(result);
    });
    if !matches!(written.await, Ok(Ok(()))) {
        eprintln!(
            "gantry: the outcome of MCP call {decision} could not be written to the audit log; its decision record is there"
        );
    }
}

/// Why an upstream server gave no answer, as the record names it, and as the caller is told.
struct Failure {
    outcome: &'static str,
    detail: String,
}

fn failure(outcome: &'static str, detail: impl Into<String>) -> Failure {
    Failure {
        outcome,
        detail: detail.into(),
    }
}

impl McpState {
    /// Every tool of every server that `rule` allows, named `<server>.<tool>`.
    // ponytail: servers are asked one after another on every tools/list, and one that fails is left out with a line
    // on stderr. Ask them at once, and cache the lists until a server says they changed, when lists get slow.
    async fn tools(&self, rule: &Rule) -> Vec<Value> {
        let mut tools = Vec::new();
        for server in self.servers.iter() {
            let mut cursor: Option<Value> = None;
            for _ in 0..MAX_PAGES {
                let params = match &cursor {
                    Some(cursor) => json!({"cursor": cursor}),
                    None => json!({}),
                };
                let page = match self.ask(server, "tools/list", params).await {
                    Ok(answer) if answer.get("result").is_some() => answer,
                    Ok(answer) => {
                        eprintln!(
                            "gantry: MCP server \"{}\" refused tools/list ({}), so its tools are left out of the list",
                            server.name, answer["error"]
                        );
                        break;
                    }
                    Err(failure) => {
                        eprintln!(
                            "gantry: MCP server \"{}\" gave no tool list: {}, so its tools are left out of the list",
                            server.name, failure.detail
                        );
                        break;
                    }
                };
                for tool in page["result"]["tools"].as_array().into_iter().flatten() {
                    let Some(name) = tool["name"].as_str() else {
                        continue;
                    };
                    let shown = format!("{}.{name}", server.name);
                    if tool_allowed(&rule.tools, &shown) {
                        let mut tool = tool.clone();
                        tool["name"] = shown.into();
                        tools.push(tool);
                    }
                }
                cursor = page["result"]
                    .get("nextCursor")
                    .filter(|c| !c.is_null())
                    .cloned();
                if cursor.is_none() {
                    break;
                }
            }
        }
        tools
    }

    /// Sends one request to a server in its session, opening one first if there is none, and once more in a new
    /// session if the server says the old one has ended. Returns the server's JSON-RPC answer to it.
    async fn ask(&self, server: &Upstream, method: &str, params: Value) -> Result<Value, Failure> {
        for _ in 0..2 {
            let session = self.session(server).await?;
            match self
                .send(server, Some(&session), method, params.clone())
                .await
            {
                Err(f) if f.outcome == "session_ended" => {
                    if let Ok(mut held) = server.session.lock() {
                        *held = None;
                    }
                }
                other => return other.map(|(answer, _)| answer),
            }
        }
        Err(failure(
            "session_ended",
            "it ended the new session as soon as it was opened",
        ))
    }

    async fn session(&self, server: &Upstream) -> Result<Session, Failure> {
        if let Some(session) = server.session.lock().ok().and_then(|s| s.clone()) {
            return Ok(session);
        }
        // ponytail: two calls that find no session at once both open one, and the last one is kept. Harmless: an
        // upstream server ends the other when it times it out.
        let params = json!({
            "protocolVersion": UPSTREAM_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "gantry", "version": gantry_core::VERSION},
        });
        let (answer, id) = self.send(server, None, "initialize", params).await?;
        if let Some(error) = answer.get("error") {
            return Err(failure(
                "initialize_refused",
                format!("it refused Gantry's initialize: {error}"),
            ));
        }
        let session = Session {
            id,
            version: answer["result"]["protocolVersion"]
                .as_str()
                .unwrap_or(UPSTREAM_VERSION)
                .to_string(),
        };
        self.notify(server, &session).await?;
        if let Ok(mut held) = server.session.lock() {
            *held = Some(session.clone());
        }
        Ok(session)
    }

    fn request(
        &self,
        server: &Upstream,
        session: Option<&Session>,
        body: &Value,
    ) -> Result<axum::http::Request<Body>, Failure> {
        let mut request = axum::http::Request::post(&server.url)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream");
        if let Some(session) = session {
            request = request.header("mcp-protocol-version", &session.version);
            if let Some(id) = &session.id {
                request = request.header("mcp-session-id", id);
            }
        }
        for (name, value) in &server.headers {
            request = request.header(name, value);
        }
        request.body(Body::from(body.to_string())).map_err(|err| {
            failure(
                "unreachable",
                format!("the request could not be built: {err}"),
            )
        })
    }

    async fn notify(&self, server: &Upstream, session: &Session) -> Result<(), Failure> {
        let request = self.request(
            server,
            Some(session),
            &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        )?;
        let sent = tokio::time::timeout(
            self.app.timeouts.first_byte,
            self.app.client.request(request),
        );
        match sent.await {
            Ok(Ok(response)) if response.status().is_success() => Ok(()),
            Ok(Ok(response)) => Err(failure(
                "initialize_refused",
                format!(
                    "it answered notifications/initialized with status {}",
                    response.status()
                ),
            )),
            Ok(Err(_)) => Err(failure("unreachable", "it could not be reached")),
            Err(_) => Err(failure("timeout", "it did not answer in time")),
        }
    }

    /// One request and its answer, read from a JSON body or from an event stream until the answer to it arrives.
    /// Returns the answer and the session ID the server gave, if any.
    async fn send(
        &self,
        server: &Upstream,
        session: Option<&Session>,
        method: &str,
        params: Value,
    ) -> Result<(Value, Option<String>), Failure> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let request = self.request(
            server,
            session,
            &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}),
        )?;
        // ponytail: one limit for the whole exchange, the provider's first-byte timeout. A tool that runs longer
        // than that needs a timeout of its own on the server.
        let exchange = async {
            let response = self
                .app
                .client
                .request(request)
                .await
                .map_err(|_| failure("unreachable", "it could not be reached"))?;
            let status = response.status();
            if status == StatusCode::NOT_FOUND && session.is_some_and(|s| s.id.is_some()) {
                return Err(failure("session_ended", "it ended Gantry's session"));
            }
            if !status.is_success() {
                return Err(failure(
                    "http_error",
                    format!("it answered with status {status}"),
                ));
            }
            let session_id = response
                .headers()
                .get("mcp-session-id")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let stream = response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.starts_with("text/event-stream"));
            let mut body = response.into_body();
            let mut read: Vec<u8> = Vec::new();
            let unreadable = || failure("unreadable_answer", "its answer could not be read");
            loop {
                let frame = match body.frame().await {
                    Some(Ok(frame)) => frame,
                    Some(Err(_)) => return Err(unreadable()),
                    None => break,
                };
                let Ok(data) = frame.into_data() else {
                    continue;
                };
                if read.len() + data.len() > MAX_BODY_BYTES {
                    return Err(failure(
                        "unreadable_answer",
                        "its answer is larger than Gantry reads",
                    ));
                }
                read.extend_from_slice(&data);
                // An event stream may stay open after the answer, so it is read only until the answer is in it.
                if stream && let Some(answer) = answer_in_stream(&read, id) {
                    return Ok((answer, session_id));
                }
            }
            let answer = if stream {
                answer_in_stream(&read, id)
            } else {
                serde_json::from_slice::<Value>(&read)
                    .ok()
                    .filter(|answer| answers(answer, id))
            };
            answer.map(|answer| (answer, session_id)).ok_or_else(|| {
                failure(
                    "unreadable_answer",
                    "its answer holds no JSON-RPC answer to Gantry's request",
                )
            })
        };
        tokio::time::timeout(self.app.timeouts.first_byte, exchange)
            .await
            .unwrap_or_else(|_| Err(failure("timeout", "it did not answer in time")))
    }
}

/// Whether a JSON-RPC message is the answer to request `id`.
fn answers(message: &Value, id: u64) -> bool {
    message["id"].as_u64() == Some(id)
        && (message.get("result").is_some() || message.get("error").is_some())
}

/// The answer to request `id` among the whole events of a server-sent event stream read so far. Progress
/// notifications and other messages before it are passed over.
fn answer_in_stream(read: &[u8], id: u64) -> Option<Value> {
    let text = String::from_utf8_lossy(read).replace("\r\n", "\n");
    // The text after the last blank line may be an event cut in half: it is read again when more has arrived.
    let whole = text.rfind("\n\n").map_or("", |end| &text[..end]);
    whole.split("\n\n").find_map(|event| {
        let data: Vec<&str> = event
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .map(|data| data.strip_prefix(' ').unwrap_or(data))
            .collect();
        serde_json::from_str::<Value>(&data.join("\n"))
            .ok()
            .filter(|message| answers(message, id))
    })
}

#[cfg(test)]
mod tests {
    use super::answer_in_stream;

    #[test]
    fn the_answer_is_found_in_a_stream_once_its_event_is_whole() {
        let progress = r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{}}"#;
        let answer = r#"{"jsonrpc":"2.0","id":4,"result":{"content":[]}}"#;
        let stream = format!(
            "event: message\r\ndata: {progress}\r\n\r\nevent: message\r\ndata: {answer}\r\n\r\n"
        );
        assert_eq!(
            answer_in_stream(stream.as_bytes(), 4).map(|a| a["id"].clone()),
            Some(4.into())
        );
        // Not the answer to another request, and not before its event has ended.
        assert!(answer_in_stream(stream.as_bytes(), 5).is_none());
        let cut = format!("data: {progress}\n\ndata: {answer}\n");
        assert!(answer_in_stream(cut.as_bytes(), 4).is_none());
    }
}
