//! The MCP gateway: `/mcp`, MCP's Streamable HTTP transport, in front of the upstream MCP servers a policy names.
//!
//! A caller signs in with its Gantry key or an OAuth access token Gantry issued (`oauth`). Gantry answers
//! `initialize` itself, gathers `tools/list`, `prompts/list` and `resources/list` from every server and shows only
//! what the caller's rule allows, named `<server>.<name>`, and checks every `tools/call`, `prompts/get` and
//! `resources/read` against the rule before it forwards it. Each one is recorded before it is forwarded, and its
//! outcome after; arguments and results never are.
//!
//! A tool call passes the rule's guardrails on its arguments and its result, may wait for an admin's approval, and is
//! refused while its tool has changed since it was pinned and its server blocks changes. Its answer is streamed to a
//! caller that takes event streams, and requests the server sends inside that stream (sampling, elicitation, roots)
//! go to the caller when it said it supports them; its answers go back to the server.
//!
//! `/mcp/<bundle>` serves a virtual server: the tools a policy's `mcp_bundles` entry names, within the rule.

mod console;
mod keep;
mod oauth;

use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Path, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
    routing::any,
};
use gantry_core::{
    audit::Entry,
    guard::{self, Guardrail},
    id,
    mcp::{Bundle, ToolChanges, UserAuth, tool_allowed},
    policy::{Principal, Rule},
};
use http_body_util::BodyExt;
use serde_json::{Map, Value, json};

pub use keep::McpSetup;

use crate::{
    AppState, ClientAddr, ConfigError, DECISION, MAX_BODY_BYTES, Refusal, Secret, Snapshot,
    checked_upstream, killed, read_body,
};
use keep::Keep;

/// The MCP protocol versions Gantry speaks to callers, newest first.
const VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26"];
/// The version Gantry asks each upstream server for.
const UPSTREAM_VERSION: &str = "2025-06-18";
/// Pages of one server's list Gantry reads, so a server that always answers with a next cursor cannot hold a list
/// forever.
const MAX_PAGES: usize = 100;
/// JSON-RPC error code of a Gantry refusal, in the range JSON-RPC leaves to servers.
const REFUSED: i64 = -32001;
/// MCP's error for "the caller must open a URL first" (URL mode elicitation): a person's credential is missing.
const URL_REQUIRED: i64 = -32042;
/// Shown resource URIs: `gantry://<server>/<the server's own URI>`.
const RESOURCE_SCHEME: &str = "gantry://";
/// How long a request a server sent to a caller waits for the caller's answer before it is forgotten.
const RELAY_FOR: Duration = Duration::from_secs(30 * 60);
/// Most callers' sessions and relayed requests remembered at once.
const MAX_REMEMBERED: usize = 10_000;
/// How often a call waiting for approval looks again.
const APPROVAL_POLL: Duration = Duration::from_millis(500);

/// An upstream MCP server as `governed` hands it over: its endpoint and its credentials, read from the environment.
#[derive(Clone, Debug)]
pub struct McpRoute {
    pub name: String,
    /// The server's MCP endpoint, for example `https://mcp.example.com/mcp`.
    pub url: String,
    /// Headers sent with every request to it, such as `Authorization`.
    pub headers: Vec<(String, Secret)>,
    /// Each person's own credential, when every call must run as the person.
    pub user_auth: Option<UserAuth>,
    pub tool_changes: ToolChanges,
    /// The client secret for `user_auth: oauth` with a client registered by hand.
    pub oauth_client_secret: Option<Secret>,
}

struct Upstream {
    name: String,
    url: String,
    headers: Vec<(HeaderName, HeaderValue)>,
    user_auth: Option<UserAuth>,
    tool_changes: ToolChanges,
    client_secret: Option<String>,
    /// One session per credential: the shared one under "", each person's under their name.
    sessions: Mutex<HashMap<String, Session>>,
}

#[derive(Clone)]
struct Session {
    id: Option<String>,
    version: String,
}

/// Which session of a server a request goes in, and the person's own headers it carries.
#[derive(Clone, Default)]
struct Conn {
    key: String,
    headers: Vec<(HeaderName, HeaderValue)>,
    /// `user_headers` or `user_oauth` when the request carries the person's own credential.
    auth: Option<&'static str>,
}

/// A request a server sent inside a stream, passed to the caller under an id of Gantry's.
struct Relayed {
    server: usize,
    upstream_id: Value,
    session: Session,
    conn: Conn,
    /// The SHA-256 of the credential of the caller it went to: only that caller may answer it.
    owner: String,
    at: Instant,
}

/// What a caller said it supports at `initialize`, under the session id Gantry gave it.
struct CallerSession {
    owner: String,
    capabilities: Value,
    at: Instant,
}

pub(crate) struct Mcp {
    app: AppState,
    servers: Vec<Upstream>,
    // Each request to an upstream server gets its own id: callers share a session, so their ids could collide.
    next: AtomicU64,
    keep: Keep,
    sso: bool,
    audit_path: Option<std::path::PathBuf>,
    callers: Mutex<HashMap<String, CallerSession>>,
    relayed: Mutex<HashMap<String, Relayed>>,
    /// One pinning at a time on this gateway, so one change is recorded once.
    pinning: tokio::sync::Mutex<()>,
}

type Shared = Arc<Mcp>;

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// What the MCP gateway adds: its routes, and its pages for the console.
pub(crate) struct Built {
    pub router: Router,
    pub console: gantry_console::Extension,
}

/// The `/mcp` routes, when the policy names MCP servers.
pub(crate) fn router(
    app: &AppState,
    routes: Vec<McpRoute>,
    setup: McpSetup,
) -> Result<Option<Built>, ConfigError> {
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
            user_auth: route.user_auth,
            tool_changes: route.tool_changes,
            client_secret: route.oauth_client_secret.map(|s| s.0),
            sessions: Mutex::default(),
        });
    }
    let (sso, audit_path) = (setup.sso, setup.audit_path.clone());
    let keep = Keep::start(setup).map_err(ConfigError)?;
    if let Some(server) = servers.iter().find(|s| s.user_auth.is_some())
        && !keep.can_seal()
    {
        return Err(ConfigError(format!(
            "MCP server \"{}\" has user_auth, and {}",
            server.name,
            keep::NO_SEALER
        )));
    }
    let mcp: Shared = Arc::new(Mcp {
        app: app.clone(),
        servers,
        next: AtomicU64::new(1),
        keep,
        sso,
        audit_path,
        callers: Mutex::default(),
        relayed: Mutex::default(),
        pinning: tokio::sync::Mutex::new(()),
    });
    let router = Router::new()
        .route(
            "/mcp",
            any(|State(mcp): State<Shared>, request: Request| async move {
                serve(mcp, None, request).await
            }),
        )
        .route(
            "/mcp/{bundle}",
            any(
                |State(mcp): State<Shared>, Path(bundle): Path<String>, request: Request| async move {
                    serve(mcp, Some(bundle), request).await
                },
            ),
        )
        .merge(oauth::routes())
        .with_state(mcp.clone());
    Ok(Some(Built {
        router,
        console: console::extension(mcp),
    }))
}

async fn serve(mcp: Shared, bundle: Option<String>, request: Request) -> Response {
    let decision = id::decision_id();
    let mut response = match *request.method() {
        Method::POST => post(&mcp, bundle, request, &decision).await,
        Method::DELETE => {
            // The end of a caller's session: what it said it supports is forgotten.
            if let Some(session) = request
                .headers()
                .get("mcp-session-id")
                .and_then(|v| v.to_str().ok())
            {
                lock(&mcp.callers).remove(session);
            }
            StatusCode::NO_CONTENT.into_response()
        }
        _ => {
            // No stream of Gantry's own to listen to: server requests come inside the stream of a call.
            let mut response = (
                StatusCode::METHOD_NOT_ALLOWED,
                "Gantry's MCP endpoint takes POST, and DELETE to end a session: it opens no stream of its own. Requests from servers come inside the stream that answers a call.",
            )
                .into_response();
            response
                .headers_mut()
                .insert(header::ALLOW, HeaderValue::from_static("POST, DELETE"));
            response
        }
    };
    if let Ok(value) = HeaderValue::from_str(&decision) {
        response.headers_mut().insert(DECISION, value);
    }
    response
}

/// What was learned about one message while it was checked. It becomes the audit record.
#[derive(Clone, Default)]
struct Asked {
    client: Option<String>,
    person: Option<Principal>,
    /// First 8 hex characters of the hash of the credential's key.
    key: Option<String>,
    /// The hash a kill switch on a key is matched with.
    key_sha256: String,
    rule: Option<Rule>,
    /// Set once the body is read as a JSON-RPC message. Before that a refusal is an HTTP error.
    method: Option<String>,
    id: Option<Value>,
    server: Option<String>,
    /// ("tool", name), ("prompt", name) or ("resource", uri): the record's field and its value.
    item: Option<(&'static str, String)>,
    bundle: Option<String>,
    /// This Gantry as the caller reached it, for the links it hands out.
    origin: String,
    /// `oauth` when the caller signed in with an OAuth access token.
    via: Option<&'static str>,
    /// More fields of the decision record: guardrail findings, who approved, whose credential went upstream.
    extra: Map<String, Value>,
    /// Where the caller signs in to an upstream server, when its credential is missing.
    connect: Option<String>,
    /// What observe mode or the rule's shadow period let through.
    would_refuse: Vec<Value>,
}

async fn post(mcp: &Shared, bundle: Option<String>, request: Request, decision: &str) -> Response {
    let (parts, body) = request.into_parts();
    let mut asked = Asked {
        client: parts
            .extensions
            .get::<ClientAddr>()
            .map(|addr| addr.0.ip().to_string()),
        origin: oauth::origin(&parts),
        bundle,
        ..Asked::default()
    };
    let version = mcp.app.version();
    match answer(mcp, &version, parts, body, decision, &mut asked).await {
        Ok(response) => response,
        Err(refusal) => match record(mcp, &version, decision, &asked, Some(&refusal)).await {
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
fn refused(refusal: &Refusal, asked: &Asked, decision: &str) -> Response {
    let message = match refusal.message.strip_prefix("Refused: ") {
        Some(rest) => format!("Refused ({}): {rest} Decision {decision}.", refusal.code),
        None => format!("{} Decision {decision}.", refusal.message),
    };
    let code = match refusal.code {
        "unreadable_request" => -32600,
        "credential_needed" => URL_REQUIRED,
        _ => REFUSED,
    };
    let status = if asked.method.is_some() {
        StatusCode::OK
    } else {
        refusal.status
    };
    let mut data = json!({"gantry_code": refusal.code, "decision": decision});
    if let Some(url) = &asked.connect {
        data["elicitations"] = json!([{
            "mode": "url",
            "elicitationId": decision,
            "url": url,
            "message": message,
        }]);
    }
    let mut response = json_response(
        status,
        &json!({
            "jsonrpc": "2.0",
            "id": asked.id.clone().unwrap_or(Value::Null),
            "error": {"code": code, "message": message, "data": data},
        }),
    );
    if status == StatusCode::UNAUTHORIZED {
        // Where an MCP client finds how to sign in (RFC 9728), so it can offer OAuth instead of a pasted key.
        let path = asked
            .bundle
            .as_ref()
            .map_or_else(|| "/mcp".to_string(), |b| format!("/mcp/{b}"));
        let value = format!(
            "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource{path}\"",
            asked.origin
        );
        if let Ok(value) = HeaderValue::from_str(&value) {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, value);
        }
    }
    response
}

fn unreadable(why: &str) -> Refusal {
    Refusal::new(
        StatusCode::BAD_REQUEST,
        "unreadable_request",
        format!("Refused: {why}"),
    )
}

/// What a list method lists, and how Gantry renames it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Item {
    Tool,
    Prompt,
    Resource,
    Template,
}

impl Item {
    fn list_method(self) -> &'static str {
        match self {
            Item::Tool => "tools/list",
            Item::Prompt => "prompts/list",
            Item::Resource => "resources/list",
            Item::Template => "resources/templates/list",
        }
    }

    fn key(self) -> &'static str {
        match self {
            Item::Tool => "tools",
            Item::Prompt => "prompts",
            Item::Resource => "resources",
            Item::Template => "resourceTemplates",
        }
    }

    fn field(self) -> &'static str {
        match self {
            Item::Tool | Item::Prompt => "name",
            Item::Resource => "uri",
            Item::Template => "uriTemplate",
        }
    }

    /// How the caller sees an item a server names `name`.
    fn shown(self, server: &str, name: &str) -> String {
        match self {
            Item::Tool | Item::Prompt => format!("{server}.{name}"),
            Item::Resource | Item::Template => format!("{RESOURCE_SCHEME}{server}/{name}"),
        }
    }

    /// The patterns of the rule this kind is allowed by.
    fn patterns(self, rule: &Rule) -> &[String] {
        match self {
            Item::Tool => &rule.tools,
            Item::Prompt => &rule.mcp.prompts,
            Item::Resource | Item::Template => &rule.mcp.resources,
        }
    }
}

/// Whether the rule (and the bundle, at `/mcp/<bundle>`) allows `name`, written `<server>.<name>`.
fn allows(item: Item, rule: &Rule, bundle: Option<&Bundle>, name: &str) -> bool {
    let in_bundle = match (item, bundle) {
        (_, None) => true,
        (Item::Tool, Some(bundle)) => tool_allowed(&bundle.tools, name),
        // A bundle serves tools only.
        (_, Some(_)) => false,
    };
    in_bundle
        && tool_allowed(item.patterns(rule), name)
        && (item != Item::Tool || rule.mcp.narrow.iter().all(|l| tool_allowed(l, name)))
}

/// The header a caller narrows its tools with, for one request: a comma separated list of `tools:` patterns.
pub(crate) const NARROW_HEADER: &str = "x-gantry-mcp-tools";

/// The rule as this request sees it: its tools narrowed by the key's `mcp_tools` and the `x-gantry-mcp-tools`
/// header. Neither can allow a tool the rule does not.
fn narrowed(rule: &Rule, person: &Principal, headers: &HeaderMap) -> Result<Rule, Refusal> {
    let mut rule = rule.clone();
    if !person.options.mcp_tools.is_empty() {
        rule.mcp.narrow.push(person.options.mcp_tools.clone());
    }
    if let Some(value) = headers.get(NARROW_HEADER) {
        let bad = || {
            Refusal::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                format!(
                    "Refused: {NARROW_HEADER} is a comma separated list of MCP tools, each <server>.<tool>, <server>.* or *, or !<server>.<tool> to leave one out, for example \"github.*, !github.delete_repo\". Fix the header or remove it."
                ),
            )
        };
        let list: Vec<String> = value
            .to_str()
            .map_err(|_| bad())?
            .split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect();
        if list.is_empty()
            || list.len() > 64
            || !list.iter().all(|t| gantry_core::mcp::narrowing_entry(t))
        {
            return Err(bad());
        }
        rule.mcp.narrow.push(list);
    }
    Ok(rule)
}

/// Checks one message and answers it. Every error is a refusal, recorded by the caller.
async fn answer(
    mcp: &Shared,
    version: &Snapshot,
    parts: Parts,
    body: Body,
    decision: &str,
    asked: &mut Asked,
) -> Result<Response, Refusal> {
    let Some(policy) = &version.policy else {
        return Err(Refusal::new(
            StatusCode::NOT_FOUND,
            "unknown_route",
            "Refused: this Gantry runs without a policy, so it serves no MCP tools. Start it with a policy file that lists servers under mcp.",
        ));
    };
    let bundle = match &asked.bundle {
        Some(name) => Some(policy.mcp_bundle(name).cloned().ok_or_else(|| {
            Refusal::new(
                StatusCode::NOT_FOUND,
                "unknown_bundle",
                format!(
                    "Refused: no MCP bundle is named \"{name}\", so /mcp/{name} serves nothing. Connect to /mcp, or ask a Gantry admin which bundles the policy's mcp_bundles names."
                ),
            )
        })?),
        None => None,
    };
    let resource = format!("{}{}", asked.origin, parts.uri.path());
    let (person, key_sha256, via) = mcp
        .authenticate(policy, &parts.headers, &resource, asked)
        .await?;
    asked.key = Some(person.key.clone());
    asked.key_sha256 = key_sha256.clone();
    asked.via = via;
    asked.person = Some(person.clone());
    if let Some(bundle) = &bundle
        && !bundle.teams.is_empty()
        && !bundle.teams.contains(&person.team)
    {
        return Err(Refusal::new(
            StatusCode::FORBIDDEN,
            "bundle_not_allowed",
            format!(
                "Refused: MCP bundle \"{}\" is for team {}, and \"{}\" is of team \"{}\". Connect to /mcp, or ask a Gantry admin to add your team to the bundle.",
                bundle.name,
                bundle.teams.join(", "),
                person.name,
                person.team
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
        // The caller's answer to a request a server sent it inside a stream.
        mcp.relay_answer(&message, &key_sha256).await;
        return Ok(StatusCode::ACCEPTED.into_response());
    };
    asked.method = Some(method.to_string());
    let Some(call_id) = message.get("id").cloned() else {
        // A notification, such as notifications/initialized: nothing to answer.
        return Ok(StatusCode::ACCEPTED.into_response());
    };
    asked.id = Some(call_id.clone());
    let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
    let capabilities = parts
        .headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|session| {
            lock(&mcp.callers)
                .get(session)
                .filter(|s| s.owner == key_sha256)
                .map(|s| s.capabilities.clone())
        })
        .unwrap_or_else(|| json!({}));
    let item = match method {
        "initialize" => return Ok(mcp.initialize(&call_id, &params, &key_sha256, bundle.as_ref())),
        "ping" => return Ok(result(&call_id, json!({}))),
        "tools/call" => Some(Item::Tool),
        "prompts/get" => Some(Item::Prompt),
        "resources/read" => Some(Item::Resource),
        "tools/list" | "prompts/list" | "resources/list" | "resources/templates/list" => None,
        _ => {
            return Ok(json_response(
                StatusCode::OK,
                &json!({"jsonrpc": "2.0", "id": call_id, "error": {"code": -32601, "message": format!("Gantry's MCP endpoint serves initialize, ping, tools/list, tools/call, prompts/list, prompts/get, resources/list, resources/templates/list and resources/read; \"{method}\" is not one of them.")}}),
            ));
        }
    };
    // The name the caller asked for, as `<server>.<name>`, and the server's own name for it.
    let named = match item {
        Some(Item::Resource) => {
            let uri = params.get("uri").and_then(Value::as_str).ok_or_else(|| {
                unreadable("resources/read needs params.uri, the resource to read, as resources/list names it.")
            })?;
            let (server, own) = uri
                .strip_prefix(RESOURCE_SCHEME)
                .and_then(|rest| rest.split_once('/'))
                .unwrap_or(("", uri));
            asked.server = Some(server.to_string());
            asked.item = Some(("resource", own.to_string()));
            Some(format!("{server}.{own}"))
        }
        Some(kind) => {
            let name = params.get("name").and_then(Value::as_str).ok_or_else(|| {
                unreadable(&format!(
                    "{method} needs params.name, as {} names it.",
                    kind.list_method()
                ))
            })?;
            let field = if kind == Item::Tool { "tool" } else { "prompt" };
            match name.split_once('.') {
                Some((server, own)) => {
                    asked.server = Some(server.to_string());
                    asked.item = Some((field, own.to_string()));
                }
                None => asked.item = Some((field, name.to_string())),
            }
            Some(name.to_string())
        }
        None => None,
    };
    // A switch on a person, team or key stops their tools as it stops their models. A switch on a model named like a
    // tool (`gantry kill --model github.delete_repo`) stops that one tool for everyone.
    killed(&mcp.app, &person, &key_sha256, named.as_deref())?;
    let no_rule = Refusal::new(
        StatusCode::FORBIDDEN,
        "no_rule",
        format!(
            "Refused: no rule in the policy names \"{}\" or team \"{}\", so no MCP tool is allowed. Ask a Gantry admin to add a rule with the tools you need.",
            person.name, person.team
        ),
    );
    let rule = crate::rule_or_observed(policy, &person, no_rule, |r, by| {
        asked.would_refuse.push(crate::would_refuse_entry(r, by));
    })?;
    let rule = &narrowed(rule, &person, &parts.headers)?;
    asked.rule = Some(rule.clone());
    // Observe mode or the rule's shadow period: every tool, prompt and resource is listed and may be used, and one
    // the rule does not allow is recorded as would_refuse.
    let shadow = policy.observing(rule.shadow_until.as_deref());
    let listed = shadow.map(|_| {
        let mut open = rule.clone();
        open.tools = vec!["*".into()];
        open.mcp.prompts = vec!["*".into()];
        open.mcp.resources = vec!["*".into()];
        open
    });
    let (Some(item), Some(name)) = (item, named) else {
        let item = match method {
            "tools/list" => Item::Tool,
            "prompts/list" => Item::Prompt,
            "resources/list" => Item::Resource,
            _ => Item::Template,
        };
        let items = mcp
            .gather(
                item,
                listed.as_ref().unwrap_or(rule),
                bundle.as_ref(),
                &person,
                &asked.origin,
            )
            .await;
        return Ok(result(&call_id, json!({ item.key(): items })));
    };
    if !allows(item, rule, bundle.as_ref(), &name) {
        let noun = match item {
            Item::Tool => "tool",
            Item::Prompt => "prompt",
            _ => "resource",
        };
        if let Some(bundle) = bundle.as_ref().filter(|b| !tool_allowed(&b.tools, &name)) {
            return Err(Refusal::new(
                StatusCode::FORBIDDEN,
                "not_in_bundle",
                format!(
                    "Refused: MCP bundle \"{}\" does not serve {noun} \"{name}\". It serves: {}. Connect to /mcp for the rest of what your rule allows.",
                    bundle.name,
                    bundle.tools.join(", ")
                ),
            ));
        }
        let patterns = item.patterns(rule);
        if item == Item::Tool && tool_allowed(patterns, &name) {
            // The rule allows it: the key's mcp_tools or the request's header left it out.
            return Err(Refusal::new(
                StatusCode::FORBIDDEN,
                "tool_not_allowed",
                format!(
                    "Refused: tool \"{name}\" is allowed by rule \"{}\", and left out by this key's mcp_tools or the request's {NARROW_HEADER} header, which only narrow it. Remove it from the header, or ask a Gantry admin to change the key's mcp_tools.",
                    rule.name
                ),
            ));
        }
        let allowed = if patterns.is_empty() {
            format!("It allows no MCP {noun}s.")
        } else {
            format!("It allows: {}.", patterns.join(", "))
        };
        let (code, field) = match item {
            Item::Tool => ("tool_not_allowed", "tools"),
            Item::Prompt => ("prompt_not_allowed", "prompts"),
            _ => ("resource_not_allowed", "resources"),
        };
        let refusal = Refusal::new(
            StatusCode::FORBIDDEN,
            code,
            format!(
                "Refused: rule \"{}\" does not allow {noun} \"{name}\" for \"{}\" of team \"{}\". {allowed} Ask a Gantry admin to add it to the rule's {field} if you need it.",
                rule.name, person.name, person.team
            ),
        );
        let Some(by) = shadow else {
            return Err(refusal);
        };
        asked
            .would_refuse
            .push(crate::would_refuse_entry(refusal, by));
    }
    let index = asked
        .server
        .as_deref()
        .and_then(|s| mcp.servers.iter().position(|u| u.name == s))
        .ok_or_else(|| {
            let names: Vec<&str> = mcp.servers.iter().map(|s| s.name.as_str()).collect();
            Refusal::new(
                StatusCode::NOT_FOUND,
                "unknown_tool",
                format!(
                    "Refused: \"{name}\" is on no MCP server of this Gantry. Names are <server>.<name>, and the servers are: {}. Run {} for the names.",
                    names.join(", "),
                    item.list_method()
                ),
            )
        })?;
    let server = &mcp.servers[index];
    let conn = match mcp.conn(server, &person, &asked.origin).await {
        Ok(conn) => conn,
        Err(need) => return Err(mcp.need(asked, server, need).await),
    };
    if let Some(auth) = conn.auth {
        asked.extra.insert("upstream_auth".into(), auth.into());
    }
    let own = asked.item.clone().map(|(_, own)| own).unwrap_or_default();
    let mut forwarded = params;
    if item != Item::Tool {
        if let Some(params) = forwarded.as_object_mut() {
            let field = if item == Item::Resource {
                "uri"
            } else {
                "name"
            };
            params.insert(field.into(), own.clone().into());
        }
        if let Err(unavailable) = record(mcp, version, decision, asked, None).await {
            return Ok(refused(&unavailable, asked, decision));
        }
        let started = Instant::now();
        let upstream = mcp.ask(index, &conn, method, forwarded).await;
        let (response, outcome) = mcp
            .finish(upstream, &call_id, decision, asked, &[], started)
            .await;
        record_outcome(mcp, decision, asked, outcome).await;
        return Ok(json_response(StatusCode::OK, &response));
    }
    mcp.check_pin(index, &conn, &own).await?;
    let observe = policy.mode() == gantry_core::policy::Mode::Observe;
    let guards: Vec<Guardrail> =
        crate::observed_guards(policy, &rule.guardrails).unwrap_or_else(|| rule.guardrails.clone());
    if let Some(params) = forwarded.as_object_mut() {
        params.insert("name".into(), own.clone().into());
        if guards.iter().any(|g| g.on.request) {
            let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);
            let (arguments, found) = mcp
                .screen_arguments(&guards, arguments, decision, &person)
                .await;
            if observe {
                asked.would_refuse.extend(crate::would_block(rule, &found));
            }
            if !found.is_empty() {
                asked.extra.insert("guardrails".into(), json!(found));
            }
            match arguments {
                Ok(Some(masked)) => {
                    params.insert("arguments".into(), masked);
                }
                Ok(None) => {}
                Err(refusal) => return Err(refusal),
            }
        }
    }
    if tool_allowed(&rule.mcp.approve, &name) {
        let by = mcp
            .wait_for_approval(decision, asked, &forwarded, rule)
            .await?;
        asked.extra.insert("approved_by".into(), by.into());
    }
    // The call is on record before it is forwarded. A call that cannot be recorded does not happen.
    if let Err(unavailable) = record(mcp, version, decision, asked, None).await {
        return Ok(refused(&unavailable, asked, decision));
    }
    let started = Instant::now();
    let streams = parts
        .headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("text/event-stream"));
    let reply = mcp.start(index, &conn, "tools/call", forwarded).await;
    let upstream = match reply {
        Ok((Reply::Events(events), id)) if streams => {
            return Ok(mcp.clone().relay(
                events,
                id,
                call_id,
                decision.to_string(),
                asked.clone(),
                capabilities,
                guards,
                started,
            ));
        }
        Ok((reply, id)) => mcp.drain(reply, id).await,
        Err(failure) => Err(failure),
    };
    let (response, outcome) = mcp
        .finish(upstream, &call_id, decision, asked, &guards, started)
        .await;
    record_outcome(mcp, decision, asked, outcome).await;
    Ok(json_response(StatusCode::OK, &response))
}

impl Mcp {
    fn initialize(
        &self,
        call_id: &Value,
        params: &Value,
        owner: &str,
        bundle: Option<&Bundle>,
    ) -> Response {
        let asked_for = params.get("protocolVersion").and_then(Value::as_str);
        let protocol = VERSIONS
            .iter()
            .find(|v| Some(**v) == asked_for)
            .unwrap_or(&VERSIONS[0]);
        let session = id::random_hex(16);
        {
            let mut callers = lock(&self.callers);
            if callers.len() >= MAX_REMEMBERED {
                // ponytail: a full table forgets the oldest session; its caller then relays nothing until it
                // initializes again.
                if let Some(oldest) = callers
                    .iter()
                    .min_by_key(|(_, s)| s.at)
                    .map(|(k, _)| k.clone())
                {
                    callers.remove(&oldest);
                }
            }
            callers.insert(
                session.clone(),
                CallerSession {
                    owner: owner.to_string(),
                    capabilities: params.get("capabilities").cloned().unwrap_or(json!({})),
                    at: Instant::now(),
                },
            );
        }
        let name = bundle.map_or("gantry", |b| b.name.as_str());
        let instructions = match bundle {
            Some(b) => format!(
                "MCP bundle {}: chosen tools of the MCP servers behind this Gantry, named <server>.<tool>. Only the tools your policy rule allows are listed.",
                b.name
            ),
            None => "Tools, prompts and resources of the MCP servers behind this Gantry, named <server>.<name>. Only what your policy rule allows is listed.".to_string(),
        };
        let mut response = result(
            call_id,
            json!({
                "protocolVersion": protocol,
                "capabilities": {
                    "tools": {"listChanged": false},
                    "prompts": {"listChanged": false},
                    "resources": {"subscribe": false, "listChanged": false},
                },
                "serverInfo": {"name": name, "version": gantry_core::VERSION},
                "instructions": instructions,
            }),
        );
        if let Ok(value) = HeaderValue::from_str(&session) {
            response.headers_mut().insert("mcp-session-id", value);
        }
        response
    }

    /// Everything of one kind that `rule` (and `bundle`) allows, from every server, renamed for the caller.
    // ponytail: servers are asked one after another on every list, and one that fails is left out with a line on
    // stderr. Ask them at once, and cache the lists until a server says they changed, when lists get slow.
    async fn gather(
        &self,
        item: Item,
        rule: &Rule,
        bundle: Option<&Bundle>,
        person: &Principal,
        origin: &str,
    ) -> Vec<Value> {
        let mut out = Vec::new();
        for (index, server) in self.servers.iter().enumerate() {
            let conn = match self.conn(server, person, origin).await {
                Ok(conn) => conn,
                Err(_) => {
                    // Without the person's credential the server cannot be asked. A tool that says how to connect
                    // takes the place of its tools, so the person learns where to sign in.
                    let name = format!("{}.connect", server.name);
                    if item == Item::Tool && allows(Item::Tool, rule, bundle, &name) {
                        out.push(json!({
                            "name": name,
                            "description": format!("Connect your own account to MCP server {}. Its tools are listed once you have. Call this tool for the link.", server.name),
                            "inputSchema": {"type": "object", "properties": {}},
                        }));
                    }
                    continue;
                }
            };
            let items = self.list_server(index, &conn, item).await;
            let hidden = if item == Item::Tool {
                self.observe(index, &items).await
            } else {
                HashSet::new()
            };
            for entry in items {
                let Some(own) = entry[item.field()].as_str() else {
                    continue;
                };
                if hidden.contains(own) {
                    continue;
                }
                let check = format!("{}.{own}", server.name);
                if allows(item, rule, bundle, &check) {
                    let mut entry = entry.clone();
                    entry[item.field()] = item.shown(&server.name, own).into();
                    out.push(entry);
                }
            }
        }
        out
    }

    /// One server's whole list of one kind, every page.
    async fn list_server(&self, index: usize, conn: &Conn, item: Item) -> Vec<Value> {
        let server = &self.servers[index];
        let mut out = Vec::new();
        let mut cursor: Option<Value> = None;
        for _ in 0..MAX_PAGES {
            let params = match &cursor {
                Some(cursor) => json!({"cursor": cursor}),
                None => json!({}),
            };
            let page = match self.ask(index, conn, item.list_method(), params).await {
                Ok(answer) if answer.get("result").is_some() => answer,
                Ok(answer) => {
                    eprintln!(
                        "gantry: MCP server \"{}\" refused {} ({}), so it is left out of the list",
                        server.name,
                        item.list_method(),
                        answer["error"]
                    );
                    break;
                }
                Err(failure) => {
                    eprintln!(
                        "gantry: MCP server \"{}\" gave no answer to {}: {}, so it is left out of the list",
                        server.name,
                        item.list_method(),
                        failure.detail
                    );
                    break;
                }
            };
            out.extend(
                page["result"][item.key()]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .cloned(),
            );
            cursor = page["result"]
                .get("nextCursor")
                .filter(|c| !c.is_null())
                .cloned();
            if cursor.is_none() {
                break;
            }
        }
        out
    }

    /// Runs the request-side guardrails on a tool call's arguments: every string in them, wherever it is.
    /// Returns the masked arguments when a guardrail masked something, or the refusal when one blocked.
    async fn screen_arguments(
        &self,
        guards: &[Guardrail],
        arguments: Value,
        decision: &str,
        person: &Principal,
    ) -> (Result<Option<Value>, Refusal>, Vec<guard::AuditEntry>) {
        let mut found = Vec::new();
        strings(&arguments, String::new(), &mut found);
        let texts: Vec<Value> = found.iter().map(|(_, t)| t.clone().into()).collect();
        let verdict = self
            .screen(guards, true, json!({ "input": texts }), decision, person)
            .await;
        if let Some(blocked) = verdict.blocked {
            let refusal = Refusal::new(
                StatusCode::FORBIDDEN,
                guard::BLOCKED_CODE,
                format!(
                    "Refused: {} It was found in the tool's arguments.",
                    blocked.message
                ),
            );
            return (Err(refusal), verdict.audit);
        }
        if !verdict.changed {
            return (Ok(None), verdict.audit);
        }
        let mut masked = arguments;
        for (i, (pointer, _)) in found.iter().enumerate() {
            if let (Some(slot), Some(text)) =
                (masked.pointer_mut(pointer), verdict.body["input"].get(i))
            {
                *slot = text.clone();
            }
        }
        (Ok(Some(masked)), verdict.audit)
    }

    /// The built-in guardrails then each webhook in order, on the request side or the answer side.
    async fn screen(
        &self,
        guards: &[Guardrail],
        request: bool,
        view: Value,
        decision: &str,
        person: &Principal,
    ) -> guard::Verdict {
        let mut verdict = if request {
            guard::check(view, guards)
        } else {
            guard::check_reply(view, guards)
        };
        for guardrail in guards
            .iter()
            .filter(|g| if request { g.on.request } else { g.on.answer })
        {
            let guard::Check::Webhook(hook) = &guardrail.check else {
                continue;
            };
            if verdict.blocked.is_some() {
                break;
            }
            let sent = guard::WebhookRequest::new(
                decision,
                &person.name,
                &person.team,
                "/mcp",
                &verdict.body,
            );
            let reply = crate::ask(&self.app, guardrail.action, hook, &sent).await;
            if let Some(cause) = verdict.merge_answer(guardrail, &sent, reply) {
                eprintln!("gantry: decision {decision}: on an MCP tool call: {cause}");
            }
        }
        verdict
    }

    /// The answer to a call, as the caller gets it, and its `mcp_result` fields: the outcome, and what the answer
    /// guardrails did with the tool's result.
    async fn finish(
        &self,
        upstream: Result<Value, Failure>,
        call_id: &Value,
        decision: &str,
        asked: &Asked,
        guards: &[Guardrail],
        started: Instant,
    ) -> (Value, Map<String, Value>) {
        let mut outcome = Map::new();
        outcome.insert(
            "duration_ms".into(),
            u64::try_from(started.elapsed().as_millis())
                .unwrap_or(u64::MAX)
                .into(),
        );
        let server = asked.server.clone().unwrap_or_default();
        let mut answer = match upstream {
            Ok(answer) => answer,
            Err(failure) => {
                outcome.insert("outcome".into(), failure.outcome.into());
                let mut data = json!({"gantry_code": format!("upstream_{}", failure.outcome), "decision": decision});
                let mut code = -32603;
                let mut message = format!(
                    "Gantry got no answer from MCP server \"{server}\": {}. It may or may not have run there. Try again, and tell your Gantry admin if it keeps failing. Decision {decision}.",
                    failure.detail
                );
                // A person's credential the server no longer takes: they sign in to it again.
                if failure.outcome == "unauthorized"
                    && let (Some(index), Some(person)) = (
                        self.servers.iter().position(|s| s.name == server),
                        &asked.person,
                    )
                    && self.servers[index].user_auth.is_some()
                    && let Ok(url) = self
                        .connect_link(&self.servers[index], person, &asked.origin)
                        .await
                {
                    code = URL_REQUIRED;
                    message = format!(
                        "MCP server \"{server}\" no longer takes your credential. Open {url} to sign in to it again, then try again. Decision {decision}."
                    );
                    data["elicitations"] = json!([{"mode": "url", "elicitationId": decision, "url": url, "message": message}]);
                }
                return (
                    json!({"jsonrpc": "2.0", "id": call_id, "error": {"code": code, "message": message, "data": data}}),
                    outcome,
                );
            }
        };
        if let Some(error) = answer.get("error") {
            outcome.insert("outcome".into(), "rpc_error".into());
            outcome.insert("upstream_code".into(), error["code"].clone());
        } else {
            let failed = answer["result"]["isError"].as_bool() == Some(true);
            outcome.insert(
                "outcome".into(),
                if failed { "tool_error" } else { "ok" }.into(),
            );
            if guards.iter().any(|g| g.on.answer)
                && let Some(person) = &asked.person
            {
                let mut found = Vec::new();
                for (i, part) in answer["result"]["content"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .enumerate()
                {
                    if let Some(text) = part.get("text").and_then(Value::as_str) {
                        found.push((format!("/result/content/{i}/text"), text.to_string()));
                    }
                }
                strings(
                    &answer["result"]["structuredContent"],
                    "/result/structuredContent".into(),
                    &mut found,
                );
                let view = json!({"messages": found.iter().map(|(_, t)| json!({"role": "assistant", "content": t})).collect::<Vec<_>>()});
                let verdict = self.screen(guards, false, view, decision, person).await;
                if !verdict.audit.is_empty() {
                    outcome.insert("guardrails".into(), json!(verdict.audit));
                }
                if let Some(blocked) = verdict.blocked {
                    outcome.insert("outcome".into(), "guardrail_blocked".into());
                    return (
                        json!({"jsonrpc": "2.0", "id": call_id, "error": {"code": REFUSED, "message": format!("Refused ({}): {} It was found in the tool's result, which was not passed on. Decision {decision}.", guard::BLOCKED_CODE, blocked.message), "data": {"gantry_code": guard::BLOCKED_CODE, "decision": decision}}}),
                        outcome,
                    );
                }
                if verdict.changed {
                    for (i, (pointer, _)) in found.iter().enumerate() {
                        if let (Some(slot), Some(text)) = (
                            answer.pointer_mut(pointer),
                            verdict.body["messages"][i].get("content"),
                        ) {
                            *slot = text.clone();
                        }
                    }
                }
            }
        }
        if let Some(answer) = answer.as_object_mut() {
            answer.insert("id".into(), call_id.clone());
        }
        (answer, outcome)
    }

    /// The caller's answer to a request a server sent, passed back to that server in the session it came in.
    async fn relay_answer(&self, message: &Map<String, Value>, owner: &str) {
        let Some(gantry_id) = message.get("id").and_then(Value::as_str) else {
            return;
        };
        let relayed = {
            let mut relayed = lock(&self.relayed);
            // Only the caller the request went to may answer it.
            match relayed.get(gantry_id) {
                Some(r) if r.owner == owner => relayed.remove(gantry_id),
                _ => None,
            }
        };
        let Some(relayed) = relayed else {
            return;
        };
        let mut answer = Value::Object(message.clone());
        answer["id"] = relayed.upstream_id.clone();
        self.post_upstream(relayed.server, &relayed.session, &relayed.conn, &answer)
            .await;
    }

    /// Streams a call's answer to the caller as it comes: progress notifications as they are, requests from the
    /// server relayed if the caller supports them (and refused if not), and the answer last, checked like any other.
    #[allow(clippy::too_many_arguments)]
    fn relay(
        self: Arc<Self>,
        mut events: Events,
        id: u64,
        call_id: Value,
        decision: String,
        asked: Asked,
        capabilities: Value,
        guards: Vec<Guardrail>,
        started: Instant,
    ) -> Response {
        let (tell, heard) = tokio::sync::mpsc::channel::<Bytes>(16);
        tokio::spawn(async move {
            let send = |message: &Value| {
                let tell = tell.clone();
                let event = format!("event: message\ndata: {message}\n\n");
                async move { tell.send(Bytes::from(event)).await.is_ok() }
            };
            let upstream = loop {
                let next = tokio::time::timeout(self.app.timeouts.first_byte, events.next()).await;
                let message = match next {
                    Err(_) => break Err(failure("timeout", "it did not answer in time")),
                    Ok(Err(failure)) => break Err(failure),
                    Ok(Ok(None)) => {
                        break Err(failure(
                            "unreadable_answer",
                            "its stream ended without an answer to Gantry's request",
                        ));
                    }
                    Ok(Ok(Some(message))) => message,
                };
                if answers(&message, id) {
                    break Ok(message);
                }
                if let (Some(method), Some(upstream_id)) =
                    (message["method"].as_str(), message.get("id"))
                {
                    let wanted = method.split('/').next().unwrap_or_default();
                    if method == "ping" {
                        let pong = json!({"jsonrpc": "2.0", "id": upstream_id, "result": {}});
                        self.post_upstream(events.server, &events.session, &events.conn, &pong)
                            .await;
                        continue;
                    }
                    if capabilities.get(wanted).is_none() {
                        let refusal = json!({"jsonrpc": "2.0", "id": upstream_id, "error": {"code": -32601, "message": format!("The MCP client behind Gantry did not say it supports {wanted}, so {method} was not passed to it.")}});
                        self.post_upstream(events.server, &events.session, &events.conn, &refusal)
                            .await;
                        continue;
                    }
                    let gantry_id = format!("gantry-{}", self.next.fetch_add(1, Ordering::Relaxed));
                    {
                        let mut relayed = lock(&self.relayed);
                        relayed.retain(|_, r| r.at.elapsed() < RELAY_FOR);
                        if relayed.len() < MAX_REMEMBERED {
                            relayed.insert(
                                gantry_id.clone(),
                                Relayed {
                                    server: events.server,
                                    upstream_id: upstream_id.clone(),
                                    session: events.session.clone(),
                                    conn: events.conn.clone(),
                                    owner: asked.key_sha256.clone(),
                                    at: Instant::now(),
                                },
                            );
                        }
                    }
                    let mut message = message.clone();
                    message["id"] = gantry_id.into();
                    if !send(&message).await {
                        break Err(failure("caller_left", "the caller closed the stream"));
                    }
                    continue;
                }
                if !send(&message).await {
                    break Err(failure("caller_left", "the caller closed the stream"));
                }
            };
            let (answer, outcome) = self
                .finish(upstream, &call_id, &decision, &asked, &guards, started)
                .await;
            let _ = send(&answer).await;
            record_outcome(&self, &decision, &asked, outcome).await;
        });
        let mut response = Response::new(Body::new(Channel(heard)));
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/event-stream"),
        );
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        response
    }

    /// Holds a call until an admin approves or denies it in the console, or until the rule's timeout. Returns who
    /// approved it. The call's arguments are kept while it waits, for the admin to read, and removed after.
    async fn wait_for_approval(
        &self,
        decision: &str,
        asked: &Asked,
        params: &Value,
        rule: &Rule,
    ) -> Result<String, Refusal> {
        let person = asked.person.clone().unwrap_or_default();
        let tool = format!(
            "{}.{}",
            asked.server.clone().unwrap_or_default(),
            asked.item.clone().map(|(_, t)| t).unwrap_or_default()
        );
        let timeout = rule.mcp.approval_timeout_seconds;
        let pending = json!({
            "person": person.name,
            "team": person.team,
            "tool": tool,
            "rule": rule.name,
            "arguments": params.get("arguments").cloned().unwrap_or(Value::Null),
            "status": "pending",
            "asked_at": gantry_core::audit::timestamp(),
            "exp": keep::now() + timeout + 60,
        });
        let unavailable = |err: String| {
            Refusal::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "approval_unavailable",
                format!(
                    "Refused: tool \"{tool}\" needs an admin's approval, and the request for it could not be kept: {err}. Try again, and tell your Gantry admin if it keeps failing."
                ),
            )
        };
        self.keep
            .put("approval", decision, pending)
            .await
            .map_err(unavailable)?;
        eprintln!(
            "gantry: MCP call {decision} to {tool} by \"{}\" waits for an admin's approval in the console (/console/mcp/approvals)",
            person.name
        );
        let deadline = Instant::now() + Duration::from_secs(timeout);
        while Instant::now() < deadline {
            tokio::time::sleep(APPROVAL_POLL).await;
            let now = self
                .keep
                .get("approval", decision)
                .await
                .map_err(unavailable)?;
            let status = now
                .as_ref()
                .and_then(|v| v["status"].as_str())
                .unwrap_or("pending");
            let by = now
                .as_ref()
                .and_then(|v| v["by"].as_str())
                .unwrap_or("an admin")
                .to_string();
            match status {
                "approved" => {
                    let _ = self.keep.take("approval", decision).await;
                    return Ok(by);
                }
                "denied" => {
                    let _ = self.keep.take("approval", decision).await;
                    return Err(Refusal::new(
                        StatusCode::FORBIDDEN,
                        "approval_denied",
                        format!(
                            "Refused: rule \"{}\" needs an admin's approval for tool \"{tool}\", and {by} denied this call. Ask them why before you try again.",
                            rule.name
                        ),
                    ));
                }
                _ => {}
            }
        }
        let _ = self.keep.take("approval", decision).await;
        Err(Refusal::new(
            StatusCode::FORBIDDEN,
            "approval_timeout",
            format!(
                "Refused: rule \"{}\" needs an admin's approval for tool \"{tool}\", and none approved this call within {timeout} seconds. Ask a Gantry admin to watch the console's MCP approvals page, then try again.",
                rule.name
            ),
        ))
    }
}

/// Every string in a JSON value, with its JSON pointer under `at`.
fn strings(value: &Value, at: String, out: &mut Vec<(String, String)>) {
    match value {
        Value::String(text) => out.push((at, text.clone())),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                strings(item, format!("{at}/{i}"), out);
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                let key = key.replace('~', "~0").replace('/', "~1");
                strings(item, format!("{at}/{key}"), out);
            }
        }
        _ => {}
    }
}

/// The events of a stream as an HTTP body.
struct Channel(tokio::sync::mpsc::Receiver<Bytes>);

impl http_body::Body for Channel {
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

/// The decision record of one message, as model requests have, with the MCP method, server and tool.
async fn record(
    mcp: &Mcp,
    version: &Snapshot,
    decision: &str,
    asked: &Asked,
    refusal: Option<&Refusal>,
) -> Result<(), Refusal> {
    let path = asked
        .bundle
        .as_ref()
        .map_or_else(|| "/mcp".to_string(), |b| format!("/mcp/{b}"));
    let entry = Entry {
        id: decision,
        person: asked.person.as_ref().map(|p| p.name.as_str()),
        team: asked.person.as_ref().map(|p| p.team.as_str()),
        client: asked.client.as_deref(),
        key: asked.key.as_deref(),
        method: "POST",
        path: &path,
        allowed: refusal.is_none(),
        code: refusal.map(|r| r.code),
        rule: asked.rule.as_ref().map(|r| r.name.as_str()),
        rule_line: asked.rule.as_ref().map(|r| r.line).filter(|line| *line > 0),
        policy_sha256: &version.policy_sha256,
        keys_sha256: &version.keys_sha256,
        ..Entry::default()
    };
    let mut record = gantry_core::audit::record(&entry);
    let item = asked.item.as_ref().map(|(_, v)| v.clone());
    for (field, value) in [
        ("mcp_method", &asked.method),
        ("server", &asked.server),
        (asked.item.as_ref().map_or("tool", |(f, _)| *f), &item),
        ("bundle", &asked.bundle),
    ] {
        if let Some(value) = value {
            // Cut like every caller-chosen string on a record, so a caller cannot choose a record's size.
            record.insert(
                field.into(),
                value.chars().take(200).collect::<String>().into(),
            );
        }
    }
    if let Some(via) = asked.via {
        record.insert("via".into(), via.into());
    }
    for (field, value) in &asked.extra {
        record.insert(field.clone(), value.clone());
    }
    crate::mark_would_refuse(&mut record, asked.would_refuse.clone(), refusal.is_none());
    if append(mcp, &record).await {
        return Ok(());
    }
    eprintln!("gantry: the audit log could not be written, so decision {decision} was refused");
    Err(Refusal::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "audit_unavailable",
        "Refused: Gantry could not write this call to its audit log, and it does not forward what it cannot record. Tell your Gantry admin.",
    ))
}

/// Appends one record and waits for it. `true` when it is on file, or when this Gantry keeps no audit log.
async fn append(mcp: &Mcp, record: &Map<String, Value>) -> bool {
    let Some(audit) = &mcp.app.audit else {
        return true;
    };
    let (tell, written) = tokio::sync::oneshot::channel();
    audit.log.append_record_then(record, move |result| {
        let _ = tell.send(result);
    });
    matches!(written.await, Ok(Ok(())))
}

/// A record of something the gateway noticed or did that is no one request: a changed tool, a sign-in.
async fn event(mcp: &Mcp, name: &str, fields: Value) {
    let mut record = Map::new();
    record.insert("event".into(), name.into());
    record.insert("id".into(), id::decision_id().into());
    record.insert("time".into(), gantry_core::audit::timestamp().into());
    if let Value::Object(fields) = fields {
        record.extend(fields);
    }
    if !append(mcp, &record).await {
        eprintln!("gantry: the {name} record could not be written to the audit log: {record:?}");
    }
}

/// How a forwarded call ended, after its decision record. The tool has run by now, so a failure to write this is
/// reported and the answer still goes back.
async fn record_outcome(mcp: &Mcp, decision: &str, asked: &Asked, outcome: Map<String, Value>) {
    let mut record = Map::new();
    record.insert("event".into(), "mcp_result".into());
    record.insert("id".into(), decision.into());
    record.insert("time".into(), gantry_core::audit::timestamp().into());
    record.insert(
        "person".into(),
        asked.person.as_ref().map(|p| p.name.as_str()).into(),
    );
    record.insert(
        "team".into(),
        asked.person.as_ref().map(|p| p.team.as_str()).into(),
    );
    record.insert("key".into(), asked.key.as_deref().into());
    record.insert("server".into(), asked.server.as_deref().into());
    let (field, value) = asked.item.clone().unwrap_or(("tool", String::new()));
    record.insert(
        field.into(),
        value.chars().take(200).collect::<String>().into(),
    );
    record.extend(outcome);
    if !append(mcp, &record).await {
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

/// A server's answer: one JSON body, or an event stream still being read.
enum Reply {
    Answer(Value),
    Events(Events),
}

/// An event stream from a server, read one message at a time.
struct Events {
    body: Body,
    read: Vec<u8>,
    server: usize,
    session: Session,
    conn: Conn,
}

impl Events {
    /// The next message in the stream, `None` at its end.
    async fn next(&mut self) -> Result<Option<Value>, Failure> {
        loop {
            if let Some((message, used)) = first_event(&self.read) {
                self.read.drain(..used);
                match message {
                    Some(message) => return Ok(Some(message)),
                    None => continue,
                }
            }
            match self.body.frame().await {
                Some(Ok(frame)) => {
                    let Ok(data) = frame.into_data() else {
                        continue;
                    };
                    if self.read.len() + data.len() > MAX_BODY_BYTES {
                        return Err(failure(
                            "unreadable_answer",
                            "one event of its stream is larger than Gantry reads",
                        ));
                    }
                    self.read.extend_from_slice(&data);
                }
                Some(Err(_)) => {
                    return Err(failure("unreadable_answer", "its stream broke off"));
                }
                None => {
                    // A last event the server did not end with a blank line still counts.
                    let rest = std::mem::take(&mut self.read);
                    return Ok(event_message(&String::from_utf8_lossy(&rest)));
                }
            }
        }
    }
}

/// The first whole event of a server-sent event stream read so far: its JSON-RPC message if it carries one, and
/// how many bytes it took. `None` while no event has ended yet.
fn first_event(read: &[u8]) -> Option<(Option<Value>, usize)> {
    let lf = read.windows(2).position(|w| w == b"\n\n").map(|i| (i, 2));
    let crlf = read
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| (i, 4));
    let (end, sep) = match (lf, crlf) {
        (Some(a), Some(b)) => {
            if a.0 <= b.0 {
                a
            } else {
                b
            }
        }
        (a, b) => a.or(b)?,
    };
    Some((
        event_message(&String::from_utf8_lossy(&read[..end])),
        end + sep,
    ))
}

fn event_message(event: &str) -> Option<Value> {
    let data: Vec<&str> = event
        .lines()
        .filter_map(|line| line.trim_end_matches('\r').strip_prefix("data:"))
        .map(|data| data.strip_prefix(' ').unwrap_or(data))
        .collect();
    if data.is_empty() {
        return None;
    }
    serde_json::from_str::<Value>(&data.join("\n")).ok()
}

/// Whether a JSON-RPC message is the answer to request `id`.
fn answers(message: &Value, id: u64) -> bool {
    message["id"].as_u64() == Some(id)
        && (message.get("result").is_some() || message.get("error").is_some())
}

impl Mcp {
    /// Sends one request to a server and returns its answer, read whole. Requests the server sends meanwhile are
    /// refused: the caller of this one cannot answer them.
    async fn ask(
        &self,
        index: usize,
        conn: &Conn,
        method: &str,
        params: Value,
    ) -> Result<Value, Failure> {
        let exchange = async {
            let (reply, id) = self.start(index, conn, method, params).await?;
            self.drain(reply, id).await
        };
        tokio::time::timeout(self.app.timeouts.first_byte, exchange)
            .await
            .unwrap_or_else(|_| Err(failure("timeout", "it did not answer in time")))
    }

    /// Reads a reply to its answer.
    async fn drain(&self, reply: Reply, id: u64) -> Result<Value, Failure> {
        let mut events = match reply {
            Reply::Answer(answer) => return Ok(answer),
            Reply::Events(events) => events,
        };
        let read = async {
            while let Some(message) = events.next().await? {
                if answers(&message, id) {
                    return Ok(message);
                }
                if let (Some(method), Some(upstream_id)) =
                    (message["method"].as_str(), message.get("id"))
                {
                    let reply = if method == "ping" {
                        json!({"jsonrpc": "2.0", "id": upstream_id, "result": {}})
                    } else {
                        json!({"jsonrpc": "2.0", "id": upstream_id, "error": {"code": -32601, "message": format!("Gantry cannot pass {method} to its caller on this request: the caller did not ask for an event stream.")}})
                    };
                    self.post_upstream(events.server, &events.session, &events.conn, &reply)
                        .await;
                }
            }
            Err(failure(
                "unreadable_answer",
                "its answer holds no JSON-RPC answer to Gantry's request",
            ))
        };
        tokio::time::timeout(self.app.timeouts.first_byte, read)
            .await
            .unwrap_or_else(|_| Err(failure("timeout", "it did not answer in time")))
    }

    /// Sends one request in the server's session for `conn`, opening one first if there is none, and once more in a
    /// new session if the server says the old one has ended. Returns the reply and the id the request was sent with.
    async fn start(
        &self,
        index: usize,
        conn: &Conn,
        method: &str,
        params: Value,
    ) -> Result<(Reply, u64), Failure> {
        let server = &self.servers[index];
        for _ in 0..2 {
            let session = self.session(index, conn).await?;
            let id = self.next.fetch_add(1, Ordering::Relaxed);
            let body = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
            match self.send(index, Some(&session), conn, &body).await {
                Err(f) if f.outcome == "session_ended" => {
                    lock(&server.sessions).remove(&conn.key);
                }
                other => return other.map(|(reply, _)| (reply, id)),
            }
        }
        Err(failure(
            "session_ended",
            "it ended the new session as soon as it was opened",
        ))
    }

    async fn session(&self, index: usize, conn: &Conn) -> Result<Session, Failure> {
        let server = &self.servers[index];
        if let Some(session) = lock(&server.sessions).get(&conn.key).cloned() {
            return Ok(session);
        }
        // ponytail: two calls that find no session at once both open one, and the last one is kept. Harmless: an
        // upstream server ends the other when it times it out.
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let body = json!({"jsonrpc": "2.0", "id": id, "method": "initialize", "params": {
            "protocolVersion": UPSTREAM_VERSION,
            // Requests a server sends inside a call's stream are passed to the caller when it supports them.
            "capabilities": {"sampling": {}, "elicitation": {}, "roots": {"listChanged": false}},
            "clientInfo": {"name": "gantry", "version": gantry_core::VERSION},
        }});
        let (reply, session_id) = self.send(index, None, conn, &body).await?;
        let answer = self.drain(reply, id).await?;
        if let Some(error) = answer.get("error") {
            return Err(failure(
                "initialize_refused",
                format!("it refused Gantry's initialize: {error}"),
            ));
        }
        let session = Session {
            id: session_id,
            version: answer["result"]["protocolVersion"]
                .as_str()
                .unwrap_or(UPSTREAM_VERSION)
                .to_string(),
        };
        let notified = self
            .send(
                index,
                Some(&session),
                conn,
                &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            )
            .await;
        if let Err(f) = notified {
            return Err(failure(
                if f.outcome == "timeout" {
                    "timeout"
                } else {
                    "initialize_refused"
                },
                format!("it did not take notifications/initialized: {}", f.detail),
            ));
        }
        lock(&server.sessions).insert(conn.key.clone(), session.clone());
        Ok(session)
    }

    fn request(
        &self,
        index: usize,
        session: Option<&Session>,
        conn: &Conn,
        body: &Value,
    ) -> Result<axum::http::Request<Body>, Failure> {
        let server = &self.servers[index];
        let mut request = axum::http::Request::post(&server.url)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream");
        if let Some(session) = session {
            request = request.header("mcp-protocol-version", &session.version);
            if let Some(id) = &session.id {
                request = request.header("mcp-session-id", id);
            }
        }
        for (name, value) in server.headers.iter().chain(&conn.headers) {
            request = request.header(name, value);
        }
        request.body(Body::from(body.to_string())).map_err(|err| {
            failure(
                "unreachable",
                format!("the request could not be built: {err}"),
            )
        })
    }

    /// Sends a notification or an answer to a server, which takes it with 202 and says nothing more.
    async fn post_upstream(&self, index: usize, session: &Session, conn: &Conn, message: &Value) {
        if let Err(f) = self.send(index, Some(session), conn, message).await {
            eprintln!(
                "gantry: MCP server \"{}\" did not take an answer Gantry passed on from its caller: {}",
                self.servers[index].name, f.detail
            );
        }
    }

    /// One POST to a server. Returns its reply (an answer read whole, an event stream to read, or nothing for a 202)
    /// and the session ID it gave, if any.
    async fn send(
        &self,
        index: usize,
        session: Option<&Session>,
        conn: &Conn,
        body: &Value,
    ) -> Result<(Reply, Option<String>), Failure> {
        let request = self.request(index, session, conn, body)?;
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
            if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                return Err(failure(
                    "unauthorized",
                    format!("it refused the credential Gantry sent (status {status})"),
                ));
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
            let body = Body::new(response.into_body());
            if stream {
                return Ok((
                    Reply::Events(Events {
                        body,
                        read: Vec::new(),
                        server: index,
                        session: session.cloned().unwrap_or(Session {
                            id: session_id.clone(),
                            version: UPSTREAM_VERSION.to_string(),
                        }),
                        conn: conn.clone(),
                    }),
                    session_id,
                ));
            }
            let read = axum::body::to_bytes(body, MAX_BODY_BYTES)
                .await
                .map_err(|_| failure("unreadable_answer", "its answer could not be read"))?;
            if read.is_empty() || status == StatusCode::ACCEPTED {
                return Ok((Reply::Answer(Value::Null), session_id));
            }
            let answer = serde_json::from_slice::<Value>(&read).map_err(|_| {
                failure(
                    "unreadable_answer",
                    "its answer holds no JSON-RPC answer to Gantry's request",
                )
            })?;
            Ok((Reply::Answer(answer), session_id))
        };
        // The wait for the first byte; a stream's events are each waited for by whoever reads them.
        let reply = tokio::time::timeout(self.app.timeouts.first_byte, exchange)
            .await
            .unwrap_or_else(|_| Err(failure("timeout", "it did not answer in time")))?;
        // A JSON answer to another id is no answer to this request.
        if let (Reply::Answer(answer), Some(id)) = (&reply.0, body["id"].as_u64())
            && body.get("method").is_some()
            && !answers(answer, id)
        {
            return Err(failure(
                "unreadable_answer",
                "its answer holds no JSON-RPC answer to Gantry's request",
            ));
        }
        Ok(reply)
    }
}

#[cfg(test)]
mod tests {
    use super::{first_event, strings};

    #[test]
    fn events_are_read_one_at_a_time_once_each_is_whole() {
        let progress = r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{}}"#;
        let answer = r#"{"jsonrpc":"2.0","id":4,"result":{"content":[]}}"#;
        let stream = format!(
            "event: message\r\ndata: {progress}\r\n\r\nevent: message\r\ndata: {answer}\r\n\r\n"
        );
        let Some((first, used)) = first_event(stream.as_bytes()) else {
            panic!("the first event is whole");
        };
        assert_eq!(
            first.map(|m| m["method"].clone()),
            Some("notifications/progress".into())
        );
        let Some((second, _)) = first_event(&stream.as_bytes()[used..]) else {
            panic!("the second event is whole");
        };
        assert_eq!(second.map(|m| m["id"].clone()), Some(4.into()));
        // Not before its event has ended.
        let cut = format!("data: {answer}\n");
        assert!(first_event(cut.as_bytes()).is_none());
    }

    #[test]
    fn every_string_is_found_with_its_pointer() {
        let mut found = Vec::new();
        strings(
            &serde_json::json!({"a": ["x", {"b/c": "y"}], "n": 1}),
            String::new(),
            &mut found,
        );
        assert_eq!(
            found,
            [
                ("/a/0".to_string(), "x".to_string()),
                ("/a/1/b~1c".to_string(), "y".to_string())
            ]
        );
    }
}
