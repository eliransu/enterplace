//! The MCP gateway: `/mcp`, MCP's Streamable HTTP transport, in front of the upstream MCP servers a policy names.
//!
//! A caller signs in with its Enterplace key or an OAuth access token Enterplace issued (`oauth`). Enterplace answers
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

pub(crate) mod console;
mod duplex;
pub(crate) mod keep;
mod oauth;
pub(crate) mod sessions;

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
use enterplace_core::{
    audit::Entry,
    guard::{self, Guardrail},
    id,
    mcp::{Bundle, ToolChanges, Transport, UserAuth, tool_allowed},
    policy::{Policy, Principal, Rule},
};
use http_body_util::BodyExt;
use serde_json::{Map, Value, json};

pub use keep::McpSetup;

use crate::{
    AppState, ClientAddr, ConfigError, DECISION, MAX_BODY_BYTES, Refusal, Secret, Snapshot,
    checked_upstream, killed, read_body,
};
use keep::Keep;

/// The MCP protocol versions Enterplace speaks to callers, newest first.
const VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26"];
/// The version Enterplace asks each upstream server for.
const UPSTREAM_VERSION: &str = "2025-06-18";
/// Pages of one server's list Enterplace reads, so a server that always answers with a next cursor cannot hold a list
/// forever.
const MAX_PAGES: usize = 100;
/// JSON-RPC error code of an Enterplace refusal, in the range JSON-RPC leaves to servers.
const REFUSED: i64 = -32001;
/// MCP's error for "the caller must open a URL first" (URL mode elicitation): a person's credential is missing.
const URL_REQUIRED: i64 = -32042;
/// Shown resource URIs: `enterplace://<server>/<the server's own URI>`.
const RESOURCE_SCHEME: &str = "enterplace://";
/// How long a request a server sent to a caller waits for the caller's answer before it is forgotten.
const RELAY_FOR: Duration = Duration::from_secs(30 * 60);
/// Most callers' sessions and relayed requests remembered at once.
const MAX_REMEMBERED: usize = 10_000;
/// How often a server that keeps answering the same has its health written again, for its last listed time.
const HEALTH_EVERY: Duration = Duration::from_secs(60);
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
    /// The client secret for `user_auth: oauth` with a client registered by hand, or of a token exchange.
    pub oauth_client_secret: Option<Secret>,
    pub transport: Transport,
    /// A stdio server's environment, read from the gateway's: (the process's variable, its value).
    pub stdio_env: Vec<(String, Secret)>,
    /// What a call of any tool costs, in US dollars, and of the tools priced by name.
    pub call_price_usd: Option<f64>,
    pub tool_prices: Vec<(String, f64)>,
}

impl McpRoute {
    /// A server reached over Streamable HTTP with no credential and no price: what most embedders and tests need.
    pub fn http(name: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            url: url.into(),
            headers: Vec::new(),
            user_auth: None,
            tool_changes: ToolChanges::default(),
            oauth_client_secret: None,
            transport: Transport::Http,
            stdio_env: Vec::new(),
            call_price_usd: None,
            tool_prices: Vec::new(),
        }
    }

    /// Everything that decides how the server is reached, secrets by their hash: a server whose print is the
    /// same after a reload keeps its sessions.
    fn print(&self) -> String {
        let secrets: Vec<String> = self
            .headers
            .iter()
            .chain(&self.stdio_env)
            .map(|(name, secret)| format!("{name}={}", id::sha256_hex(secret.0.as_bytes())))
            .chain(
                self.oauth_client_secret
                    .iter()
                    .map(|s| id::sha256_hex(s.0.as_bytes())),
            )
            .collect();
        format!(
            "{}|{}|{:?}|{:?}|{:?}|{secrets:?}|{:?}|{:?}",
            self.name,
            self.url,
            self.transport,
            self.user_auth,
            self.tool_changes,
            self.call_price_usd,
            self.tool_prices
        )
    }
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
    transport: Transport,
    stdio_env: Vec<(String, String)>,
    /// The open connection of each session of a server that is not Streamable HTTP (`duplex`).
    duplex: tokio::sync::Mutex<HashMap<String, Arc<duplex::Duplex>>>,
    call_price_usd: Option<f64>,
    tool_prices: Vec<(String, f64)>,
    /// Tokens got by token exchange, by the hash of the token they were traded for: (token, its expiry).
    exchanged: Mutex<HashMap<String, (String, u64)>>,
    print: String,
}

impl Upstream {
    /// What one call of `tool` (the server's own name) costs, when the policy prices it.
    fn price_of(&self, tool: &str) -> Option<f64> {
        self.tool_prices
            .iter()
            .find(|(name, _)| name == tool)
            .map(|(_, price)| *price)
            .or(self.call_price_usd)
    }
}

type Server = Arc<Upstream>;
/// The policy's servers, and the same as the gateway reaches them.
type Served = (Arc<Vec<McpRoute>>, Arc<Vec<Server>>);

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

/// A request a server sent inside a stream, passed to the caller under an id of Enterplace's.
struct Relayed {
    server: Server,
    upstream_id: Value,
    session: Session,
    conn: Conn,
    /// The SHA-256 of the credential of the caller it went to: only that caller may answer it.
    owner: String,
    at: Instant,
}

/// What a caller said it supports at `initialize`, under the session id Enterplace gave it.
struct CallerSession {
    owner: String,
    capabilities: Value,
    at: Instant,
    /// For the sessions list: who opened it, as what client, when, and when it was last used.
    person: String,
    team: String,
    org: String,
    client_name: Option<String>,
    client_version: Option<String>,
    user_agent: Option<String>,
    oauth_client: Option<String>,
    bundle: Option<String>,
    started: String,
    last_used: String,
}

pub(crate) struct Mcp {
    app: AppState,
    /// The servers of the policy version they were built from. A reload that changes `mcp:` puts a new list in the
    /// version; the next request builds what changed and keeps the rest, sessions included.
    servers: Mutex<Served>,
    // Each request to an upstream server gets its own id: callers share a session, so their ids could collide.
    next: AtomicU64,
    keep: Keep,
    sso: bool,
    audit_path: Option<std::path::PathBuf>,
    callers: Mutex<HashMap<String, CallerSession>>,
    /// Sessions an admin ended: a request in one is refused until its client connects again.
    revoked: Mutex<HashSet<String>>,
    relayed: Mutex<HashMap<String, Relayed>>,
    /// One pinning at a time on this gateway, so one change is recorded once.
    pinning: tokio::sync::Mutex<()>,
    /// Each server's health as this gateway last wrote it to the store: (up, when), so a list writes only a change
    /// or every HEALTH_EVERY.
    health: Mutex<HashMap<String, (bool, Instant)>>,
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
    pub console: enterplace_console::Extension,
}

/// The `/mcp` routes, when the policy names MCP servers.
pub(crate) fn router(
    app: &AppState,
    routes: Arc<Vec<McpRoute>>,
    setup: McpSetup,
) -> Result<Option<Built>, ConfigError> {
    // Served whenever there is a policy to reload: a server added later needs the routes to be there.
    if routes.is_empty() && app.reloader.is_none() {
        return Ok(None);
    }
    let mut servers = Vec::new();
    for route in routes.iter() {
        servers.push(Arc::new(upstream_of(route)?));
    }
    let (sso, audit_path) = (setup.sso, setup.audit_path.clone());
    let keep = Keep::start(setup).map_err(ConfigError)?;
    if let Some(server) = servers.iter().find(|s| keeps_credentials(&s.user_auth))
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
        servers: Mutex::new((routes, Arc::new(servers))),
        next: AtomicU64::new(1),
        keep,
        sso,
        audit_path,
        callers: Mutex::default(),
        revoked: Mutex::default(),
        relayed: Mutex::default(),
        pinning: tokio::sync::Mutex::new(()),
        health: Mutex::default(),
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
    // For the admin API's session routes. Weak: the gateway's routes own the MCP gateway, not its own state.
    let _ = app.mcp.set(Arc::downgrade(&mcp));
    Ok(Some(Built {
        router,
        console: console::extension(mcp),
    }))
}

/// Whether each person's own credential to a server is kept, sealed: not so for a token traded on every call.
pub(crate) fn keeps_credentials(auth: &Option<UserAuth>) -> bool {
    matches!(auth, Some(UserAuth::Headers(_) | UserAuth::OAuth { .. }))
}

/// A server as requests are sent to it, from what the policy and the environment say of it.
fn upstream_of(route: &McpRoute) -> Result<Upstream, ConfigError> {
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
    Ok(Upstream {
        url: if matches!(route.transport, Transport::Stdio { .. }) {
            String::new()
        } else {
            checked_upstream(&route.url)?
        },
        name: route.name.clone(),
        headers,
        user_auth: route.user_auth.clone(),
        tool_changes: route.tool_changes,
        client_secret: route.oauth_client_secret.as_ref().map(|s| s.0.clone()),
        sessions: Mutex::default(),
        transport: route.transport.clone(),
        stdio_env: route
            .stdio_env
            .iter()
            .map(|(name, secret)| (name.clone(), secret.0.clone()))
            .collect(),
        duplex: tokio::sync::Mutex::default(),
        call_price_usd: route.call_price_usd,
        tool_prices: route.tool_prices.clone(),
        exchanged: Mutex::default(),
        print: route.print(),
    })
}

impl Mcp {
    /// The servers of the policy version in use. After a reload that changed them, a server reached as before is
    /// kept with its sessions, and a new or changed one is built now.
    fn servers(&self) -> Arc<Vec<Server>> {
        let version = self.app.version();
        let mut held = lock(&self.servers);
        if !Arc::ptr_eq(&held.0, &version.mcp) {
            let mut servers = Vec::new();
            for route in version.mcp.iter() {
                let print = route.print();
                match held.1.iter().find(|s| s.print == print) {
                    Some(kept) => servers.push(kept.clone()),
                    None => match upstream_of(route) {
                        Ok(built) => servers.push(Arc::new(built)),
                        // The reload checked it, so this is not reached; said rather than served half built.
                        Err(err) => eprintln!("enterplace: {err} The server is left out."),
                    },
                }
            }
            *held = (version.mcp.clone(), Arc::new(servers));
        }
        held.1.clone()
    }
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
            // No stream of Enterplace's own to listen to: server requests come inside the stream of a call.
            let mut response = (
                StatusCode::METHOD_NOT_ALLOWED,
                "Enterplace's MCP endpoint takes POST, and DELETE to end a session: it opens no stream of its own. Requests from servers come inside the stream that answers a call.",
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
    /// The caller's `user-agent`, which names the coding tool for the coverage report.
    user_agent: Option<String>,
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
    /// This Enterplace as the caller reached it, for the links it hands out.
    origin: String,
    /// `oauth` when the caller signed in with an OAuth access token.
    via: Option<&'static str>,
    /// The OAuth client the caller signed in through, and what the client called itself at `initialize`.
    oauth_client: Option<String>,
    client_name: Option<String>,
    /// The token the caller holds at its identity provider (`x-enterplace-subject-token`), for a server reached by
    /// token exchange. Never recorded.
    subject: Option<String>,
    /// What the call costs when the server answers it, and the budgets it counts against.
    price: Option<(f64, Vec<(String, enterplace_core::policy::Period)>)>,
    /// More fields of the decision record: guardrail findings, who approved, whose credential went upstream.
    extra: Map<String, Value>,
    /// Where the caller signs in to an upstream server, when its credential is missing.
    connect: Option<String>,
    /// What observe mode or the rule's shadow period let through.
    would_refuse: Vec<Value>,
    /// The events plugins of the caller's rule and the call's session and turn, kept for the tool's result.
    plugins: Option<Arc<(Vec<Guardrail>, enterplace_core::events::Context)>>,
}

async fn post(mcp: &Shared, bundle: Option<String>, request: Request, decision: &str) -> Response {
    let (parts, body) = request.into_parts();
    let mut asked = Asked {
        client: parts
            .extensions
            .get::<ClientAddr>()
            .map(|addr| addr.0.ip().to_string()),
        user_agent: parts
            .headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .filter(|v| !v.is_empty())
            .map(str::to_string),
        origin: oauth::origin(&parts),
        subject: parts
            .headers
            .get(SUBJECT_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty()),
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
    let tool = asked.item.as_ref().map_or("", |(_, name)| name.as_str());
    let fix = crate::fix::fix(
        refusal.code,
        &crate::fix::Facts {
            base: &asked.origin,
            caller: asked.person.as_ref().map_or("", |p| p.name.as_str()),
            team: asked.person.as_ref().map_or("", |p| p.team.as_str()),
            rule: asked.rule.as_ref().map_or("", |r| r.name.as_str()),
            server: asked.server.as_deref().unwrap_or_default(),
            tool,
            message: &refusal.message,
            record: refusal.record.as_deref(),
            ..crate::fix::Facts::default()
        },
    );
    let fixed = fix
        .as_ref()
        .map(|f| format!(" {}", crate::fix::sentence(f)))
        .unwrap_or_default();
    let message = match refusal.message.strip_prefix("Refused: ") {
        Some(rest) => format!(
            "Refused ({}): {rest}{fixed} Decision {decision}.",
            refusal.code
        ),
        None => format!("{}{fixed} Decision {decision}.", refusal.message),
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
    let mut data = json!({"enterplace_code": refusal.code, "decision": decision});
    if let Some(fix) = fix {
        data["fix"] = fix;
    }
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

/// What a list method lists, and how Enterplace renames it.
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

/// Whether the tool a caller names `<server>.<tool>` is switched off in the console's tool catalog.
fn disabled(policy: &Policy, name: &str) -> bool {
    name.split_once('.').is_some_and(|(server, tool)| {
        policy
            .mcp_server(server)
            .is_some_and(|s| s.tool_disabled(tool))
    })
}

/// What the policy says of a tool beyond the caller's rule: switched off, and who its server is granted to.
#[derive(Clone, Copy)]
struct Gate<'a> {
    policy: &'a Policy,
    /// The caller, whose grants apply. `None` while observing (observe mode, a rule's shadow period): the rule
    /// decides alone, and what a grant would refuse is recorded apart.
    person: Option<&'a Principal>,
}

impl Gate<'_> {
    /// `None` when the tool's server has no access list; otherwise whether the caller is granted the tool.
    fn granted(&self, name: &str) -> Option<bool> {
        let person = self.person?;
        let (server, tool) = name.split_once('.')?;
        self.policy
            .mcp_server(server)?
            .grants_tool(&person.team, &person.name, tool)
    }
}

/// Whether the rule (and the bundle, at `/mcp/<bundle>`) allows `name`, written `<server>.<name>`. A tool switched
/// off is allowed by nothing. On a server with an access list, its grants allow a tool in place of the rule's
/// `tools:`, and the rule's `!` entries still deny.
fn allows(item: Item, rule: &Rule, bundle: Option<&Bundle>, name: &str, gate: Gate) -> bool {
    if item == Item::Tool && disabled(gate.policy, name) {
        return false;
    }
    let in_bundle = match (item, bundle) {
        (_, None) => true,
        (Item::Tool, Some(bundle)) => tool_allowed(&bundle.tools, name),
        // A bundle serves tools only.
        (_, Some(_)) => false,
    };
    let by_rule = match (item, gate.granted(name)) {
        (Item::Tool, Some(granted)) => {
            granted
                && !rule
                    .tools
                    .iter()
                    .filter_map(|p| p.strip_prefix('!'))
                    .any(|p| enterplace_core::mcp::pattern_matches(p, name))
        }
        _ => tool_allowed(item.patterns(rule), name),
    };
    in_bundle
        && by_rule
        && (item != Item::Tool || rule.mcp.narrow.iter().all(|l| tool_allowed(l, name)))
}

/// The header a caller gives the token it holds at its identity provider in, for servers reached by token exchange.
pub(crate) const SUBJECT_HEADER: &str = "x-enterplace-subject-token";

/// The header a caller narrows its tools with, for one request: a comma separated list of `tools:` patterns.
pub(crate) const NARROW_HEADER: &str = "x-enterplace-mcp-tools";

/// The rule as this request sees it: its tools narrowed by the key's `mcp_tools` and the `x-enterplace-mcp-tools`
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
            || !list
                .iter()
                .all(|t| enterplace_core::mcp::narrowing_entry(t))
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
            "Refused: this Enterplace runs without a policy, so it serves no MCP tools. Start it with a policy file that lists servers under mcp.",
        ));
    };
    let bundle = match &asked.bundle {
        Some(name) => Some(policy.mcp_bundle(name).cloned().ok_or_else(|| {
            Refusal::new(
                StatusCode::NOT_FOUND,
                "unknown_bundle",
                format!(
                    "Refused: no MCP bundle is named \"{name}\", so /mcp/{name} serves nothing. Connect to /mcp, or ask an Enterplace admin which bundles the policy's mcp_bundles names."
                ),
            )
        })?),
        None => None,
    };
    let resource = format!("{}{}", asked.origin, parts.uri.path());
    let (person, key_sha256, via) = mcp
        .authenticate(policy, &parts.headers, &resource, asked)
        .await?;
    crate::cert_bound(&person, parts.extensions.get())?;
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
                "Refused: MCP bundle \"{}\" is for team {}, and \"{}\" is of team \"{}\". Connect to /mcp, or ask an Enterplace admin to add your team to the bundle.",
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
    let session_header = parts
        .headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok());
    let capabilities = session_header
        .and_then(|session| {
            lock(&mcp.callers)
                .get_mut(session)
                .filter(|s| s.owner == key_sha256)
                .map(|s| {
                    s.last_used = enterplace_core::audit::timestamp();
                    asked.client_name = s.client_name.clone();
                    s.capabilities.clone()
                })
        })
        .unwrap_or_else(|| json!({}));
    if method != "initialize"
        && let Some(session) = session_header
        && lock(&mcp.revoked).contains(session)
    {
        return Err(Refusal::new(
            StatusCode::NOT_FOUND,
            "session_revoked",
            "Refused: an Enterplace admin ended this MCP session. Connect the MCP client again to open a new one.",
        ));
    }
    let item = match method {
        "initialize" => return Ok(mcp.initialize(&call_id, &params, asked, bundle.as_ref())),
        "ping" => return Ok(result(&call_id, json!({}))),
        "tools/call" => Some(Item::Tool),
        "prompts/get" => Some(Item::Prompt),
        "resources/read" => Some(Item::Resource),
        "tools/list" | "prompts/list" | "resources/list" | "resources/templates/list" => None,
        _ => {
            return Ok(json_response(
                StatusCode::OK,
                &json!({"jsonrpc": "2.0", "id": call_id, "error": {"code": -32601, "message": format!("Enterplace's MCP endpoint serves initialize, ping, tools/list, tools/call, prompts/list, prompts/get, resources/list, resources/templates/list and resources/read; \"{method}\" is not one of them.")}}),
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
    // tool (`enterplace kill --model github.delete_repo`) stops that one tool for everyone.
    killed(&mcp.app, &person, &key_sha256, named.as_deref())?;
    let no_rule = Refusal::new(
        StatusCode::FORBIDDEN,
        "no_rule",
        format!(
            "Refused: no rule in the policy names \"{}\" or team \"{}\", so no MCP tool is allowed. Ask an Enterplace admin to add a rule with the tools you need.",
            person.name, person.team
        ),
    );
    let rule = crate::rule_or_observed(policy, &person, no_rule, |r, by| {
        asked.would_refuse.push(crate::would_refuse_entry(r, by));
    })?;
    let rule = &narrowed(rule, &person, &parts.headers)?;
    asked.rule = Some(rule.clone());
    let shadow = policy.observing(rule.shadow_until.as_deref());
    if !rule.mcp.clients.is_empty() {
        let client = asked
            .client_name
            .clone()
            .or_else(|| asked.user_agent.clone())
            .unwrap_or_else(|| "unnamed".into());
        asked.extra.insert(
            "mcp_client".into(),
            client.chars().take(200).collect::<String>().into(),
        );
        if !enterplace_core::mcp::client_allowed(
            &rule.mcp.clients,
            asked.client_name.as_deref(),
            asked.user_agent.as_deref(),
            asked.oauth_client.as_deref(),
        ) {
            let refusal = Refusal::new(
                StatusCode::FORBIDDEN,
                "mcp_client_not_allowed",
                format!(
                    "Refused: rule \"{}\" lets only these MCP clients connect: {}. This client called itself \"{client}\". Use one of them, or ask an Enterplace admin to add this client to the rule's mcp_clients.",
                    rule.name,
                    rule.mcp.clients.join(", ")
                ),
            );
            match shadow {
                Some(by) => asked
                    .would_refuse
                    .push(crate::would_refuse_entry(refusal, by)),
                None => return Err(refusal),
            }
        }
    }
    // Observe mode or the rule's shadow period: every tool, prompt and resource is listed and may be used, and one
    // the rule does not allow is recorded as would_refuse.
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
        let gate = Gate {
            policy,
            person: listed.is_none().then_some(&person),
        };
        let items = mcp
            .gather(
                item,
                listed.as_ref().unwrap_or(rule),
                bundle.as_ref(),
                &person,
                asked.subject.as_deref(),
                gate,
            )
            .await;
        return Ok(result(&call_id, json!({ item.key(): items })));
    };
    if item == Item::Tool && disabled(policy, &name) {
        return Err(Refusal::new(
            StatusCode::FORBIDDEN,
            "tool_disabled",
            format!(
                "Refused: tool \"{name}\" is switched off for everyone in this Enterplace's tool catalog. Ask an Enterplace admin to switch it on (MCP, Servers, Tools) if you need it."
            ),
        ));
    }
    let caller = Gate {
        policy,
        person: Some(&person),
    };
    if item == Item::Tool && caller.granted(&name) == Some(false) {
        let refusal = Refusal::new(
            StatusCode::FORBIDDEN,
            "mcp_access_denied",
            format!(
                "Refused: MCP server \"{}\" may be used only by the teams, people and apps an Enterplace admin granted it to, and \"{}\" of team \"{}\" is not granted tool \"{name}\". Ask an Enterplace admin to grant it to you or your team in the console (MCP, Servers, Access).",
                asked.server.as_deref().unwrap_or_default(),
                person.name,
                person.team
            ),
        );
        match shadow {
            Some(by) => asked
                .would_refuse
                .push(crate::would_refuse_entry(refusal, by)),
            None => return Err(refusal),
        }
    }
    let gate = Gate {
        policy,
        person: shadow.is_none().then_some(&person),
    };
    if !allows(item, rule, bundle.as_ref(), &name, gate) {
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
                    "Refused: tool \"{name}\" is allowed by rule \"{}\", and left out by this key's mcp_tools or the request's {NARROW_HEADER} header, which only narrow it. Remove it from the header, or ask an Enterplace admin to change the key's mcp_tools.",
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
                "Refused: rule \"{}\" does not allow {noun} \"{name}\" for \"{}\" of team \"{}\". {allowed} Ask an Enterplace admin to add it to the rule's {field} if you need it.",
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
    let servers = mcp.servers();
    let server = asked
        .server
        .as_deref()
        .and_then(|s| servers.iter().find(|u| u.name == s))
        .cloned()
        .ok_or_else(|| {
            let names: Vec<&str> = servers.iter().map(|s| s.name.as_str()).collect();
            Refusal::new(
                StatusCode::NOT_FOUND,
                "unknown_tool",
                format!(
                    "Refused: \"{name}\" is on no MCP server of this Enterplace. Names are <server>.<name>, and the servers are: {}. Run {} for the names.",
                    names.join(", "),
                    item.list_method()
                ),
            )
        })?;
    let server = &server;
    let conn = match mcp.conn(server, &person, asked.subject.as_deref()).await {
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
        let upstream = mcp.ask(server, &conn, method, forwarded).await;
        let (response, outcome) = mcp
            .finish(upstream, &call_id, decision, asked, &[], started)
            .await;
        record_outcome(mcp, decision, asked, outcome).await;
        return Ok(json_response(StatusCode::OK, &response));
    }
    mcp.check_pin(server, &conn, &own).await?;
    // A priced tool counts against the budgets of whoever calls it, and is refused once one of them is spent.
    if let Some(price) = server.price_of(&own) {
        let budgets = policy.applied(
            &person,
            rule,
            enterplace_core::policy::Context {
                sent: &name,
                model: &name,
                customer: None,
                tags: &[],
            },
        );
        if price > 0.0 && !crate::spend::room(&mcp.app.spend, &budgets).await {
            let refusal = Refusal::new(
                StatusCode::TOO_MANY_REQUESTS,
                "budget_exceeded",
                format!(
                    "Refused: tool \"{name}\" costs ${price} a call, and a budget \"{}\" counts against (of rule \"{}\", its key or the limits: list) is spent for this period. It starts again at the next period; ask an Enterplace admin to raise it if you need more before then.",
                    person.name, rule.name
                ),
            );
            match shadow {
                Some(by) => asked
                    .would_refuse
                    .push(crate::would_refuse_entry(refusal, by)),
                None => return Err(refusal),
            }
        }
        let counted = budgets
            .into_iter()
            .filter_map(|a| match a.limit {
                enterplace_core::policy::Limit::Budget(b) => Some((a.scope, b.per)),
                _ => None,
            })
            .collect();
        asked.price = Some((price, counted));
    }
    let observe = policy.mode() == enterplace_core::policy::Mode::Observe;
    let guards: Vec<Guardrail> = crate::guards_of(policy, Some(&person), rule);
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
    // Events plugins see the call as it will be sent: the tool, and its arguments after the guardrails.
    if crate::events::active(&mcp.app, &guards) {
        use enterplace_core::events as core;
        let plugins = crate::events::guards_for(&mcp.app, &guards);
        let context =
            crate::events::context_of(&person, &parts.headers, "mcp", decision, "/mcp", "");
        asked
            .extra
            .insert("session".into(), context.session_id.as_str().into());
        asked
            .extra
            .insert("turn".into(), context.turn_id.as_str().into());
        if let Some(refusal) = crate::events::refused_session(&mcp.app, &plugins, &context) {
            return Err(refusal);
        }
        let mut call = core::Event::mcp_call(
            &server.name,
            &own,
            forwarded.get("arguments").cloned().unwrap_or(json!({})),
        );
        call.at = vec!["/arguments".into()];
        let call = [call.placed(&context.turn_id, 0)];
        let judged = crate::events::judge(
            &mcp.app,
            &plugins,
            &context,
            "mcp",
            &call,
            None,
            "this tool call",
        )
        .await;
        if observe {
            asked
                .would_refuse
                .extend(crate::would_block(rule, &judged.audit));
        }
        if !judged.audit.is_empty() {
            let mut found: Vec<Value> = asked
                .extra
                .get("guardrails")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            found.extend(judged.audit.iter().map(|entry| json!(entry)));
            asked.extra.insert("guardrails".into(), found.into());
        }
        asked.extra.insert("events".into(), judged.entries.into());
        if let Some(blocked) = judged.blocked {
            return Err(Refusal::new(
                StatusCode::FORBIDDEN,
                guard::BLOCKED_CODE,
                format!("Refused: {}", blocked.message),
            ));
        }
        if !judged.masks.is_empty() {
            if let Some(params) = forwarded.as_object_mut() {
                params.entry("arguments").or_insert_with(|| json!({}));
            }
            // Never forward the unmasked arguments because the masked ones could not be written.
            core::apply_masks(&mut forwarded, &call, &judged.masks).map_err(|cause| {
                eprintln!("enterplace: decision {decision}: an events plugin's mask of an MCP tool call could not be written: {cause}");
                Refusal::new(
                    StatusCode::BAD_GATEWAY,
                    guard::BLOCKED_CODE,
                    "Refused: an events plugin masked this tool call's arguments, and its mask could not be written, so the call was not made. Tell your Enterplace admin.",
                )
            })?;
        }
        asked.plugins = Some(Arc::new((plugins, context)));
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
    let reply = mcp.start(server, &conn, "tools/call", forwarded).await;
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
        asked: &Asked,
        bundle: Option<&Bundle>,
    ) -> Response {
        let owner = asked.key_sha256.as_str();
        let info = |field: &str| {
            params["clientInfo"][field]
                .as_str()
                .map(|v| v.chars().take(200).collect::<String>())
        };
        let person = asked.person.clone().unwrap_or_default();
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
                    person: person.name,
                    team: person.team,
                    org: person.org,
                    client_name: info("name"),
                    client_version: info("version"),
                    user_agent: asked.user_agent.clone(),
                    oauth_client: asked.oauth_client.clone(),
                    bundle: asked.bundle.clone(),
                    started: enterplace_core::audit::timestamp(),
                    last_used: enterplace_core::audit::timestamp(),
                },
            );
        }
        let name = bundle.map_or("enterplace", |b| b.name.as_str());
        let instructions = match bundle {
            Some(b) => format!(
                "MCP bundle {}: chosen tools of the MCP servers behind this Enterplace, named <server>.<tool>. Only the tools your policy rule allows are listed.",
                b.name
            ),
            None => "Tools, prompts and resources of the MCP servers behind this Enterplace, named <server>.<name>. Only what your policy rule allows is listed.".to_string(),
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
                "serverInfo": {"name": name, "version": enterplace_core::VERSION},
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
        subject: Option<&str>,
        gate: Gate<'_>,
    ) -> Vec<Value> {
        let mut out = Vec::new();
        for server in self.servers().iter() {
            let conn = match self.conn(server, person, subject).await {
                Ok(conn) => conn,
                Err(_) => {
                    // Without the person's credential the server cannot be asked. A tool that says how to connect
                    // takes the place of its tools, so the person learns where to sign in.
                    let name = format!("{}.connect", server.name);
                    if item == Item::Tool && allows(Item::Tool, rule, bundle, &name, gate) {
                        out.push(json!({
                            "name": name,
                            "description": format!("Connect your own account to MCP server {}. Its tools are listed once you have. Call this tool for the link.", server.name),
                            "inputSchema": {"type": "object", "properties": {}},
                        }));
                    }
                    continue;
                }
            };
            let items = self.list_server(server, &conn, item).await;
            let hidden = if item == Item::Tool {
                self.observe(server, &items).await
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
                if allows(item, rule, bundle, &check, gate) {
                    let mut entry = entry.clone();
                    entry[item.field()] = item.shown(&server.name, own).into();
                    out.push(entry);
                }
            }
        }
        out
    }

    /// One server's whole list of one kind, every page. A server that fails is left out, with a line on stderr.
    async fn list_server(&self, server: &Server, conn: &Conn, item: Item) -> Vec<Value> {
        let listed = self.list_checked(server, conn, item).await;
        // The shared credential's answer is the server's health; one person's credential says only theirs.
        if item == Item::Tool && conn.key.is_empty() {
            let up = listed.is_ok();
            let due = lock(&self.health)
                .get(&server.name)
                .is_none_or(|(was, at)| *was != up || at.elapsed() >= HEALTH_EVERY);
            if due {
                self.note_health(server, &listed).await;
            }
        }
        match listed {
            Ok(out) => out,
            Err((out, why)) => {
                eprintln!(
                    "enterplace: MCP server \"{}\" {why}, so it is left out of the list",
                    server.name
                );
                out
            }
        }
    }

    /// Writes what one tool list says of the server's health to the store, where every gateway and the console read
    /// it: up or down, when it last listed its tools and how many, and its last error.
    async fn note_health(
        &self,
        server: &Server,
        listed: &Result<Vec<Value>, (Vec<Value>, String)>,
    ) -> Value {
        let at = enterplace_core::audit::timestamp();
        let mut health = self
            .keep
            .get("health", &server.name)
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| json!({"listed_at": null, "tools": null, "last_error": null}));
        health["checked_at"] = at.clone().into();
        match listed {
            Ok(tools) => {
                health["status"] = "up".into();
                health["listed_at"] = at.into();
                health["tools"] = tools.len().into();
                health["error"] = Value::Null;
            }
            Err((_, why)) => {
                let why = format!("{} {why}", server.name);
                health["status"] = "down".into();
                health["error"] = why.clone().into();
                health["last_error"] = why.into();
                health["last_error_at"] = at.into();
            }
        }
        if let Err(err) = self.keep.put("health", &server.name, health.clone()).await {
            eprintln!(
                "enterplace: the health of MCP server \"{}\" could not be written: {err}",
                server.name
            );
        }
        lock(&self.health).insert(server.name.clone(), (listed.is_ok(), Instant::now()));
        health
    }

    /// One server's whole list of one kind, or what it listed before it failed and why.
    async fn list_checked(
        &self,
        server: &Server,
        conn: &Conn,
        item: Item,
    ) -> Result<Vec<Value>, (Vec<Value>, String)> {
        let mut out = Vec::new();
        let mut cursor: Option<Value> = None;
        for _ in 0..MAX_PAGES {
            let params = match &cursor {
                Some(cursor) => json!({"cursor": cursor}),
                None => json!({}),
            };
            let page = match self.ask(server, conn, item.list_method(), params).await {
                Ok(answer) if answer.get("result").is_some() => answer,
                Ok(answer) => {
                    let why = format!("refused {} ({})", item.list_method(), answer["error"]);
                    return Err((out, why));
                }
                Err(failure) => {
                    let why = format!(
                        "gave no answer to {}: {}",
                        item.list_method(),
                        failure.detail
                    );
                    return Err((out, why));
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
        Ok(out)
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
                eprintln!("enterplace: decision {decision}: on an MCP tool call: {cause}");
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
                let mut data = json!({"enterplace_code": format!("upstream_{}", failure.outcome), "decision": decision});
                let mut code = -32603;
                let mut message = format!(
                    "Enterplace got no answer from MCP server \"{server}\": {}. It may or may not have run there. Try again, and tell your Enterplace admin if it keeps failing. Decision {decision}.",
                    failure.detail
                );
                // A person's credential the server no longer takes: they sign in to it again.
                if failure.outcome == "unauthorized"
                    && let (Some(upstream), Some(person)) = (
                        self.servers().iter().find(|s| s.name == server).cloned(),
                        &asked.person,
                    )
                    && matches!(
                        upstream.user_auth,
                        Some(UserAuth::Headers(_) | UserAuth::OAuth { .. })
                    )
                    && let Ok(url) = self.connect_link(&upstream, person, &asked.origin).await
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
                        json!({"jsonrpc": "2.0", "id": call_id, "error": {"code": REFUSED, "message": format!("Refused ({}): {} It was found in the tool's result, which was not passed on. Decision {decision}.", guard::BLOCKED_CODE, blocked.message), "data": {"enterplace_code": guard::BLOCKED_CODE, "decision": decision}}}),
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
        // Events plugins see the tool's result as the caller is about to get it.
        if answer.get("error").is_none()
            && let Some(kept) = &asked.plugins
        {
            use enterplace_core::events as core;
            let (plugins, context) = &**kept;
            let mut text = Vec::new();
            let mut at = Vec::new();
            for (i, part) in answer["result"]["content"]
                .as_array()
                .into_iter()
                .flatten()
                .enumerate()
            {
                if let Some(piece) = part.get("text").and_then(Value::as_str) {
                    text.push(piece.to_string());
                    at.push(format!("/result/content/{i}/text"));
                }
            }
            let tool = asked.item.as_ref().map_or("", |(_, name)| name.as_str());
            let mut event = core::Event::mcp_result(&server, tool, text.join("\n"));
            event.at = at;
            let event = [event.placed(&context.turn_id, 1)];
            let judged = crate::events::judge(
                &self.app,
                plugins,
                context,
                "mcp",
                &event,
                None,
                "this tool's result",
            )
            .await;
            if !judged.audit.is_empty() {
                let mut found: Vec<Value> = outcome
                    .get("guardrails")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                found.extend(judged.audit.iter().map(|entry| json!(entry)));
                outcome.insert("guardrails".into(), found.into());
            }
            outcome.insert("events".into(), judged.entries.into());
            let unwritten = judged.blocked.is_none()
                && core::apply_masks(&mut answer, &event, &judged.masks).is_err();
            if let Some(message) = judged
                .blocked
                .map(|b| b.message)
                .or_else(|| unwritten.then(|| "An events plugin masked this tool's result, and its mask could not be written.".to_string()))
            {
                outcome.insert("outcome".into(), "guardrail_blocked".into());
                return (
                    json!({"jsonrpc": "2.0", "id": call_id, "error": {"code": REFUSED, "message": format!("Refused ({}): {message} The tool's result was not passed on. Decision {decision}.", guard::BLOCKED_CODE), "data": {"enterplace_code": guard::BLOCKED_CODE, "decision": decision}}}),
                    outcome,
                );
            }
        }
        if let Some(answer) = answer.as_object_mut() {
            answer.insert("id".into(), call_id.clone());
        }
        (answer, outcome)
    }

    /// The caller's answer to a request a server sent, passed back to that server in the session it came in.
    async fn relay_answer(&self, message: &Map<String, Value>, owner: &str) {
        let Some(enterplace_id) = message.get("id").and_then(Value::as_str) else {
            return;
        };
        let relayed = {
            let mut relayed = lock(&self.relayed);
            // Only the caller the request went to may answer it.
            match relayed.get(enterplace_id) {
                Some(r) if r.owner == owner => relayed.remove(enterplace_id),
                _ => None,
            }
        };
        let Some(relayed) = relayed else {
            return;
        };
        let mut answer = Value::Object(message.clone());
        answer["id"] = relayed.upstream_id.clone();
        self.post_upstream(&relayed.server, &relayed.session, &relayed.conn, &answer)
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
                            "its stream ended without an answer to Enterplace's request",
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
                        self.post_upstream(&events.server, &events.session, &events.conn, &pong)
                            .await;
                        continue;
                    }
                    if capabilities.get(wanted).is_none() {
                        let refusal = json!({"jsonrpc": "2.0", "id": upstream_id, "error": {"code": -32601, "message": format!("The MCP client behind Enterplace did not say it supports {wanted}, so {method} was not passed to it.")}});
                        self.post_upstream(&events.server, &events.session, &events.conn, &refusal)
                            .await;
                        continue;
                    }
                    let enterplace_id =
                        format!("enterplace-{}", self.next.fetch_add(1, Ordering::Relaxed));
                    {
                        let mut relayed = lock(&self.relayed);
                        relayed.retain(|_, r| r.at.elapsed() < RELAY_FOR);
                        if relayed.len() < MAX_REMEMBERED {
                            relayed.insert(
                                enterplace_id.clone(),
                                Relayed {
                                    server: events.server.clone(),
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
                    message["id"] = enterplace_id.into();
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
            "asked_at": enterplace_core::audit::timestamp(),
            "exp": keep::now() + timeout + 60,
        });
        let unavailable = |err: String| {
            Refusal::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "approval_unavailable",
                format!(
                    "Refused: tool \"{tool}\" needs an admin's approval, and the request for it could not be kept: {err}. Try again, and tell your Enterplace admin if it keeps failing."
                ),
            )
        };
        self.keep
            .put("approval", decision, pending)
            .await
            .map_err(unavailable)?;
        eprintln!(
            "enterplace: MCP call {decision} to {tool} by \"{}\" waits for an admin's approval in the console (/console/mcp/approvals)",
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
                "Refused: rule \"{}\" needs an admin's approval for tool \"{tool}\", and none approved this call within {timeout} seconds. Ask an Enterplace admin to watch the console's MCP approvals page, then try again.",
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
        user_agent: asked.user_agent.as_deref(),
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
    let mut record = enterplace_core::audit::record(&entry);
    if let (Some(refusal), Some(_)) = (refusal, &asked.item) {
        count(mcp, asked, refusal.code);
    }
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
    eprintln!("enterplace: the audit log could not be written, so decision {decision} was refused");
    Err(Refusal::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "audit_unavailable",
        "Refused: Enterplace could not write this call to its audit log, and it does not forward what it cannot record. Tell your Enterplace admin.",
    ))
}

/// Appends one record and waits for it. `true` when it is on file, or when this Enterplace keeps no audit log.
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
    record.insert("time".into(), enterplace_core::audit::timestamp().into());
    if let Value::Object(fields) = fields {
        record.extend(fields);
    }
    if !append(mcp, &record).await {
        eprintln!(
            "enterplace: the {name} record could not be written to the audit log: {record:?}"
        );
    }
}

/// Counts a call to a tool, prompt or resource for `/metrics`, by server and outcome. A server the policy does not
/// name is counted as `unknown`, so a caller cannot add label values.
fn count(mcp: &Mcp, asked: &Asked, outcome: &str) {
    let server = asked
        .server
        .as_deref()
        .filter(|name| mcp.servers().iter().any(|s| s.name == *name))
        .unwrap_or("unknown");
    mcp.app.metrics.mcp_called(server, outcome);
}

/// How a forwarded call ended, after its decision record. The tool has run by now, so a failure to write this is
/// reported and the answer still goes back.
async fn record_outcome(mcp: &Mcp, decision: &str, asked: &Asked, outcome: Map<String, Value>) {
    count(
        mcp,
        asked,
        outcome
            .get("outcome")
            .and_then(Value::as_str)
            .unwrap_or("ok"),
    );
    let mut record = Map::new();
    record.insert("event".into(), "mcp_result".into());
    record.insert("id".into(), decision.into());
    record.insert("time".into(), enterplace_core::audit::timestamp().into());
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
    // A priced call the server answered is charged, as a model's answer is: a usage record, and its budgets.
    let ran = matches!(
        outcome.get("outcome").and_then(Value::as_str),
        Some("ok" | "tool_error" | "guardrail_blocked")
    );
    if let (Some((price, counted)), Some(person), true) = (&asked.price, &asked.person, ran) {
        let version = mcp.app.version();
        let tool = format!("{}.{value}", asked.server.as_deref().unwrap_or_default());
        let mut extra = Map::new();
        extra.insert("mcp_tool".into(), tool.as_str().into());
        let (charged, mut usage) = crate::spend::charge(
            &mcp.app.spend,
            crate::spend::Line {
                decision,
                person: &person.name,
                team: &person.team,
                key: &person.key,
                org: &person.org,
                customer: None,
                tags: &[],
                counted,
                model: &tool,
                provider: "mcp",
                version: (&version.policy_sha256, &version.keys_sha256),
                price: None,
                usage: None,
                share: 1.0,
                unreported: *price,
                succeeded: true,
                extra,
            },
        );
        record.insert("charged_usd".into(), charged.into());
        // The price is the policy's: what the call cost is known, where a model's unreported usage is not.
        usage.insert("cost_usd".into(), charged.into());
        usage.insert("price".into(), "known".into());
        usage.insert("usage".into(), "per_call".into());
        if !append(mcp, &usage).await {
            eprintln!(
                "enterplace: the usage record of MCP call {decision} could not be written to the audit log"
            );
        }
    }
    record.extend(outcome);
    if !append(mcp, &record).await {
        eprintln!(
            "enterplace: the outcome of MCP call {decision} could not be written to the audit log; its decision record is there"
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
    server: Server,
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
                            "one event of its stream is larger than Enterplace reads",
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
        server: &Server,
        conn: &Conn,
        method: &str,
        params: Value,
    ) -> Result<Value, Failure> {
        let exchange = async {
            let (reply, id) = self.start(server, conn, method, params).await?;
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
                        json!({"jsonrpc": "2.0", "id": upstream_id, "error": {"code": -32601, "message": format!("Enterplace cannot pass {method} to its caller on this request: the caller did not ask for an event stream.")}})
                    };
                    self.post_upstream(&events.server, &events.session, &events.conn, &reply)
                        .await;
                }
            }
            Err(failure(
                "unreadable_answer",
                "its answer holds no JSON-RPC answer to Enterplace's request",
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
        server: &Server,
        conn: &Conn,
        method: &str,
        params: Value,
    ) -> Result<(Reply, u64), Failure> {
        for _ in 0..2 {
            let session = self.session(server, conn).await?;
            let id = self.next.fetch_add(1, Ordering::Relaxed);
            let body = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
            match self.send(server, Some(&session), conn, &body).await {
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

    async fn session(&self, server: &Server, conn: &Conn) -> Result<Session, Failure> {
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
            "clientInfo": {"name": "enterplace", "version": enterplace_core::VERSION},
        }});
        let (reply, session_id) = self.send(server, None, conn, &body).await?;
        let answer = self.drain(reply, id).await?;
        if let Some(error) = answer.get("error") {
            return Err(failure(
                "initialize_refused",
                format!("it refused Enterplace's initialize: {error}"),
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
                server,
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
        server: &Server,
        session: Option<&Session>,
        conn: &Conn,
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
    async fn post_upstream(
        &self,
        server: &Server,
        session: &Session,
        conn: &Conn,
        message: &Value,
    ) {
        if let Err(f) = self.send(server, Some(session), conn, message).await {
            eprintln!(
                "enterplace: MCP server \"{}\" did not take an answer Enterplace passed on from its caller: {}",
                server.name, f.detail
            );
        }
    }

    /// One POST to a server. Returns its reply (an answer read whole, an event stream to read, or nothing for a 202)
    /// and the session ID it gave, if any.
    async fn send(
        &self,
        server: &Server,
        session: Option<&Session>,
        conn: &Conn,
        body: &Value,
    ) -> Result<(Reply, Option<String>), Failure> {
        if !matches!(server.transport, Transport::Http) {
            let answer = self
                .send_duplex(server, session.is_some(), conn, body)
                .await?;
            return Ok((Reply::Answer(answer), None));
        }
        let request = self.request(server, session, conn, body)?;
        let exchange = async {
            let response = self
                .app
                .client
                .request(request)
                .await
                .map_err(|_| failure("unreachable", "it could not be reached"))?;
            let status = response.status();
            if status == StatusCode::NOT_FOUND && session.is_some_and(|s| s.id.is_some()) {
                return Err(failure("session_ended", "it ended Enterplace's session"));
            }
            if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                return Err(failure(
                    "unauthorized",
                    format!("it refused the credential Enterplace sent (status {status})"),
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
                        server: server.clone(),
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
                    "its answer holds no JSON-RPC answer to Enterplace's request",
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
                "its answer holds no JSON-RPC answer to Enterplace's request",
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
