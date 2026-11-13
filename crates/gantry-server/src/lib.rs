//! HTTP server of the Gantry AI gateway.

use std::{
    collections::BTreeMap,
    future::Future,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Request, State},
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, Version, header,
        request::Parts,
    },
    response::{IntoResponse, Response},
    routing::{any, get, head},
};
use gantry_core::{
    audit::{AuditLog, Entry},
    config::Kind,
    eventstream, gemini,
    guard::{self, Guardrail},
    id,
    policy::{Decision, Models, Policy, Principal, Rule},
    sigv4, translate,
};

mod admin;
mod alias;
mod metrics;
mod reload;
mod spend;

use http_body_util::BodyExt;
use hyper_rustls::HttpsConnector;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::{conn::auto::Builder, graceful::GracefulShutdown},
    service::TowerToHyperService,
};
pub use reload::{Governed, Reload, Reloader, Trigger, governed};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower::ServiceExt;

/// Address the server binds to when none is given.
/// Loopback only: exposing the gateway is an explicit choice.
pub const DEFAULT_ADDR: &str = "127.0.0.1:8080";

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;

/// Largest request body the gateway reads. Large enough for prompts that carry images.
pub const MAX_BODY_BYTES: usize = 32 * MIB;

/// Most request-body bytes held in memory at once, across all callers.
/// Without this, a handful of callers sending the largest body at the same time decide how much memory the gateway uses.
pub const MAX_BUFFERED_BYTES: usize = 256 * MIB;

/// The most of that budget one caller's requests may hold, so one key cannot use up the memory every other caller needs.
pub const MAX_BUFFERED_BYTES_PER_CALLER: usize = MAX_BUFFERED_BYTES / 4;

/// The memory a request's body holds: its part of the whole budget and of its caller's share.
type Held = Vec<OwnedSemaphorePermit>;

/// The routes this version forwards, and the kind of provider each one reaches.
const CHAT: &str = "/v1/chat/completions";
const MESSAGES: &str = "/v1/messages";
const COUNT_TOKENS: &str = "/v1/messages/count_tokens";
const MODELS: &str = "/v1/models";
/// OpenAI's Responses API (Codex CLI and newer SDKs) and embeddings: forwarded as sent, to openai providers only.
const RESPONSES: &str = "/v1/responses";
const EMBEDDINGS: &str = "/v1/embeddings";
/// Images, audio, moderations and rerank: forwarded as sent, to openai providers only. Transcriptions come as
/// multipart/form-data, whose `model` field is what the policy reads.
const IMAGES: &str = "/v1/images/generations";
const TRANSCRIPTIONS: &str = "/v1/audio/transcriptions";
const SPEECH: &str = "/v1/audio/speech";
const MODERATIONS: &str = "/v1/moderations";
const RERANK: &str = "/v1/rerank";

/// The routes forwarded as sent, to providers of kind openai only.
fn openai_only(path: &str) -> bool {
    matches!(
        path,
        RESPONSES | EMBEDDINGS | IMAGES | TRANSCRIPTIONS | SPEECH | MODERATIONS | RERANK
    )
}

fn route_kind(method: &Method, path: &str) -> Option<Kind> {
    if method != Method::POST {
        return None;
    }
    match path {
        CHAT => Some(Kind::OpenAi),
        _ if openai_only(path) => Some(Kind::OpenAi),
        MESSAGES | COUNT_TOKENS => Some(Kind::Anthropic),
        _ => None,
    }
}

/// A query parameter's name, the values it takes in words, and the test of a value.
type Param = (&'static str, &'static str, fn(&str) -> bool);

/// The query parameters each route may carry, each with the values it may take. Anything else is refused, never
/// dropped. Values are checked too: a value is forwarded as sent, so a free one could carry anything to the
/// provider, the caller's own Gantry key included.
fn allowed_query(path: &str) -> &'static [Param] {
    match path {
        // Claude Code adds beta=true to the messages routes.
        MESSAGES | COUNT_TOKENS => &[("beta", "true or false", |v| matches!(v, "true" | "false"))],
        // Anthropic's model list takes up to 1000 per page.
        MODELS => &[("limit", "a whole number from 1 to 1000", |v| {
            v.len() <= 4
                && v.bytes().all(|b| b.is_ascii_digit())
                && v.parse::<u16>().is_ok_and(|n| (1..=1000).contains(&n))
        })],
        _ => &[],
    }
}
const DECISION: HeaderName = HeaderName::from_static("x-gantry-decision");

/// How long the gateway waits at each point where the other side could stall it forever.
#[derive(Clone, Debug)]
pub struct Timeouts {
    /// For a client to finish sending its request headers, from the moment it connects or finishes a request.
    pub read_headers: Duration,
    /// For a client to finish sending its request body.
    pub read_body: Duration,
    /// For a TCP connection to the provider.
    pub connect: Duration,
    /// For the provider to start answering. Models can think for a long time before the first byte.
    pub first_byte: Duration,
    /// For requests in flight to finish after a stop signal.
    pub shutdown: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            read_headers: Duration::from_secs(10),
            read_body: Duration::from_secs(30),
            connect: Duration::from_secs(5),
            first_byte: Duration::from_secs(120),
            shutdown: Duration::from_secs(30),
        }
    }
}

/// A provider key. It can be cloned and sent, and it cannot be printed.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[secret]")
    }
}

/// Where decisions are recorded, and what each record says about the setup that made it.
#[derive(Clone, Debug)]
pub struct Audit {
    pub log: Arc<AuditLog>,
    pub provider: String,
    pub policy_sha256: String,
    pub keys_sha256: String,
}

/// A provider as the server sees it: where it is, how to authenticate to it, and what it serves.
#[derive(Clone, Debug, Default)]
pub struct ProviderRoute {
    pub name: String,
    pub kind: Kind,
    /// Base URL, for example `https://api.anthropic.com`. It may end in the vendor's path, such as `/openai/v1`.
    pub url: String,
    pub key: Option<Secret>,
    /// The exact model names it serves. Empty means every model: only the single `upstream` of tests and benchmarks.
    pub models: Vec<String>,
    /// The name the provider knows each model by: the Azure deployment or the Bedrock model ID.
    pub upstream_models: BTreeMap<String, String>,
    /// Azure's api-version.
    pub api_version: Option<String>,
    /// Bedrock's AWS region, and the access key its requests are signed with.
    pub region: Option<String>,
    pub aws: Option<sigv4::Credentials>,
    /// The provider a request goes to when this one fails before the answer starts.
    pub fallback: Option<String>,
    /// How many times such a failure is tried again on this provider first.
    pub retries: u32,
    /// Chat completions requests for its models are translated to the messages API.
    pub accept_chat: bool,
    /// Messages requests (Claude Code) for its models are translated to the chat completions API.
    pub accept_messages: bool,
}

/// What the server needs to start.
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// The providers requests are forwarded to. A request goes to the one that lists its model.
    pub providers: Vec<ProviderRoute>,
    /// One base URL that serves every model on the chat route, for tests, benchmarks and `--unchecked`.
    pub upstream: Option<String>,
    /// The policy every request is checked against. `None` forwards everything unchecked, for benchmarks on loopback.
    pub policy: Option<Policy>,
    /// Sent to `upstream` in place of the caller's Gantry key.
    pub provider_key: Option<Secret>,
    /// With a policy and no audit log, decisions are made and not recorded. Only tests and benchmarks run that way.
    pub audit: Option<Audit>,
    pub timeouts: Timeouts,
    /// Most request-body bytes held in memory at once. `None` is `MAX_BUFFERED_BYTES`. One caller gets a quarter of it.
    pub max_buffered_bytes: Option<usize>,
    /// The files of the admin console, served at `/console`. `None` serves no console.
    pub console: Option<gantry_console::ConsoleConfig>,
    /// The audit log whose usage records of the current month count against budgets from the start.
    pub spent_from: Option<PathBuf>,
    /// Model names callers send that are served by one or more deployments.
    pub aliases: Vec<gantry_core::config::Alias>,
}

/// A configuration the server refuses to start with. The message names the cause and the fix.
#[derive(Debug)]
pub struct ConfigError(String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

/// The address of the client on the other end of a connection.
#[derive(Clone, Copy)]
struct ClientAddr(SocketAddr);

/// What decides requests: the policy with its keys, the providers' models, and the hashes of the files they came
/// from. A reload replaces it whole, so a request is decided, recorded and sent under one version from start to end.
#[derive(Debug)]
struct Snapshot {
    policy: Option<Policy>,
    providers: Vec<Upstream>,
    aliases: Vec<gantry_core::config::Alias>,
    policy_sha256: String,
    keys_sha256: String,
}

/// The version in use. Requests take a snapshot of it. A reload puts a new one in place.
type Live = Arc<RwLock<Arc<Snapshot>>>;

#[derive(Clone)]
struct AppState {
    // One pooled client for the life of the process: connections to the provider are reused across requests.
    client: Client<HttpsConnector<HttpConnector>, Body>,
    live: Live,
    audit: Option<Audit>,
    reloader: Option<Arc<Reloader>>,
    timeouts: Timeouts,
    // One permit per KiB of request body held in memory.
    buffer: Arc<Semaphore>,
    // One caller's share of it, in KiB.
    share_kib: usize,
    // The same, per caller. Grows by one entry per person or workload that sends a request.
    shares: Arc<std::sync::Mutex<std::collections::HashMap<String, Arc<Semaphore>>>>,
    // Budgets, rate limits and the cache. Kept across reloads: a new policy does not forget what was spent.
    spend: Arc<spend::Spend>,
    // Counters for `/metrics`, shared with `spend`, which counts what was charged.
    metrics: Arc<metrics::Metrics>,
    // Kill switches, kept beside the keys file. None when Gantry serves no keys file.
    kills: Option<Arc<gantry_core::kill::Switches>>,
    // Which deployments of an alias are cooling down or busy. Kept across reloads.
    pool: Arc<alias::Pool>,
}

impl AppState {
    fn version(&self) -> Arc<Snapshot> {
        // A poisoned lock still holds a whole version: the writer swaps an Arc and cannot leave half of one.
        match self.live.read() {
            Ok(version) => version.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

/// A provider ready to be sent to: its checked base URL and its key as the header it goes in.
#[derive(Clone, Debug)]
struct Upstream {
    name: String,
    kind: Kind,
    url: String,
    key: Option<(HeaderName, HeaderValue)>,
    models: Vec<String>,
    upstream_models: BTreeMap<String, String>,
    api_version: Option<String>,
    region: Option<String>,
    aws: Option<sigv4::Credentials>,
    fallback: Option<String>,
    retries: u32,
    accept_chat: bool,
    accept_messages: bool,
}

impl Upstream {
    fn serves(&self, model: &str) -> bool {
        self.models.is_empty() || self.models.iter().any(|m| m == model)
    }
}

/// The provider key as the header its kind of provider expects, marked sensitive so nothing that prints headers shows it.
fn key_header(kind: Kind, key: &Secret) -> Result<(HeaderName, HeaderValue), ConfigError> {
    let (name, text) = match kind {
        // Vertex AI takes an OAuth access token as a Bearer token.
        // ponytail: the token comes from key_env at start and lasts about an hour; sign in with a service account if Vertex is used for long.
        Kind::OpenAi | Kind::Vertex | Kind::VertexAnthropic => {
            (header::AUTHORIZATION, format!("Bearer {}", key.0))
        }
        Kind::Gemini => (HeaderName::from_static("x-goog-api-key"), key.0.clone()),
        Kind::Anthropic => (HeaderName::from_static("x-api-key"), key.0.clone()),
        Kind::Azure => (HeaderName::from_static("api-key"), key.0.clone()),
        Kind::Bedrock => {
            return Err(ConfigError(
                "a bedrock provider takes no provider key: its requests are signed with the AWS access key. Remove the key and set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.".into(),
            ));
        }
    };
    let mut value = HeaderValue::from_str(&text).map_err(|_| {
        ConfigError("the provider key holds a character that cannot go in an HTTP header. Check the variable for a stray newline or quote.".into())
    })?;
    value.set_sensitive(true);
    Ok((name, value))
}

/// Builds the router. Tests and embedders call this directly.
pub fn app(config: Config) -> Result<Router, ConfigError> {
    build(config, |_| None).map(|(router, _, _)| router)
}

/// Builds the router, and the reloader that `make_reloader` makes from the live version, if it makes one.
/// The gateway's router, its reloader, and the router of `GET /metrics` for a listener of its own.
type Built = (Router, Option<Arc<Reloader>>, Router);

fn build(
    config: Config,
    make_reloader: impl FnOnce(&Live) -> Option<Arc<Reloader>>,
) -> Result<Built, ConfigError> {
    let upstream = config
        .upstream
        .map(|raw| checked_upstream(&raw))
        .transpose()?;
    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(config.timeouts.connect));
    connector.enforce_http(false);
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .wrap_connector(connector);
    let mut providers = Vec::new();
    for route in &config.providers {
        if route.kind == Kind::Bedrock && (route.aws.is_none() || route.region.is_none()) {
            return Err(ConfigError(format!(
                "provider \"{}\" is of kind bedrock and has no AWS region or access key. Set its region, and AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in Gantry's environment.",
                route.name
            )));
        }
        providers.push(Upstream {
            name: route.name.clone(),
            kind: route.kind,
            url: checked_upstream(&route.url)?,
            key: route
                .key
                .as_ref()
                .map(|key| key_header(route.kind, key))
                .transpose()?,
            models: route.models.clone(),
            upstream_models: route.upstream_models.clone(),
            api_version: route.api_version.clone(),
            region: route.region.clone(),
            aws: route.aws.clone(),
            fallback: route.fallback.clone(),
            retries: route.retries,
            accept_chat: route.accept_chat,
            accept_messages: route.accept_messages,
        });
    }
    if let Some(url) = upstream {
        // The single upstream of tests and benchmarks is named after the setup that records it.
        let name = config
            .audit
            .as_ref()
            .map_or_else(|| "upstream".to_string(), |a| a.provider.clone());
        providers.push(Upstream {
            name,
            kind: Kind::OpenAi,
            url,
            key: config
                .provider_key
                .as_ref()
                .map(|key| key_header(Kind::OpenAi, key))
                .transpose()?,
            models: Vec::new(),
            upstream_models: BTreeMap::new(),
            api_version: None,
            region: None,
            aws: None,
            fallback: None,
            retries: 0,
            accept_chat: false,
            accept_messages: false,
        });
    }
    let console = config.console;
    let budget = config.max_buffered_bytes.unwrap_or(MAX_BUFFERED_BYTES);
    let (policy_sha256, keys_sha256) = config.audit.as_ref().map_or_else(Default::default, |a| {
        (a.policy_sha256.clone(), a.keys_sha256.clone())
    });
    let live: Live = Arc::new(RwLock::new(Arc::new(Snapshot {
        policy: config.policy,
        providers,
        aliases: config.aliases,
        policy_sha256,
        keys_sha256,
    })));
    let reloader = make_reloader(&live);
    let spend = Arc::new(spend::Spend::default());
    if let Some(path) = &config.spent_from {
        spend.replay(path).map_err(ConfigError)?;
    }
    let state = AppState {
        client: Client::builder(TokioExecutor::new()).build(connector),
        live,
        audit: config.audit,
        reloader: reloader.clone(),
        timeouts: config.timeouts,
        buffer: Arc::new(Semaphore::new(budget / KIB)),
        share_kib: budget / 4 / KIB,
        shares: Arc::default(),
        metrics: spend.metrics.clone(),
        spend,
        kills: reloader.as_ref().map(|r| {
            Arc::new(gantry_core::kill::Switches::open(
                gantry_core::kill::path_beside(r.keys_path()),
            ))
        }),
        pool: Arc::default(),
    };
    let metrics = Router::new()
        .route("/metrics", get(metrics::serve))
        .with_state(state.clone());
    let mut router = Router::new()
        // Every other method on these two paths goes to `handle`, which refuses it with a decision and a record,
        // as it does any other request it does not serve.
        .route("/healthz", get(healthz).fallback(handle))
        // Claude Code warms its connection with this probe at startup. Answering it keeps one refused record per launch
        // out of the audit log. It reaches no provider and says nothing about who may do what.
        .route(
            "/api/hello",
            head(|| async { StatusCode::OK }).fallback(handle),
        );
    // The admin API changes the keys file, so it exists only when Gantry serves from one.
    if reloader.is_some() {
        router = router
            .route("/admin/keys", any(admin::handle))
            .route("/admin/keys/{prefix}", any(admin::handle))
            .route("/admin/kills", any(admin::handle));
    }
    let router = router.fallback(handle).with_state(state);
    let router = match console {
        Some(console) => router.nest("/console", gantry_console::router(console)),
        None => router,
    };
    Ok((router, reloader, metrics))
}

/// The provider URL by the one rule `gantry check` uses too (`gantry_core::config::base_url`), then parsed as a URI.
fn checked_upstream(raw: &str) -> Result<String, ConfigError> {
    let url = gantry_core::config::base_url(raw).map_err(|problem| {
        let mut problem = problem;
        if let Some(first) = problem.get_mut(..1) {
            first.make_ascii_uppercase();
        }
        ConfigError(problem)
    })?;
    match url.parse::<Uri>() {
        Ok(uri) if uri.host().is_some_and(|h| !h.is_empty()) => Ok(url),
        _ => Err(ConfigError(
            "The provider URL is not a URL. Write it like https://api.openai.com, or with the vendor's path, like https://api.groq.com/openai/v1.".into(),
        )),
    }
}

/// Healthy means able to do the job. A Gantry that can no longer write its audit log refuses every
/// request, so it says so here and a load balancer stops sending it traffic.
/// The body names the version in use, and a version on disk that was rejected, so an admin can see both at once.
async fn healthz(State(state): State<AppState>) -> Response {
    let (status, text) = match &state.audit {
        Some(audit) if audit.log.is_broken() => (
            StatusCode::SERVICE_UNAVAILABLE,
            "the audit log cannot be written",
        ),
        _ => (StatusCode::OK, "ok"),
    };
    let version = state.version();
    let rejected = state.reloader.as_ref().and_then(|r| r.rejected());
    let body = serde_json::json!({
        "status": text,
        "policy_sha256": version.policy_sha256,
        "keys_sha256": version.keys_sha256,
        "rejected": rejected.map(|(policy, keys)| serde_json::json!({ "policy_sha256": policy, "keys_sha256": keys })),
    });
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

/// Why a request does not go through. Every one has a stable code, the cause and the fix,
/// and never an address, an internal error or another caller's data.
struct Refusal {
    status: StatusCode,
    code: &'static str,
    message: String,
    retry: bool,
    /// Seconds the caller should wait, when that is known. Sent as Retry-After, and the caller may send again.
    retry_after: Option<u64>,
    /// UX12-2: fields the decision record gains, naming what refused it: `limit: {kind, of, value}` for a rate or
    /// TPM limit, `key_models: true` for the key's own model list. The console reads them.
    record: Option<Box<serde_json::Value>>,
}

impl Refusal {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            retry: false,
            retry_after: None,
            record: None,
        }
    }

    /// The response, in the shape the caller's client already knows how to show: Anthropic's on the messages
    /// routes, OpenAI's everywhere else. The decision ID is inside the message because most clients show only that.
    fn respond(self, decision: &str, anthropic: bool) -> Response {
        let message = match self.message.strip_prefix("Refused: ") {
            Some(rest) => format!("Refused ({}): {rest} Decision {decision}.", self.code),
            None => format!("{} Decision {decision}.", self.message),
        };
        let body = if anthropic {
            serde_json::json!({
                "type": "error",
                "error": { "type": anthropic_type(self.code, self.status), "message": message },
                "gantry_code": self.code,
                "decision": decision,
            })
        } else {
            serde_json::json!({ "error": { "message": message, "type": "gantry_error", "code": self.code, "decision": decision } })
        };
        let mut response = (
            self.status,
            [(header::CONTENT_TYPE, "application/json")],
            body.to_string(),
        )
            .into_response();
        if let Some(wait) = self.retry_after.or(self.retry.then_some(1)) {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, wait.into());
        }
        // Claude Code reads this to decide whether to send the request again. Only a full memory budget, a rate limit
        // or a provider that could not be reached may clear by itself; every other refusal would come back the same.
        let again = self.retry || self.retry_after.is_some() || self.code.starts_with("upstream_");
        response.headers_mut().insert(
            HeaderName::from_static("x-should-retry"),
            HeaderValue::from_static(if again { "true" } else { "false" }),
        );
        response
    }
}

/// The error type Anthropic's clients expect for each Gantry code. Fixed, so a client can rely on it.
fn anthropic_type(code: &str, status: StatusCode) -> &'static str {
    match code {
        "no_key" | "unknown_key" | "key_expired" => "authentication_error",
        "no_rule" | "model_not_allowed" | "unknown_model" | "killed" | guard::BLOCKED_CODE => {
            "permission_error"
        }
        "unknown_route" => "not_found_error",
        "body_too_large" => "request_too_large",
        "busy" if status == StatusCode::TOO_MANY_REQUESTS => "rate_limit_error",
        "rate_limited" | "budget_exceeded" | "key_budget_exceeded" => "rate_limit_error",
        "busy" => "overloaded_error",
        "upstream_timeout" => "timeout_error",
        _ if status.is_client_error() => "invalid_request_error",
        _ => "api_error",
    }
}

/// Headers that belong to one connection and must not travel through a proxy, in either direction.
fn hop_by_hop() -> [HeaderName; 8] {
    [
        header::CONNECTION,
        HeaderName::from_static("keep-alive"),
        header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHORIZATION,
        header::TE,
        header::TRAILER,
        header::TRANSFER_ENCODING,
        header::UPGRADE,
    ]
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    // A Connection header can name further headers that are hop-by-hop for this one message.
    let named: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in named.iter().chain(hop_by_hop().iter()) {
        headers.remove(name);
    }
}

/// The one field of the request the policy needs. Everything else in the body is left alone.
struct Peek {
    model: String,
}

impl<'de> serde::Deserialize<'de> for Peek {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Keys;
        impl<'de> serde::de::Visitor<'de> for Keys {
            type Value = Peek;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object with one \"model\" string")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Peek, A::Error> {
                use serde::de::Error;
                let mut model = None;
                while let Some(key) = map.next_key::<std::borrow::Cow<'de, str>>()? {
                    if key == "model" {
                        if model.replace(map.next_value::<String>()?).is_some() {
                            return Err(A::Error::duplicate_field("model"));
                        }
                    } else if key.eq_ignore_ascii_case("model") {
                        // Some servers read JSON keys without regard to case. A second spelling of "model"
                        // would let the policy check one model while the provider runs another.
                        return Err(A::Error::custom("a second spelling of the model key"));
                    } else {
                        map.next_value::<serde::de::IgnoredAny>()?;
                    }
                }
                model
                    .map(|model| Peek { model })
                    .ok_or_else(|| A::Error::missing_field("model"))
            }
        }
        deserializer.deserialize_map(Keys)
    }
}

/// The Gantry key on a request, or the refusal if there is none or it is ambiguous.
/// A credential is a Bearer token in Authorization or the value of x-api-key: the two places clients put one.
fn caller_key(headers: &HeaderMap) -> Result<&str, Refusal> {
    let no_key = || {
        Refusal::new(
            StatusCode::UNAUTHORIZED,
            "no_key",
            "Refused: this request carries no Gantry key. Send your Gantry key as a Bearer token or in x-api-key.",
        )
    };
    let ambiguous = || {
        // Checking one credential and forwarding another is how a proxy gets bypassed.
        Refusal::new(
            StatusCode::BAD_REQUEST,
            "ambiguous_key",
            "Refused: this request carries more than one credential. Send exactly one: your Gantry key, as a Bearer token or in x-api-key.",
        )
    };
    let one = |name: HeaderName| -> Result<Option<&str>, Refusal> {
        let mut values = headers.get_all(name).iter();
        let Some(first) = values.next() else {
            return Ok(None);
        };
        if values.next().is_some() {
            return Err(ambiguous());
        }
        first.to_str().map(Some).map_err(|_| no_key())
    };
    let not_bearer = || {
        Refusal::new(
            StatusCode::UNAUTHORIZED,
            "no_key",
            "Refused: the Authorization header holds no Bearer token: it is empty or uses another scheme. Send your Gantry key as `Authorization: Bearer <key>` or in x-api-key, and only there.",
        )
    };
    let bearer = match one(header::AUTHORIZATION)? {
        Some(value) => {
            let scheme = value.get(..7).ok_or_else(not_bearer)?;
            if !scheme.eq_ignore_ascii_case("bearer ") {
                return Err(not_bearer());
            }
            Some(value[7..].trim())
        }
        None => None,
    };
    let api_key = one(HeaderName::from_static("x-api-key"))?.map(str::trim);
    match (bearer, api_key) {
        (Some(a), Some(b)) if a.is_empty() != b.is_empty() => Err(Refusal::new(
            StatusCode::BAD_REQUEST,
            "ambiguous_key",
            format!(
                "Refused: this request carries an empty {} next to another credential. Send exactly one: your Gantry key, as a Bearer token or in x-api-key, and remove the empty header.",
                if a.is_empty() {
                    "Bearer token"
                } else {
                    "x-api-key"
                }
            ),
        )),
        (Some(a), Some(b)) if a != b => Err(ambiguous()),
        (Some(key), _) | (None, Some(key)) if !key.is_empty() => Ok(key),
        _ => Err(no_key()),
    }
}

/// Reads a request body into memory, within the size limit, the time limit and the memory budget.
/// The permit holds the body's share of the budget until the request has been handed to the provider.
async fn read_body(
    caller: Option<&str>,
    state: &AppState,
    headers: &HeaderMap,
    mut body: Body,
) -> Result<(Bytes, Held), Refusal> {
    let too_large = || {
        Refusal::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "body_too_large",
            format!(
                "Refused: the request body is larger than {} MiB, the most Gantry will read. Send a smaller request.",
                MAX_BODY_BYTES / MIB
            ),
        )
    };
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    if declared.is_some_and(|length| length > MAX_BODY_BYTES) {
        return Err(too_large());
    }
    let read = async {
        // Memory is reserved as bytes arrive, never ahead of them: a caller that announces a large body
        // and sends nothing holds nothing. Nobody waits in a queue for memory either, so one large
        // request cannot hold up small ones behind it.
        let share = caller.and_then(|name| {
            let mut shares = state.shares.lock().ok()?;
            let share = shares
                .entry(name.to_string())
                .or_insert_with(|| Arc::new(Semaphore::new(state.share_kib)));
            Some(share.clone())
        });
        let mut held: Held = Vec::new();
        let mut reserved_kib = 0;
        let mut bytes = Vec::with_capacity(declared.unwrap_or(0).min(64 * KIB));
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| {
                Refusal::new(
                    StatusCode::BAD_REQUEST,
                    "unreadable_request",
                    "Refused: the request body stopped before it was complete. Send it again.",
                )
            })?;
            let Ok(data) = frame.into_data() else {
                continue;
            };
            if bytes.len() + data.len() > MAX_BODY_BYTES {
                return Err(too_large());
            }
            // Memory is counted by bytes received, not by frames: a body sent one byte at a time must not
            // be charged a KiB per byte, or a few callers could fill the budget with almost nothing.
            let total_kib = (bytes.len() + data.len()).div_ceil(KIB);
            let kib = u32::try_from(total_kib - reserved_kib).unwrap_or(u32::MAX);
            reserved_kib = total_kib;
            if kib == 0 {
                bytes.extend_from_slice(&data);
                continue;
            }
            if total_kib > state.share_kib {
                // No amount of waiting makes this fit, so it is not answered as "try again".
                return Err(Refusal::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "body_too_large",
                    "Refused: this request body is larger than the memory one caller may hold at once. Send a smaller request.",
                ));
            }
            // The caller's own share is taken first: a caller over its share is told so, and takes nothing from the rest.
            let own = match &share {
                Some(share) => match share.clone().try_acquire_many_owned(kib) {
                    Ok(permit) => Some(permit),
                    Err(_) => {
                        let mut busy = Refusal::new(
                            StatusCode::TOO_MANY_REQUESTS,
                            "busy",
                            format!(
                                "Refused: your requests in flight already hold {} MiB of request bodies, the most one caller may hold at once. Wait for some to finish and send this one again.",
                                state.share_kib / KIB
                            ),
                        );
                        busy.retry = true;
                        return Err(busy);
                    }
                },
                None => None,
            };
            let Ok(permit) = state.buffer.clone().try_acquire_many_owned(kib) else {
                let mut busy = Refusal::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "busy",
                    "Refused: Gantry is holding as many large requests as it has memory for. Send this one again in a moment.",
                );
                busy.retry = true;
                return Err(busy);
            };
            // One permit per budget for the whole body, however many frames it came in.
            for (slot, new) in [(0, Some(permit)), (1, own)] {
                match (held.get_mut(slot), new) {
                    (Some(all), Some(new)) => all.merge(new),
                    (None, Some(new)) => held.push(new),
                    _ => {}
                }
            }
            bytes.extend_from_slice(&data);
        }
        Ok((Bytes::from(bytes), held))
    };
    match tokio::time::timeout(state.timeouts.read_body, read).await {
        Ok(result) => result,
        Err(_) => Err(Refusal::new(
            StatusCode::REQUEST_TIMEOUT,
            "body_timeout",
            format!(
                "Refused: the request body did not arrive within {} seconds. Send it again.",
                state.timeouts.read_body.as_secs()
            ),
        )),
    }
}

/// What was learned about a request while it was being checked. It becomes the audit record.
#[derive(Default)]
struct Seen<'a> {
    provider: Option<usize>,
    person: Option<&'a Principal>,
    key: Option<String>,
    model: Option<String>,
    rule: Option<&'a Rule>,
    /// The deployment an alias picked first, as `provider/model`.
    deployment: Option<String>,
    translated: bool,
    /// `hit` or `miss`, for a rule with a cache.
    cache: Option<&'static str>,
    /// The cached answer's request, settled once the decision is recorded.
    hit: Option<Box<spend::Admitted>>,
}

/// On the messages routes the caller is most likely Claude Code asking for its default model: the fix is the
/// caller's own variables, with no admin needed.
fn claude_code_hint(path: &str) -> &'static str {
    if path.starts_with(MESSAGES) {
        "In Claude Code, set ANTHROPIC_MODEL and ANTHROPIC_SMALL_FAST_MODEL to models it allows. "
    } else {
        ""
    }
}

fn allowed_models(rule: &Rule) -> String {
    match &rule.models {
        Models::Only(models) if !models.is_empty() => format!("Allowed: {}.", models.join(", ")),
        _ => "This rule allows no models.".to_string(),
    }
}

/// What happens to a request that passed its check: it goes to a provider, or Gantry answers it itself.
enum Next {
    Forward(Parts, Bytes, Held),
    Answer(Response),
}

/// Checks a request against the policy. Returns it rebuilt with the same bytes, or the refusal to send back.
async fn check<'a>(
    state: &AppState,
    version: &Snapshot,
    policy: &'a Policy,
    request: Request,
    seen: &mut Seen<'a>,
) -> Result<Next, Refusal> {
    let (parts, body) = request.into_parts();
    let key = caller_key(&parts.headers)?;
    // Read before the key's header is removed below: Anthropic's clients send their key in x-api-key.
    let anthropic_client =
        parts.headers.contains_key("x-api-key") || parts.headers.contains_key("anthropic-version");
    // A stranger is refused before their body is read, so an unknown caller cannot make the gateway buffer anything.
    let Some(person) = policy.identify(key) else {
        // Enough of the hash to tell two unknown keys apart in the audit log, and far too little to find the key.
        seen.key = Some(id::sha256_hex(key.as_bytes())[..8].to_string());
        let hint = if key.starts_with("sk-") {
            " This looks like a provider key. Send your Gantry key instead: the provider key stays with Gantry."
        } else {
            ""
        };
        return Err(Refusal::new(
            StatusCode::UNAUTHORIZED,
            "unknown_key",
            format!(
                "Refused: Gantry does not know this key. It was never issued or it has been removed. A key just issued works within 2 seconds. A key from gantry login is replaced by the next login and removed by gantry logout: run gantry login again. Otherwise ask a Gantry admin.{hint}"
            ),
        ));
    };
    seen.person = Some(person);
    // Allowed requests name their key too: during a rotation a person has two, and the record says which was used.
    seen.key = Some(person.key.clone());
    if person.expires.is_some() && person.expired(&gantry_core::audit::timestamp()) {
        return Err(Refusal::new(
            StatusCode::UNAUTHORIZED,
            "key_expired",
            format!(
                "Refused: the key {} of \"{}\" expired at {} (UTC). Ask a Gantry admin for a new key, or, if it came from gantry login, run gantry login <gantry url> again.",
                person.key,
                person.name,
                person.expires.as_deref().unwrap_or_default()
            ),
        ));
    }
    let key_sha256 = id::sha256_hex(key.as_bytes());
    killed(state, person, &key_sha256, None)?;
    // The key must not travel on in any other header either, under whatever name the caller chose for it.
    let (key, mut parts) = (key.to_string(), parts);
    // Compared without regard to case, and on the random part alone as well, so a key that was upper-cased
    // or sent without its prefix is caught too. A key that was split or encoded is beyond a text match.
    let key = key.to_ascii_lowercase();
    // Only text long enough to be a secret is searched for. A short hand-made key such as "json" would
    // otherwise match ordinary headers and strip them.
    let random = key.strip_prefix(id::KEY_PREFIX);
    let carries = |text: &[u8]| {
        let text = text.to_ascii_lowercase();
        let found = [Some(key.as_str()), random]
            .into_iter()
            .flatten()
            .filter(|needle| needle.len() >= 16)
            .any(|needle| text.windows(needle.len()).any(|w| w == needle.as_bytes()));
        // A shorter key is still caught where it stands as a word of its own, such as `X-Token: Bearer <key>`.
        // ponytail: a short hand-made key inside a longer word still travels; issued keys are 71 characters.
        found
            || text
                .split(|b| b.is_ascii_whitespace() || b",;=:".contains(b))
                .any(|word| !word.is_empty() && word == key.as_bytes())
    };
    let carrying: Vec<HeaderName> = parts
        .headers
        .iter()
        .filter(|(name, value)| carries(value.as_bytes()) || carries(name.as_str().as_bytes()))
        .map(|(name, _)| name.clone())
        .collect();
    for name in carrying {
        if name != header::AUTHORIZATION {
            parts.headers.remove(name);
        }
    }
    if parts.method == Method::GET && parts.uri.path() == MODELS {
        check_query(&parts.uri)?;
        seen.rule = policy.rule_for(person);
        return Ok(Next::Answer(model_list(
            version,
            seen.rule,
            person,
            anthropic_client,
        )));
    }
    let Some(route) = route_kind(&parts.method, parts.uri.path()) else {
        return Err(unknown_route());
    };
    // Gantry reads and checks the body as plain JSON. Forwarded under another Content-Encoding, the provider would
    // try to decode bytes that were never encoded, or a masked body that was written out again.
    if let Some(coding) = parts
        .headers
        .get_all(header::CONTENT_ENCODING)
        .iter()
        .find(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"))
    {
        return Err(Refusal::new(
            StatusCode::BAD_REQUEST,
            "unreadable_request",
            format!(
                "Refused: the body is sent with Content-Encoding \"{}\". Gantry reads and checks request bodies as plain JSON. Send it uncompressed, without Content-Encoding.",
                String::from_utf8_lossy(coding.as_bytes())
            ),
        ));
    }
    let (bytes, permit) = read_body(Some(&person.name), state, &parts.headers, body).await?;
    let peek = if parts.uri.path() == TRANSCRIPTIONS {
        form_model(&parts.headers, &bytes)?
    } else {
        serde_json::from_slice(&bytes).map_err(|_| {
            Refusal::new(
                StatusCode::BAD_REQUEST,
                "unreadable_request",
                "Refused: the request body must be a JSON object with exactly one \"model\" field that is a string, so the policy can be checked.",
            )
        })?
    };
    // Rules decide on the name the caller sent, an alias included: an admin allows "smart", not each deployment.
    let decision = policy.decide(person, &peek.model);
    let model = seen.model.insert(peek.model);
    killed(state, person, &key_sha256, Some(model))?;
    // UX12-1: a switch on a model also stops each alias that can send to it.
    for deployment in version
        .aliases
        .iter()
        .filter(|a| a.name == *model)
        .flat_map(|a| &a.deployments)
    {
        killed(state, person, &key_sha256, Some(&deployment.model))?;
    }
    match decision {
        Decision::Allow(rule) => {
            seen.rule = Some(rule);
            let (chain, translate) = targets(state, version, route, parts.uri.path(), model)?;
            let chosen = chain.first().map_or(0, |c| c.0);
            let alias = version.aliases.iter().find(|a| a.name == *model);
            // A named fallback takes the same body, so it must take the same translation. QA14-2: a fallback a kill
            // switch stops (by its own name, or a model of its deployments, as for the alias itself) is not taken.
            let stopped = |m: &str| killed(state, person, &key_sha256, Some(m)).is_err();
            let fallback = |target: Option<&String>| {
                target
                    .filter(|t| !stopped(t))
                    .and_then(|t| targets(state, version, route, parts.uri.path(), t).ok())
                    .filter(|(chain, t)| *t == translate && !chain.iter().any(|(_, m)| stopped(m)))
                    .map(|(chain, _)| chain)
                    .unwrap_or_default()
            };
            let (context, content) = alias.map_or_else(Default::default, |a| {
                (
                    fallback(a.context_window_fallback.as_ref()),
                    fallback(a.content_policy_fallback.as_ref()),
                )
            });
            if alias.is_some() {
                seen.deployment = chain
                    .first()
                    .map(|(i, m)| alias::label(&version.providers[*i].name, m));
            }
            let model = model.clone();
            seen.provider = Some(chosen);
            check_query(&parts.uri)?;
            // Translated here, before the record is written, so a field that cannot be carried across is a
            // recorded refusal and never a request sent with that field missing.
            let from_messages = translate && route == Kind::Anthropic;
            let (bytes, translated) = if translate {
                seen.translated = true;
                if from_messages {
                    // Now a chat request. A Google provider translates it once more as it is sent, and its answer
                    // comes back as chat with usage, then as messages.
                    (to_chat_request(&bytes)?, Some(true))
                } else if version.providers[chosen].kind.google() {
                    // Checked here, and translated as it is sent: the guardrails read and mask the chat body.
                    let include_usage = to_gemini(&bytes)?.2;
                    (bytes, Some(include_usage))
                } else {
                    let (bytes, include_usage) = to_messages(&bytes)?;
                    (bytes, Some(include_usage))
                }
            } else {
                (bytes, None)
            };
            parts.extensions.insert(Plan {
                provider: chosen,
                model,
                translated,
                from_messages,
                chain,
                cooldown: alias.map(|a| Duration::from_secs(a.cooldown_seconds)),
                context,
                content,
            });
            Ok(Next::Forward(parts, bytes, permit))
        }
        Decision::NoRule => Err(Refusal::new(
            StatusCode::FORBIDDEN,
            "no_rule",
            format!(
                "Refused: no rule in the policy names \"{}\" or team \"{}\", so nothing is allowed. Ask a Gantry admin to add a rule.",
                person.name, person.team
            ),
        )),
        Decision::KeyModelNotAllowed(rule) => {
            seen.rule = Some(rule);
            let hint = claude_code_hint(parts.uri.path());
            let mut refusal = Refusal::new(
                StatusCode::FORBIDDEN,
                "model_not_allowed",
                format!(
                    "Refused: the key {} of \"{}\" may not use model \"{model}\". Its own list allows: {}. {hint}Ask a Gantry admin to change the key's models if you need this one.",
                    person.key,
                    person.name,
                    person.models.as_deref().unwrap_or_default().join(", ")
                ),
            );
            refusal.record = Some(Box::new(serde_json::json!({ "key_models": true })));
            Err(refusal)
        }
        Decision::ModelNotAllowed(rule) => {
            seen.rule = Some(rule);
            let hint = match &rule.models {
                Models::Only(models) if models.is_empty() => "",
                _ => claude_code_hint(parts.uri.path()),
            };
            Err(Refusal::new(
                StatusCode::FORBIDDEN,
                "model_not_allowed",
                format!(
                    "Refused: team \"{}\" may not use model \"{model}\" under rule \"{}\". {} {hint}Ask a Gantry admin to change the policy if you need this one.",
                    person.team,
                    rule.name,
                    allowed_models(rule)
                ),
            ))
        }
    }
}

/// Refuses a request a kill switch stops, naming the switch, its reason and who set it. A switch list that cannot
/// be read refuses every request: Gantry cannot tell that the caller is not stopped.
fn killed(
    state: &AppState,
    person: &Principal,
    key_sha256: &str,
    model: Option<&str>,
) -> Result<(), Refusal> {
    let Some(switches) = &state.kills else {
        return Ok(());
    };
    let kills = switches.current().map_err(|err| {
        Refusal::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "kills_unreadable",
            format!("Refused: {err} Until then Gantry cannot tell whether a kill switch stops this request. Tell your Gantry admin."),
        )
    })?;
    match kills
        .iter()
        .find(|k| k.stops(&person.name, &person.team, key_sha256, model))
    {
        None => Ok(()),
        Some(kill) => Err(Refusal::new(
            StatusCode::FORBIDDEN,
            "killed",
            format!(
                "Refused: a kill switch stops traffic for {}: \"{}\" (set by {} at {} UTC). It stays stopped until an admin runs gantry unkill. Ask {}.",
                kill.label(),
                kill.reason,
                kill.by,
                kill.at,
                kill.by
            ),
        )),
    }
}

fn unknown_route() -> Refusal {
    Refusal::new(
        StatusCode::NOT_FOUND,
        "unknown_route",
        "Refused: this version of Gantry serves POST /v1/chat/completions, POST /v1/responses, POST /v1/embeddings, POST /v1/images/generations, POST /v1/audio/transcriptions, POST /v1/audio/speech, POST /v1/moderations, POST /v1/rerank, POST /v1/messages, POST /v1/messages/count_tokens, GET /v1/models and GET /healthz. Check the method and the path.",
    )
}

/// How a checked request is forwarded, carried from the check to the send.
#[derive(Clone)]
struct Plan {
    /// The provider that serves its model, by position in the provider list.
    provider: usize,
    model: String,
    /// Set when a chat completions request was translated to the messages API: whether the client asked for
    /// usage in its stream.
    translated: Option<bool>,
    /// A messages request (Claude Code) translated to chat completions, whose answer goes back as messages.
    from_messages: bool,
    /// The deployments to try in order: each a provider by position and the model sent there. One entry for a
    /// model that is not an alias.
    chain: Vec<(usize, String)>,
    /// For an alias: how long a deployment that failed is passed over.
    cooldown: Option<Duration>,
    /// Where the request goes when the provider says the prompt is longer than its context window.
    context: Vec<(usize, String)>,
    /// Where the request goes when the provider refuses it under its content policy.
    content: Vec<(usize, String)>,
}

/// The model of a multipart form (an audio transcription), read as `Peek` reads a JSON body's.
fn form_model(headers: &HeaderMap, bytes: &[u8]) -> Result<Peek, Refusal> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let unreadable = |why: &str| {
        Refusal::new(
            StatusCode::BAD_REQUEST,
            "unreadable_request",
            format!(
                "Refused: {why}. Send the audio as multipart/form-data with exactly one model field, so the policy can be checked."
            ),
        )
    };
    let range = alias::multipart_model(content_type, bytes).map_err(unreadable)?;
    let model = std::str::from_utf8(&bytes[range])
        .map_err(|_| unreadable("the model field is not text"))?;
    Ok(Peek {
        model: model.to_string(),
    })
}

/// The deployments that can take this request, in the order to try them, and whether it is translated. A model
/// that is not an alias has one: the provider that lists it.
fn targets(
    state: &AppState,
    version: &Snapshot,
    route: Kind,
    path: &str,
    model: &str,
) -> Result<(Vec<(usize, String)>, bool), Refusal> {
    let Some(alias) = version.aliases.iter().find(|a| a.name == model) else {
        let (index, translate) = provider_for(version, route, path, model)?;
        return Ok((vec![(index, model.to_string())], translate));
    };
    let mut first_refusal = None;
    let mut eligible = Vec::new();
    let mut translate = None;
    for (at, deployment) in alias.deployments.iter().enumerate() {
        let Some(index) = version
            .providers
            .iter()
            .position(|p| p.name == deployment.provider)
        else {
            continue;
        };
        match fits(&version.providers[index], route, path, &deployment.model) {
            // Every deployment tried for one request takes the same body, translated or not.
            Ok(t) if *translate.get_or_insert(t) == t => eligible.push((at, index)),
            Ok(_) => {}
            Err(refusal) => {
                first_refusal.get_or_insert(refusal);
            }
        }
    }
    if eligible.is_empty() {
        return Err(first_refusal.unwrap_or_else(|| {
            Refusal::new(
                StatusCode::FORBIDDEN,
                "unknown_model",
                format!("Refused: alias \"{model}\" has no deployment Gantry can reach. Ask a Gantry admin to check its providers."),
            )
        }));
    }
    let positions: Vec<usize> = eligible.iter().map(|(at, _)| *at).collect();
    let order = state.pool.order(alias, &positions, Instant::now());
    let chain = order
        .into_iter()
        .filter_map(|at| {
            let index = eligible.iter().find(|(p, _)| *p == at)?.1;
            Some((index, alias.deployments.get(at)?.model.clone()))
        })
        .collect();
    Ok((chain, translate.unwrap_or(false)))
}

/// A chat completions request as a messages request, and whether its client asked for usage in the stream.
fn to_messages(bytes: &[u8]) -> Result<(Bytes, bool), Refusal> {
    let request: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| {
        Refusal::new(
            StatusCode::BAD_REQUEST,
            "unreadable_request",
            "Refused: the request body is not JSON. Send a chat completions request as a JSON object.",
        )
    })?;
    let messages = translate::openai_to_anthropic_request(&request).map_err(|err| {
        Refusal::new(
            StatusCode::BAD_REQUEST,
            "untranslatable",
            format!("Refused: {err}"),
        )
    })?;
    Ok((
        Bytes::from(messages.to_string()),
        translate::include_usage(&request),
    ))
}

/// A messages request as a chat completions request. Betas in anthropic-beta are not carried (see
/// `translate::SAFE_TO_DROP`); a body field one of them would enable is refused by name.
fn to_chat_request(bytes: &[u8]) -> Result<Bytes, Refusal> {
    let request: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| {
        Refusal::new(
            StatusCode::BAD_REQUEST,
            "unreadable_request",
            "Refused: the request body is not JSON. Send a messages request as a JSON object.",
        )
    })?;
    let chat = translate::anthropic_to_openai_request(&request).map_err(|err| {
        Refusal::new(
            StatusCode::BAD_REQUEST,
            "untranslatable",
            format!("Refused: {err}"),
        )
    })?;
    Ok(Bytes::from(chat.to_string()))
}

/// A chat completions request as a Gemini generateContent body, whether it streams, and whether its client asked
/// for usage in the stream.
fn to_gemini(bytes: &[u8]) -> Result<(Bytes, bool, bool), Refusal> {
    let request: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| {
        Refusal::new(
            StatusCode::BAD_REQUEST,
            "unreadable_request",
            "Refused: the request body is not JSON. Send a chat completions request as a JSON object.",
        )
    })?;
    let (body, stream) = gemini::openai_to_gemini_request(&request).map_err(|err| {
        Refusal::new(
            StatusCode::BAD_REQUEST,
            "untranslatable",
            format!("Refused: {err}"),
        )
    })?;
    Ok((
        Bytes::from(body.to_string()),
        stream,
        translate::include_usage(&request),
    ))
}

/// The one provider that serves this model, if it speaks the API of the route the request came on, or takes chat
/// requests translated. Returns its position and whether the request is to be translated.
fn provider_for(
    version: &Snapshot,
    route: Kind,
    path: &str,
    model: &str,
) -> Result<(usize, bool), Refusal> {
    let Some(index) = version.providers.iter().position(|p| p.serves(model)) else {
        // 403, as for a model the policy does not allow. Found by running Claude Code through Gantry: it replaces the
        // message of a 404 with its own, so the caller lost the model name and the decision ID, and it sends a 400 up
        // to six times with parts of the request removed. A 403 is shown as it is, once.
        return Err(Refusal::new(
            StatusCode::FORBIDDEN,
            "unknown_model",
            format!(
                "Refused: no provider of this Gantry serves model \"{model}\". Check the model name, or ask a Gantry admin to add it to a provider."
            ),
        ));
    };
    fits(&version.providers[index], route, path, model).map(|translate| (index, translate))
}

/// Whether this provider can take a request on `route` and `path`, and if so whether it is translated.
fn fits(provider: &Upstream, route: Kind, path: &str, model: &str) -> Result<bool, Refusal> {
    if provider.kind.api() == route {
        if matches!(provider.kind, Kind::Bedrock | Kind::VertexAnthropic) && path == COUNT_TOKENS {
            return Err(Refusal::new(
                StatusCode::BAD_REQUEST,
                "wrong_route",
                format!(
                    "Refused: model \"{model}\" is served by provider \"{}\" of kind {}, and Gantry does not count tokens there. Send the request to {MESSAGES} without counting first.",
                    provider.name,
                    provider.kind.word()
                ),
            ));
        }
        if openai_only(path) && provider.kind != Kind::OpenAi {
            return Err(Refusal::new(
                StatusCode::BAD_REQUEST,
                "wrong_route",
                format!(
                    "Refused: model \"{model}\" is served by provider \"{}\" of kind {}, and Gantry forwards {path} to providers of kind openai only. Send this request to {CHAT} instead.",
                    provider.name,
                    provider.kind.word()
                ),
            ));
        }
        // Gemini and Vertex AI take chat requests translated to their own body.
        return Ok(provider.kind.google());
    }
    if route == Kind::OpenAi && provider.accept_chat && path == CHAT {
        return Ok(true);
    }
    if route == Kind::Anthropic && provider.accept_messages {
        if path == MESSAGES {
            return Ok(true);
        }
        return Err(Refusal::new(
            StatusCode::BAD_REQUEST,
            "wrong_route",
            format!(
                "Refused: model \"{model}\" is served by provider \"{}\" of kind {}, which takes messages requests translated to chat completions, and Gantry does not count tokens for it. Send the request to {MESSAGES} without counting first.",
                provider.name,
                provider.kind.word()
            ),
        ));
    }
    if openai_only(path) {
        return Err(Refusal::new(
            StatusCode::BAD_REQUEST,
            "wrong_route",
            format!(
                "Refused: model \"{model}\" is served by provider \"{}\" of kind {}, and Gantry forwards {path} to providers of kind openai only. Use a model on a provider of kind openai, or send this request to the route that provider speaks ({}).",
                provider.name,
                provider.kind.word(),
                if provider.kind.api() == Kind::Anthropic {
                    MESSAGES
                } else {
                    CHAT
                }
            ),
        ));
    }
    let (speaks, other, offer) = match provider.kind.api() {
        Kind::Anthropic => (
            "the messages API",
            MESSAGES,
            " A Gantry admin can let chat requests reach it, translated, with `accept_chat: true` on the provider.",
        ),
        _ => (
            "the chat completions API",
            CHAT,
            " A Gantry admin can let messages requests (Claude Code) reach it, translated, with `accept_messages: true` on the provider.",
        ),
    };
    Err(Refusal::new(
        StatusCode::BAD_REQUEST,
        "wrong_route",
        format!(
            "Refused: model \"{model}\" is served by provider \"{}\", which speaks {speaks}. Send this request to {other} instead of {path}.{offer}",
            provider.name
        ),
    ))
}

/// The models this caller may use. Each person sees what their rule allows, not everything the provider keys could
/// reach. A caller that sends x-api-key or anthropic-version, as Anthropic's clients and Claude Code do, gets
/// Anthropic's list of messages models; any other caller gets OpenAI's list of chat models.
fn model_list(
    version: &Snapshot,
    rule: Option<&Rule>,
    person: &Principal,
    anthropic_client: bool,
) -> Response {
    // The rule's models, narrowed by the key's own list when it has one.
    let allowed = |model: &str| {
        rule.is_some_and(|rule| rule.allows(model))
            && person
                .models
                .as_ref()
                .is_none_or(|m| m.iter().any(|k| k == model))
    };
    // An alias is listed beside the models, under the API its deployments take.
    let aliases = |takes: fn(&Upstream) -> bool| {
        version.aliases.iter().filter_map(move |a| {
            let first = a.deployments.first()?;
            let provider = version
                .providers
                .iter()
                .find(|p| p.name == first.provider)?;
            takes(provider).then_some((&a.name, &provider.name))
        })
    };
    let chat = |p: &Upstream| p.kind.api() == Kind::OpenAi;
    // A chat provider that takes messages translated is offered to Claude Code too.
    let messages = |p: &Upstream| p.kind.api() == Kind::Anthropic || p.accept_messages;
    if !anthropic_client {
        let data: Vec<serde_json::Value> = version
            .providers
            .iter()
            .filter(|provider| chat(provider))
            .flat_map(|provider| provider.models.iter().map(move |m| (m, &provider.name)))
            .chain(aliases(chat))
            .filter(|(model, _)| allowed(model))
            .map(|(model, provider)| {
                serde_json::json!({ "id": model, "object": "model", "created": 0, "owned_by": provider })
            })
            .collect();
        let body = serde_json::json!({ "object": "list", "data": data });
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            body.to_string(),
        )
            .into_response();
    }
    // Only models the messages route reaches: this is Anthropic's model list, and Claude Code offers whatever it
    // lists. A model on an openai provider without accept_messages would be refused with wrong_route every time.
    let data: Vec<serde_json::Value> = version
        .providers
        .iter()
        .filter(|provider| messages(provider))
        .flat_map(|provider| provider.models.iter())
        .chain(aliases(messages).map(|(name, _)| name))
        .filter(|model| allowed(model))
        .map(|model| {
            serde_json::json!({
                "type": "model",
                "id": model,
                "display_name": model,
                "description": rule.map(|r| format!("Allowed by Gantry rule \"{}\"", r.name)),
            })
        })
        .collect();
    let body = serde_json::json!({
        "data": data,
        "has_more": false,
        "first_id": data.first().and_then(|m| m["id"].as_str()),
        "last_id": data.last().and_then(|m| m["id"].as_str()),
    });
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

/// Every query parameter must be one the route allows, once, with a value it may take. One that is not is refused
/// by name, never dropped. The value is never repeated in the refusal: it could be a secret.
fn check_query(uri: &Uri) -> Result<(), Refusal> {
    let allowed = allowed_query(uri.path());
    let refuse = |problem: String| {
        Refusal::new(
            StatusCode::BAD_REQUEST,
            "unknown_query",
            format!("Refused: {problem} Remove it and send again."),
        )
    };
    let mut seen = Vec::new();
    for pair in uri
        .query()
        .unwrap_or("")
        .split('&')
        .filter(|p| !p.is_empty())
    {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let Some((_, takes, valid)) = allowed.iter().find(|(known, _, _)| *known == name) else {
            let list = if allowed.is_empty() {
                "none".to_string()
            } else {
                allowed
                    .iter()
                    .map(|(known, _, _)| *known)
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            return Err(refuse(format!(
                "the query parameter \"{name}\" is not one Gantry forwards on {}. Allowed here: {list}.",
                uri.path()
            )));
        };
        if seen.contains(&name) {
            return Err(refuse(format!(
                "the query parameter \"{name}\" is given more than once. Give it once."
            )));
        }
        seen.push(name);
        if !valid(value) {
            return Err(refuse(format!(
                "the query parameter \"{name}\" has a value Gantry does not forward on {}: it takes {takes}.",
                uri.path()
            )));
        }
    }
    Ok(())
}

/// Every request except the health check: gives it a decision ID, checks it, records it, and only then forwards it.
async fn handle(State(state): State<AppState>, request: Request) -> Response {
    let arrived = Instant::now();
    let decision = id::decision_id();
    let anthropic = matches!(request.uri().path(), MESSAGES | COUNT_TOKENS);
    // One snapshot for the whole request: a reload that lands meanwhile applies to the next request, not this one.
    let version = state.version();
    let outcome = match &version.policy {
        Some(policy) => decide(&state, &version, policy, request, &decision).await,
        None => unchecked(&state, request).await,
    };
    let mut response = match outcome {
        Ok(Next::Answer(response)) => response,
        Ok(Next::Forward(parts, bytes, _memory)) => {
            match send(&state, &version, parts, bytes, arrived, &decision).await {
                Ok(response) => response,
                Err(failure) => failure.respond(&decision, anthropic),
            }
        }
        Err(refusal) => refusal.respond(&decision, anthropic),
    };
    if let Some(check) = response.extensions_mut().remove::<AnswerCheck>() {
        response = match answer_guarded(&state, check, &decision, response).await {
            Ok(response) => response,
            Err(refusal) => refusal.respond(&decision, anthropic),
        };
    }
    if let Ok(value) = HeaderValue::from_str(&decision) {
        response.headers_mut().insert(DECISION, value);
    }
    response
}

async fn unchecked(state: &AppState, request: Request) -> Result<Next, Refusal> {
    if request.method() != Method::POST || request.uri().path() != CHAT {
        return Err(unknown_route());
    }
    // The body is read here too, so a slow client is cut off as a slow client and not reported as a slow provider.
    let (parts, body) = request.into_parts();
    let (bytes, permit) = read_body(None, state, &parts.headers, body).await?;
    Ok(Next::Forward(parts, bytes, permit))
}

async fn decide(
    state: &AppState,
    version: &Snapshot,
    policy: &Policy,
    request: Request,
    decision: &str,
) -> Result<Next, Refusal> {
    let client = request
        .extensions()
        .get::<ClientAddr>()
        .map(|addr| addr.0.ip().to_string());
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let mut seen = Seen::default();
    let mut outcome = check(state, version, policy, request, &mut seen).await;
    // What the guardrails found, when the rule has any: an empty list says they ran and found nothing.
    let mut found = None;
    let guards = seen.rule.map_or(&[][..], |rule| rule.guardrails.as_slice());
    // An audio upload holds no text a guardrail reads. It is forwarded, and its record says the guardrails did not
    // run on it, rather than that they ran and found nothing.
    let on_request = guards.iter().any(|g| g.on.request);
    // QA14-5: a form's text fields (the transcription prompt) are checked; only a form with none is not text.
    let not_text = on_request
        && path == TRANSCRIPTIONS
        && match &outcome {
            Ok(Next::Forward(parts, bytes, _)) => {
                form_texts(&parts.headers, bytes).is_ok_and(|t| t.is_empty())
            }
            _ => true,
        };
    outcome = match outcome {
        Ok(Next::Forward(parts, bytes, held)) if on_request && !not_text => {
            let (checked, entries) = guarded(state, guards, &seen, decision, parts, bytes).await;
            found = Some(entries);
            checked.map(|(parts, bytes)| Next::Forward(parts, bytes, held))
        }
        other => other,
    };
    // Limits come after the guardrails: the cache key and the budget's estimate are of the body that is sent, masked
    // if a guardrail masked it, and a request a guardrail blocks is never served from the cache or counted.
    outcome = match outcome {
        Ok(Next::Forward(mut parts, bytes, held)) => {
            match limit(
                state, version, policy, &mut seen, decision, &mut parts, &bytes,
            )
            .await
            {
                Ok(Some(answer)) => Ok(Next::Answer(answer)),
                Ok(None) => Ok(Next::Forward(parts, bytes, held)),
                Err(refusal) => Err(refusal),
            }
        }
        other => other,
    };
    // Guardrails on the answer travel with the request (or a cached answer) to the end, where the answer is whole.
    let on_answer: Vec<Guardrail> = guards.iter().filter(|g| g.on.answer).cloned().collect();
    if !on_answer.is_empty() && matches!(path.as_str(), CHAT | MESSAGES | RESPONSES) {
        let check = AnswerCheck {
            guards: on_answer,
            person: seen.person.map(|p| p.name.clone()).unwrap_or_default(),
            team: seen.person.map(|p| p.team.clone()).unwrap_or_default(),
            path: path.clone(),
            buffer_stream: seen.rule.is_some_and(|r| r.limits.buffer_stream),
        };
        match &mut outcome {
            Ok(Next::Forward(parts, _, _)) => {
                parts.extensions.insert(check);
            }
            Ok(Next::Answer(response)) if seen.cache == Some("hit") => {
                response.extensions_mut().insert(check);
            }
            _ => {}
        }
    }
    let provider_name = seen
        .provider
        .and_then(|i| version.providers.get(i))
        .map_or("", |p| p.name.as_str());
    state.metrics.decided(
        &path,
        outcome.as_ref().err().map(|refusal| refusal.code),
        provider_name,
    );
    if let Some(audit) = &state.audit {
        let entry = Entry {
            id: decision,
            person: seen.person.map(|p| p.name.as_str()),
            team: seen.person.map(|p| p.team.as_str()),
            client: client.as_deref(),
            key: seen.key.as_deref(),
            method: &method,
            path: &path,
            model: seen.model.as_deref(),
            allowed: outcome.is_ok(),
            code: outcome.as_ref().err().map(|refusal| refusal.code),
            rule: seen.rule.map(|rule| rule.name.as_str()),
            rule_line: seen.rule.map(|rule| rule.line).filter(|line| *line > 0),
            provider: provider_name,
            policy_sha256: &version.policy_sha256,
            keys_sha256: &version.keys_sha256,
            translated: seen.translated,
            cache: seen.cache,
        };
        // The record is written before anything is forwarded. A request that cannot be recorded does not happen.
        let mut record = gantry_core::audit::record(&entry);
        if let Some(found) = &found {
            record.insert(
                "guardrails".into(),
                serde_json::to_value(found).unwrap_or_default(),
            );
        } else if not_text && outcome.is_ok() {
            record.insert("guardrails".into(), "not_run: the body is audio".into());
        }
        if let Some(serde_json::Value::Object(extra)) =
            outcome.as_ref().err().and_then(|r| r.record.as_deref())
        {
            record.extend(extra.clone());
        }
        if let Some(deployment) = &seen.deployment {
            // The model on the record is the alias the caller sent and the rule decided on; this is where it went first.
            record.insert(
                "alias".into(),
                seen.model.as_deref().unwrap_or_default().into(),
            );
            record.insert("deployment".into(), deployment.as_str().into());
        }
        let (tell, written) = tokio::sync::oneshot::channel();
        audit.log.append_record_then(&record, move |result| {
            let _ = tell.send(result);
        });
        if !matches!(written.await, Ok(Ok(()))) {
            eprintln!(
                "gantry: the audit log could not be written, so decision {decision} was refused"
            );
            state
                .metrics
                .decided(&path, Some("audit_unavailable"), provider_name);
            // No Retry-After: this does not clear by itself, an admin has to look.
            return Err(Refusal::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "audit_unavailable",
                "Refused: Gantry could not write this request to its audit log, and it does not forward what it cannot record. Tell your Gantry admin.",
            ));
        }
    }
    if let (Some(admitted), Ok(Next::Answer(response))) = (seen.hit.take(), &outcome) {
        (*admitted).settle(response.status(), spend::Ended::Complete, None, true, None);
    }
    outcome
}

/// Applies the rule's cache, rate and budget to a request about to be recorded and sent (spend.rs). Returns the
/// cached answer, in the format the caller sent its request in, when there is one.
async fn limit(
    state: &AppState,
    version: &Snapshot,
    policy: &Policy,
    seen: &mut Seen<'_>,
    decision: &str,
    parts: &mut Parts,
    bytes: &Bytes,
) -> Result<Option<Response>, Refusal> {
    // Only a request the policy allowed is forwarded, and it has all four.
    let (Some(rule), Some(person), Some(provider), Some(model)) = (
        seen.rule,
        seen.person,
        seen.provider.and_then(|i| version.providers.get(i)),
        seen.model.as_deref(),
    ) else {
        return Ok(None);
    };
    // An alias is priced, budgeted and cached as the model it is sent to first. A fallback that answers is
    // charged at its own model's price when the answer is settled.
    let plan = parts.extensions.get::<Plan>();
    let deployed = plan.and_then(|p| p.chain.first()).map(|(_, m)| m.clone());
    let sent = model;
    let model = deployed.as_deref().unwrap_or(model);
    let ask = spend::Ask {
        decision,
        person,
        rule,
        model,
        sent,
        provider: &provider.name,
        version: (&version.policy_sha256, &version.keys_sha256),
        prices: policy.prices(),
        headers: &parts.headers,
        route: parts.uri.path_and_query().map_or("/", |pq| pq.as_str()),
        body: bytes,
        free: parts.uri.path() == COUNT_TOKENS,
    };
    match spend::admit(&state.spend, state.audit.as_ref().map(|a| &a.log), ask)? {
        spend::Admit::Hit(response, admitted) => {
            seen.cache = Some("hit");
            seen.hit = Some(admitted);
            // The cache holds the provider's own format, so a translated request gets its hit translated too.
            let plan = parts.extensions.get::<Plan>();
            Ok(Some(
                for_caller(provider.kind, &provider.name, plan, decision, response).await?,
            ))
        }
        spend::Admit::Go(meter, cache) => {
            seen.cache = cache;
            parts.extensions.insert(meter);
            Ok(None)
        }
    }
}

/// Runs a rule's guardrails on an allowed request: the built-in ones first, then each webhook in order.
/// Returns the request to forward (masked, or with its bytes untouched) or the refusal, and what was found.
async fn guarded(
    state: &AppState,
    guards: &[Guardrail],
    seen: &Seen<'_>,
    decision: &str,
    mut parts: Parts,
    bytes: Bytes,
) -> (Result<(Parts, Bytes), Refusal>, Vec<guard::AuditEntry>) {
    let unreadable = |why: String| {
        Refusal::new(
            StatusCode::BAD_REQUEST,
            "unreadable_request",
            format!(
                "Refused: {why}, so the guardrails could not read it, and a rule with guardrails does not forward text they cannot read. Send it in a documented shape."
            ),
        )
    };
    // A form (a transcription) shows the guardrails its text fields, and gets what they mask written back in place.
    let mut form = None;
    if parts.uri.path() == TRANSCRIPTIONS {
        match form_texts(&parts.headers, &bytes) {
            Ok(fields) => form = Some(fields),
            Err(why) => return (Err(unreadable(why)), Vec::new()),
        }
    }
    // A guardrail reads the last copy of a duplicated key, and a provider may act on the first: the copy checked
    // must be the only one.
    if form.is_none()
        && let Err(err) = gantry_core::chat::reject_duplicate_keys(&bytes)
    {
        return (
            Err(Refusal::new(
                StatusCode::BAD_REQUEST,
                "unreadable_request",
                format!(
                    "Refused: the guardrails could not read the request body: {err}. Send a JSON object that names each key once."
                ),
            )),
            Vec::new(),
        );
    }
    let value = match &form {
        Some(fields) => serde_json::json!({
            "input": fields.iter().map(|(_, text)| text.as_str()).collect::<Vec<_>>()
        }),
        None => match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(value) => value,
            Err(_) => {
                return (
                    Err(Refusal::new(
                        StatusCode::BAD_REQUEST,
                        "unreadable_request",
                        "Refused: the request body is not valid JSON, so the guardrails could not read it. Send a JSON object.",
                    )),
                    Vec::new(),
                );
            }
        },
    };
    // Images, rerank and moderations carry their text in fields the guardrails do not read: shown to them as
    // `input`, and what they mask is written back where it came from.
    let pointers = match text_fields(parts.uri.path(), &value) {
        Ok(pointers) => pointers,
        Err(field) => {
            return (
                Err(unreadable(format!(
                    "the request's {field} is not in a shape Gantry reads"
                ))),
                Vec::new(),
            );
        }
    };
    let mut original = None;
    let value = if pointers.is_empty() {
        value
    } else {
        let texts: Vec<serde_json::Value> = pointers
            .iter()
            .map(|p| value.pointer(p).cloned().unwrap_or_default())
            .collect();
        original = Some(value);
        serde_json::json!({ "input": texts })
    };
    let mut verdict = guard::check(value, guards);
    let (person, team) = seen
        .person
        .map_or(("", ""), |p| (p.name.as_str(), p.team.as_str()));
    for guardrail in guards.iter().filter(|g| g.on.request) {
        let guard::Check::Webhook(hook) = &guardrail.check else {
            continue;
        };
        if verdict.blocked.is_some() {
            break;
        }
        let sent =
            guard::WebhookRequest::new(decision, person, team, parts.uri.path(), &verdict.body);
        let answer = ask(state, guardrail.action, hook, &sent).await;
        if let Some(cause) = verdict.merge_answer(guardrail, &sent, answer) {
            eprintln!("gantry: decision {decision}: {cause}");
        }
    }
    if let Some(blocked) = verdict.blocked {
        let refusal = Refusal::new(
            StatusCode::FORBIDDEN,
            guard::BLOCKED_CODE,
            format!("Refused: {}", blocked.message),
        );
        return (Err(refusal), verdict.audit);
    }
    if let Some(mut original) = original
        && verdict.changed
    {
        for (i, pointer) in pointers.iter().enumerate() {
            if let (Some(slot), Some(masked)) =
                (original.pointer_mut(pointer), verdict.body["input"].get(i))
            {
                *slot = masked.clone();
            }
        }
        verdict.body = original;
    }
    let written = match (&form, verdict.changed) {
        (Some(fields), true) => {
            // Written back from the end, so each field's range still holds when it is replaced.
            let mut out = bytes.to_vec();
            for (i, (range, _)) in fields.iter().enumerate().rev() {
                let masked = verdict.body["input"][i].as_str().unwrap_or_default();
                out.splice(range.clone(), masked.bytes());
            }
            Some(out)
        }
        (None, true) => serde_json::to_vec(&verdict.body).ok(),
        _ => None,
    };
    let bytes = if verdict.changed {
        let Some(masked) = written else {
            // Never forward the unmasked body because the masked one could not be written.
            let refusal = Refusal::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                guard::BLOCKED_CODE,
                "Refused: the masked request could not be written, so it was not sent. Tell your Gantry admin.",
            );
            return (Err(refusal), verdict.audit);
        };
        parts
            .headers
            .insert(header::CONTENT_LENGTH, HeaderValue::from(masked.len()));
        Bytes::from(masked)
    } else {
        bytes
    };
    (Ok((parts, bytes)), verdict.audit)
}

/// The guardrails a rule runs on answers, and who asked, carried from the decision to the answer.
#[derive(Clone)]
struct AnswerCheck {
    guards: Vec<Guardrail>,
    person: String,
    team: String,
    path: String,
    /// The rule's `buffer_stream`: a streamed answer is held whole and checked too.
    buffer_stream: bool,
}

/// Runs `on: [answer]` guardrails on a whole answer before it reaches the caller: a block replaces it with a
/// refusal, a mask rewrites its text. Writes an `answer_guardrails` record with the decision's ID, and waits for
/// it: an answer whose check cannot be recorded is not passed on. A streamed answer is passed on unchecked, and
/// its record says so, unless the rule sets `buffer_stream`: then the stream is held whole, checked, and replayed
/// (unchanged, or with the masked text), so the caller's first token waits for the model's last.
async fn answer_guarded(
    state: &AppState,
    check: AnswerCheck,
    decision: &str,
    response: Response,
) -> Result<Response, Refusal> {
    // An error is the provider's or Gantry's own words, not the model's.
    if !response.status().is_success() {
        return Ok(response);
    }
    let record = |found: serde_json::Value, verdict: &str| {
        let mut record = serde_json::Map::new();
        record.insert("event".into(), "answer_guardrails".into());
        record.insert("id".into(), decision.into());
        record.insert("time".into(), gantry_core::audit::timestamp().into());
        record.insert("verdict".into(), verdict.into());
        record.insert("guardrails".into(), found);
        record
    };
    let streamed = is_type(&response, "text/event-stream");
    if streamed && !check.buffer_stream {
        if let Some(audit) = &state.audit {
            let record = record("not_run: the answer is streamed".into(), "not_run");
            audit.log.append_record_then(&record, |_| {});
        }
        return Ok(response);
    }
    let (mut parts, body) = response.into_parts();
    let bytes = whole(body).await?;
    let unreadable = || {
        Refusal::new(
            StatusCode::BAD_GATEWAY,
            guard::BLOCKED_CODE,
            "Refused: the provider's answer is not JSON Gantry can read, and guardrails must check it before it is passed on. Try again. If it keeps happening, tell your Gantry admin.",
        )
    };
    let (mut answer, pointers, texts) = if streamed {
        let slots = stream_texts(&bytes).ok_or_else(unreadable)?;
        let texts = slots.into_iter().map(|(_, text)| text.into()).collect();
        (serde_json::Value::Null, Vec::new(), texts)
    } else {
        let answer: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| unreadable())?;
        let pointers = answer_texts(&answer);
        let texts: Vec<serde_json::Value> = pointers
            .iter()
            .map(|p| answer.pointer(p).cloned().unwrap_or_default())
            .collect();
        (answer, pointers, texts)
    };
    let view = serde_json::json!({
        "messages": texts
            .iter()
            .map(|t| serde_json::json!({"role": "assistant", "content": t}))
            .collect::<Vec<_>>()
    });
    let mut verdict = guard::check_reply(view, &check.guards);
    for guardrail in &check.guards {
        let guard::Check::Webhook(hook) = &guardrail.check else {
            continue;
        };
        if verdict.blocked.is_some() {
            break;
        }
        let sent = guard::WebhookRequest::new(
            decision,
            &check.person,
            &check.team,
            &check.path,
            &verdict.body,
        );
        let reply = ask(state, guardrail.action, hook, &sent).await;
        if let Some(cause) = verdict.merge_answer(guardrail, &sent, reply) {
            eprintln!("gantry: decision {decision}: on the answer: {cause}");
        }
    }
    let word = match (&verdict.blocked, verdict.changed) {
        (Some(_), _) => "block",
        (None, true) => "mask",
        (None, false) => "pass",
    };
    if let Some(audit) = &state.audit {
        let record = record(
            serde_json::to_value(&verdict.audit).unwrap_or_default(),
            word,
        );
        let (tell, written) = tokio::sync::oneshot::channel();
        audit.log.append_record_then(&record, move |result| {
            let _ = tell.send(result);
        });
        if !matches!(written.await, Ok(Ok(()))) {
            return Err(Refusal::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "audit_unavailable",
                "Refused: Gantry could not write the guardrails' check of this answer to its audit log, and it does not pass on what it cannot record. Tell your Gantry admin.",
            ));
        }
    }
    if let Some(blocked) = verdict.blocked {
        let kinds: Vec<String> = verdict
            .audit
            .iter()
            .filter(|e| e.guardrail == blocked.guardrail && e.action == "block")
            .map(|e| format!("{} ({})", e.kind, e.count))
            .collect();
        return Err(Refusal::new(
            StatusCode::FORBIDDEN,
            guard::BLOCKED_CODE,
            format!(
                "Refused: guardrail \"{}\" withheld the model's answer, which contained {}. The answer was produced and is counted in usage. Ask in another way, or ask a Gantry admin about the guardrail.",
                blocked.guardrail,
                kinds.join(", ")
            ),
        ));
    }
    if !verdict.changed {
        return Ok(Response::from_parts(parts, Body::from(bytes)));
    }
    let masked_text = |i: usize| {
        verdict
            .body
            .pointer(&format!("/messages/{i}/content"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    };
    if streamed {
        let masked: Vec<Option<String>> = (0..texts.len()).map(masked_text).collect();
        let replay = mask_stream(&bytes, &masked).ok_or_else(unreadable)?;
        parts.headers.remove(header::CONTENT_LENGTH);
        return Ok(Response::from_parts(parts, Body::from(replay)));
    }
    for (i, pointer) in pointers.iter().enumerate() {
        if let (Some(slot), Some(masked)) = (
            answer.pointer_mut(pointer),
            verdict.body.pointer(&format!("/messages/{i}/content")),
        ) {
            *slot = masked.clone();
        }
    }
    let masked = serde_json::to_vec(&answer).map_err(|_| unreadable())?;
    parts.headers.remove(header::CONTENT_LENGTH);
    Ok(Response::from_parts(parts, Body::from(masked)))
}

/// Where the model's text is in one event of a stream, as (slot, JSON pointer) pairs: a slot is one text the
/// deltas build up. Chat chunks (`choices[].delta.content`, tool call arguments), messages text deltas, and
/// Responses `response.output_text.delta`.
fn event_texts(event: &serde_json::Value) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for (i, choice) in event["choices"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
    {
        let n = choice["index"].as_u64().unwrap_or(i as u64);
        if choice["delta"]["content"].is_string() {
            found.push((format!("c{n}"), format!("/choices/{i}/delta/content")));
        }
        for (j, call) in choice["delta"]["tool_calls"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            if call["function"]["arguments"].is_string() {
                let k = call["index"].as_u64().unwrap_or(j as u64);
                found.push((
                    format!("t{n}.{k}"),
                    format!("/choices/{i}/delta/tool_calls/{j}/function/arguments"),
                ));
            }
        }
    }
    if event["type"] == "content_block_delta" && event["delta"]["text"].is_string() {
        found.push((format!("m{}", event["index"]), "/delta/text".into()));
    }
    if event["type"] == "response.output_text.delta" && event["delta"].is_string() {
        found.push((
            format!("r{}.{}", event["output_index"], event["content_index"]),
            "/delta".into(),
        ));
    }
    found
}

/// The JSON of each `data:` line of a stream, with the line's index; a data line that is not JSON (`[DONE]`) is
/// skipped. None when the stream is not UTF-8.
fn stream_events(bytes: &[u8]) -> Option<Vec<(usize, serde_json::Value)>> {
    let text = std::str::from_utf8(bytes).ok()?;
    Some(
        text.split_inclusive('\n')
            .enumerate()
            .filter_map(|(at, line)| {
                let data = line.strip_prefix("data:")?.trim();
                Some((at, serde_json::from_str(data).ok()?))
            })
            .collect(),
    )
}

/// Each text a stream builds up from its deltas, in the order it starts.
fn stream_texts(bytes: &[u8]) -> Option<Vec<(String, String)>> {
    let mut slots: Vec<(String, String)> = Vec::new();
    for (_, event) in stream_events(bytes)? {
        for (slot, pointer) in event_texts(&event) {
            let piece = event
                .pointer(&pointer)
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match slots.iter_mut().find(|(s, _)| *s == slot) {
                Some((_, text)) => text.push_str(piece),
                None => slots.push((slot, piece.to_string())),
            }
        }
    }
    Some(slots)
}

/// The stream again, every event in place, with each masked text whole in its first delta and the later deltas of
/// that text empty. A whole copy of an original text in a closing event (Responses' `output_text.done` and
/// `response.completed`) is replaced by its masked text too, so the original never reaches the caller.
fn mask_stream(bytes: &[u8], masked: &[Option<String>]) -> Option<Vec<u8>> {
    let originals = stream_texts(bytes)?;
    let text = std::str::from_utf8(bytes).ok()?;
    let mut events: std::collections::HashMap<usize, serde_json::Value> =
        stream_events(bytes)?.into_iter().collect();
    let swap: Vec<(&str, &str)> = originals
        .iter()
        .zip(masked)
        .filter_map(|((_, from), to)| Some((from.as_str(), to.as_deref()?)))
        .filter(|(from, to)| from != to)
        .collect();
    let mut started = std::collections::HashSet::new();
    let mut out = String::with_capacity(text.len());
    for (at, line) in text.split_inclusive('\n').enumerate() {
        let Some(mut event) = events.remove(&at) else {
            out.push_str(line);
            continue;
        };
        for (slot, pointer) in event_texts(&event) {
            let Some(i) = originals.iter().position(|(s, _)| *s == slot) else {
                continue;
            };
            let Some(Some(whole)) = masked.get(i) else {
                continue;
            };
            let piece = if started.insert(slot) {
                whole.clone()
            } else {
                String::new()
            };
            if let Some(target) = event.pointer_mut(&pointer) {
                *target = piece.into();
            }
        }
        replace_texts(&mut event, &swap);
        let ending = &line[line.trim_end_matches(['\r', '\n']).len()..];
        out.push_str(&format!("data: {event}{ending}"));
    }
    Some(out.into_bytes())
}

fn replace_texts(value: &mut serde_json::Value, swap: &[(&str, &str)]) {
    match value {
        serde_json::Value::String(s) => {
            if let Some((_, to)) = swap.iter().find(|(from, _)| from == s) {
                *s = (*to).to_string();
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(|v| replace_texts(v, swap)),
        serde_json::Value::Object(map) => map.values_mut().for_each(|v| replace_texts(v, swap)),
        _ => {}
    }
}

/// Where the model's text is in a whole answer, as JSON pointers: chat completions (`choices[].message.content`
/// and tool call arguments), messages (`content[].text`, tool_use input is JSON and not text) and Responses
/// (`output[].content[].text`).
fn answer_texts(answer: &serde_json::Value) -> Vec<String> {
    let mut pointers = Vec::new();
    let list = |v: &serde_json::Value| v.as_array().cloned().unwrap_or_default();
    for (i, choice) in list(&answer["choices"]).iter().enumerate() {
        if choice["message"]["content"].is_string() {
            pointers.push(format!("/choices/{i}/message/content"));
        }
        for (j, call) in list(&choice["message"]["tool_calls"]).iter().enumerate() {
            if call["function"]["arguments"].is_string() {
                pointers.push(format!(
                    "/choices/{i}/message/tool_calls/{j}/function/arguments"
                ));
            }
        }
    }
    if answer["type"] == "message" {
        for (i, block) in list(&answer["content"]).iter().enumerate() {
            if block["text"].is_string() {
                pointers.push(format!("/content/{i}/text"));
            }
        }
    }
    for (i, item) in list(&answer["output"]).iter().enumerate() {
        for (j, part) in list(&item["content"]).iter().enumerate() {
            if part["text"].is_string() {
                pointers.push(format!("/output/{i}/content/{j}/text"));
            }
        }
    }
    pointers
}

/// The text fields of a form (a transcription's prompt, language and the like: every field but the model that is
/// not a file), with where each value is. Err says why the form or a field cannot be read as text.
fn form_texts(
    headers: &HeaderMap,
    bytes: &[u8],
) -> Result<Vec<(std::ops::Range<usize>, String)>, String> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    alias::form_parts(content_type, bytes)
        .map_err(|why| why.to_string())?
        .into_iter()
        .filter(|part| !part.file && part.name != "model")
        .map(|part| {
            let text = std::str::from_utf8(&bytes[part.value.clone()])
                .map_err(|_| format!("form field \"{}\" is not UTF-8 text", part.name))?;
            Ok((part.value, text.to_string()))
        })
        .collect()
}

/// Where an images, rerank or moderations request keeps its text, as JSON pointers. Err names a text-bearing field
/// of a shape Gantry does not read (QA14-5): it is refused, never forwarded unchecked.
fn text_fields(path: &str, body: &serde_json::Value) -> Result<Vec<String>, String> {
    use serde_json::Value;
    // Every string inside a value. A rerank document may be an object whose fields the caller ranks on
    // (Cohere's rank_fields), so all of them are text.
    fn strings(value: &Value, at: String, out: &mut Vec<String>) {
        match value {
            Value::String(_) => out.push(at),
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
    let mut pointers = Vec::new();
    match path {
        IMAGES => match &body["prompt"] {
            Value::String(_) => pointers.push("/prompt".into()),
            Value::Null => {}
            _ => return Err("prompt".into()),
        },
        RERANK => {
            strings(&body["query"], "/query".into(), &mut pointers);
            strings(&body["documents"], "/documents".into(), &mut pointers);
        }
        // OpenAI's moderation input: a string, a list of strings, or text and image_url items.
        MODERATIONS => match &body["input"] {
            Value::String(_) => pointers.push("/input".into()),
            Value::Null => {}
            Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    match (item, item["type"].as_str()) {
                        (Value::String(_), _) => pointers.push(format!("/input/{i}")),
                        (Value::Object(_), Some("text")) if item["text"].is_string() => {
                            pointers.push(format!("/input/{i}/text"));
                        }
                        (Value::Object(_), Some("image_url")) => {}
                        _ => return Err(format!("input item {}", i + 1)),
                    }
                }
            }
            _ => return Err("input".into()),
        },
        // The guardrails read speech's input and instructions where they are, as strings only.
        SPEECH => {
            for field in ["input", "instructions"] {
                if !matches!(body[field], Value::String(_) | Value::Null) {
                    return Err(field.into());
                }
            }
        }
        _ => {}
    }
    Ok(pointers)
}

/// Asks a remote guardrail (a webhook, or a vendor in its own API) through the provider client, all calls within
/// the guardrail's timeout. Returns the answer in the contract's terms, or why there is none, for the server's log.
async fn ask(
    state: &AppState,
    action: guard::Action,
    hook: &guard::Webhook,
    sent: &guard::WebhookRequest,
) -> Result<guard::WebhookAnswer, String> {
    // ponytail: credentials are read from the environment on each call. Start and reload refuse a policy whose
    // variables are unset, and a running process's environment does not change, so this is only a lookup.
    let env = |variable: &str| std::env::var(variable).ok();
    let mut exchange = gantry_core::vendors::Exchange::new(
        &hook.vendor,
        &hook.url,
        action,
        hook.key_env.as_deref(),
        &hook.headers_env,
        sent,
        &env,
    );
    let calls = async {
        let mut reply = exchange.start()?;
        loop {
            match reply {
                gantry_core::vendors::Reply::Done(answer) => return Ok(answer),
                gantry_core::vendors::Reply::Next(call) => {
                    let bytes = post(state, call).await?;
                    reply = exchange.answer(&bytes)?;
                }
            }
        }
    };
    tokio::time::timeout(hook.timeout, calls)
        .await
        .unwrap_or_else(|_| {
            Err(format!(
                "gave no answer within {} ms",
                hook.timeout.as_millis()
            ))
        })
}

/// One POST to a guardrail service; the answer's bytes, or why there are none.
async fn post(state: &AppState, call: gantry_core::vendors::Call) -> Result<Vec<u8>, String> {
    let mut request = Request::post(&call.url);
    for (name, value) in &call.headers {
        request = request.header(name.as_str(), value.as_str());
    }
    let request = request
        .body(Body::from(call.body))
        .map_err(|err| format!("the url or a header cannot be used: {err}"))?;
    let response = state
        .client
        .request(request)
        .await
        .map_err(|err| format!("could not be reached: {err}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("answered with status {status}"));
    }
    // An answer can carry every message masked, so it may be as large as a request.
    http_body_util::Limited::new(response.into_body(), MAX_BODY_BYTES)
        .collect()
        .await
        .map(|b| b.to_bytes().to_vec())
        .map_err(|err| format!("the answer could not be read: {err}"))
}

/// Sends a checked request to its provider, and streams the answer back as it arrives. A connection failure, a
/// timeout, a 429 or a 5xx is tried again on the same provider up to its `retries`, then on its `fallback`. All of
/// that happens before the first byte of an answer reaches the caller; once one has, nothing is tried again.
async fn send(
    state: &AppState,
    version: &Snapshot,
    mut parts: Parts,
    bytes: Bytes,
    arrived: Instant,
    decision: &str,
) -> Result<Response, Refusal> {
    let plan = parts.extensions.remove::<Plan>();
    let answer_check = parts.extensions.remove::<AnswerCheck>();
    // Gantry's, not the provider's. Dropped unused, it gives back its reservation.
    let mut admitted = parts
        .extensions
        .remove::<spend::Meter>()
        .and_then(|meter| meter.take());
    // A checked request carries its plan. An unchecked one goes to the single upstream.
    let first = plan.as_ref().map_or_else(
        || {
            version
                .providers
                .iter()
                .position(|p| p.models.is_empty())
                .unwrap_or(0)
        },
        |plan| plan.provider,
    );
    let Some(provider) = version.providers.get(first) else {
        return Err(Refusal::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_upstream",
            "This Gantry has no provider configured. Its admin must set GANTRY_UPSTREAM and restart it.",
        ));
    };
    let headers = &mut parts.headers;
    strip_hop_by_hop(headers);
    // The client sets Host for the provider. Keeping the caller's would name the gateway instead.
    headers.remove(header::HOST);
    // Cookies mean nothing to a provider and can carry a session from wherever the caller's tool runs.
    headers.remove(header::COOKIE);
    // The body may be translated or adjusted for the provider, so its length is set from what is sent.
    headers.remove(header::CONTENT_LENGTH);
    if version.policy.is_some() {
        // The caller's credential is a Gantry key. It must never reach the provider, in whichever header it came.
        // Headers that pick the provider account or project go too: the provider key is Gantry's, and so is that choice.
        let private: Vec<HeaderName> = headers
            .keys()
            .filter(|name| {
                let name = name.as_str();
                // AWS headers are Gantry's to sign and set: a caller's would sit beside the signature and could
                // choose account options at Bedrock.
                name.starts_with("x-amz")
                    // Any header named for a credential, whatever the provider calls it. An idempotency key is not one.
                    || name != "idempotency-key"
                    && [
                        "authorization",
                        "key",
                        "token",
                        "secret",
                        "organization",
                        "project",
                    ]
                    .iter()
                    .any(|word| name.contains(word))
            })
            .cloned()
            .collect();
        for name in private {
            headers.remove(name);
        }
    }
    // With a policy every query parameter has been checked against the route's list, so what is left goes on.
    // A translated request goes to the messages route, which it now is.
    let route = match plan.as_ref().map(|p| (p.from_messages, p.translated)) {
        Some((true, _)) => CHAT.to_string(),
        Some((false, Some(_))) => MESSAGES.to_string(),
        _ => parts
            .uri
            .path_and_query()
            .map_or("/", |pq| pq.as_str())
            .to_string(),
    };
    let mut chain = plan
        .as_ref()
        .map_or_else(|| vec![(first, String::new())], |p| p.chain.clone());
    // A provider's own fallback takes the same model; an alias has its deployments instead.
    if let Some(plan) = plan.as_ref().filter(|p| p.cooldown.is_none())
        && let Some(fallback) = provider
            .fallback
            .as_ref()
            .and_then(|name| version.providers.iter().position(|p| p.name == *name))
    {
        chain.push((fallback, plan.model.clone()));
    }
    let mut attempts: Vec<(String, String)> = Vec::new();
    let mut sent = None;
    let try_chain = Tries {
        state,
        version,
        parts: &parts,
        bytes: &bytes,
        route: &route,
        plan: plan.as_ref(),
    };
    let (mut last, mut served, mut busy) = try_chain
        .run(&chain, &mut attempts, &mut sent, &mut admitted)
        .await?;
    // A named fallback for a prompt too long for the model's context, or one refused under the provider's content
    // policy. The error answer is read whole only when the alias names a fallback for it.
    if let Some(plan) = plan
        .as_ref()
        .filter(|p| !p.context.is_empty() || !p.content.is_empty())
        && let Some(Ok(response)) = last.as_mut()
        && response.status().is_client_error()
    {
        let body = whole(std::mem::take(response.body_mut())).await?;
        let next = match alias::refused(&body) {
            Some(alias::Refused::ContextWindow) => &plan.context,
            Some(alias::Refused::ContentPolicy) => &plan.content,
            None => &Vec::new(),
        };
        *response.body_mut() = Body::from(body);
        if !next.is_empty() {
            (last, served, busy) = try_chain
                .run(next, &mut attempts, &mut sent, &mut admitted)
                .await?;
        }
    }
    let (served, served_model) = served;
    let answered = Instant::now();
    if attempts.len() > 1 {
        record_attempts(state, decision, &attempts);
    }
    let response = last.unwrap_or_else(|| Err(unknown_route()))?;
    let response = native(&version.providers[served], response).await?;
    // Usage is read in the provider's format (Bedrock's already decoded) before any translation, and settled with
    // the provider that answered, a fallback included.
    let response = match admitted {
        Some(mut admitted) => {
            let price = version
                .policy
                .as_ref()
                .and_then(|p| gantry_core::usage::price_for(&served_model, p.prices()));
            admitted.served_by(&version.providers[served].name, &served_model, price);
            spend::Metered::wrap(response, admitted)
        }
        None => response,
    };
    // An alias's deployment stays busy until its answer has been passed on.
    let response = match busy {
        Some(busy) => response.map(|body| {
            Body::new(Holding {
                inner: body,
                _busy: busy,
            })
        }),
        None => response,
    };
    let mut response = for_caller(
        version.providers[served].kind,
        &version.providers[served].name,
        plan.as_ref(),
        decision,
        response,
    )
    .await?;
    strip_hop_by_hop(response.headers_mut());
    // Time from the request reaching Gantry's handler to it leaving for the provider, plus the time to hand the
    // answer back: identifying, deciding, recording. It does not cover reading the request off the socket or
    // streaming the answer, so the bench reads it as a breakdown and gates on what the client sees.
    let own = (sent.unwrap_or(answered) - arrived) + answered.elapsed();
    state.metrics.overhead(own);
    if let Ok(value) =
        HeaderValue::from_str(&format!("gantry;dur={:.3}", own.as_secs_f64() * 1000.0))
    {
        // Appended, not inserted: the provider's own timings stay.
        response
            .headers_mut()
            .append(HeaderName::from_static("server-timing"), value);
    }
    if let Some(check) = answer_check {
        response.extensions_mut().insert(check);
    }
    Ok(response)
}

/// What every attempt at one request shares.
struct Tries<'a> {
    state: &'a AppState,
    version: &'a Snapshot,
    parts: &'a Parts,
    bytes: &'a Bytes,
    route: &'a str,
    plan: Option<&'a Plan>,
}

/// The last outcome of a chain, which deployment gave it (provider position and model), and, for an alias, the
/// count that keeps that deployment busy.
type Tried = (
    Option<Result<Response, Refusal>>,
    (usize, String),
    Option<alias::Busy>,
);

impl Tries<'_> {
    /// Tries each deployment of `chain` in turn, each up to its provider's retries, until one answers with
    /// something other than a connection failure, a timeout, a 429 or a 5xx.
    async fn run(
        &self,
        chain: &[(usize, String)],
        attempts: &mut Vec<(String, String)>,
        sent: &mut Option<Instant>,
        admitted: &mut Option<spend::Admitted>,
    ) -> Result<Tried, Refusal> {
        let cooldown = self.plan.and_then(|p| p.cooldown);
        let mut tried: Tried = (None, chain.first().cloned().unwrap_or_default(), None);
        'providers: for (index, model) in chain {
            let provider = &self.version.providers[*index];
            let label = alias::label(&provider.name, model);
            for retry in 0..=provider.retries {
                if retry > 0 {
                    // ponytail: 200 ms doubling (100 << retry, from retry 1) with no jitter and no Retry-After; add
                    // both if providers ask for it.
                    tokio::time::sleep(Duration::from_millis(100 << retry.min(5))).await;
                }
                let request = outbound(
                    provider, self.parts, self.bytes, self.route, self.plan, model,
                )?;
                let started = Instant::now();
                sent.get_or_insert(started);
                let busy = cooldown.map(|_| self.state.pool.busy(&label));
                // Dropped while waiting here (the caller hung up), the request is charged: the provider has it.
                if let Some(admitted) = admitted.as_mut() {
                    admitted.forwarded(true);
                }
                let outcome = attempt(self.state, provider, request).await;
                // A request that never reached an answer is not charged; an answer is settled when it is passed on.
                if let Some(admitted) = admitted.as_mut() {
                    admitted.forwarded(outcome.is_ok());
                }
                let (again, outcome_word) = match &outcome {
                    Ok(response) => {
                        let status = response.status();
                        (
                            status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error(),
                            status.as_u16().to_string(),
                        )
                    }
                    Err(refusal) => (
                        refusal.code.starts_with("upstream_"),
                        refusal.code.to_string(),
                    ),
                };
                self.state
                    .metrics
                    .attempted(&provider.name, &outcome_word, started.elapsed());
                attempts.push((
                    if cooldown.is_some() {
                        label.clone()
                    } else {
                        provider.name.clone()
                    },
                    outcome_word,
                ));
                tried = (Some(outcome), (*index, model.clone()), busy);
                if let Some(cooldown) = cooldown {
                    if again {
                        self.state.pool.failed(&label, cooldown);
                    } else {
                        self.state.pool.answered(&label);
                    }
                }
                if !again {
                    break 'providers;
                }
            }
        }
        Ok(tried)
    }
}

/// An answer's body that keeps its deployment counted as busy until it has been read or dropped.
struct Holding {
    inner: Body,
    _busy: alias::Busy,
}

impl http_body::Body for Holding {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, axum::Error>>> {
        std::pin::Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

/// The request for one attempt at one provider: its URL, its body in the form the provider takes, and its key.
/// `model` is the model it is sent to there: the caller's, or an alias's deployment.
fn outbound(
    provider: &Upstream,
    parts: &Parts,
    bytes: &Bytes,
    route: &str,
    plan: Option<&Plan>,
    model: &str,
) -> Result<axum::http::Request<Body>, Refusal> {
    // The body names the model the caller sent. Sent to another, it names that one.
    let rewritten;
    let bytes = match plan {
        Some(plan) if plan.model != model => {
            let content_type = parts
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok());
            rewritten = alias::with_model(content_type, bytes, model);
            &rewritten
        }
        _ => bytes,
    };
    // Every model of an azure or bedrock provider, and of the providers it falls back from, has a name there:
    // `gantry check` makes sure. This is the refusal if a hand-built configuration skipped that.
    let mapped = || {
        provider.upstream_models.get(model).ok_or_else(|| {
            Refusal::new(
                StatusCode::FORBIDDEN,
                "unknown_model",
                format!(
                    "Refused: provider \"{}\" has no deployment or model ID for model \"{model}\". Ask a Gantry admin to add it.",
                    provider.name
                ),
            )
        })
    };
    let mut headers = parts.headers.clone();
    let (url, body) = match provider.kind {
        Kind::OpenAi | Kind::Anthropic => (
            gantry_core::config::join(&provider.url, route),
            bytes.clone(),
        ),
        Kind::Azure => (
            format!(
                "{}/openai/deployments/{}/chat/completions?api-version={}",
                provider.url,
                sigv4::uri_encode(mapped()?, false),
                provider.api_version.as_deref().unwrap_or_default()
            ),
            bytes.clone(),
        ),
        Kind::Gemini | Kind::Vertex => {
            let (body, stream, _) = to_gemini(bytes)?;
            let has_path = provider
                .url
                .split_once("://")
                .is_some_and(|(_, rest)| rest.contains('/'));
            // A Gemini API URL without a path gets the version Gantry's translation follows.
            let base = if has_path {
                provider.url.clone()
            } else {
                format!("{}/v1beta", provider.url)
            };
            let method = if stream {
                "streamGenerateContent?alt=sse"
            } else {
                "generateContent"
            };
            (
                format!("{base}/models/{}:{method}", sigv4::uri_encode(model, false)),
                body,
            )
        }
        Kind::VertexAnthropic => {
            let (body, stream) = vertex_body(bytes)?;
            let method = if stream {
                "streamRawPredict"
            } else {
                "rawPredict"
            };
            (
                format!(
                    "{}/models/{}:{method}",
                    provider.url,
                    sigv4::uri_encode(model, false)
                ),
                body,
            )
        }
        Kind::Bedrock => {
            let (body, stream) = bedrock_body(bytes, &headers)?;
            let action = if stream {
                "invoke-with-response-stream"
            } else {
                "invoke"
            };
            (
                format!(
                    "{}/model/{}/{action}",
                    provider.url,
                    sigv4::uri_encode(mapped()?, false)
                ),
                body,
            )
        }
    };
    let Ok(uri) = url.parse::<Uri>() else {
        return Err(Refusal::new(
            StatusCode::BAD_REQUEST,
            "bad_path",
            "The request path is not a valid URL path.",
        ));
    };
    if plan.is_some_and(|p| p.from_messages) {
        // Anthropic's version, betas and client headers mean nothing to a chat provider (SAFE_TO_DROP in
        // translate.rs).
        let anthropic: Vec<HeaderName> = headers
            .keys()
            .filter(|name| name.as_str().starts_with("anthropic-"))
            .cloned()
            .collect();
        for name in anthropic {
            headers.remove(name);
        }
    }
    if plan.is_some_and(|p| p.translated.is_some() && !p.from_messages)
        && matches!(provider.kind, Kind::Anthropic | Kind::VertexAnthropic)
    {
        // A chat client sends no API version. Anthropic requires one; this is the version the translation follows.
        headers
            .entry(HeaderName::from_static("anthropic-version"))
            .or_insert(HeaderValue::from_static("2023-06-01"));
    }
    if let Some((name, value)) = &provider.key {
        headers.insert(name.clone(), value.clone());
    }
    if provider.kind == Kind::Bedrock {
        sign_for_bedrock(provider, &uri, &body, &mut headers)?;
    }
    let mut request = axum::http::Request::new(Body::from(body));
    *request.method_mut() = parts.method.clone();
    *request.uri_mut() = uri;
    *request.version_mut() = Version::HTTP_11;
    *request.headers_mut() = headers;
    Ok(request)
}

/// A messages request as Bedrock's InvokeModel takes it: no model (it is in the path), no stream (that is the
/// action), its API version and betas in the body. Returns the body and whether the answer is to stream.
fn bedrock_body(bytes: &[u8], headers: &HeaderMap) -> Result<(Bytes, bool), Refusal> {
    let Ok(serde_json::Value::Object(mut body)) = serde_json::from_slice(bytes) else {
        return Err(Refusal::new(
            StatusCode::BAD_REQUEST,
            "unreadable_request",
            "Refused: the request body is not a JSON object. Send a messages request.",
        ));
    };
    body.remove("model");
    let stream = body.remove("stream") == Some(serde_json::Value::Bool(true));
    body.entry("anthropic_version")
        .or_insert_with(|| "bedrock-2023-05-31".into());
    // Bedrock reads betas from the body. They are carried over as sent: one Bedrock does not offer is its 400 to give.
    let betas: Vec<serde_json::Value> = headers
        .get_all("anthropic-beta")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|beta| !beta.is_empty())
        .map(serde_json::Value::from)
        .collect();
    if !betas.is_empty() {
        body.entry("anthropic_beta").or_insert_with(|| betas.into());
    }
    let body = serde_json::to_vec(&body).map_err(|_| {
        Refusal::new(
            StatusCode::BAD_REQUEST,
            "unreadable_request",
            "Refused: the request body could not be prepared for Amazon Bedrock. Send a messages request.",
        )
    })?;
    Ok((Bytes::from(body), stream))
}

/// A messages request as Vertex AI's rawPredict takes Claude's: no model (it is in the path), the Vertex API
/// version in the body. `stream` stays in the body and also picks streamRawPredict. Returns the body and whether
/// the answer streams.
fn vertex_body(bytes: &[u8]) -> Result<(Bytes, bool), Refusal> {
    let Ok(serde_json::Value::Object(mut body)) = serde_json::from_slice(bytes) else {
        return Err(Refusal::new(
            StatusCode::BAD_REQUEST,
            "unreadable_request",
            "Refused: the request body is not a JSON object. Send a messages request.",
        ));
    };
    body.remove("model");
    let stream = body.get("stream") == Some(&serde_json::Value::Bool(true));
    body.entry("anthropic_version")
        .or_insert_with(|| "vertex-2023-10-16".into());
    let body = serde_json::to_vec(&body).map_err(|_| {
        Refusal::new(
            StatusCode::BAD_REQUEST,
            "unreadable_request",
            "Refused: the request body could not be prepared for Vertex AI. Send a messages request.",
        )
    })?;
    Ok((Bytes::from(body), stream))
}

/// Signs a Bedrock request with AWS Signature Version 4, and sets the headers the signature covers.
fn sign_for_bedrock(
    provider: &Upstream,
    uri: &Uri,
    body: &[u8],
    headers: &mut HeaderMap,
) -> Result<(), Refusal> {
    let failed = || {
        Refusal::new(
            StatusCode::BAD_GATEWAY,
            "upstream_failed",
            "Gantry could not sign the request for Amazon Bedrock. Tell your Gantry admin: the AWS credentials or region may hold a character that cannot be sent.",
        )
    };
    let (Some(credentials), Some(region), Some(host)) =
        (&provider.aws, &provider.region, uri.authority())
    else {
        return Err(failed());
    };
    // The betas went into the body. The other Anthropic headers mean nothing to Bedrock.
    headers.remove("anthropic-beta");
    headers.remove("anthropic-version");
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    let signed = sigv4::sign(
        credentials,
        region,
        "bedrock",
        &sigv4::Request {
            method: "POST",
            path: uri.path(),
            query: "",
            headers: &[
                ("host", host.as_str()),
                ("content-type", "application/json"),
            ],
            payload: body,
        },
        &sigv4::amz_date_now(),
    );
    // Set here and kept by the client, so the Host sent is the one signed.
    headers.insert(
        header::HOST,
        HeaderValue::from_str(host.as_str()).map_err(|_| failed())?,
    );
    for (name, value) in signed {
        let mut value = HeaderValue::from_str(&value).map_err(|_| failed())?;
        value.set_sensitive(true);
        headers.insert(HeaderName::from_static(name), value);
    }
    Ok(())
}

/// One attempt: sends the request and waits for the provider to start answering.
async fn attempt(
    state: &AppState,
    provider: &Upstream,
    request: axum::http::Request<Body>,
) -> Result<Response, Refusal> {
    let upstream = &provider.url;
    let outcome =
        tokio::time::timeout(state.timeouts.first_byte, state.client.request(request)).await;
    match outcome {
        Ok(Ok(response)) => Ok(response.map(Body::new)),
        Ok(Err(err)) => {
            // The detail is for the admin's log. The caller cannot act on it and must not see addresses.
            eprintln!("gantry: the provider at {upstream} failed: {err}");
            let (code, message) = if err.is_connect() {
                (
                    "upstream_unreachable",
                    "Gantry could not reach the provider. Try again. If it keeps happening, tell your Gantry admin.",
                )
            } else {
                (
                    "upstream_failed",
                    "The provider broke the connection before answering. Try again. If it keeps happening, tell your Gantry admin.",
                )
            };
            Err(Refusal::new(StatusCode::BAD_GATEWAY, code, message))
        }
        Err(_) => {
            eprintln!(
                "gantry: the provider at {upstream} sent nothing for {} seconds",
                state.timeouts.first_byte.as_secs()
            );
            Err(Refusal::new(
                StatusCode::GATEWAY_TIMEOUT,
                "upstream_timeout",
                format!(
                    "The provider did not start answering within {} seconds. Try again. If it keeps happening, tell your Gantry admin.",
                    state.timeouts.first_byte.as_secs()
                ),
            ))
        }
    }
}

/// Writes which providers were tried and how each answered, after the request record that let it through.
/// That record is written before anything is forwarded, so it cannot know; this one follows it, with the same ID.
fn record_attempts(state: &AppState, decision: &str, attempts: &[(String, String)]) {
    let Some(audit) = &state.audit else {
        return;
    };
    let list: Vec<serde_json::Value> = attempts
        .iter()
        .map(|(provider, outcome)| serde_json::json!({ "provider": provider, "outcome": outcome }))
        .collect();
    let mut record = serde_json::Map::new();
    record.insert("event".into(), "attempts".into());
    record.insert("id".into(), decision.into());
    record.insert("time".into(), gantry_core::audit::timestamp().into());
    record.insert("attempts".into(), list.into());
    // The answer is already on its way. A log that cannot take this record refuses the next request instead.
    audit.log.append_record_then(&record, |_| {});
}

/// The most of a provider's answer Gantry reads whole, to translate it. Streamed answers are not held.
const MAX_ANSWER_BYTES: usize = 64 * MIB;

async fn whole(body: Body) -> Result<Bytes, Refusal> {
    http_body_util::Limited::new(body, MAX_ANSWER_BYTES)
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .map_err(|_| {
            Refusal::new(
                StatusCode::BAD_GATEWAY,
                "upstream_failed",
                "The provider's answer broke off or was larger than Gantry translates. Try again. If it keeps happening, tell your Gantry admin.",
            )
        })
}

fn is_type(response: &Response, prefix: &str) -> bool {
    response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with(prefix))
}

fn json_body(mut response: Response, body: Vec<u8>) -> Response {
    let headers = response.headers_mut();
    headers.remove(header::CONTENT_LENGTH);
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    *response.body_mut() = Body::from(body);
    response
}

/// Bedrock's event stream and errors as Anthropic's, so every messages answer reads the same from here on.
async fn native(provider: &Upstream, mut response: Response) -> Result<Response, Refusal> {
    if provider.kind == Kind::Bedrock {
        if !response.status().is_success() {
            let error_type = response
                .headers()
                .get("x-amzn-errortype")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let body = whole(std::mem::take(response.body_mut())).await?;
            let error = eventstream::anthropic_error(&error_type, &body);
            response = json_body(response, error.to_string().into_bytes());
        } else if is_type(&response, "application/vnd.amazon.eventstream") {
            let mut sse = eventstream::BedrockToSse::default();
            response = map_body(response, "text/event-stream", move |input| match input {
                Some(bytes) => sse.feed(bytes),
                None => sse.finish(),
            });
        }
    }
    Ok(response)
}

/// A messages or Gemini answer (by the `kind` of provider that gave it) as a chat completions one, when the request
/// was translated. `include_usage` is set then: whether the client asked for usage in its stream.
async fn to_chat(
    kind: Kind,
    include_usage: Option<bool>,
    decision: &str,
    mut response: Response,
) -> Result<Response, Refusal> {
    // Gemini may send no responseId; a strict chat client refuses "id": null, and the decision ID is unique.
    let fallback_id = format!("chatcmpl-{decision}");
    let Some(include_usage) = include_usage else {
        return Ok(response);
    };
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    if response.status().is_success() && is_type(&response, "text/event-stream") && kind.google() {
        let mut stream =
            gemini::GeminiToOpenAiStream::new(include_usage, created).with_id(fallback_id);
        return Ok(map_body(response, "text/event-stream", move |input| {
            match input {
                Some(bytes) => stream.feed(bytes),
                None => stream.finish(),
            }
            .map_err(|err| err.to_string())
        }));
    }
    if response.status().is_success() && is_type(&response, "text/event-stream") {
        let mut stream = translate::AnthropicToOpenAiStream::new(include_usage, created);
        return Ok(map_body(response, "text/event-stream", move |input| {
            match input {
                Some(bytes) => stream.feed(bytes),
                None => stream.finish(),
            }
            .map_err(|err| err.to_string())
        }));
    }
    let body = whole(std::mem::take(response.body_mut())).await?;
    let answer: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    let out = if response.status().is_success() {
        let translated = if kind.google() {
            gemini::gemini_to_openai_response(&answer, created)
        } else {
            translate::anthropic_to_openai_response(&answer, created)
        };
        let mut translated = translated.map_err(|err| {
            Refusal::new(
                StatusCode::BAD_GATEWAY,
                "untranslatable",
                format!("The provider's answer could not be translated to the chat completions format: {err}"),
            )
        })?;
        if translated["id"].is_null() {
            translated["id"] = serde_json::Value::String(fallback_id);
        }
        translated
    } else {
        // An error in the shape OpenAI's clients read, with the provider's own type and message.
        let error = &answer["error"];
        let message = error["message"]
            .as_str()
            .map_or_else(|| String::from_utf8_lossy(&body).into_owned(), String::from);
        serde_json::json!({
            "error": {
                "message": message,
                // Gemini names its error in status, such as RESOURCE_EXHAUSTED.
                "type": error["type"].as_str().or(error["status"].as_str()).unwrap_or("api_error"),
                "code": serde_json::Value::Null,
            }
        })
    };
    Ok(json_body(response, out.to_string().into_bytes()))
}

/// The answer in the format the caller asked in: as sent, as chat completions (`to_chat`), or, for a messages
/// request translated to chat, as messages.
async fn for_caller(
    kind: Kind,
    provider: &str,
    plan: Option<&Plan>,
    decision: &str,
    response: Response,
) -> Result<Response, Refusal> {
    match plan {
        Some(plan) if plan.from_messages => {
            // A Google answer becomes chat first, which the step below reads.
            let response = if kind.google() {
                to_chat(kind, Some(true), decision, response).await?
            } else {
                response
            };
            to_anthropic(provider, decision, response).await
        }
        _ => to_chat(kind, plan.and_then(|p| p.translated), decision, response).await,
    }
}

/// A chat completions answer as a messages one, streamed or whole, errors included.
async fn to_anthropic(
    provider: &str,
    decision: &str,
    mut response: Response,
) -> Result<Response, Refusal> {
    let fallback_id = format!("msg_{decision}");
    if response.status().is_success() && is_type(&response, "text/event-stream") {
        let mut stream = translate::OpenAiToAnthropicStream::new(fallback_id);
        return Ok(map_body(response, "text/event-stream", move |input| {
            match input {
                Some(bytes) => stream.feed(bytes),
                None => stream.finish(),
            }
            .map_err(|err| err.to_string())
        }));
    }
    let body = whole(std::mem::take(response.body_mut())).await?;
    let answer: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    let out = if response.status().is_success() {
        let mut translated = translate::openai_to_anthropic_response(&answer).map_err(|err| {
            Refusal::new(
                StatusCode::BAD_GATEWAY,
                "untranslatable",
                format!(
                    "The provider's answer could not be translated to the messages format: {err}"
                ),
            )
        })?;
        if translated["id"].is_null() {
            translated["id"] = serde_json::Value::String(fallback_id);
        }
        translated
    } else {
        // An error in the shape Anthropic's clients read, with the provider's own message.
        let error = &answer["error"];
        let message = error["message"]
            .as_str()
            .map_or_else(|| String::from_utf8_lossy(&body).into_owned(), String::from);
        let status = response.status();
        // Claude Code reads this: a busy or failing provider may clear, a request it refused will not.
        let again = status.as_u16() == 408
            || status.as_u16() == 409
            || status.as_u16() == 429
            || status.is_server_error();
        response.headers_mut().insert(
            HeaderName::from_static("x-should-retry"),
            HeaderValue::from_static(if again { "true" } else { "false" }),
        );
        let message = format!(
            "Provider \"{provider}\" answered {}: {} Decision {decision}.",
            status.as_u16(),
            message.trim()
        );
        serde_json::json!({
            "type": "error",
            "decision": decision,
            "error": {
                // By status: OpenAI's own types (server_error, insufficient_quota) are not Anthropic's.
                "type": match response.status().as_u16() {
                    401 => "authentication_error",
                    403 => "permission_error",
                    404 => "not_found_error",
                    413 => "request_too_large",
                    429 => "rate_limit_error",
                    503 | 529 => "overloaded_error",
                    _ => anthropic_type("", response.status()),
                },
                "message": message,
            }
        })
    };
    Ok(json_body(response, out.to_string().into_bytes()))
}

/// A step that turns the bytes of a streamed answer into another format as they arrive. `None` is the end.
type Step = Box<dyn FnMut(Option<&[u8]>) -> Result<Vec<u8>, String> + Send>;

/// A streamed answer passed through a [`Step`], one piece at a time: nothing is held back for the whole answer.
struct Mapped {
    inner: Body,
    step: Step,
    done: bool,
}

impl http_body::Body for Mapped {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, axum::Error>>> {
        use std::task::Poll;
        let this = &mut *self;
        loop {
            if this.done {
                return Poll::Ready(None);
            }
            let input = match std::pin::Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(err))) => return Poll::Ready(Some(Err(err))),
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => Some(data),
                    Err(_) => continue,
                },
                Poll::Ready(None) => {
                    this.done = true;
                    None
                }
            };
            match (this.step)(input.as_deref()) {
                Ok(out) if out.is_empty() => {}
                Ok(out) => return Poll::Ready(Some(Ok(http_body::Frame::data(Bytes::from(out))))),
                Err(err) => {
                    // The caller has part of an answer. Breaking the stream is the only honest way to say it is incomplete.
                    eprintln!("gantry: a streamed answer could not be converted: {err}");
                    this.done = true;
                    return Poll::Ready(Some(Err(axum::Error::new(err))));
                }
            }
        }
    }
}

fn map_body(
    mut response: Response,
    content_type: &'static str,
    step: impl FnMut(Option<&[u8]>) -> Result<Vec<u8>, String> + Send + 'static,
) -> Response {
    let inner = std::mem::take(response.body_mut());
    let headers = response.headers_mut();
    headers.remove(header::CONTENT_LENGTH);
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    *response.body_mut() = Body::new(Mapped {
        inner,
        step: Box::new(step),
        done: false,
    });
    response
}

/// Resolves when the process is asked to stop: Ctrl-C, or SIGTERM where the platform has it.
pub async fn stop_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
        let term = async {
            match terminate.as_mut() {
                Some(signal) => {
                    signal.recv().await;
                }
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            // An error here means no handler could be installed. Stopping is the safe response.
            _ = tokio::signal::ctrl_c() => {}
            _ = term => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Serves on a listener until `stop` resolves, then lets requests in flight finish.
/// They get `timeouts.shutdown` to do so, and a second stop signal ends the wait at once.
pub async fn serve_on(
    listener: tokio::net::TcpListener,
    app: Router,
    timeouts: Timeouts,
    stop: impl Future<Output = ()>,
) {
    accept_loop(listener, app, timeouts, stop, None).await;
}

/// `serve_on` with TLS terminated by Gantry: every connection must finish a TLS handshake first.
pub async fn serve_on_tls(
    listener: tokio::net::TcpListener,
    app: Router,
    timeouts: Timeouts,
    stop: impl Future<Output = ()>,
    tls: tokio_rustls::TlsAcceptor,
) {
    accept_loop(listener, app, timeouts, stop, Some(tls)).await;
}

/// Reads a PEM certificate chain and private key for `gantry serve --tls-cert --tls-key`.
pub fn tls_acceptor(cert: &Path, key: &Path) -> Result<tokio_rustls::TlsAcceptor, String> {
    use tokio_rustls::rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    };
    let certs = CertificateDer::pem_file_iter(cert)
        .and_then(|certs| certs.collect::<Result<Vec<_>, _>>())
        .map_err(|err| format!("could not read a certificate from {} (--tls-cert): {err}. Give a PEM file that starts with -----BEGIN CERTIFICATE-----, the server certificate first and then any intermediates.", cert.display()))?;
    if certs.is_empty() {
        return Err(format!(
            "{} (--tls-cert) holds no certificate. Give a PEM file that starts with -----BEGIN CERTIFICATE-----.",
            cert.display()
        ));
    }
    let private = PrivateKeyDer::from_pem_file(key).map_err(|err| format!("could not read a private key from {} (--tls-key): {err}. Give the PEM private key of the certificate (PKCS#8, PKCS#1 or SEC1), unencrypted.", key.display()))?;
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|err| format!("TLS could not be set up: {err}. Report this as a bug."))?
    .with_no_client_auth()
    .with_single_cert(certs, private)
    .map_err(|err| format!("the key in {} does not match the certificate in {}, or is not usable: {err}. Give the key the certificate was issued for.", key.display(), cert.display()))?;
    let mut config = config;
    // HTTP/1 only, as on plain HTTP (see accept_loop): announcing h2 would make clients try it.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

async fn accept_loop(
    listener: tokio::net::TcpListener,
    app: Router,
    timeouts: Timeouts,
    stop: impl Future<Output = ()>,
    tls: Option<tokio_rustls::TlsAcceptor>,
) {
    // HTTP/1 only, and no protocol upgrades: an HTTP/2 connection has no idle deadline here, with or without TLS.
    let mut builder = Builder::new(TokioExecutor::new()).http1_only();
    // Without this, a client that opens a connection and never finishes its headers holds it forever.
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(timeouts.read_headers);
    let graceful = GracefulShutdown::new();
    tokio::pin!(stop);
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, peer)) = accepted else {
                    // Out of file descriptors, most likely. Back off instead of spinning.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                };
                let over_tls = tls.is_some();
                let service = app.clone().map_request(move |mut request: axum::http::Request<_>| {
                    request.extensions_mut().insert(ClientAddr(peer));
                    // The console marks its cookies Secure on a connection Gantry terminated TLS for (QA14-6).
                    if over_tls {
                        request.extensions_mut().insert(axum::http::uri::Scheme::HTTPS);
                    }
                    // The console reads the client's address from here, for its records.
                    request.extensions_mut().insert(axum::extract::ConnectInfo(peer));
                    request
                });
                // Set by the first request on this connection that hyper has read the headers of.
                let asked = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let saw = asked.clone();
                let service = service.map_request(move |request: axum::http::Request<_>| {
                    saw.store(true, std::sync::atomic::Ordering::Relaxed);
                    request
                });
                let (builder, watcher, deadline, tls) = (builder.clone(), graceful.watcher(), timeouts.read_headers, tls.clone());
                tokio::spawn(async move {
                    // hyper's header deadline starts with the first byte of a request and does not cover a
                    // connection that sends nothing, one byte, or a protocol preface and then waits. So the
                    // connection as a whole gets the same deadline to produce its first request.
                    let started = tokio::time::Instant::now();
                    let first_request = async {
                        tokio::time::sleep_until(started + deadline).await;
                        asked.load(std::sync::atomic::Ordering::Relaxed)
                    };
                    let service = TowerToHyperService::new(service);
                    match tls {
                        None => {
                            let connection = watcher.watch(builder.serve_connection(TokioIo::new(stream), service));
                            run_connection(connection, first_request).await;
                        }
                        Some(tls) => {
                            // The handshake counts against the same deadline: a client that stalls in it is closed.
                            let Ok(Ok(stream)) = tokio::time::timeout_at(started + deadline, tls.accept(stream)).await else {
                                return;
                            };
                            let connection = watcher.watch(builder.serve_connection(TokioIo::new(stream), service));
                            run_connection(connection, first_request).await;
                        }
                    }
                });
            }
            () = &mut stop => break,
        }
    }
    drop(listener);
    tokio::select! {
        () = graceful.shutdown() => {}
        () = tokio::time::sleep(timeouts.shutdown) => {}
        () = stop_signal() => {}
    }
}

/// Drives a connection, and drops it at the deadline unless it has produced a request by then.
async fn run_connection<C: Future>(connection: C, first_request: impl Future<Output = bool>) {
    tokio::pin!(connection);
    tokio::select! {
        _ = &mut connection => {}
        asked = first_request => {
            if asked {
                let _ = connection.await;
            }
        }
    }
}

/// Binds and serves until the process is asked to stop.
pub async fn serve(addr: SocketAddr, config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let timeouts = config.timeouts.clone();
    let log = config.audit.as_ref().map(|audit| audit.log.clone());
    let app = app(config)?;
    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|err| {
        format!("could not listen on {addr}: {err}. Is the port in use? Choose another address.")
    })?;
    serve_on(listener, app, timeouts, stop_signal()).await;
    if let Some(log) = log {
        flush(log).await;
    }
    Ok(())
}

/// Writes the records still waiting, such as the usage record of an answer that ended just before the stop, before
/// the process ends and takes the writer with it.
async fn flush(log: Arc<AuditLog>) {
    let _ = tokio::task::spawn_blocking(move || log.flush()).await;
}

fn parse_addr(raw: &str, source: &str) -> Result<SocketAddr, String> {
    raw.parse().map_err(|_| {
        // A name would be resolved to whichever address comes first, which may not be the one meant.
        match raw.strip_prefix("localhost:") {
            Some(port) => format!(
                "{source} is \"{raw}\". Gantry listens on an IP address, not a host name: use 127.0.0.1:{port} for this machine."
            ),
            None => format!(
                "{source} is \"{raw}\", which is not an IP address and port. Use one such as 127.0.0.1:8080 (this machine only) or 0.0.0.0:8080 (every network interface); host names are not accepted."
            ),
        }
    })
}

/// `gantry serve <policy>`: checks the files, opens the audit log, and serves with every request identified, decided
/// and recorded. The files are checked again once a second and on SIGHUP, and a change that passes is used at once.
pub async fn serve_policy(
    name: &str,
    policy_path: &Path,
    keys_path: Option<&Path>,
    listen: Option<&str>,
    metrics: Option<&str>,
    tls: Option<(&Path, &Path)>,
) -> Result<(), Box<dyn std::error::Error>> {
    // The addresses and the TLS files are checked before anything is written to the audit log.
    let tls = tls.map(|(cert, key)| tls_acceptor(cert, key)).transpose()?;
    let scheme = if tls.is_some() { "https" } else { "http" };
    let addr = parse_addr(listen.unwrap_or(DEFAULT_ADDR), "--listen")?;
    let metrics_addr = metrics
        .map(|raw| parse_addr(raw, "--metrics"))
        .transpose()?;
    if metrics_addr == Some(addr) {
        return Err("--metrics and --listen name the same address. Give /metrics a port of its own, for example --metrics 127.0.0.1:9464.".into());
    }
    let started = governed(policy_path, keys_path, &|variable| {
        std::env::var(variable).ok()
    })?;
    let loaded = &started.loaded;
    // Listen first, then say so: "listening" must be true when it is printed.
    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|err| {
        format!(
            "could not listen on {addr}: {err}. Is the port in use? Choose another with --listen."
        )
    })?;
    // The port the system gave, when --listen asked for port 0.
    let addr = listener.local_addr().unwrap_or(addr);
    println!("{name} listening on {scheme}://{addr}");
    println!(
        "Console: {scheme}://{addr}/console (sign in with an admin key{})",
        if loaded.sso.is_some() {
            " or single sign-on"
        } else {
            ""
        }
    );
    // Without the secret every single sign-on fails at the identity provider, long after this start looked fine.
    if let Some(sso) = &loaded.sso
        && std::env::var_os(&sso.client_secret_env).is_none_or(|v| v.is_empty())
    {
        eprintln!(
            "warning: console single sign-on is set in the policy, and {} (its client secret) is not set, so every sign-on will fail. Set it (`export {}=...`) and restart; signing in with an admin key still works.",
            sso.client_secret_env, sso.client_secret_env
        );
    }
    if let Some(metrics_addr) = metrics_addr {
        let metrics = tokio::net::TcpListener::bind(metrics_addr).await.map_err(|err| {
            format!("could not listen on {metrics_addr} for /metrics: {err}. Is the port in use? Choose another with --metrics.")
        })?;
        println!("Metrics: http://{metrics_addr}/metrics");
        if !metrics_addr.ip().is_loopback() {
            eprintln!(
                "warning: /metrics on {metrics_addr} takes no key and can be reached from other machines. It shows team, model and provider names and spend: keep it on a network only your scraper reaches."
            );
        }
        let router = started.metrics.clone();
        tokio::spawn(async move {
            let _ = axum::serve(metrics, router).await;
        });
    }
    match started.log.records_at_open() {
        0 => println!(
            "Audit log: {} is new. The chain starts at record 1.",
            loaded.audit_path.display()
        ),
        n => println!(
            "Audit log: {} holds {}, all verified. The chain continues at record {}.",
            loaded.audit_path.display(),
            gantry_core::count(usize::try_from(n).unwrap_or(usize::MAX), "record"),
            n + 1
        ),
    }
    println!(
        "{}, {}, {}.",
        gantry_core::count(loaded.policy.rules(), "rule"),
        gantry_core::count(loaded.policy.keys(), "key"),
        gantry_core::config::describe(&loaded.providers)
    );
    println!(
        "Changes to {} and {} are used within 2 seconds, or at once on SIGHUP.",
        policy_path.display(),
        loaded.keys_path.display()
    );
    if loaded.policy.keys() == 0 {
        eprintln!(
            "warning: no keys in {}, so every request will be refused. Add one with `gantry key new <name> --team <team>`: it is used within 2 seconds.",
            loaded.keys_path.display()
        );
    }
    if !addr.ip().is_loopback() && tls.is_none() {
        eprintln!(
            "warning: {addr} can be reached from other machines, and Gantry keys travel to it over plain HTTP. Use --tls-cert and --tls-key, or put TLS in front of it, before real use."
        );
    }
    // Records reach the operating system before a request is forwarded. This puts them on disk once a second.
    let log = started.log.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            let log = log.clone();
            let _ = tokio::task::spawn_blocking(move || log.sync()).await;
        }
    });
    started.reloader.watch();
    #[cfg(unix)]
    {
        let reloader = started.reloader.clone();
        let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            .map_err(|err| format!("could not listen for SIGHUP: {err}. Start Gantry again."))?;
        tokio::spawn(async move {
            while hangup.recv().await.is_some() {
                reloader.signal();
            }
        });
    }
    match tls {
        Some(tls) => {
            serve_on_tls(
                listener,
                started.router,
                Timeouts::default(),
                stop_signal(),
                tls,
            )
            .await;
        }
        None => serve_on(listener, started.router, Timeouts::default(), stop_signal()).await,
    }
    flush(started.log.clone()).await;
    Ok(())
}

/// `gantry serve --unchecked`: forwards without identity, policy or audit. Loopback only, for benchmarks.
pub async fn serve_from_env(name: &str, unchecked: bool) -> Result<(), Box<dyn std::error::Error>> {
    if !unchecked {
        return Err("give the policy file to serve with: `gantry serve gantry.policy.yaml`. \
                    To forward without checking, on this machine only, run `gantry serve --unchecked`."
            .into());
    }
    // A value that is set and cannot be read must stop the start, not fall back to the default without a word.
    let raw = match std::env::var("GANTRY_ADDR") {
        Ok(raw) => raw,
        Err(std::env::VarError::NotPresent) => DEFAULT_ADDR.to_string(),
        Err(std::env::VarError::NotUnicode(_)) => return Err("GANTRY_ADDR is set to something that is not text. Use host:port, for example 127.0.0.1:8080.".into()),
    };
    let addr = parse_addr(&raw, "GANTRY_ADDR")?;
    if !addr.ip().is_loopback() {
        return Err(format!(
            "GANTRY_ADDR is {addr}, which other machines can reach. With --unchecked, Gantry forwards every request without checking who sent it, \
             so it only runs on a loopback address such as 127.0.0.1:8080."
        )
        .into());
    }
    let config = Config {
        upstream: std::env::var("GANTRY_UPSTREAM").ok(),
        ..Config::default()
    };
    drop(app(config.clone()).map_err(|err| format!("GANTRY_UPSTREAM: {err}"))?);
    println!("{name} listening on http://{addr}");
    eprintln!(
        "warning: running unchecked. Every request is forwarded without identity, policy or audit. Loopback only."
    );
    serve(addr, config).await
}
