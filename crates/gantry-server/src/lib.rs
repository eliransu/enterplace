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
    policy::{CallerKey, Decision, Models, Policy, Principal, Rule},
    sigv4, translate,
};

mod admin;
mod alias;
mod batch;
pub mod cloud;
mod cloud_batch;
mod cors;
mod credentials;
pub mod insights;
mod jwt;
mod manage;
mod mcp;
mod metrics;
pub mod oci;
mod policy_api;
mod realtime;
mod reload;
mod spend;
pub mod store;
mod teams_api;
mod traces;
pub use manage::{AdminApi, AdminCall, AdminRoute};
pub use mcp::{McpRoute, McpSetup};
pub use traces::TraceExport;

pub use credentials::{MasterKey, credential_problems};
use http_body_util::BodyExt;
use hyper_rustls::HttpsConnector;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::{conn::auto::Builder, graceful::GracefulShutdown},
    service::TowerToHyperService,
};
pub use reload::{
    Governed, Host, OrgChain, Reload, Reloader, Trigger, governed, governed_with, open_store,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower::ServiceExt;

/// Address the server binds to when none is given.
/// Loopback only: exposing the gateway is an explicit choice.
pub const DEFAULT_ADDR: &str = "127.0.0.1:8080";

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;

/// The longest an async job may run before its answer is no longer held: what its held entry outlives at most.
pub(crate) const MAX_JOB_SECONDS: u64 = 3600;

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
/// Image edits and variations come as multipart/form-data, as transcriptions do, and are priced per image.
const IMAGE_EDITS: &str = "/v1/images/edits";
const IMAGE_VARIATIONS: &str = "/v1/images/variations";
const TRANSCRIPTIONS: &str = "/v1/audio/transcriptions";
const SPEECH: &str = "/v1/audio/speech";
const MODERATIONS: &str = "/v1/moderations";
const RERANK: &str = "/v1/rerank";
/// OpenAI's legacy text completions: forwarded as sent, priced from its usage.
const COMPLETIONS: &str = "/v1/completions";
/// `/passthrough/<provider>/<native path>`: a provider's own API, reached as sent on the paths a rule names.
const PASSTHROUGH: &str = "/passthrough/";
/// `/bedrock/<native path>` and `/vertex/<native path>`: Amazon Bedrock's and Vertex AI's own APIs, signed with the
/// provider's cloud credentials (SigV4, Google OAuth) on the way out, on the paths a rule names.
const BEDROCK_PASSTHROUGH: &str = "/bedrock/";
const VERTEX_PASSTHROUGH: &str = "/vertex/";
use batch::PROVIDER_HEADER;

/// A request for a provider's own API, by any of the passthrough prefixes.
fn is_passthrough(path: &str) -> bool {
    [PASSTHROUGH, BEDROCK_PASSTHROUGH, VERTEX_PASSTHROUGH]
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

/// Google's own Gemini API, as Gemini CLI and Google's SDKs send it: `/v1beta/models/<model>:<method>` (or `/v1/`),
/// forwarded as sent to providers of kind gemini or vertex. `GET` of this path lists the models a caller may use.
const GEMINI_MODELS: &str = "/v1beta/models";
const GEMINI_METHODS: [&str; 5] = [
    "generateContent",
    "streamGenerateContent",
    "countTokens",
    "embedContent",
    "batchEmbedContents",
];

/// A native Gemini path's API version, model and method. A model with a slash or an escape is not one: it could
/// name another resource at the provider than the one the policy checked.
pub(crate) fn gemini_native(path: &str) -> Option<(&'static str, &str, &'static str)> {
    let (version, rest) = ["v1beta", "v1"].into_iter().find_map(|version| {
        let rest = path
            .strip_prefix('/')?
            .strip_prefix(version)?
            .strip_prefix("/models/")?;
        Some((version, rest))
    })?;
    let (model, method) = rest.rsplit_once(':')?;
    let method = GEMINI_METHODS.into_iter().find(|m| *m == method)?;
    (!model.is_empty() && !model.contains(['/', '%', ':'])).then_some((version, model, method))
}

/// Any path of Google's Gemini API Gantry serves: the methods and the model list. Its key may come in
/// `x-goog-api-key` or `?key=`, and its refusals are in Google's shape.
pub(crate) fn gemini_path(path: &str) -> bool {
    path == GEMINI_MODELS || path.starts_with("/v1beta/models/") || gemini_native(path).is_some()
}

fn gemini_streams(path: &str) -> bool {
    gemini_native(path).is_some_and(|(_, _, method)| method == "streamGenerateContent")
}

/// The routes forwarded as sent, to providers of kind openai only.
fn openai_only(path: &str) -> bool {
    matches!(
        path,
        RESPONSES
            | EMBEDDINGS
            | IMAGES
            | IMAGE_EDITS
            | IMAGE_VARIATIONS
            | TRANSCRIPTIONS
            | SPEECH
            | MODERATIONS
            | RERANK
            | COMPLETIONS
    )
}

/// The routes whose body is a multipart form: the policy reads its `model` field, the guardrails its text fields.
fn is_form(path: &str) -> bool {
    matches!(path, TRANSCRIPTIONS | IMAGE_EDITS | IMAGE_VARIATIONS)
}

fn route_kind(method: &Method, path: &str) -> Option<Kind> {
    if method != Method::POST {
        return None;
    }
    match path {
        CHAT => Some(Kind::OpenAi),
        _ if openai_only(path) => Some(Kind::OpenAi),
        MESSAGES | COUNT_TOKENS => Some(Kind::Anthropic),
        _ if gemini_native(path).is_some() => Some(Kind::Gemini),
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
        // Google's SDKs ask for server-sent events; without alt=sse the stream is a JSON array (see `handle`).
        _ if gemini_streams(path) => &[("alt", "sse", |v| v == "sse")],
        // Gantry lists every model at once, so a page size is taken and has nothing to cut.
        GEMINI_MODELS => &[("pageSize", "a whole number from 1 to 1000", |v| {
            v.len() <= 4 && v.parse::<u16>().is_ok_and(|n| (1..=1000).contains(&n))
        })],
        _ => &[],
    }
}
const DECISION: HeaderName = HeaderName::from_static("x-gantry-decision");
/// Where a caller sends their own provider key, on a rule with `caller_provider_key: allowed`.
const CALLER_PROVIDER_KEY: &str = "x-gantry-provider-key";

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
    /// For a provider's whole answer, body included, from sending. A provider, alias or deployment may set its own.
    pub total: Duration,
    /// Between two pieces of a provider's answer once it has started.
    pub idle: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            read_headers: Duration::from_secs(10),
            read_body: Duration::from_secs(30),
            connect: Duration::from_secs(5),
            first_byte: Duration::from_secs(120),
            shutdown: Duration::from_secs(30),
            // Long enough for a reasoning model's longest answer; a stream that stalls is cut by `idle` long before.
            total: Duration::from_secs(1800),
            idle: Duration::from_secs(300),
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
    /// Bedrock's AWS region, and the AWS credentials its requests are signed with, kept current.
    pub region: Option<String>,
    pub aws: Option<cloud::Live<sigv4::Credentials>>,
    /// A bearer token kept current, when it does not come from `key`: Vertex AI's Google OAuth access token, Azure
    /// OpenAI's Microsoft Entra ID token, or watsonx.ai's IBM Cloud IAM token. Sent as the `Authorization` header.
    pub google: Option<cloud::Live<HeaderValue>>,
    /// The provider a request goes to when this one fails before the answer starts.
    pub fallback: Option<String>,
    /// How many times such a failure is tried again on this provider first.
    pub retries: u32,
    /// Chat completions requests for its models are translated to the messages API.
    pub accept_chat: bool,
    /// Messages requests (Claude Code) for its models are translated to the chat completions API.
    pub accept_messages: bool,
    /// Its own time limits, where an alias or deployment does not set one.
    pub timeouts: gantry_core::config::Timeouts,
    /// A pool of keys used in turn, in place of `key`. A key answered 401 or 403 is set aside; one answered 429 rests.
    pub keys: Vec<Secret>,
    /// Picks the pool's key with the fewest requests sent, not the next in turn.
    pub least_used_key: bool,
    /// Each pool key's share of requests, by position in `keys`. Missing entries are 1.
    pub key_weights: Vec<u32>,
    /// How long a pool key answered 401 or 403 is set aside. `None` is an hour.
    pub key_quarantine: Option<Duration>,
    /// Headers sent with every request to it, as (name, value).
    pub headers: Vec<(String, Secret)>,
    /// The HTTP proxy its requests go through, `http://[user:pass@]host:port`.
    pub proxy: Option<Secret>,
    /// Bedrock or Vertex AI: the bucket its batch jobs read and write, for `/v1/batches`.
    pub batch: Option<gantry_core::config::ProviderBatch>,
    /// watsonx.ai's project.
    pub project_id: Option<String>,
    /// Chat completions requests for its models are sent to the Responses API, translated both ways.
    pub chat_as_responses: bool,
    /// OCI Generative AI: requests are signed with this API signing key instead of carrying a provider key.
    pub oci: Option<Arc<oci::Signer>>,
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
    /// Where OpenTelemetry traces go. `None` traces nothing.
    pub traces: Option<TraceExport>,
    /// The token of the one-time setup link, offered while the keys file has no admin key.
    pub setup: Option<String>,
    /// Upstream MCP servers whose tools are served at `/mcp`. Empty serves no `/mcp`.
    pub mcp: Vec<McpRoute>,
    /// Where the MCP gateway keeps OAuth tokens, people's credentials, tool pins and calls waiting for approval.
    pub mcp_setup: McpSetup,
    /// What several gateways share (`store:` in the policy). `None` keeps keys, switches and spend to this process.
    pub store: Option<Arc<dyn gantry_core::store::Store>>,
    /// Where rules with `capture:` keep redacted bodies, sealed. `None` keeps none.
    pub bodies: Option<Arc<dyn gantry_core::insights::Bodies>>,
    /// What a binary that embeds the gateway adds to it.
    pub extension: Extension,
}

/// Fields added to the body of `GET /healthz` and `GET /readyz`. Asked on every call, so keep it cheap. A field
/// whose value is an object with `"ready": false` (a license that ran out, say) makes `/readyz` answer 503.
pub type Health = Arc<dyn Fn() -> serde_json::Map<String, serde_json::Value> + Send + Sync>;

/// What a binary that embeds the gateway adds to it. The open source binary adds nothing.
#[derive(Clone, Default)]
pub struct Extension {
    /// Routes merged into the gateway's router. A path the gateway already serves panics at start.
    pub routes: Router,
    /// Pages, nav entries and a way to sign in, added to the console.
    pub console: gantry_console::Extension,
    /// Fields added to `GET /healthz`. They never replace the gateway's own (`status` and the versions).
    pub health: Option<Health>,
    /// Takes the prompt and answer of requests the binary was told to keep. `None` keeps no text, as the open
    /// source gateway never does.
    pub capture: Option<Arc<dyn Capture>>,
    /// Called with the chain of each organization a policy reload adds (`audit: { per_org: true }`), once it is open
    /// and before any request can be recorded in it: the binary exports, retains and ships it as it does those of
    /// [`Host::org_chains`].
    pub on_org: Option<Arc<dyn Fn(OrgChain) + Send + Sync>>,
    /// Routes added to the admin API, under `/admin`. The gateway checks the caller and writes the admin record.
    pub admin: Option<Arc<dyn AdminApi>>,
    /// Rewrites requests before they are checked and sent, and answers before they are checked and returned.
    pub transform: Option<Arc<dyn Transform>>,
}

/// Who and what a transform is rewriting for.
#[derive(Clone, Copy, Debug)]
pub struct TransformContext<'a> {
    pub decision: &'a str,
    pub person: &'a str,
    pub team: &'a str,
    pub route: &'a str,
}

/// A binary's own rewrite of requests and answers, in process: add a system prompt, redact, drop a field. It runs
/// first, before the rule's `transform` guardrails, its function tool check and its other guardrails, so they all
/// read what it wrote. Each change is recorded as a diff summary (paths only). A request may not change `model` or
/// `stream`. An `Err` refuses the request, or withholds the answer: its text is logged, never sent to the caller.
/// A streamed answer is not passed to `answer`.
pub trait Transform: Send + Sync {
    fn request(
        &self,
        _context: &TransformContext<'_>,
        _body: &mut serde_json::Value,
    ) -> Result<(), String> {
        Ok(())
    }

    fn answer(
        &self,
        _context: &TransformContext<'_>,
        _body: &mut serde_json::Value,
    ) -> Result<(), String> {
        Ok(())
    }
}

/// Prompt and answer text handed to a binary that embeds the gateway, for an operator who opted in to sending it
/// somewhere. The audit log never holds text; this is the only way text leaves the request path.
pub trait Capture: Send + Sync {
    /// Whether to keep the text of a request by someone of this team. Asked once per admitted request: keep it cheap.
    fn wanted(&self, team: &str) -> bool;
    /// Called on the audit writer's thread, before the request's usage record is written, so a reader of the log
    /// finds the text already handed over. Pass it on and return at once.
    fn take(&self, captured: Captured);
}

/// One request's text as sent to the provider (after the rule's guardrails masked it) and its answer as the
/// provider gave it, by reference.
#[derive(Clone, Debug)]
pub struct Captured {
    pub decision: String,
    pub person: String,
    pub team: String,
    pub model: String,
    pub provider: String,
    pub route: String,
    pub request: Bytes,
    /// The answer's bytes; `None` when it was not kept (larger than the gateway keeps, or no answer came).
    pub answer: Option<Bytes>,
    /// Whether `answer` is an event stream.
    pub streamed: bool,
}

impl Captured {
    /// Each text part of the request as (role, text): system prompt, messages, inputs.
    pub fn prompt(&self) -> Vec<(String, String)> {
        serde_json::from_slice(&self.request)
            .map(|body| {
                gantry_core::guard::text_parts(&body)
                    .into_iter()
                    .map(|part| (part.role, part.text))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Each text of the answer: message contents and tool call arguments, a stream's deltas joined.
    pub fn answer_text(&self) -> Vec<String> {
        let Some(answer) = &self.answer else {
            return Vec::new();
        };
        if self.streamed {
            return stream_texts(answer)
                .unwrap_or_default()
                .into_iter()
                .map(|(_, text)| text)
                .collect();
        }
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(answer) else {
            return Vec::new();
        };
        answer_texts(&value)
            .iter()
            .filter_map(|p| {
                value
                    .pointer(p)
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            })
            .collect()
    }
}

impl std::fmt::Debug for Extension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Extension")
            .field("console", &self.console)
            .field("health", &self.health.is_some())
            .finish_non_exhaustive()
    }
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
pub(crate) struct ClientAddr(SocketAddr);

/// The client's own address: the connection's, or, from a trusted proxy, the one it names in X-Forwarded-For.
pub(crate) fn client_ip(
    policy: &Policy,
    addr: Option<&ClientAddr>,
    headers: &HeaderMap,
) -> Option<std::net::IpAddr> {
    addr.map(|addr| {
        let forwarded: Vec<&str> = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        policy.client_ip(addr.0.ip(), &forwarded)
    })
}

/// Set by the accept loop once a stop signal came: `/readyz` then answers 503 while requests in flight finish.
#[derive(Clone)]
struct Draining(Arc<std::sync::atomic::AtomicBool>);

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

/// A pooled client to providers.
type Upstreams = Client<HttpsConnector<HttpConnector>, Body>;
/// A pooled client whose connections are tunnelled through a provider's HTTP proxy.
type Proxied =
    Client<HttpsConnector<hyper_util::client::legacy::connect::proxy::Tunnel<HttpConnector>>, Body>;

/// The version in use. Requests take a snapshot of it. A reload puts a new one in place.
type Live = Arc<RwLock<Arc<Snapshot>>>;

/// The policy in force now, reloads included, for a binary that embeds the gateway (an alert on a share of a
/// budget asks `Policy::applied`). Answers `None` until the gateway is built, and when it serves without a policy.
#[derive(Clone, Default)]
pub struct PolicyNow(Arc<std::sync::OnceLock<Live>>);

impl PolicyNow {
    pub fn with<R>(&self, read: impl FnOnce(&Policy) -> R) -> Option<R> {
        let snapshot = match self.0.get()?.read() {
            Ok(live) => live.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        snapshot.policy.as_ref().map(read)
    }

    fn set(&self, live: &Live) {
        let _ = self.0.set(live.clone());
    }
}

#[derive(Clone)]
struct AppState {
    // One pooled client for the life of the process: connections to the provider are reused across requests.
    client: Client<HttpsConnector<HttpConnector>, Body>,
    // Clients for providers with a connect timeout of their own, by that timeout.
    clients: Arc<std::sync::Mutex<std::collections::HashMap<Duration, Upstreams>>>,
    // Clients through a provider's proxy, by its connect timeout and the proxy.
    proxied: Arc<std::sync::Mutex<std::collections::HashMap<(Duration, String), Proxied>>>,
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
    // One span per request, when traces are exported.
    tracer: Option<Arc<traces::Tracer>>,
    // Fields an embedding binary adds to /healthz.
    health: Option<Health>,
    // The signing keys of the identity providers whose JWTs the policy trusts. Kept across reloads.
    jwks: Arc<jwt::Keys>,
    // Who owns each file, batch and fine-tuning job created through this gateway (batch.rs).
    owned: Arc<batch::Registry>,
    // Admin routes an embedding binary adds (manage.rs).
    admin_api: Option<Arc<dyn AdminApi>>,
    // The embedding binary's rewrite of requests and answers.
    transform: Option<Arc<dyn Transform>>,
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
    aws: Option<cloud::Live<sigv4::Credentials>>,
    google: Option<cloud::Live<HeaderValue>>,
    fallback: Option<String>,
    retries: u32,
    accept_chat: bool,
    accept_messages: bool,
    timeouts: gantry_core::config::Timeouts,
    /// The key pool, each key as its header and its fingerprint (never the key). Empty without a pool.
    pool: Vec<((HeaderName, HeaderValue), String)>,
    least_used_key: bool,
    /// Each pool key's weight, by position in `pool`.
    key_weights: Vec<u32>,
    key_quarantine: Duration,
    /// Sent with every request, marked sensitive.
    headers: Vec<(HeaderName, HeaderValue)>,
    proxy: Option<Proxy>,
    batch: Option<gantry_core::config::ProviderBatch>,
    project_id: Option<String>,
    chat_as_responses: bool,
    oci: Option<Arc<oci::Signer>>,
}

/// A provider's HTTP proxy: where requests are tunnelled through (CONNECT), and its Basic credentials.
#[derive(Clone, Debug)]
struct Proxy {
    uri: axum::http::Uri,
    auth: Option<HeaderValue>,
    /// Names its pooled clients: the URL as given, credentials included, so two proxies never share one.
    id: String,
}

/// A proxy URL checked: http(s), a host, no path; user and password, if any, become a Basic header.
fn proxy_of(provider: &str, url: &str) -> Result<Proxy, ConfigError> {
    let bad = || {
        ConfigError(format!(
            "the proxy of provider \"{provider}\" is not a URL of the form http://[user:password@]host:port. Check the variable its proxy_env names."
        ))
    };
    let (scheme, rest) = url.trim().split_once("://").ok_or_else(bad)?;
    if !matches!(scheme, "http" | "https") {
        return Err(bad());
    }
    let rest = rest.trim_end_matches('/');
    let (userinfo, host) = match rest.rsplit_once('@') {
        Some((userinfo, host)) => (Some(userinfo), host),
        None => (None, rest),
    };
    if host.is_empty() || host.contains(['/', '?', '#']) {
        return Err(bad());
    }
    let uri: axum::http::Uri = format!("{scheme}://{host}").parse().map_err(|_| bad())?;
    let auth = match userinfo {
        Some(userinfo) => {
            let mut value = HeaderValue::from_str(&format!(
                "Basic {}",
                gantry_core::eventstream::base64_encode(userinfo.as_bytes())
            ))
            .map_err(|_| bad())?;
            value.set_sensitive(true);
            Some(value)
        }
        None => None,
    };
    Ok(Proxy {
        uri,
        auth,
        id: url.trim().to_string(),
    })
}

impl Upstream {
    fn serves(&self, model: &str) -> bool {
        self.models.is_empty()
            || self
                .models
                .iter()
                .any(|m| gantry_core::config::model_matches(m, model))
    }

    /// Whether it lists `model` by its exact name, not only through a pattern.
    fn lists(&self, model: &str) -> bool {
        self.models.iter().any(|m| m == model)
    }
}

/// The provider key as the header its kind of provider expects, marked sensitive so nothing that prints headers shows it.
fn key_header(kind: Kind, key: &Secret) -> Result<(HeaderName, HeaderValue), ConfigError> {
    let (name, text) = match kind {
        // Vertex AI takes an OAuth access token as a Bearer token. One from key_env lasts about an hour; without
        // key_env, `cloud::google` signs in and renews it.
        // watsonx.ai's key here is an IAM token already: `gantry serve` trades the API key for one (cloud::ibm).
        Kind::OpenAi
        | Kind::Vertex
        | Kind::VertexAnthropic
        | Kind::VertexOpenAi
        | Kind::Cohere
        | Kind::Watsonx
        | Kind::Replicate => (header::AUTHORIZATION, format!("Bearer {}", key.0)),
        Kind::Gemini => (HeaderName::from_static("x-goog-api-key"), key.0.clone()),
        Kind::Anthropic => (HeaderName::from_static("x-api-key"), key.0.clone()),
        Kind::Azure => (HeaderName::from_static("api-key"), key.0.clone()),
        Kind::Sagemaker => {
            return Err(ConfigError(
                "a sagemaker provider takes no provider key: its requests are signed with AWS credentials. Remove the key, and run Gantry with an AWS role or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.".into(),
            ));
        }
        Kind::Bedrock | Kind::BedrockConverse => {
            return Err(ConfigError(
                "a bedrock provider takes no provider key: its requests are signed with AWS credentials. Remove the key, and run Gantry with an AWS role or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.".into(),
            ));
        }
    };
    let mut value = HeaderValue::from_str(&text).map_err(|_| {
        ConfigError("the provider key holds a character that cannot go in an HTTP header. Check the variable for a stray newline or quote.".into())
    })?;
    value.set_sensitive(true);
    Ok((name, value))
}

/// The policy with a price for each model a provider knows by another name (a Bedrock model ID, an Azure deployment)
/// when the model's own name has none and the provider's name does, so budgets reserve and charge it at the price of
/// what is called. A Bedrock inference profile (`us.anthropic...`) is priced as its model.
pub(crate) fn mapped_prices(policy: Option<Policy>, providers: &[Upstream]) -> Option<Policy> {
    let policy = policy?;
    let mut prices = policy.prices().clone();
    let mut added = false;
    for provider in providers {
        for (model, id) in &provider.upstream_models {
            if gantry_core::usage::price_for(model, &prices).is_some() {
                continue;
            }
            let bare = id.rsplit('/').next().unwrap_or(id);
            let bare = [
                "us.", "eu.", "apac.", "global.", "us-gov.", "jp.", "au.", "ca.",
            ]
            .iter()
            .find_map(|p| bare.strip_prefix(p))
            .unwrap_or(bare);
            if let Some(price) = [id.as_str(), bare]
                .iter()
                .find_map(|name| gantry_core::usage::price_for(name, &prices))
            {
                prices.insert(model.clone(), price);
                added = true;
            }
        }
    }
    Some(if added {
        policy.with_prices(prices)
    } else {
        policy
    })
}

/// Builds the router. Tests and embedders call this directly.
pub fn app(config: Config) -> Result<Router, ConfigError> {
    build(config, |_| None).map(|(router, _, _)| router)
}

/// Builds the router, and the reloader that `make_reloader` makes from the live version, if it makes one.
/// The gateway's router, its reloader, and the router of `GET /metrics` for a listener of its own.
type Built = (Router, Option<Arc<Reloader>>, Router);

/// The upstream a provider route becomes, checked: a Bedrock or Vertex provider needs its credentials, and the key
/// must fit in a header.
pub(crate) fn upstream_of(route: &ProviderRoute) -> Result<Upstream, ConfigError> {
    if route.kind.aws() && (route.aws.is_none() || route.region.is_none()) {
        return Err(ConfigError(format!(
            "provider \"{}\" is of kind bedrock and has no AWS region or credentials. Set its region, and give it credentials from `gantry_server::cloud::aws`.",
            route.name
        )));
    }
    if route.kind.google_auth() && route.key.is_none() && route.google.is_none() {
        return Err(ConfigError(format!(
            "provider \"{}\" is on Vertex AI and has no access token. Give it a key, or credentials from `gantry_server::cloud::google`.",
            route.name
        )));
    }
    let pool = route
        .keys
        .iter()
        .map(|key| {
            key_header(route.kind, key)
                // A hash prefix names the key in records and logs; no part of the key itself is ever shown.
                .map(|header| (header, id::sha256_hex(key.0.as_bytes())[..8].to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let headers = route
        .headers
        .iter()
        .map(|(name, value)| {
            let bad = || {
                ConfigError(format!(
                    "header {name} of provider \"{}\" cannot be sent: its name or its value holds a character an HTTP header cannot. Check headers_env and the variable it names.",
                    route.name
                ))
            };
            let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| bad())?;
            let mut value = HeaderValue::from_str(value.0.trim()).map_err(|_| bad())?;
            value.set_sensitive(true);
            Ok((name, value))
        })
        .collect::<Result<Vec<_>, ConfigError>>()?;
    let proxy = route
        .proxy
        .as_ref()
        .map(|url| proxy_of(&route.name, &url.0))
        .transpose()?;
    let key_weights: Vec<u32> = (0..pool.len())
        .map(|i| route.key_weights.get(i).copied().unwrap_or(1).max(1))
        .collect();
    Ok(Upstream {
        name: route.name.clone(),
        kind: route.kind,
        url: checked_upstream(&route.url)?,
        // A pool's first key stands in where one key is used (batches, realtime).
        key: match pool.first() {
            Some((header, _)) => Some(header.clone()),
            None => route
                .key
                .as_ref()
                .map(|key| key_header(route.kind, key))
                .transpose()?,
        },
        models: route.models.clone(),
        upstream_models: route.upstream_models.clone(),
        api_version: route.api_version.clone(),
        region: route.region.clone(),
        aws: route.aws.clone(),
        google: route.google.clone(),
        fallback: route.fallback.clone(),
        retries: route.retries,
        accept_chat: route.accept_chat,
        accept_messages: route.accept_messages,
        timeouts: route.timeouts,
        key_weights: if pool.len() > 1 {
            key_weights
        } else {
            Vec::new()
        },
        pool: if pool.len() > 1 { pool } else { Vec::new() },
        least_used_key: route.least_used_key,
        key_quarantine: route.key_quarantine.unwrap_or(Duration::from_secs(3600)),
        headers,
        proxy,
        batch: route.batch.clone(),
        project_id: route.project_id.clone(),
        chat_as_responses: route.chat_as_responses,
        oci: route.oci.clone(),
    })
}

fn build(
    config: Config,
    make_reloader: impl FnOnce(&Live) -> Option<Arc<Reloader>>,
) -> Result<Built, ConfigError> {
    let upstream = config
        .upstream
        .map(|raw| checked_upstream(&raw))
        .transpose()?;
    let mut providers = Vec::new();
    for route in &config.providers {
        providers.push(upstream_of(route)?);
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
            google: None,
            fallback: None,
            retries: 0,
            accept_chat: false,
            accept_messages: false,
            timeouts: gantry_core::config::Timeouts::default(),
            pool: Vec::new(),
            least_used_key: false,
            key_weights: Vec::new(),
            key_quarantine: Duration::from_secs(3600),
            headers: Vec::new(),
            proxy: None,
            batch: None,
            project_id: None,
            chat_as_responses: false,
            oci: None,
        });
    }
    let console = config.console;
    let budget = config.max_buffered_bytes.unwrap_or(MAX_BUFFERED_BYTES);
    let (policy_sha256, keys_sha256) = config.audit.as_ref().map_or_else(Default::default, |a| {
        (a.policy_sha256.clone(), a.keys_sha256.clone())
    });
    let live: Live = Arc::new(RwLock::new(Arc::new(Snapshot {
        policy: mapped_prices(config.policy, &providers),
        providers,
        aliases: config.aliases,
        policy_sha256,
        keys_sha256,
    })));
    let reloader = make_reloader(&live);
    let mut spend = spend::Spend::default();
    spend.store = config.store.clone();
    spend.bodies = config.bodies.clone();
    spend.capture = config.extension.capture.clone();
    let spend = Arc::new(spend);
    // Holds on parallel limits still in flight at the turn of the hour move to the new hour's counter, also on a
    // gateway that admits nothing meanwhile.
    if spend.store.is_some()
        && let Ok(runtime) = tokio::runtime::Handle::try_current()
    {
        let mover = Arc::downgrade(&spend);
        runtime.spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            loop {
                tick.tick().await;
                let Some(spend) = mover.upgrade() else { break };
                spend.move_holds();
            }
        });
    }
    // With a store, who owns each file, batch and job is kept there, so every replica answers for it.
    let owned = Arc::new(match &config.mcp_setup.postgres {
        Some(pg) => batch::Registry::with_store(pg.clone()).map_err(ConfigError)?,
        None => batch::Registry::default(),
    });
    if let Some(path) = &config.spent_from {
        let snapshot = match live.read() {
            Ok(version) => version.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        spend
            .replay(path, snapshot.policy.as_ref())
            .map_err(ConfigError)?;
        owned.replay(path, &spend).map_err(ConfigError)?;
    }
    let client = client_with(config.timeouts.connect);
    // Spans are finished from the audit records, so traces need the audit log.
    let tracer = match (config.traces, &config.audit) {
        (Some(export), Some(audit)) => {
            let tracer = Arc::new(traces::Tracer::new(export));
            let seen = tracer.clone();
            if audit
                .log
                .stats()
                .observer
                .set(Box::new(move |fields| seen.observe(fields)))
                .is_err()
            {
                return Err(ConfigError(
                    "this audit log already feeds a trace exporter. Start one Gantry per audit log.".into(),
                ));
            }
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(tracer.clone().run(client.clone()));
            }
            Some(tracer)
        }
        _ => None,
    };
    let state = AppState {
        client,
        clients: Arc::default(),
        proxied: Arc::default(),
        tracer,
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
        pool: Arc::new(alias::Pool::new(config.store.clone())),
        health: config.extension.health.clone(),
        jwks: Arc::default(),
        owned,
        admin_api: config.extension.admin.clone(),
        transform: config.extension.transform.clone(),
    };
    let keep = Arc::new(state.clone());
    batch::spawn_poller(Arc::downgrade(&keep));
    spawn_probes(Arc::downgrade(&keep));
    let metrics = Router::new()
        .route("/metrics", get(metrics::serve))
        .with_state(state.clone());
    let mut router = Router::new()
        // Every other method on these two paths goes to `handle`, which refuses it with a decision and a record,
        // as it does any other request it does not serve.
        .route("/healthz", get(healthz).fallback(handle))
        .route("/readyz", get(readyz).fallback(handle))
        // Claude Code warms its connection with this probe at startup. Answering it keeps one refused record per launch
        // out of the audit log. It reaches no provider and says nothing about who may do what.
        .route(
            "/api/hello",
            head(|| async { StatusCode::OK }).fallback(handle),
        );
    // The admin API changes the keys file, so it exists only when Gantry serves from one.
    if reloader.is_some() {
        router = router
            .route("/admin", any(manage::dispatch))
            .route("/admin/{*rest}", any(manage::dispatch));
    }
    let mcp = mcp::router(&state, config.mcp, config.mcp_setup)?;
    let cors_state = state.clone();
    let router = router
        .merge(batch::routes(keep))
        .merge(realtime::routes())
        .fallback(handle)
        .with_state(state);
    let mut console_extension = config.extension.console;
    let router = match mcp {
        Some(mcp) => {
            console_extension.nav.extend(mcp.console.nav);
            console_extension.routes = console_extension.routes.merge(mcp.console.routes);
            router.merge(mcp.router)
        }
        None => router,
    };
    // Over every route but the console's, nested below; the layer itself skips the admin API.
    let router = router
        .merge(config.extension.routes)
        .layer(axum::middleware::from_fn_with_state(
            cors_state,
            cors::layer,
        ));
    let router = match console {
        Some(console) => router.nest(
            "/console",
            gantry_console::router_with(console, config.setup.clone(), console_extension),
        ),
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
    let mut body = serde_json::json!({
        "status": text,
        "policy_sha256": version.policy_sha256,
        "keys_sha256": version.keys_sha256,
        "rejected": rejected.map(|(policy, keys)| serde_json::json!({ "policy_sha256": policy, "keys_sha256": keys })),
    });
    if let (Some(health), Some(fields)) = (&state.health, body.as_object_mut()) {
        for (name, value) in health() {
            fields.entry(name).or_insert(value);
        }
    }
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

/// Ready means a request sent now would be served, not refused for a reason of the gateway's own: the audit log
/// takes records, the store answers when there is one, a policy with keys (or an identity provider) is loaded,
/// nothing an embedder checks says otherwise, and the gateway is not draining after a stop signal. An orchestrator
/// sends traffic only while this is 200. `/healthz` stays the liveness check: a gateway that is not ready is alive.
async fn readyz(
    State(state): State<AppState>,
    draining: Option<axum::Extension<Draining>>,
) -> Response {
    let mut checks = serde_json::Map::new();
    let check = |ready: bool, reason: Option<String>| {
        let mut entry = serde_json::json!({ "ready": ready });
        if let Some(reason) = reason {
            entry["reason"] = reason.into();
        }
        entry
    };
    checks.insert(
        "audit".into(),
        match &state.audit {
            Some(audit) if audit.log.is_broken() => check(false, Some("the audit log cannot be written, so every request would be refused (audit_unavailable). Free disk space or fix the file's permissions, then restart Gantry.".into())),
            Some(_) => check(true, None),
            None => check(true, Some("no audit log: this gateway forwards without recording, for tests and benchmarks".into())),
        },
    );
    if let Some(store) = &state.spend.store {
        checks.insert(
            "store".into(),
            match store.reachable() {
                Ok(()) => check(true, None),
                Err(err) => check(false, Some(format!("{err}. Requests under a budget or rate limit would be refused (store_unavailable) until it is back."))),
            },
        );
    }
    let version = state.version();
    checks.insert(
        "policy".into(),
        match &version.policy {
            None => check(true, Some("no policy: this gateway forwards unchecked, on loopback, for benchmarks".into())),
            Some(policy) if policy.keys() == 0 && policy.jwt().is_empty() => check(false, Some("the policy has no keys and no jwt: issuer, so every request would be refused. Add a key with `gantry key new <name> --team <team>`.".into())),
            Some(_) => check(true, None),
        },
    );
    // Probed deployments are detail: one that is down is passed over, and the gateway still serves.
    let probes = state.pool.probes();
    if !probes.is_empty() {
        let mut deployments = serde_json::Map::new();
        for (name, probed) in probes {
            deployments.insert(
                name,
                serde_json::json!({ "up": probed.up, "checked": probed.time, "outcome": probed.outcome }),
            );
        }
        checks.insert(
            "deployments".into(),
            serde_json::json!({ "ready": true, "probed": deployments }),
        );
    }
    if draining.is_some_and(|d| d.0.0.load(std::sync::atomic::Ordering::Relaxed)) {
        checks.insert(
            "draining".into(),
            check(false, Some("a stop signal came: requests in flight are finishing and no new connection is taken".into())),
        );
    }
    if let Some(health) = &state.health {
        for (name, value) in health() {
            checks.entry(name).or_insert(value);
        }
    }
    let ready = checks
        .values()
        .all(|c| c.get("ready").and_then(serde_json::Value::as_bool) != Some(false));
    let body = serde_json::json!({
        "status": if ready { "ready" } else { "not_ready" },
        "policy_sha256": version.policy_sha256,
        "keys_sha256": version.keys_sha256,
        "checks": checks,
    });
    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
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
        let message = self.shown(decision);
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
        self.with_body(body)
    }

    fn shown(&self, decision: &str) -> String {
        match self.message.strip_prefix("Refused: ") {
            Some(rest) => format!("Refused ({}): {rest} Decision {decision}.", self.code),
            None => format!("{} Decision {decision}.", self.message),
        }
    }

    /// The response in Google's error shape, for Gemini CLI and Google's SDKs on the Gemini API's routes.
    fn respond_gemini(self, decision: &str) -> Response {
        let body = gemini_error(self.status, self.code, &self.shown(decision), decision);
        self.with_body(body)
    }

    fn with_body(self, body: serde_json::Value) -> Response {
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

/// An error as Google's APIs send one: the HTTP status as a number, its gRPC name, and Gantry's code as the reason.
fn gemini_error(
    status: StatusCode,
    code: &str,
    message: &str,
    decision: &str,
) -> serde_json::Value {
    let name = match status.as_u16() {
        400 | 413 => "INVALID_ARGUMENT",
        401 => "UNAUTHENTICATED",
        403 => "PERMISSION_DENIED",
        404 => "NOT_FOUND",
        429 => "RESOURCE_EXHAUSTED",
        503 => "UNAVAILABLE",
        504 => "DEADLINE_EXCEEDED",
        _ => "INTERNAL",
    };
    serde_json::json!({ "error": {
        "code": status.as_u16(),
        "message": message,
        "status": name,
        "details": [{
            "@type": "type.googleapis.com/google.rpc.ErrorInfo",
            "reason": code,
            "domain": "gantry",
            "metadata": { "decision": decision },
        }],
    }})
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

/// On the Gemini API's routes, Google's SDKs (Gemini CLI among them) send the key in `x-goog-api-key` or `?key=`.
/// It is moved to the Authorization header, where the rest of the check reads it, and taken out of the query, so the
/// query that is forwarded, traced or shown never holds it. More than one key, or one beside another credential,
/// is refused: checking one and forwarding another is how a proxy gets bypassed.
fn gemini_key(parts: &mut Parts) -> Result<(), Refusal> {
    const GOOG: &str = "x-goog-api-key";
    if !gemini_path(parts.uri.path()) {
        return Ok(());
    }
    let ambiguous = || {
        Refusal::new(
            StatusCode::BAD_REQUEST,
            "ambiguous_key",
            "Refused: this request carries more than one credential. Send exactly one: your Gantry key, in x-goog-api-key (GEMINI_API_KEY in Gemini CLI), in ?key= or as a Bearer token.",
        )
    };
    let mut found: Vec<String> = parts
        .headers
        .get_all(GOOG)
        .iter()
        .map(|v| String::from_utf8_lossy(v.as_bytes()).trim().to_string())
        .collect();
    let mut kept = Vec::new();
    let query = parts.uri.query().unwrap_or_default();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        match pair.split_once('=') {
            Some(("key", value)) => found.push(value.trim().to_string()),
            _ if pair == "key" => found.push(String::new()),
            _ => kept.push(pair),
        }
    }
    if found.is_empty() {
        return Ok(());
    }
    if parts.uri.query().is_some() {
        let path = parts.uri.path();
        let rebuilt = if kept.is_empty() {
            path.to_string()
        } else {
            format!("{path}?{}", kept.join("&"))
        };
        parts.uri = rebuilt.parse().map_err(|_| unknown_route())?;
    }
    parts.headers.remove(GOOG);
    let key = found.swap_remove(0);
    if !found.is_empty()
        || parts.headers.contains_key(header::AUTHORIZATION)
        || parts.headers.contains_key("x-api-key")
    {
        return Err(ambiguous());
    }
    let mut value = HeaderValue::from_str(&format!("Bearer {key}")).map_err(|_| {
        Refusal::new(
            StatusCode::UNAUTHORIZED,
            "no_key",
            "Refused: the Gemini API key holds characters a Gantry key never has. Set GEMINI_API_KEY to your Gantry key alone.",
        )
    })?;
    value.set_sensitive(true);
    parts.headers.insert(header::AUTHORIZATION, value);
    Ok(())
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
    /// How the cached answer was found: exact or semantic, its similarity, scope and the decision that made it.
    found: Option<spend::Hit>,
    /// The decision of the embeddings request a semantic cache made for this one.
    embedding: Option<String>,
    /// Where `prompt_cache: auto` placed cache breakpoints in the body.
    prompt_cache: Option<Vec<&'static str>>,
    /// The caller's Gantry key, for the embeddings request a semantic cache makes as the same person. Never recorded.
    credential: Option<String>,
    /// The first 8 hex characters of the SHA-256 of a provider key the caller sent, never the key.
    caller_key: Option<String>,
    /// The end customer the request is for, from its key or `x-gantry-customer`.
    customer: Option<String>,
    /// Its tags, from its key and `x-gantry-tags`.
    tags: Vec<String>,
    /// How an alias chose its deployment, and why.
    routing: Option<serde_json::Value>,
    /// Set when the key was replaced by a rotation and is in its grace period.
    rotated: Option<serde_json::Value>,
    /// What observe mode or a shadow period let through: one entry per decision that would have refused it.
    would_refuse: Vec<serde_json::Value>,
}

const CUSTOMER: &str = "x-gantry-customer";
const TAGS: &str = "x-gantry-tags";

/// The end customer and tags of a request: the key's, and those the caller sends in `x-gantry-customer` and
/// `x-gantry-tags` when the rule lets them. A name the rule does not list is refused by name, so a caller cannot
/// charge another customer or forge a tag. Both headers are taken out: they are Gantry's, not the provider's.
pub(crate) fn customer_and_tags(
    headers: &mut HeaderMap,
    person: &Principal,
    rule: &Rule,
    seen: &mut Seen<'_>,
    // Observe mode or the rule's shadow period: a customer or tag the rule refuses is recorded and taken.
    by: Option<&'static str>,
) -> Result<(), Refusal> {
    let once = |name: &str, headers: &HeaderMap| -> Result<Option<String>, Refusal> {
        let mut values = headers.get_all(name).iter();
        let first = values.next();
        if values.next().is_some() {
            return Err(Refusal::new(
                StatusCode::BAD_REQUEST,
                "bad_header",
                format!("Refused: {name} is sent more than once. Send it once."),
            ));
        }
        first
            .map(|v| {
                v.to_str().map(|t| t.trim().to_string()).map_err(|_| {
                    Refusal::new(
                        StatusCode::BAD_REQUEST,
                        "bad_header",
                        format!("Refused: {name} holds characters that are not text. Send names in letters, digits, dots, dashes, underscores and @."),
                    )
                })
            })
            .transpose()
    };
    let customer = once(CUSTOMER, headers)?;
    let tags = once(TAGS, headers)?;
    headers.remove(CUSTOMER);
    headers.remove(TAGS);
    seen.customer = person.customer.clone();
    if let Some(customer) = customer.filter(|c| !c.is_empty()) {
        if !gantry_core::config::valid_name(&customer) {
            return Err(Refusal::new(
                StatusCode::BAD_REQUEST,
                "bad_header",
                "Refused: x-gantry-customer names a customer in letters, digits, dots, dashes, underscores and @ only, at most 100 characters.",
            ));
        }
        match &person.customer {
            // Observed, the key's own customer stays the one charged: the key says whose it is.
            Some(own) if *own != customer => enforce(
                seen,
                Refusal::new(
                    StatusCode::FORBIDDEN,
                    "customer_not_allowed",
                    format!(
                        "Refused: the key {} is for customer \"{own}\", and this request names customer \"{customer}\" in x-gantry-customer. Leave the header out, or use that customer's key.",
                        person.key
                    ),
                ),
                by,
            )?,
            Some(_) => {}
            None => {
                if !rule.accepts_customer(&customer) {
                    enforce(
                        seen,
                        Refusal::new(
                            StatusCode::FORBIDDEN,
                            "customer_not_allowed",
                            format!(
                                "Refused: rule \"{}\" does not let a caller name customer \"{customer}\" in x-gantry-customer. Leave the header out, or ask a Gantry admin to add it (or \"*\") to the rule's customers.",
                                rule.name
                            ),
                        ),
                        by,
                    )?;
                }
                seen.customer = Some(customer);
            }
        }
    }
    let mut all = person.tags.clone();
    for tag in tags
        .iter()
        .flat_map(|t| t.split(','))
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        if all.iter().any(|t| t == tag) {
            continue;
        }
        if !gantry_core::config::valid_name(tag) {
            return Err(Refusal::new(
                StatusCode::BAD_REQUEST,
                "bad_header",
                "Refused: x-gantry-tags is a comma-separated list of tags, each in letters, digits, dots, dashes, underscores and @ only, at most 100 characters.",
            ));
        }
        if !rule.accepts_tag(tag) {
            enforce(
                seen,
                Refusal::new(
                    StatusCode::FORBIDDEN,
                    "tag_not_allowed",
                    format!(
                        "Refused: rule \"{}\" does not let a caller send tag \"{tag}\" in x-gantry-tags. Remove it, or ask a Gantry admin to add it to the rule's tags.",
                        rule.name
                    ),
                ),
                by,
            )?;
        }
        all.push(tag.to_string());
    }
    if all.len() > gantry_core::config::MAX_TAGS {
        return Err(Refusal::new(
            StatusCode::BAD_REQUEST,
            "bad_header",
            format!(
                "Refused: this request carries {} tags with its key's, more than {}. Send fewer in x-gantry-tags.",
                all.len(),
                gantry_core::config::MAX_TAGS
            ),
        ));
    }
    seen.tags = all;
    Ok(())
}

/// Headers a coding agent names its session in, the first found wins: Gantry's own, then Claude Code's and Codex's.
const SESSION_HEADERS: [&str; 4] = [
    "x-gantry-session",
    "x-claude-code-session-id",
    "session_id",
    "x-session-id",
];

/// The person and the session their client names, for session affinity. Hashed: a session ID may be a secret.
fn session_of(headers: &HeaderMap, person: &Principal) -> Option<String> {
    SESSION_HEADERS
        .iter()
        .find_map(|name| headers.get(*name)?.to_str().ok().filter(|v| !v.is_empty()))
        .map(|session| id::sha256_hex(format!("{}\n{session}", person.name).as_bytes()))
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

/// The provider key the caller sent in `x-gantry-provider-key`, if any. Sent twice it is refused: checking one and
/// sending the other is how a proxy gets bypassed.
fn caller_provider_key(headers: &HeaderMap) -> Result<Option<String>, Refusal> {
    let mut values = headers.get_all(CALLER_PROVIDER_KEY).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(Refusal::new(
            StatusCode::BAD_REQUEST,
            "ambiguous_key",
            "Refused: this request carries x-gantry-provider-key more than once. Send your provider key once, or not at all to use Gantry's.",
        ));
    }
    let key = first.to_str().map(str::trim).unwrap_or_default();
    if key.is_empty() {
        return Err(Refusal::new(
            StatusCode::BAD_REQUEST,
            "caller_provider_key_invalid",
            "Refused: x-gantry-provider-key is empty or holds characters a provider key never has. Send your provider key alone, or leave the header out to use Gantry's.",
        ));
    }
    Ok(Some(key.to_string()))
}

/// Whether `rule` lets the caller's own provider key go to a provider of `kind`. Without the rule's opt-in the request
/// is refused: a key that is ignored would have the caller pay nothing they expected, or Gantry pay what they did.
fn caller_paid(rule: Option<&Rule>, kind: Option<Kind>, key: Option<&str>) -> Result<(), Refusal> {
    let Some(key) = key else {
        return Ok(());
    };
    let allowed = rule.is_some_and(|r| r.limits.caller_provider_key != CallerKey::Refused);
    if !allowed {
        return Err(Refusal::new(
            StatusCode::FORBIDDEN,
            "caller_provider_key_not_allowed",
            format!(
                "Refused: {} does not take a caller's own provider key, and this request carries one in x-gantry-provider-key. Send it without that header to use Gantry's key, or ask a Gantry admin to set `caller_provider_key: allowed` on the rule.",
                rule.map_or_else(|| "no rule".to_string(), |r| format!("rule \"{}\"", r.name))
            ),
        ));
    }
    match kind {
        Some(kind) if kind.aws() => Err(Refusal::new(
            StatusCode::BAD_REQUEST,
            "caller_provider_key_unsupported",
            "Refused: this model is served on Amazon Bedrock, whose requests Gantry signs with AWS keys, so a provider key in x-gantry-provider-key cannot be used for it. Send it without that header.",
        )),
        Some(kind) => key_header(kind, &Secret::new(key)).map(|_| ()).map_err(|_| {
            Refusal::new(
                StatusCode::BAD_REQUEST,
                "caller_provider_key_invalid",
                "Refused: x-gantry-provider-key holds a character that cannot go in an HTTP header. Send your provider key alone.",
            )
        }),
        None => Ok(()),
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
    minted: &'a std::sync::OnceLock<Principal>,
    client_ip: Option<std::net::IpAddr>,
) -> Result<Next, Refusal> {
    let (mut parts, body) = request.into_parts();
    gemini_key(&mut parts)?;
    let key = caller_key(&parts.headers)?;
    let provider_key = caller_provider_key(&parts.headers)?;
    seen.credential = Some(key.to_string());
    seen.caller_key = provider_key
        .as_deref()
        .map(|k| id::sha256_hex(k.as_bytes())[..8].to_string());
    // Read before the key's header is removed below: Anthropic's clients send their key in x-api-key.
    let anthropic_client =
        parts.headers.contains_key("x-api-key") || parts.headers.contains_key("anthropic-version");
    let (person, key_sha256) = identify(
        state,
        policy,
        key,
        parts.uri.path(),
        client_ip,
        minted,
        seen,
    )
    .await?;
    // The key must not travel on in any other header either, under whatever name the caller chose for it.
    let (key, mut parts) = (key.to_string(), parts);
    // Taken out at once: nothing after this (guardrail webhooks, traces, the provider) can see it in the headers.
    parts.headers.remove(CALLER_PROVIDER_KEY);
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
    let listing = parts.uri.path() == MODELS
        || (gemini_path(parts.uri.path()) && gemini_native(parts.uri.path()).is_none());
    if parts.method == Method::GET && listing {
        check_query(&parts.uri)?;
        // In observe mode a caller no rule names lists what observe mode would forward: every model.
        seen.rule = policy.rule_for(person).or_else(|| {
            policy
                .observing(None)
                .map(|_| &*gantry_core::policy::OBSERVED)
        });
        caller_paid(seen.rule, None, provider_key.as_deref())?;
        if parts.uri.path() != MODELS {
            return gemini_model_list(version, seen.rule, person, parts.uri.path())
                .map(Next::Answer);
        }
        return Ok(Next::Answer(model_list(
            version,
            seen.rule,
            person,
            anthropic_client,
        )));
    }
    if is_passthrough(parts.uri.path()) {
        let query_carries_key = parts.uri.query().is_some_and(|q| carries(q.as_bytes()));
        return passthrough(
            state,
            version,
            policy,
            person,
            &key_sha256,
            parts,
            body,
            query_carries_key,
            provider_key,
            seen,
        )
        .await;
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
    let peek = if let Some((_, model, _)) = gemini_native(parts.uri.path()) {
        // The model is in the path. One named in the body as well must be the same, or the policy would check one
        // model while the provider runs another.
        gemini_body_model(&bytes, model)?;
        Peek {
            model: model.to_string(),
        }
    } else if is_form(parts.uri.path()) {
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
    let mut decision = policy.decide(person, &peek.model);
    let shadow = match decision {
        Decision::Allow(_) => None,
        Decision::ModelNotAllowed(rule) => Some(policy.observing(rule.shadow_until.as_deref())),
        // A caller no rule names, or a key's own model list, has no shadow period of its own: only the mode.
        Decision::NoRule | Decision::KeyModelNotAllowed(_) => Some(policy.observing(None)),
    };
    if let Some(Some(by)) = shadow {
        observed(
            seen,
            rule_refusal(decision, person, &peek.model, parts.uri.path()),
            by,
        );
        decision = Decision::Allow(match decision {
            Decision::ModelNotAllowed(rule) | Decision::KeyModelNotAllowed(rule) => rule,
            _ => &gantry_core::policy::OBSERVED,
        });
    }
    if let Decision::Allow(rule) = decision {
        seen.rule = Some(rule);
        seen.model = Some(peek.model.clone());
        let by = policy.observing(rule.shadow_until.as_deref());
        customer_and_tags(&mut parts.headers, person, rule, seen, by)?;
    }
    // A copy of its own, so seen can still take what is observed below.
    seen.model = Some(peek.model.clone());
    let model = &peek.model;
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
            // Tags were read and checked with the customer above. Gantry's own: the provider has no use for it.
            let tags = seen.tags.clone();
            parts.headers.remove("x-gantry-session");
            let mut want = Want {
                team: &person.team,
                tags: &tags,
                regions: rule.limits.regions.as_deref(),
                session: session_of(&parts.headers, person),
                customer: seen.customer.clone(),
                headers: &parts.headers,
                body: &bytes,
            };
            let found = match targets(state, version, parts.uri.path(), model, &want, false) {
                Err(refusal) if refusal.code == "region_not_allowed" => {
                    let Some(by) = policy.observing(rule.shadow_until.as_deref()) else {
                        return Err(refusal);
                    };
                    // Observed residency: recorded, then routed as if the rule kept requests nowhere in particular.
                    observed(seen, refusal, by);
                    want.regions = None;
                    targets(state, version, parts.uri.path(), model, &want, false)
                }
                other => other,
            };
            let (chain, shape, routing) = found?;
            seen.routing = routing;
            let chosen = chain.first().map_or(0, |c| c.provider);
            let alias = version.aliases.iter().find(|a| a.name == *model);
            // A fallback may speak the other API: its hop gets the body translated as it is sent. QA14-2: a fallback
            // a kill switch stops (by its own name, or a model of its deployments, as for the alias itself) is not
            // taken.
            let stopped = |m: &str| killed(state, person, &key_sha256, Some(m)).is_err();
            let fallback = |target: Option<&String>| {
                target
                    .filter(|t| !stopped(t))
                    .and_then(|t| targets(state, version, parts.uri.path(), t, &want, true).ok())
                    // A fallback of the other API, or a Google one, is translated as it is sent (Tries::view); a
                    // body already made a Responses request is not, so a hop there must take that shape too.
                    .filter(|(chain, t, _)| {
                        (*t == shape
                            || (matches!(parts.uri.path(), CHAT | MESSAGES)
                                && shape != Shape::Responses
                                && *t != Shape::Responses))
                            && !chain.iter().any(|hop| stopped(&hop.model))
                    })
                    .map(|(chain, _, _)| chain)
                    .unwrap_or_default()
            };
            let (context, content) = alias.map_or_else(Default::default, |a| {
                (
                    fallback(a.context_window_fallback.as_ref()),
                    fallback(a.content_policy_fallback.as_ref()),
                )
            });
            // An alias's fallbacks never widen access: the caller's rule must allow each by name.
            let mut fallbacks: Vec<Chain> = alias
                .map(|a| {
                    a.fallbacks
                        .iter()
                        .filter(|t| matches!(policy.decide(person, t), Decision::Allow(_)))
                        .map(|t| fallback(Some(t)))
                        .filter(|chain| !chain.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            if alias.is_some() {
                seen.deployment = chain
                    .first()
                    .map(|hop| alias::label(&version.providers[hop.provider].name, &hop.model));
            }
            let model = model.clone();
            seen.provider = Some(chosen);
            caller_paid(
                Some(rule),
                version.providers.get(chosen).map(|p| p.kind),
                provider_key.as_deref(),
            )?;
            check_query(&parts.uri)?;
            // Translated here, before the record is written, so a field that cannot be carried across is a
            // recorded refusal and never a request sent with that field missing.
            let from_messages = shape == Shape::Chat && route == Kind::Anthropic;
            // The caller's own `fallbacks`, tried after the alias's: each one its rule allows, and a refusal naming
            // one it does not. Gantry's field, so the provider never sees it.
            let (bytes, asked) = body_fallbacks(&bytes)?;
            for target in &asked {
                if !matches!(policy.decide(person, target), Decision::Allow(_)) {
                    return Err(Refusal::new(
                        StatusCode::FORBIDDEN,
                        "model_not_allowed",
                        format!(
                            "Refused: the request's fallbacks name model \"{target}\", which your rule does not allow. Remove it from fallbacks, or ask a Gantry admin to allow it."
                        ),
                    ));
                }
            }
            fallbacks.extend(
                asked
                    .iter()
                    .map(|t| fallback(Some(t)))
                    .filter(|chain| !chain.is_empty()),
            );
            let fallback_on = match alias {
                Some(a) => a.fallback_on.clone(),
                None if !asked.is_empty() => gantry_core::config::FallbackOn::DEFAULT.to_vec(),
                None => Vec::new(),
            };
            // Read only when a fallback may need the request translated as it is sent.
            let crossing = !context.is_empty() || !content.is_empty() || !fallbacks.is_empty();
            let include_usage = route == Kind::OpenAi
                && crossing
                && serde_json::from_slice::<serde_json::Value>(&bytes)
                    .is_ok_and(|request| translate::include_usage(&request));
            let path = parts.uri.path();
            // The API the body is in once it is planned: a fallback of another API translates it from here.
            let body_api = match shape {
                Shape::Messages => Kind::Anthropic,
                Shape::Chat if from_messages => Kind::OpenAi,
                _ => route,
            };
            let from_responses = path == RESPONSES && shape != Shape::Sent;
            seen.translated = shape != Shape::Sent;
            if path == RESPONSES {
                // The response it gets is the caller's: theirs alone to read back, delete or cancel.
                let sent = serde_json::from_slice::<serde_json::Value>(&bytes).unwrap_or_default();
                parts.extensions.insert(batch::creator(
                    person,
                    seen,
                    sent["store"] == true,
                    sent["background"] == true && sent["stream"] != true,
                ));
            }
            let mut bytes = bytes;
            if from_responses {
                bytes = to_chat_from_responses(&bytes)?;
            }
            if from_messages {
                bytes = to_chat_request(&bytes)?;
            }
            let chat_like = from_messages || from_responses || path == CHAT;
            let mut translated = None;
            let mut as_responses = None;
            let sent_route = match shape {
                Shape::Messages => {
                    let (messages, include_usage) = to_messages(&bytes)?;
                    bytes = messages;
                    translated = Some(include_usage);
                    Some(MESSAGES)
                }
                Shape::Responses => {
                    let (request, include_usage) = to_responses_request(&bytes)?;
                    bytes = request;
                    as_responses = Some(include_usage);
                    Some(RESPONSES)
                }
                Shape::Native => {
                    // Checked here, and translated as it is sent: the guardrails read and mask the caller's body.
                    let first = chain
                        .first()
                        .map_or(model.as_str(), |hop| hop.model.as_str());
                    let route = if chat_like { CHAT } else { path };
                    native_body(&version.providers[chosen], first, &bytes, route)?;
                    if chat_like {
                        translated = Some(translate::include_usage(
                            &serde_json::from_slice(&bytes).unwrap_or_default(),
                        ));
                    }
                    chat_like.then_some(CHAT)
                }
                Shape::Chat => {
                    if from_messages {
                        translated = Some(true);
                    }
                    Some(CHAT)
                }
                Shape::Sent => None,
            };
            parts.extensions.insert(Plan {
                provider: chosen,
                model,
                translated,
                from_messages,
                from_responses,
                as_responses,
                sent_route,
                chain,
                cooldown: alias.map(|a| Duration::from_secs(a.cooldown_seconds)),
                context,
                content,
                passthrough: None,
                caller_key: provider_key.map(Secret::new),
                fallbacks,
                fallback_on,
                body_api,
                include_usage,
            });
            Ok(Next::Forward(parts, bytes, permit))
        }
        Decision::NoRule => Err(rule_refusal(decision, person, model, parts.uri.path())),
        Decision::KeyModelNotAllowed(rule) | Decision::ModelNotAllowed(rule) => {
            seen.rule = Some(rule);
            Err(rule_refusal(decision, person, model, parts.uri.path()))
        }
    }
}

/// A JSON body's `fallbacks` (models or aliases to try when the requested one fails), and the body without it.
/// A body without one comes back as it is.
fn body_fallbacks(bytes: &Bytes) -> Result<(Bytes, Vec<String>), Refusal> {
    let Ok(serde_json::Value::Object(mut body)) = serde_json::from_slice(bytes) else {
        return Ok((bytes.clone(), Vec::new()));
    };
    let Some(asked) = body.remove("fallbacks") else {
        return Ok((bytes.clone(), Vec::new()));
    };
    let names: Option<Vec<String>> = asked.as_array().and_then(|list| {
        list.iter()
            .map(|v| v.as_str().map(str::to_string))
            .collect()
    });
    let Some(names) = names else {
        return Err(Refusal::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Refused: fallbacks must be a list of model or alias names, such as [\"gpt-4o-mini\"].",
        ));
    };
    Ok((
        Bytes::from(serde_json::Value::Object(body).to_string()),
        names,
    ))
}

/// The refusal of a request the rules do not allow. An allowed one has none: it gets a generic `no_rule`.
fn rule_refusal(decision: Decision<'_>, person: &Principal, model: &str, path: &str) -> Refusal {
    match decision {
        Decision::Allow(_) | Decision::NoRule => no_rule(person),
        Decision::KeyModelNotAllowed(_) => {
            let hint = claude_code_hint(path);
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
            refusal
        }
        Decision::ModelNotAllowed(rule) => {
            let hint = match &rule.models {
                Models::Only(models) if models.is_empty() => "",
                _ => claude_code_hint(path),
            };
            Refusal::new(
                StatusCode::FORBIDDEN,
                "model_not_allowed",
                format!(
                    "Refused: team \"{}\" may not use model \"{model}\" under rule \"{}\". {} {hint}Ask a Gantry admin to change the policy if you need this one.",
                    person.team,
                    rule.name,
                    allowed_models(rule)
                ),
            )
        }
    }
}

/// In observe mode, each guardrail of `rule` set to block that found something, as the `would_refuse` entry of the
/// refusal it would have made.
pub(crate) fn would_block(rule: &Rule, entries: &[guard::AuditEntry]) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for guard in rule
        .guardrails
        .iter()
        .filter(|g| g.action == guard::Action::Block)
    {
        let found: Vec<String> = entries
            .iter()
            .filter(|e| e.guardrail == guard.name && e.action == guard::SHADOW)
            .map(|e| format!("{} ({})", e.kind, e.count))
            .collect();
        if found.is_empty() {
            continue;
        }
        let mut refusal = Refusal::new(
            StatusCode::FORBIDDEN,
            guard::BLOCKED_CODE,
            format!(
                "Refused: guardrail \"{}\" would block this request: it contains {}. Observe mode let it through.",
                guard.name,
                found.join(", ")
            ),
        );
        refusal.record = Some(Box::new(serde_json::json!({ "guardrail": guard.name })));
        out.push(would_refuse_entry(refusal, "observe"));
    }
    out
}

/// In observe mode, `guards` as in their shadow period: each records what it finds, and neither blocks nor masks.
/// `None` in enforce mode, where they run as written.
pub(crate) fn observed_guards(policy: &Policy, guards: &[Guardrail]) -> Option<Vec<Guardrail>> {
    (policy.mode() == gantry_core::policy::Mode::Observe && !guards.is_empty()).then(|| {
        guards
            .iter()
            .cloned()
            .map(|mut g| {
                g.shadow_until = Some("9999-12-31".into());
                g
            })
            .collect()
    })
}

/// Records a decision against a request that observe mode or a shadow period does not enforce: the request goes on,
/// and its record lists what would have refused it, with the refusal's code, message and detail.
pub(crate) fn observed(seen: &mut Seen<'_>, refusal: Refusal, by: &'static str) {
    seen.would_refuse.push(would_refuse_entry(refusal, by));
}

/// One `would_refuse` entry: the refusal's code, why it was not enforced, its message and detail.
pub(crate) fn would_refuse_entry(refusal: Refusal, by: &'static str) -> serde_json::Value {
    let mut entry = serde_json::Map::new();
    entry.insert("code".into(), refusal.code.into());
    entry.insert("by".into(), by.into());
    entry.insert("message".into(), refusal.message.into());
    if let Some(serde_json::Value::Object(extra)) = refusal.record.map(|r| *r) {
        entry.extend(extra);
    }
    serde_json::Value::Object(entry)
}

/// Refuses with `refusal`, unless `by` (observe mode or a shadow period) says to record it and go on.
pub(crate) fn enforce(
    seen: &mut Seen<'_>,
    refusal: Refusal,
    by: Option<&'static str>,
) -> Result<(), Refusal> {
    match by {
        Some(by) => {
            observed(seen, refusal, by);
            Ok(())
        }
        None => Err(refusal),
    }
}

/// The caller's rule. With none, observe mode forwards under a rule that allows everything, and `refused` goes on
/// the record as `would_refuse` through `observe`.
pub(crate) fn rule_or_observed<'a>(
    policy: &'a Policy,
    person: &Principal,
    refused: Refusal,
    observe: impl FnOnce(Refusal, &'static str),
) -> Result<&'a Rule, Refusal> {
    if let Some(rule) = policy.rule_for(person) {
        return Ok(rule);
    }
    match policy.observing(None) {
        Some(by) => {
            observe(refused, by);
            Ok(&gantry_core::policy::OBSERVED)
        }
        None => Err(refused),
    }
}

/// The refusal of a caller no rule names.
pub(crate) fn no_rule(person: &Principal) -> Refusal {
    Refusal::new(
        StatusCode::FORBIDDEN,
        "no_rule",
        format!(
            "Refused: no rule in the policy names \"{}\" or team \"{}\", so nothing is allowed. Ask a Gantry admin to add a rule.",
            person.name, person.team
        ),
    )
}

/// Puts what observe mode or a shadow period let through on a decision record: `outcome: would_refuse` on a
/// request that went on, and the list of refusals it would have had.
pub(crate) fn mark_would_refuse(
    record: &mut serde_json::Map<String, serde_json::Value>,
    would_refuse: Vec<serde_json::Value>,
    allowed: bool,
) {
    if would_refuse.is_empty() {
        return;
    }
    if allowed {
        record.insert("outcome".into(), "would_refuse".into());
    }
    record.insert("would_refuse".into(), would_refuse.into());
}

/// Who sent the request, from their Gantry key: refused when the key is unknown, expired or stopped by a kill switch.
/// A stranger is refused before their body is read. Returns the person and the SHA-256 of the key.
/// Who sends a request, by their Gantry key or a JWT from an issuer the policy trusts, refused when unknown,
/// expired, stopped by a kill switch, from an address range their key or rule does not allow, or for a route their
/// key may not call. Every route that takes a Gantry key comes here: the model routes, files, batches,
/// fine-tuning and realtime. Returns the person and the SHA-256 kill switches know the caller by.
pub(crate) async fn identify<'a>(
    state: &AppState,
    policy: &'a Policy,
    key: &str,
    path: &str,
    client_ip: Option<std::net::IpAddr>,
    minted: &'a std::sync::OnceLock<Principal>,
    seen: &mut Seen<'a>,
) -> Result<(&'a Principal, String), Refusal> {
    // A stranger is refused before their body is read, so an unknown caller cannot make the gateway buffer anything.
    // A JWT from an issuer the policy trusts stands in for a key; it is checked before anything else is read too.
    let identified: Option<&'a Principal> = match policy.identify(key) {
        Some(person) => Some(person),
        None if !policy.jwt().is_empty() && jwt::looks_like(key) => {
            seen.key = Some(id::sha256_hex(key.as_bytes())[..8].to_string());
            let person = jwt::verify(&state.client, &state.jwks, policy.jwt(), key)
                .await
                .map_err(|refused| {
                    let status = if refused.unavailable {
                        StatusCode::SERVICE_UNAVAILABLE
                    } else {
                        StatusCode::UNAUTHORIZED
                    };
                    let mut refusal = Refusal::new(status, refused.code, refused.message);
                    refusal.retry = refused.unavailable;
                    refusal
                })?;
            Some(minted.get_or_init(|| person))
        }
        None => None,
    };
    let Some(person) = identified else {
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
    // A JWT caller is named by its issuer and subject, as a key by its hash, so a key_prefix switch can stop it.
    let key_sha256 = match &person.jwt {
        Some(jwt) => id::sha256_hex(format!("{}\n{}", jwt.issuer, jwt.subject).as_bytes()),
        None => id::sha256_hex(key.as_bytes()),
    };
    killed(state, person, &key_sha256, None)?;
    let blocked = |from: &[gantry_core::policy::Cidr]| {
        !from.is_empty() && !client_ip.is_some_and(|ip| from.iter().any(|c| c.contains(ip)))
    };
    let where_from =
        client_ip.map_or_else(|| "an unknown address".to_string(), |ip| ip.to_string());
    if blocked(&person.options.from) {
        let mut refusal = Refusal::new(
            StatusCode::FORBIDDEN,
            "ip_not_allowed",
            format!(
                "Refused: the key {} of \"{}\" may be used only from its listed address ranges, and this request came from {where_from}. Send it from an allowed network, or ask a Gantry admin to change the key's from list.",
                person.key, person.name
            ),
        );
        refusal.record = Some(Box::new(serde_json::json!({ "ip_not_allowed": "key" })));
        enforce(seen, refusal, policy.observing(None))?;
    }
    if let Some(rule) = policy.rule_for(person)
        && blocked(&rule.limits.from)
    {
        seen.rule = Some(rule);
        let mut refusal = Refusal::new(
            StatusCode::FORBIDDEN,
            "ip_not_allowed",
            format!(
                "Refused: rule \"{}\" allows requests only from its listed address ranges, and this request came from {where_from}. Send it from an allowed network, or ask a Gantry admin to change the rule's from list.",
                rule.name
            ),
        );
        refusal.record = Some(Box::new(serde_json::json!({ "ip_not_allowed": "rule" })));
        enforce(
            seen,
            refusal,
            policy.observing(rule.shadow_until.as_deref()),
        )?;
    }
    if !person.options.reaches(path) {
        return Err(Refusal::new(
            StatusCode::FORBIDDEN,
            "route_not_allowed",
            format!(
                "Refused: the key {} of \"{}\" may call only {}, and this request is for {}. Ask a Gantry admin to change the key's routes if it needs this one.",
                person.key,
                person.name,
                person.options.routes.join(", "),
                path
            ),
        ));
    }
    if let Some(next) = &person.options.replaced_by {
        // Every use of a key in its rotation's grace period is recorded as such, so the stragglers can be found.
        seen.rotated = Some(serde_json::json!({ "replaced_by": next, "expires": person.expires }));
    }
    Ok((person, key_sha256))
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

/// A request for a provider's own API: allowed only on a path the caller's rule names for that provider, with any
/// `model` in its body checked as on every other route. It is then recorded, limited and metered like the rest.
#[allow(clippy::too_many_arguments)]
async fn passthrough<'a>(
    state: &AppState,
    version: &Snapshot,
    policy: &'a Policy,
    person: &'a Principal,
    key_sha256: &str,
    mut parts: Parts,
    body: Body,
    query_carries_key: bool,
    provider_key: Option<String>,
    seen: &mut Seen<'a>,
) -> Result<Next, Refusal> {
    let path = parts.uri.path().to_string();
    let (name, native) = match path.strip_prefix(PASSTHROUGH) {
        Some(rest) => match rest.split_once('/') {
            Some((name, path)) => (name.to_string(), format!("/{path}")),
            None => (rest.to_string(), "/".to_string()),
        },
        None => {
            let (cloud, rest, of) = match path.strip_prefix(BEDROCK_PASSTHROUGH) {
                Some(rest) => ("Amazon Bedrock", rest, Kind::bedrock as fn(Kind) -> bool),
                None => (
                    "Vertex AI",
                    path.strip_prefix(VERTEX_PASSTHROUGH).unwrap_or_default(),
                    Kind::google_auth as fn(Kind) -> bool,
                ),
            };
            let named = parts
                .headers
                .get(PROVIDER_HEADER)
                .and_then(|v| v.to_str().ok());
            let all: Vec<&Upstream> = version
                .providers
                .iter()
                .filter(|p| of(p.kind) && named.is_none_or(|n| n == p.name))
                .collect();
            let name = match all.as_slice() {
                [one] => one.name.clone(),
                [] => {
                    return Err(Refusal::new(
                        StatusCode::NOT_FOUND,
                        "unknown_provider",
                        format!(
                            "Refused: this Gantry has no {cloud} provider{} to pass through to. Ask a Gantry admin to add one, or check the {PROVIDER_HEADER} header.",
                            named.map(|n| format!(" named \"{n}\"")).unwrap_or_default()
                        ),
                    ));
                }
                _ => {
                    return Err(Refusal::new(
                        StatusCode::BAD_REQUEST,
                        "provider_needed",
                        format!(
                            "Refused: more than one {cloud} provider could take this. Name one in the {PROVIDER_HEADER} header."
                        ),
                    ));
                }
            };
            (name, format!("/{rest}"))
        }
    };
    parts.headers.remove(PROVIDER_HEADER);
    let Some(index) = version.providers.iter().position(|p| p.name == name) else {
        return Err(Refusal::new(
            StatusCode::NOT_FOUND,
            "unknown_provider",
            format!(
                "Refused: there is no provider \"{name}\" to pass through to. Use /passthrough/<provider>/<path> with a provider named in the policy."
            ),
        ));
    };
    seen.provider = Some(index);
    let rule = rule_or_observed(policy, person, no_rule(person), |r, by| {
        observed(seen, r, by);
    })?;
    seen.rule = Some(rule);
    let by = policy.observing(rule.shadow_until.as_deref());
    customer_and_tags(&mut parts.headers, person, rule, seen, by)?;
    if let Some(regions) = &rule.limits.regions {
        // A provider's own API has no region label: residency cannot be shown, so it is refused.
        enforce(
            seen,
            Refusal::new(
                StatusCode::FORBIDDEN,
                "region_not_allowed",
                format!(
                    "Refused: rule \"{}\" keeps requests in {}, and a passthrough call goes to the provider as is, with no region Gantry can show. Use a model route with an alias whose deployments are in those regions.",
                    rule.name,
                    regions.join(", ")
                ),
            ),
            by,
        )?;
    }
    // A dot segment could climb out of the listed prefix at the provider, whatever the prefix match says here.
    let climbs = native
        .split('/')
        .any(|seg| seg == "." || seg == ".." || seg.contains('%'));
    if climbs || !rule.reaches(&name, &native) {
        let refusal = Refusal::new(
            StatusCode::FORBIDDEN,
            "passthrough_not_allowed",
            format!(
                "Refused: rule \"{}\" does not let you reach {native} at provider \"{name}\" as sent. Ask a Gantry admin to add the path under the rule's passthrough:.",
                rule.name
            ),
        );
        // A path that climbs is refused in every mode: it is not a path any rule could list.
        enforce(seen, refusal, by.filter(|_| !climbs))?;
    }
    caller_paid(
        Some(rule),
        version.providers.get(index).map(|p| p.kind),
        provider_key.as_deref(),
    )?;
    if query_carries_key {
        return Err(Refusal::new(
            StatusCode::BAD_REQUEST,
            "key_in_query",
            "Refused: the query carries your Gantry key, which must never reach a provider. Send it in the Authorization header only.",
        ));
    }
    let (bytes, permit) = read_body(Some(&person.name), state, &parts.headers, body).await?;
    // Bedrock and Vertex AI name the model in the path (/model/<id>/..., .../models/<model>:<method>): it is decided on
    // by the name the policy knows it by.
    let in_path = version.providers.get(index).and_then(|p| {
        let id = if p.kind == Kind::Sagemaker {
            native.strip_prefix("/endpoints/")?.split('/').next()?
        } else if p.kind.aws() {
            native.strip_prefix("/model/")?.split('/').next()?
        } else if p.kind.google_auth() {
            native.split("/models/").nth(1)?.split([':', '/']).next()?
        } else if let Some(rest) = native.strip_prefix("/v2/models/") {
            // KServe v2 (Triton): the model is the path segment after /v2/models/.
            rest.split('/').next()?
        } else {
            return None;
        };
        Some(
            p.upstream_models
                .iter()
                .find(|(_, upstream)| upstream.as_str() == id)
                .map_or(id, |(model, _)| model.as_str())
                .to_string(),
        )
    });
    let model = in_path.or_else(|| {
        serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|v| v.get("model").and_then(|m| m.as_str()).map(String::from))
    });
    if let Some(model) = &model {
        seen.model = Some(model.clone());
        if !matches!(policy.decide(person, model), Decision::Allow(_)) {
            enforce(
                seen,
                Refusal::new(
                    StatusCode::FORBIDDEN,
                    "model_not_allowed",
                    format!(
                        "Refused: rule \"{}\" does not allow model \"{model}\" for \"{}\". {} Ask a Gantry admin if you need it.",
                        rule.name,
                        person.name,
                        allowed_models(rule)
                    ),
                ),
                by,
            )?;
        }
    }
    killed(state, person, key_sha256, model.as_deref())?;
    let target = match parts.uri.query() {
        Some(query) => format!("{native}?{query}"),
        None => native,
    };
    let model = model.unwrap_or_default();
    parts.extensions.insert(Plan {
        provider: index,
        model: model.clone(),
        translated: None,
        from_messages: false,
        from_responses: false,
        as_responses: None,
        sent_route: None,
        chain: vec![Hop::plain(index, model)],
        cooldown: None,
        context: Vec::new(),
        content: Vec::new(),
        passthrough: Some(target),
        caller_key: provider_key.map(Secret::new),
        fallbacks: Vec::new(),
        fallback_on: Vec::new(),
        body_api: Kind::OpenAi,
        include_usage: false,
    });
    Ok(Next::Forward(parts, bytes, permit))
}

fn unknown_route() -> Refusal {
    Refusal::new(
        StatusCode::NOT_FOUND,
        "unknown_route",
        "Refused: this version of Gantry serves POST /v1/chat/completions, POST /v1/responses, POST /v1/embeddings, POST /v1/images/generations, POST /v1/images/edits, POST /v1/images/variations, POST /v1/audio/transcriptions, POST /v1/audio/speech, POST /v1/moderations, POST /v1/rerank, POST /v1/completions, POST /v1/messages, POST /v1/messages/count_tokens, GET /v1/models, Google's Gemini API (POST /v1beta/models/<model>:generateContent, :streamGenerateContent, :countTokens, :embedContent, :batchEmbedContents, and GET /v1beta/models), the passthrough prefixes /passthrough/<provider>/, /bedrock/ and /vertex/, GET /healthz and GET /readyz. Check the method and the path.",
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
    /// A Responses request translated to chat completions, whose answer goes back as a response.
    from_responses: bool,
    /// A chat request sent to the Responses API: whether the client asked for usage in its stream.
    as_responses: Option<bool>,
    /// The route the body now is, when it was translated to another API's: sent there.
    sent_route: Option<&'static str>,
    /// The deployments to try in order: each a provider by position and the model sent there. One entry for a
    /// model that is not an alias.
    chain: Chain,
    /// For an alias: how long a deployment that failed is passed over.
    cooldown: Option<Duration>,
    /// Where the request goes when the provider says the prompt is longer than its context window.
    context: Chain,
    /// Where the request goes when the provider refuses it under its content policy.
    content: Chain,
    /// For a passthrough request: the native path and query it is sent to, as sent.
    passthrough: Option<String>,
    /// The caller's own provider key, sent in place of Gantry's, on a rule that allows it.
    caller_key: Option<Secret>,
    /// An alias's `fallbacks`, each a chain of its own, tried in turn on a failure `fallback_on` names.
    fallbacks: Vec<Chain>,
    fallback_on: Vec<gantry_core::config::FallbackOn>,
    /// The API the forwarded body is in: messages, or chat completions (Google's providers translate it as sent).
    /// A hop of the other API gets it translated, so a fallback can cross from one to the other.
    body_api: Kind,
    /// Whether a chat client asked for usage in its stream.
    include_usage: bool,
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

/// What the caller brings to the choice of deployment: their team and tags for kept deployments, their rule's
/// residency, and their session.
struct Want<'a> {
    team: &'a str,
    tags: &'a [String],
    /// The regions a deployment must be labelled with. `None` sets no residency.
    regions: Option<&'a [String]>,
    /// Person and session, for an alias with session affinity.
    session: Option<String>,
    /// What a deployment's `when` may look at.
    customer: Option<String>,
    headers: &'a HeaderMap,
    body: &'a [u8],
}

/// One place a request may go: a provider by position, the model sent there, and, for an alias's deployment, its
/// time limits and how long it is passed over after a failure.
#[derive(Clone, Debug, Default)]
struct Hop {
    provider: usize,
    model: String,
    timeouts: gantry_core::config::Timeouts,
    cooldown: Option<Duration>,
}

impl Hop {
    fn plain(provider: usize, model: String) -> Self {
        Hop {
            provider,
            model,
            ..Hop::default()
        }
    }
}

/// Where a request may go, in the order to try it.
type Chain = Vec<Hop>;

/// The deployments that can take this request, in the order to try them, whether it is translated, and how the
/// first was chosen (for the record). A model that is not an alias has one: the provider that lists it.
fn targets(
    state: &AppState,
    version: &Snapshot,
    path: &str,
    model: &str,
    want: &Want<'_>,
    across: bool,
) -> Result<(Chain, Shape, Option<serde_json::Value>), Refusal> {
    // A fallback may go to a provider of the other API: chat to messages and back, translated as it is sent.
    let fits = |provider: &Upstream, path: &str, model: &str| {
        fits(provider, path, model).or_else(|refusal| match provider.kind.api() {
            Kind::Anthropic if across && path == CHAT => Ok(Shape::Messages),
            Kind::OpenAi if across && path == MESSAGES => Ok(Shape::Chat),
            _ => Err(refusal),
        })
    };
    let Some(alias) = version.aliases.iter().find(|a| a.name == model) else {
        if let Some(regions) = want.regions {
            // A model sent to its provider directly has no region label: residency cannot be shown, so it is refused.
            return Err(Refusal::new(
                StatusCode::FORBIDDEN,
                "region_not_allowed",
                format!(
                    "Refused: your rule keeps requests in {}, and model \"{model}\" is not an alias whose deployments are labelled with a region, so where it runs cannot be shown. Use an alias with a deployment in one of those regions, or ask a Gantry admin to add region: to its deployments.",
                    regions.join(", ")
                ),
            ));
        }
        let (index, shape, sent) = if across {
            let (index, sent) = find_provider(version, model).ok_or_else(|| unserved(model))?;
            let shape = fits(&version.providers[index], path, &sent)?;
            (index, shape, sent)
        } else {
            provider_for(version, path, model)?
        };
        return Ok((vec![Hop::plain(index, sent)], shape, None));
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
        match fits(&version.providers[index], path, &deployment.model) {
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
    let mut routing = serde_json::json!({ "balance": alias.balance.word() });
    // Residency is a filter, never a preference: a deployment outside the allowed regions is not tried at all.
    if let Some(regions) = want.regions {
        eligible.retain(|(at, _)| {
            alias.deployments[*at]
                .region
                .as_ref()
                .is_some_and(|r| regions.contains(r))
        });
        if eligible.is_empty() {
            return Err(Refusal::new(
                StatusCode::FORBIDDEN,
                "region_not_allowed",
                format!(
                    "Refused: your rule keeps requests in {}, and alias \"{model}\" has no deployment labelled with one of those regions, so the request was not sent anywhere. Ask a Gantry admin to add a deployment in one of them.",
                    regions.join(", ")
                ),
            ));
        }
        routing["regions"] = regions.into();
    }
    // Deployments kept for a team, tag or condition: a request that matches some goes only to those; one that
    // matches none goes to the deployments kept for nobody.
    let matches = |f: &gantry_core::config::For| match f {
        gantry_core::config::For::Team(team) => team == want.team,
        gantry_core::config::For::Tag(tag) => want.tags.contains(tag),
    };
    // The body is read for a condition only when a deployment has one that needs it.
    let facts = std::cell::OnceCell::new();
    let facts = || *facts.get_or_init(|| body_facts(want.body));
    let meets = |w: &gantry_core::config::When| {
        w.team.as_ref().is_none_or(|t| t == want.team)
            && w.tag.as_ref().is_none_or(|t| want.tags.contains(t))
            && w.customer
                .as_ref()
                .is_none_or(|c| want.customer.as_ref() == Some(c))
            && w.header.as_ref().is_none_or(|(name, value)| {
                want.headers
                    .get(name.as_str())
                    .and_then(|v| v.to_str().ok())
                    == Some(value.as_str())
            })
            && w.min_prompt_tokens.is_none_or(|min| facts().0 >= min)
            && w.max_prompt_tokens.is_none_or(|max| facts().0 <= max)
            && w.tools.is_none_or(|tools| facts().1 == tools)
            && w.images.is_none_or(|images| facts().2 == images)
    };
    let kept_for = |d: &gantry_core::config::Deployment| d.for_.is_some() || d.when.is_some();
    let kept: Vec<(usize, usize)> = eligible
        .iter()
        .copied()
        .filter(|(at, _)| {
            let d = &alias.deployments[*at];
            kept_for(d) && d.for_.as_ref().is_none_or(matches) && d.when.as_ref().is_none_or(meets)
        })
        .collect();
    if kept.is_empty() {
        eligible.retain(|(at, _)| !kept_for(&alias.deployments[*at]));
        if eligible.is_empty() {
            return Err(Refusal::new(
                StatusCode::FORBIDDEN,
                "no_deployment",
                format!(
                    "Refused: every deployment of alias \"{model}\" that is allowed here is kept for another team or tag. Send a tag the alias keeps a deployment for, or ask a Gantry admin to add a deployment for everyone."
                ),
            ));
        }
    } else {
        let label = kept
            .iter()
            .map(|(at, _)| match &alias.deployments[*at].for_ {
                Some(gantry_core::config::For::Team(t)) => format!("team:{t}"),
                Some(gantry_core::config::For::Tag(t)) => format!("tag:{t}"),
                None => "when".to_string(),
            })
            .next()
            .unwrap_or_default();
        routing["for"] = label.into();
        eligible = kept;
    }
    // A deployment at its max_parallel, rpm or tpm is passed over; with every one there, the caller waits.
    let tokens = body_facts(want.body).0;
    let full = eligible.len();
    eligible.retain(|(at, _)| state.pool.has_room(&alias.deployments[*at], tokens));
    if eligible.is_empty() && full > 0 {
        return Err(Refusal::new(
            StatusCode::TOO_MANY_REQUESTS,
            "deployment_limit",
            format!(
                "Refused: every deployment of alias \"{model}\" is at its max_parallel, rpm or tpm. Try again in a moment, or ask a Gantry admin to raise the limits or add a deployment."
            ),
        ));
    }
    let positions: Vec<usize> = eligible.iter().map(|(at, _)| *at).collect();
    let none = gantry_core::usage::PriceOverrides::new();
    let prices = version.policy.as_ref().map_or(&none, Policy::prices);
    let cost: Vec<Option<f64>> = alias
        .deployments
        .iter()
        .map(|d| gantry_core::usage::price_for(&d.model, prices).map(|p| p.input + p.output))
        .collect();
    let ask = alias::Ask {
        session: want.session.clone(),
        cost: &cost,
    };
    let (order, reason) = state.pool.order(alias, &positions, Instant::now(), &ask);
    routing["reason"] = reason.into();
    if let Some(first) = order.first().and_then(|at| alias.deployments.get(*at)) {
        routing["deployment"] = alias::label(&first.provider, &first.model).into();
        if let Some(region) = &first.region {
            routing["region"] = region.as_str().into();
        }
    }
    let chain = order
        .into_iter()
        .filter_map(|at| {
            let index = eligible.iter().find(|(p, _)| *p == at)?.1;
            let deployment = alias.deployments.get(at)?;
            Some(Hop {
                provider: index,
                model: deployment.model.clone(),
                timeouts: deployment.timeouts.or(alias.timeouts),
                cooldown: Some(Duration::from_secs(alias.cooldown_seconds)),
            })
        })
        .collect();
    Ok((chain, translate.unwrap_or(Shape::Sent), Some(routing)))
}

/// What a deployment's `when` may ask of a request body: its size in tokens (bytes over four), whether it offers
/// tools, and whether any message holds an image.
// ponytail: bytes over four, not a tokenizer; close enough to send a long prompt to a long-context model.
fn body_facts(body: &[u8]) -> (u64, bool, bool) {
    let tokens = u64::try_from(body.len() / 4).unwrap_or(u64::MAX);
    let Ok(request) = serde_json::from_slice::<serde_json::Value>(body) else {
        return (tokens, false, false);
    };
    let tools = request["tools"].as_array().is_some_and(|t| !t.is_empty());
    fn image(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::Array(items) => items.iter().any(image),
            serde_json::Value::Object(map) => {
                matches!(
                    map.get("type").and_then(serde_json::Value::as_str),
                    Some("image_url" | "image" | "input_image")
                ) || map.values().any(image)
            }
            _ => false,
        }
    }
    let images = ["messages", "input", "contents"]
        .iter()
        .any(|field| image(&request[*field]));
    (tokens, tools, images)
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

/// A name as it goes into a provider path segment, every byte but the unreserved ones percent-encoded.
pub(crate) fn sigv4_encode(name: &str) -> String {
    sigv4::uri_encode(name, false)
}

/// A request body as JSON, or the refusal that says it is not.
fn json_of(bytes: &[u8], what: &str) -> Result<serde_json::Value, Refusal> {
    serde_json::from_slice(bytes).map_err(|_| {
        Refusal::new(
            StatusCode::BAD_REQUEST,
            "unreadable_request",
            format!("Refused: the request body is not JSON. Send {what} as a JSON object."),
        )
    })
}

fn untranslatable(err: impl std::fmt::Display) -> Refusal {
    Refusal::new(
        StatusCode::BAD_REQUEST,
        "untranslatable",
        format!("Refused: {err}"),
    )
}

/// A Responses request as a chat completions request, for a provider that does not speak Responses.
fn to_chat_from_responses(bytes: &[u8]) -> Result<Bytes, Refusal> {
    let request = json_of(bytes, "a Responses request")?;
    let chat =
        gantry_core::responses::responses_to_chat_request(&request).map_err(untranslatable)?;
    Ok(Bytes::from(chat.to_string()))
}

/// A chat completions request as a Responses request, and whether its client asked for usage in the stream.
fn to_responses_request(bytes: &[u8]) -> Result<(Bytes, bool), Refusal> {
    let request = json_of(bytes, "a chat completions request")?;
    let out =
        gantry_core::responses::chat_to_responses_request(&request).map_err(untranslatable)?;
    Ok((
        Bytes::from(out.to_string()),
        translate::include_usage(&request),
    ))
}

/// Whether an Azure OpenAI provider's URL is the v1 API (`https://<resource>.openai.azure.com/openai/v1`).
pub(crate) fn azure_v1(url: &str) -> bool {
    url.trim_end_matches('/').ends_with("/openai/v1")
}

/// The project of a Vertex AI provider URL (`.../projects/<project>/locations/...`).
fn vertex_project(url: &str) -> Option<&str> {
    url.split("/projects/").nth(1)?.split('/').next()
}

/// The body a provider of a kind that translates (`Shape::Native`) takes for a request in the caller's format on
/// `route` (chat, embeddings, rerank), and whether its answer streams. `model` is the caller's name for the model.
fn native_body(
    provider: &Upstream,
    model: &str,
    bytes: &[u8],
    route: &str,
) -> Result<(Bytes, bool), Refusal> {
    let request = json_of(bytes, "the request")?;
    let id = provider
        .upstream_models
        .get(model)
        .map_or(model, String::as_str);
    let project = provider.project_id.as_deref();
    let body = match (route, provider.kind) {
        (COUNT_TOKENS, Kind::Gemini | Kind::Vertex) => {
            // A messages request (Claude Code counts before it sends) as Gemini's countTokens body: its contents and
            // system instruction. countTokens takes no tools, so a request with tools is refused, not under-counted.
            if request.get("tools").is_some_and(|t| !t.is_null()) {
                return Err(untranslatable(
                    "The parameter \"tools\" has no equivalent in Gemini's countTokens. Count the request without tools, or send it to /v1/messages without counting first.",
                ));
            }
            let chat: serde_json::Value = serde_json::from_slice(&to_chat_request(bytes)?)
                .map_err(|_| untranslatable("the request could not be read as chat"))?;
            let (gemini, _) = gemini::openai_to_gemini_request(&chat).map_err(untranslatable)?;
            let mut out = serde_json::json!({"contents": gemini["contents"]});
            if !gemini["systemInstruction"].is_null() {
                out["systemInstruction"] = gemini["systemInstruction"].clone();
            }
            (out, false)
        }
        (CHAT, Kind::Gemini | Kind::Vertex) => {
            gemini::openai_to_gemini_request(&request).map_err(untranslatable)?
        }
        (CHAT, Kind::BedrockConverse) => {
            gantry_core::converse::openai_to_converse_request(&request, id)
                .map_err(untranslatable)?
        }
        (CHAT, Kind::Cohere) => {
            let stream = request["stream"] == true;
            (
                gantry_core::cohere::openai_to_cohere_request(&request).map_err(untranslatable)?,
                stream,
            )
        }
        (CHAT, Kind::Replicate) => (
            gantry_core::replicate::openai_to_prediction(&request, id).map_err(untranslatable)?,
            false,
        ),
        (CHAT, Kind::Watsonx) => {
            gantry_core::cohere::openai_to_watsonx_request(&request, project.unwrap_or_default())
                .map_err(untranslatable)?
        }
        (EMBEDDINGS, kind) => {
            use gantry_core::embed::Target;
            let target = match kind {
                Kind::Gemini => Target::Gemini,
                Kind::Vertex => Target::Vertex,
                Kind::Cohere => Target::Cohere,
                Kind::Watsonx => Target::Watsonx,
                _ => Target::bedrock(id).unwrap_or(Target::Titan),
            };
            (
                gantry_core::embed::request(target, id, &request, project)
                    .map_err(untranslatable)?,
                false,
            )
        }
        (RERANK, Kind::Vertex) => {
            // Vertex AI's Ranking API: each document a record, ranked by score.
            let documents = request["documents"].as_array().ok_or_else(|| {
                untranslatable(
                    "\"documents\" must be a list of strings for Vertex AI's ranking API.",
                )
            })?;
            let mut records = Vec::new();
            for (i, doc) in documents.iter().enumerate() {
                let Some(text) = doc.as_str() else {
                    return Err(untranslatable(
                        "A document that is not a string has no equivalent in Vertex AI's ranking API. Send each document as text.",
                    ));
                };
                records.push(serde_json::json!({"id": i.to_string(), "content": text}));
            }
            let mut out = serde_json::json!({
                "model": model,
                "query": request["query"],
                "records": records,
                "ignoreRecordDetailsInResponse": true,
            });
            if let Some(n) = request["top_n"].as_u64() {
                out["topN"] = n.into();
            }
            for key in request.as_object().map(|o| o.keys()).into_iter().flatten() {
                if !matches!(key.as_str(), "model" | "query" | "documents" | "top_n") {
                    return Err(untranslatable(format!(
                        "The parameter \"{key}\" has no equivalent in Vertex AI's ranking API. Remove it."
                    )));
                }
            }
            (out, false)
        }
        _ => return Ok((Bytes::copy_from_slice(bytes), false)),
    };
    Ok((Bytes::from(body.0.to_string()), body.1))
}

/// The one provider that serves this model, if it speaks the API of the route the request came on, or takes chat
/// requests translated. Returns its position and whether the request is to be translated.
fn provider_for(
    version: &Snapshot,
    path: &str,
    model: &str,
) -> Result<(usize, Shape, String), Refusal> {
    let (index, sent) = find_provider(version, model).ok_or_else(|| unserved(model))?;
    fits(&version.providers[index], path, &sent).map(|shape| (index, shape, sent))
}

/// The provider that serves `model` and the name it is sent there by. An exact name wins over a pattern, and a
/// pattern over `<provider>/<model>`.
fn find_provider(version: &Snapshot, model: &str) -> Option<(usize, String)> {
    version
        .providers
        .iter()
        .position(|p| p.lists(model))
        .or_else(|| version.providers.iter().position(|p| p.serves(model)))
        .map(|index| (index, model.to_string()))
        .or_else(|| {
            let (name, rest) = model.split_once('/')?;
            let index = version
                .providers
                .iter()
                .position(|p| p.name == name && !p.models.is_empty() && p.serves(rest))?;
            Some((index, rest.to_string()))
        })
}

/// No provider serves the model. 403, as for a model the policy does not allow. Found by running Claude Code through
/// Gantry: it replaces the message of a 404 with its own, so the caller lost the model name and the decision ID, and
/// it sends a 400 up to six times with parts of the request removed. A 403 is shown as it is, once.
fn unserved(model: &str) -> Refusal {
    Refusal::new(
        StatusCode::FORBIDDEN,
        "unknown_model",
        format!(
            "Refused: no provider of this Gantry serves model \"{model}\". Check the model name, or ask a Gantry admin to add it to a provider."
        ),
    )
}

/// What a request's body becomes on its way to a provider. Every deployment tried for one request takes the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    /// Forwarded as sent.
    Sent,
    /// Kept in the caller's format (chat, embeddings, rerank) here and translated to the provider's own body as it
    /// is sent: Gemini, Vertex AI, Bedrock Converse, Cohere, watsonx.
    Native,
    /// A chat completions body: a messages request (Claude Code) for a chat provider, or a Responses request for a
    /// provider that takes chat as sent.
    Chat,
    /// Translated to the messages API.
    Messages,
    /// A chat request translated to the Responses API, for a model served only through it.
    Responses,
}

/// Whether this provider can take a request on `route` and `path`, and if so in what shape.
fn fits(provider: &Upstream, path: &str, model: &str) -> Result<Shape, Refusal> {
    let kind = provider.kind;
    let wrong = |what: String| {
        Err(Refusal::new(
            StatusCode::BAD_REQUEST,
            "wrong_route",
            format!(
                "Refused: model \"{model}\" is served by provider \"{}\" of kind {}, {what}",
                provider.name,
                kind.word()
            ),
        ))
    };
    // Google's own API goes as sent, to Google's providers only.
    if gemini_native(path).is_some() {
        if kind.google() {
            return Ok(Shape::Sent);
        }
        return wrong(format!(
            "and Gantry sends Google's Gemini API ({path}) to providers of kind gemini or vertex only. Use a model on one of those, or send this request to {CHAT} instead."
        ));
    }
    let chat_as_sent = matches!(
        kind,
        Kind::OpenAi | Kind::Azure | Kind::VertexOpenAi | Kind::Sagemaker
    );
    match path {
        COUNT_TOKENS => match kind {
            Kind::Anthropic | Kind::Bedrock | Kind::VertexAnthropic => Ok(Shape::Sent),
            Kind::Gemini | Kind::Vertex => Ok(Shape::Native),
            _ if provider.accept_messages => wrong(format!(
                "which takes messages requests translated to chat completions, and Gantry does not count tokens for it. Send the request to {MESSAGES} without counting first."
            )),
            _ => wrong(format!(
                "which speaks the chat completions API. Send this request to {CHAT} instead of {path}."
            )),
        },
        MESSAGES => match kind.api() {
            Kind::Anthropic => Ok(Shape::Sent),
            _ if provider.accept_messages => Ok(Shape::Chat),
            _ => wrong(format!(
                "which speaks the chat completions API. Send this request to {CHAT} instead of {path}. A Gantry admin can let messages requests (Claude Code) reach it, translated, with `accept_messages: true` on the provider."
            )),
        },
        CHAT => match kind {
            _ if chat_as_sent && provider.chat_as_responses => Ok(Shape::Responses),
            _ if chat_as_sent => Ok(Shape::Sent),
            _ if kind.translates_chat() => Ok(Shape::Native),
            _ if provider.accept_chat => Ok(Shape::Messages),
            _ => wrong(format!(
                "which speaks the messages API. Send this request to {MESSAGES} instead of {path}. A Gantry admin can let chat requests reach it, translated, with `accept_chat: true` on the provider."
            )),
        },
        RESPONSES => match kind {
            Kind::OpenAi | Kind::Azure => Ok(Shape::Sent),
            Kind::VertexOpenAi | Kind::Sagemaker => Ok(Shape::Chat),
            _ if kind.translates_chat() => Ok(Shape::Native),
            _ => Ok(Shape::Messages),
        },
        EMBEDDINGS => match kind {
            Kind::OpenAi | Kind::Azure => Ok(Shape::Sent),
            Kind::Gemini | Kind::Vertex | Kind::Cohere | Kind::Watsonx => Ok(Shape::Native),
            Kind::BedrockConverse => {
                let id = provider
                    .upstream_models
                    .get(model)
                    .map_or(model, String::as_str);
                match gantry_core::embed::Target::bedrock(id) {
                    Some(_) => Ok(Shape::Native),
                    None => wrong(format!(
                        "and its Bedrock model ID \"{id}\" is not an embeddings model Gantry translates to (Amazon Titan Text Embeddings, Cohere Embed). Use one of those for {path}."
                    )),
                }
            }
            _ => wrong(format!(
                "which has no embeddings API. Use a model on a provider that embeds for {path}."
            )),
        },
        RERANK => match kind {
            Kind::OpenAi | Kind::Cohere => Ok(Shape::Sent),
            Kind::Vertex => Ok(Shape::Native),
            _ => wrong(format!(
                "which has no rerank API Gantry reaches. Use a model on an openai, cohere or vertex provider for {path}."
            )),
        },
        _ if openai_only(path) && kind == Kind::OpenAi => Ok(Shape::Sent),
        IMAGES | TRANSCRIPTIONS | SPEECH | COMPLETIONS if kind == Kind::Azure => Ok(Shape::Sent),
        _ => wrong(format!(
            "and Gantry forwards {path} to providers of kind openai only. Use a model on a provider of kind openai, or send this request to the route that provider speaks ({}).",
            if kind.api() == Kind::Anthropic {
                MESSAGES
            } else {
                CHAT
            }
        )),
    }
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
            // A pattern is not a model a client can pick from a list.
            .flat_map(|provider| {
                provider
                    .models
                    .iter()
                    .filter(|m| !m.contains('*'))
                    .map(move |m| (m, &provider.name))
            })
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
        .flat_map(|provider| provider.models.iter().filter(|m| !m.contains('*')))
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

/// Refuses a Gemini API body that is not a JSON object, or that names a model other than the one in the path, at the
/// top or in countTokens' generateContentRequest.
fn gemini_body_model(bytes: &[u8], model: &str) -> Result<(), Refusal> {
    let body: serde_json::Value = serde_json::from_slice(bytes).unwrap_or_default();
    if !body.is_object() {
        return Err(Refusal::new(
            StatusCode::BAD_REQUEST,
            "unreadable_request",
            "Refused: the request body must be a JSON object, as Google's Gemini API takes it, so the policy and guardrails can read it.",
        ));
    }
    for named in [&body["model"], &body["generateContentRequest"]["model"]] {
        let Some(named) = named.as_str() else {
            continue;
        };
        if named != model && named.strip_prefix("models/") != Some(model) {
            return Err(Refusal::new(
                StatusCode::BAD_REQUEST,
                "ambiguous_model",
                format!(
                    "Refused: the path names model \"{model}\" and the body names \"{named}\". Name one model: remove it from the body, or make the two the same."
                ),
            ));
        }
    }
    Ok(())
}

/// A Gemini API body with the model it names, at the top or in countTokens' generateContentRequest, replaced by
/// `model`. A body that names none goes as it came.
fn gemini_with_model(bytes: &Bytes, model: &str) -> Bytes {
    let Ok(mut body) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return bytes.clone();
    };
    let mut changed = false;
    let to = serde_json::Value::from(format!("models/{model}"));
    if body.get("model").is_some_and(serde_json::Value::is_string) {
        body["model"] = to.clone();
        changed = true;
    }
    if body["generateContentRequest"]
        .get("model")
        .is_some_and(serde_json::Value::is_string)
    {
        body["generateContentRequest"]["model"] = to;
        changed = true;
    }
    if changed {
        Bytes::from(body.to_string())
    } else {
        bytes.clone()
    }
}

/// The models this caller may use on Google's Gemini API, as its `models.list` (or `models.get`, for a path that
/// names one) answers: those of gemini and vertex providers, and aliases whose deployments are there, that the
/// rule (and the key's own list) allows.
fn gemini_model_list(
    version: &Snapshot,
    rule: Option<&Rule>,
    person: &Principal,
    path: &str,
) -> Result<Response, Refusal> {
    let allowed = |model: &str| {
        rule.is_some_and(|rule| rule.allows(model))
            && person
                .models
                .as_ref()
                .is_none_or(|m| m.iter().any(|k| k == model))
    };
    let google = |name: &str| {
        version
            .providers
            .iter()
            .any(|p| p.name == name && p.kind.google())
    };
    let mut models: Vec<&String> = version
        .providers
        .iter()
        .filter(|p| p.kind.google())
        .flat_map(|p| p.models.iter())
        .chain(
            version
                .aliases
                .iter()
                .filter(|a| a.deployments.first().is_some_and(|d| google(&d.provider)))
                .map(|a| &a.name),
        )
        .filter(|model| allowed(model))
        .collect();
    models.dedup();
    let entry = |model: &str| {
        serde_json::json!({
            "name": format!("models/{model}"),
            "displayName": model,
            "description": rule.map(|r| format!("Allowed by Gantry rule \"{}\"", r.name)),
            "supportedGenerationMethods": GEMINI_METHODS,
        })
    };
    let body = match path.strip_prefix("/v1beta/models/") {
        None => {
            serde_json::json!({ "models": models.iter().map(|m| entry(m)).collect::<Vec<_>>() })
        }
        Some(one) => {
            if !models.iter().any(|m| *m == one) {
                return Err(Refusal::new(
                    StatusCode::NOT_FOUND,
                    "unknown_model",
                    format!(
                        "Refused: model \"{one}\" is not one you may use through this Gantry. List the ones you may with GET {GEMINI_MODELS}."
                    ),
                ));
            }
            entry(one)
        }
    };
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response())
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
pub(crate) async fn handle(State(state): State<AppState>, mut request: Request) -> Response {
    let arrived = Instant::now();
    let decision = id::decision_id();
    const TRACEPARENT: HeaderName = HeaderName::from_static("traceparent");
    if let Some(tracer) = &state.tracer {
        let ours = tracer.begin(
            &decision,
            request.method(),
            request.uri().path(),
            request.headers().get(&TRACEPARENT),
        );
        // The provider sees Gantry's span as the parent of its own.
        if let Some(ours) = ours {
            request.headers_mut().insert(TRACEPARENT, ours);
        }
    }
    let anthropic = matches!(request.uri().path(), MESSAGES | COUNT_TOKENS);
    let gemini = gemini_path(request.uri().path());
    let respond = |refusal: Refusal| {
        if gemini {
            refusal.respond_gemini(&decision)
        } else {
            refusal.respond(&decision, anthropic)
        }
    };
    // Google's streamGenerateContent without alt=sse answers with one JSON array. Gantry asks the provider for events
    // (to meter and guard the stream as it comes) and writes them out as that array at the end.
    let as_array = gemini_streams(request.uri().path())
        && !request
            .uri()
            .query()
            .is_some_and(|q| q.split('&').any(|p| p == "alt=sse"));
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
                Err(failure) => {
                    upstream_failed(&state, &version, &decision, &failure, arrived);
                    respond(failure)
                }
            }
        }
        Err(refusal) => respond(refusal),
    };
    let creator = response.extensions_mut().remove::<batch::Creator>();
    if let Some(check) = response.extensions_mut().remove::<AnswerCheck>() {
        response = match answer_guarded(&state, check, &decision, response).await {
            Ok(response) => response,
            Err(refusal) => respond(refusal),
        };
    }
    if as_array && response.status().is_success() && is_type(&response, "text/event-stream") {
        response = events_as_array(response);
    }
    // After the answer guardrails: what is recorded or kept is what the caller got.
    if let Some(creator) = creator {
        response = batch::watch(&state, &decision, creator, response);
    }
    if let Ok(value) = HeaderValue::from_str(&decision) {
        response.headers_mut().insert(DECISION, value.clone());
        response
            .headers_mut()
            .insert(HeaderName::from_static("x-gantry-request-id"), value);
    }
    if let Some(tracer) = &state.tracer {
        tracer.answered(&decision, response.status().as_u16());
    }
    response
}

/// A Gemini event stream as the JSON array Google's streamGenerateContent sends without alt=sse: each event's data
/// as an element, written out as the events come.
fn events_as_array(response: Response) -> Response {
    let mut pending: Vec<u8> = Vec::new();
    let mut started = false;
    map_body(response, "application/json", move |input| {
        let done = input.is_none();
        pending.extend_from_slice(input.unwrap_or_default());
        let end = if done {
            pending.len()
        } else {
            whole_events(&pending)
        };
        let mut out = Vec::new();
        let events: Vec<u8> = pending.drain(..end).collect();
        for line in String::from_utf8_lossy(&events).lines() {
            let Some(data) = line.strip_prefix("data:").map(str::trim) else {
                continue;
            };
            if data.is_empty() {
                continue;
            }
            out.extend_from_slice(if started { b",\r\n" } else { b"[" });
            started = true;
            out.extend_from_slice(data.as_bytes());
        }
        if done {
            out.extend_from_slice(if started { b"]" } else { b"[]" });
        }
        Ok(out)
    })
}

/// Records a request that was decided and forwarded, and got no answer from any provider, so the request log counts
/// it as an error. Does not wait: the caller has its answer already.
fn upstream_failed(
    state: &AppState,
    version: &Snapshot,
    decision: &str,
    failure: &Refusal,
    arrived: Instant,
) {
    let (Some(audit), Some(_)) = (&state.audit, &version.policy) else {
        return;
    };
    let mut record = serde_json::Map::new();
    record.insert("event".into(), "upstream_error".into());
    record.insert("id".into(), decision.into());
    record.insert("time".into(), gantry_core::audit::timestamp().into());
    record.insert("status".into(), failure.status.as_u16().into());
    record.insert("code".into(), failure.code.into());
    if let Some(tried) = failure.record.as_deref() {
        for field in ["provider", "tries"] {
            if let Some(value) = tried.get(field) {
                record.insert(field.into(), value.clone());
            }
        }
    }
    record.insert(
        "latency_ms".into(),
        u64::try_from(arrived.elapsed().as_millis())
            .unwrap_or(u64::MAX)
            .into(),
    );
    let decision = decision.to_string();
    audit.log.append_record_then(&record, move |result| {
        if let Err(err) = result {
            eprintln!("gantry: the upstream error record of decision {decision} could not be written: {err}");
        }
    });
}

async fn unchecked(state: &AppState, request: Request) -> Result<Next, Refusal> {
    if request.method() != Method::POST || request.uri().path() != CHAT {
        return Err(unknown_route());
    }
    // Without a policy no rule allows it, and it is never forwarded.
    if request.headers().contains_key(CALLER_PROVIDER_KEY) {
        return Err(caller_paid(None, None, Some("-"))
            .err()
            .unwrap_or_else(unknown_route));
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
    let client_ip = client_ip(
        policy,
        request.extensions().get::<ClientAddr>(),
        request.headers(),
    );
    let client = client_ip.map(|ip| ip.to_string());
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    // Holds the person a JWT names, for as long as the record of this request needs it.
    let minted = std::sync::OnceLock::new();
    // The coding tool or SDK that sent it: the request log and the coverage report read it from the record.
    let user_agent = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .map(str::to_owned);
    let mut seen = Seen::default();
    let mut outcome = check(
        state, version, policy, request, &mut seen, &minted, client_ip,
    )
    .await;
    // What the guardrails found, when the rule has any: an empty list says they ran and found nothing.
    let mut found = None;
    let mut guards = seen.rule.map_or(&[][..], |rule| rule.guardrails.as_slice());
    // In observe mode every guardrail runs as in its shadow period: it records what it finds, and neither blocks nor
    // masks. A block it would have made goes on the record as would_refuse.
    let shadowed = observed_guards(policy, guards);
    let observe = shadowed.is_some();
    if let Some(shadowed) = &shadowed {
        guards = shadowed;
    }
    // An audio upload holds no text a guardrail reads. It is forwarded, and its record says the guardrails did not
    // run on it, rather than that they ran and found nothing.
    let on_request = guards.iter().any(|g| g.on.request);
    // QA14-5: a form's text fields (the transcription prompt) are checked; only a form with none is not text.
    let not_text = on_request
        && match &outcome {
            Ok(Next::Forward(parts, bytes, _)) if is_form(&path) => {
                form_texts(&parts.headers, bytes).is_ok_and(|t| t.is_empty())
            }
            // A passthrough call with no body (a GET of a batch) has nothing to read.
            Ok(Next::Forward(_, bytes, _)) if is_passthrough(&path) => bytes.is_empty(),
            _ => is_form(&path),
        };
    // Transforms first, so the tool check and the guardrails read what is really sent.
    let mut transforms = Vec::new();
    let has_transforms = state.transform.is_some()
        || guards
            .iter()
            .any(|g| matches!(g.check, guard::Check::Transform(_)));
    if has_transforms
        && let Ok(Next::Forward(parts, bytes, _)) = &mut outcome
        && let Ok(mut body) = serde_json::from_slice::<serde_json::Value>(bytes)
    {
        let (person, team) = seen
            .person
            .map_or(("", ""), |p| (p.name.as_str(), p.team.as_str()));
        let context = TransformContext {
            decision,
            person,
            team,
            route: &path,
        };
        let (found, refused) = transformed(
            state,
            guards,
            &context,
            gantry_core::transform::Side::Request,
            &mut body,
        )
        .await;
        let changed = found.iter().any(|s| s.outcome == "changed");
        transforms = found;
        match (refused, changed) {
            (Some(refusal), _) => outcome = Err(refusal),
            (None, true) => match serde_json::to_vec(&body) {
                Ok(written) => {
                    parts
                        .headers
                        .insert(header::CONTENT_LENGTH, HeaderValue::from(written.len()));
                    *bytes = Bytes::from(written);
                }
                Err(_) => {
                    outcome = Err(Refusal::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        TRANSFORM_FAILED,
                        "Refused: the transformed request could not be written, so it was not sent. Tell your Gantry admin.",
                    ));
                }
            },
            (None, false) => {}
        }
    }
    // The function tools a request declares are checked against the rule's tools: before the guardrails read it.
    let mut tool_entries = Vec::new();
    if let Some(rule) = seen
        .rule
        .filter(|r| gantry_core::fntools::checked(&r.tools))
    {
        let mut refused = None;
        if let Ok(Next::Forward(parts, bytes, _)) = &mut outcome
            && let Ok(mut body) = serde_json::from_slice::<serde_json::Value>(bytes)
        {
            let verdict = gantry_core::fntools::request(&mut body, &rule.tools, rule.tool_strip);
            tool_entries = verdict.audit;
            if !verdict.refused.is_empty() {
                refused = Some(Refusal::new(
                    StatusCode::FORBIDDEN,
                    gantry_core::fntools::NOT_ALLOWED,
                    gantry_core::fntools::refusal(&rule.name, &verdict.refused, &rule.tools, false),
                ));
            } else if verdict.changed {
                match serde_json::to_vec(&body) {
                    Ok(stripped) => {
                        parts
                            .headers
                            .insert(header::CONTENT_LENGTH, HeaderValue::from(stripped.len()));
                        *bytes = Bytes::from(stripped);
                    }
                    // Never forward the tools that were to be stripped because the stripped body could not be written.
                    Err(_) => {
                        refused = Some(Refusal::new(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            gantry_core::fntools::NOT_ALLOWED,
                            "Refused: the request with its disallowed function tools taken out could not be written, so it was not sent. Tell your Gantry admin.",
                        ));
                    }
                }
            }
        }
        if let Some(refusal) = refused
            && let Err(refusal) = enforce(
                &mut seen,
                refusal,
                policy.observing(rule.shadow_until.as_deref()),
            )
        {
            outcome = Err(refusal);
        }
    }
    outcome = match outcome {
        Ok(Next::Forward(parts, bytes, held)) if on_request && !not_text => {
            let (checked, entries) = guarded(state, guards, &seen, decision, parts, bytes).await;
            if let (true, Some(rule)) = (observe, seen.rule) {
                let blocked = would_block(rule, &entries);
                seen.would_refuse.extend(blocked);
            }
            found = Some(entries);
            checked.map(|(parts, bytes)| Next::Forward(parts, bytes, held))
        }
        other => other,
    };
    if !tool_entries.is_empty() {
        let mut all = tool_entries;
        all.extend(found.take().unwrap_or_default());
        found = Some(all);
    }
    // Limits come after the guardrails: the cache key and the budget's estimate are of the body that is sent, masked
    // if a guardrail masked it, and a request a guardrail blocks is never served from the cache or counted.
    outcome = match outcome {
        Ok(Next::Forward(mut parts, mut bytes, held)) => {
            // Cache breakpoints are placed after the guardrails read the body (they change no text) and before the
            // cache key is taken of what is sent.
            if prompt_cacheable(version, &seen, &parts) {
                if let Some((marked, marks)) = spend::prompt_cache(&bytes) {
                    parts
                        .headers
                        .insert(header::CONTENT_LENGTH, HeaderValue::from(marked.len()));
                    bytes = marked;
                    seen.prompt_cache = Some(marks);
                }
            }
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
    let generates = gemini_native(&path)
        .is_some_and(|(_, _, m)| matches!(m, "generateContent" | "streamGenerateContent"));
    let answer_tools = seen
        .rule
        .filter(|r| gantry_core::fntools::checked(&r.tools))
        .map(|r| (r.name.clone(), r.tools.clone(), r.tool_strip));
    if (!on_answer.is_empty() || answer_tools.is_some() || state.transform.is_some())
        && (matches!(path.as_str(), CHAT | MESSAGES | RESPONSES) || generates)
    {
        let check = AnswerCheck {
            guards: on_answer,
            tools: answer_tools,
            person: seen.person.map(|p| p.name.clone()).unwrap_or_default(),
            team: seen.person.map(|p| p.team.clone()).unwrap_or_default(),
            path: path.clone(),
            buffer_stream: seen.rule.is_some_and(|r| r.limits.buffer_stream),
            stream_every: seen
                .rule
                .and_then(|r| r.limits.check_stream_every)
                .map(|n| n as usize),
            gate: None,
        };
        match &mut outcome {
            Ok(Next::Forward(parts, _, _)) => {
                let mut check = check;
                // An answer the guardrails block or mask is never cached: it waits for their pass.
                check.gate = parts
                    .extensions
                    .get::<spend::Meter>()
                    .and_then(spend::Meter::gate);
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
    state.metrics.inspected(&[], seen.cache);
    if let Some(audit) = &state.audit {
        let entry = Entry {
            id: decision,
            person: seen.person.map(|p| p.name.as_str()),
            team: seen.person.map(|p| p.team.as_str()),
            client: client.as_deref(),
            user_agent: user_agent.as_deref(),
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
        if !transforms.is_empty() {
            record.insert(
                "transforms".into(),
                serde_json::to_value(&transforms).unwrap_or_default(),
            );
        }
        if let Some(found) = &found {
            let found = serde_json::to_value(found).unwrap_or_default();
            state
                .metrics
                .inspected(&gantry_core::insights::kinds(Some(&found)), None);
            record.insert("guardrails".into(), found);
        } else if not_text && outcome.is_ok() {
            let why = if is_passthrough(&path) {
                "not_run: the request has no body"
            } else if path.starts_with("/v1/images/") {
                "not_run: the form holds only an image"
            } else {
                "not_run: the body is audio"
            };
            record.insert("guardrails".into(), why.into());
        }
        if let Some(serde_json::Value::Object(extra)) =
            outcome.as_ref().err().and_then(|r| r.record.as_deref())
        {
            record.extend(extra.clone());
        }
        // Only when set, so records of an install without organizations, customers or tags keep their shape.
        if let Some(org) = seen
            .person
            .map(|p| p.org.as_str())
            .filter(|o| !o.is_empty())
        {
            record.insert("org".into(), org.into());
        }
        if let Some(customer) = &seen.customer {
            record.insert("customer".into(), customer.as_str().into());
        }
        if !seen.tags.is_empty() {
            record.insert("tags".into(), seen.tags.clone().into());
        }
        if let Some(prefix) = &seen.caller_key {
            // That the caller's own key was sent, and which: never the key.
            record.insert("caller_provider_key".into(), true.into());
            record.insert("caller_provider_key_sha256".into(), prefix.as_str().into());
        }
        if let Some(found) = &seen.found {
            record.insert("cache_match".into(), found.matched.into());
            record.insert("cache_scope".into(), found.scope.into());
            record.insert("cache_origin".into(), found.origin.as_str().into());
            if let Some(similarity) = found.similarity {
                record.insert("cache_similarity".into(), similarity.into());
            }
        }
        if let Some(embedding) = &seen.embedding {
            record.insert("cache_embedding".into(), embedding.as_str().into());
        }
        if let Some(marks) = &seen.prompt_cache {
            record.insert("prompt_cache".into(), marks.clone().into());
        }
        if let Some(routing) = &seen.routing {
            record.insert("routing".into(), routing.clone());
        }
        if let Some(rotated) = &seen.rotated {
            record.insert("key_rotated".into(), rotated.clone());
        }
        if let Some(jwt) = seen.person.and_then(|p| p.jwt.as_ref()) {
            record.insert("auth".into(), "jwt".into());
            record.insert("jwt_issuer".into(), jwt.issuer.as_str().into());
            record.insert("jwt_subject".into(), jwt.subject.as_str().into());
        }
        mark_would_refuse(
            &mut record,
            std::mem::take(&mut seen.would_refuse),
            outcome.is_ok(),
        );
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
    let deployed = plan
        .and_then(|p| p.chain.first())
        .map(|hop| hop.model.clone());
    let sent = model;
    let model = deployed.as_deref().unwrap_or(model);
    let applied = policy.applied(
        person,
        rule,
        gantry_core::policy::Context {
            sent,
            model,
            customer: seen.customer.as_deref(),
            tags: &seen.tags,
        },
    );
    let mut ask = spend::Ask {
        applied: &applied,
        customer: seen.customer.as_deref(),
        tags: &seen.tags,
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
        free: parts.uri.path() == COUNT_TOKENS
            || gemini_native(parts.uri.path()).is_some_and(|(_, _, m)| m == "countTokens"),
        caller_paid: plan
            .and_then(|p| p.caller_key.as_ref())
            .map(|_| rule.limits.caller_provider_key == CallerKey::AllowedBudgeted),
        probe: None,
    };
    if let (Some(semantic), Some((partition, text)), Some(credential)) = (
        &rule.limits.semantic,
        spend::semantic_text(&state.spend, &ask),
        seen.credential.as_deref(),
    ) {
        let (vector, id) = embed(state, credential, &semantic.model, &text).await;
        seen.embedding = id;
        // An embedding that failed costs the request its semantic lookup, not its answer: the exact cache and the
        // provider still serve it. The embeddings decision says why it failed.
        ask.probe = vector.map(|vector| spend::Probe {
            partition,
            vector,
            threshold: semantic.threshold,
        });
    }
    match spend::admit(&state.spend, state.audit.as_ref().map(|a| &a.log), ask).await? {
        spend::Admit::Hit(response, admitted, found) => {
            seen.cache = Some("hit");
            seen.hit = Some(admitted);
            seen.found = Some(found);
            // The cache holds the provider's own format, so a translated request gets its hit translated too.
            let plan = parts.extensions.get::<Plan>();
            Ok(Some(
                for_caller(provider.kind, &provider.name, plan, decision, response).await?,
            ))
        }
        spend::Admit::Go(meter, cache, would_refuse) => {
            seen.cache = cache;
            for (refusal, by) in would_refuse {
                observed(seen, refusal, by);
            }
            parts.extensions.insert(meter);
            Ok(None)
        }
    }
}

/// Whether `prompt_cache: auto` may mark this request: a messages request whose every possible destination speaks the
/// messages API, where `cache_control` breakpoints are documented (Anthropic, Bedrock and Vertex AI for Claude). A
/// request translated to chat completions is left alone.
fn prompt_cacheable(version: &Snapshot, seen: &Seen<'_>, parts: &Parts) -> bool {
    if !seen.rule.is_some_and(|r| r.limits.prompt_cache) || parts.uri.path() != MESSAGES {
        return false;
    }
    let messages = |i: &usize| {
        version.providers.get(*i).is_some_and(|p| {
            matches!(
                p.kind,
                Kind::Anthropic | Kind::Bedrock | Kind::VertexAnthropic
            )
        })
    };
    match parts.extensions.get::<Plan>() {
        Some(plan) => {
            !plan.from_messages
                && plan
                    .chain
                    .iter()
                    .chain(&plan.context)
                    .chain(&plan.content)
                    .chain(plan.fallbacks.iter().flatten())
                    .all(|hop| messages(&hop.provider))
                && messages(&plan.provider)
        }
        None => seen.provider.as_ref().is_some_and(messages),
    }
}

/// Boxed, so the request path can make a request of its own through itself.
fn handle_boxed(
    state: AppState,
    request: Request,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>> {
    Box::pin(handle(State(state), request))
}

/// Embeds a request's text for the semantic cache through Gantry's own embeddings route, as the person who sent the
/// request: decided by the policy, guarded, limited, charged and recorded as a request of its own. Returns the
/// vector, if one came back, and the embeddings request's decision ID.
async fn embed(
    state: &AppState,
    credential: &str,
    model: &str,
    text: &str,
) -> (Option<Vec<f32>>, Option<String>) {
    let body = serde_json::json!({ "model": model, "input": text }).to_string();
    let Ok(request) = Request::post(EMBEDDINGS)
        .header(header::AUTHORIZATION, format!("Bearer {credential}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
    else {
        return (None, None);
    };
    let response = handle_boxed(state.clone(), request).await;
    let id = response
        .headers()
        .get(DECISION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    if !response.status().is_success() {
        return (None, id);
    }
    let Ok(bytes) = whole(response.into_body()).await else {
        return (None, id);
    };
    let vector = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|answer| {
            answer["data"][0]["embedding"]
                .as_array()?
                .iter()
                .map(|n| n.as_f64().map(|n| n as f32))
                .collect::<Option<Vec<f32>>>()
        })
        .filter(|v| !v.is_empty());
    (vector, id)
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
    if is_form(parts.uri.path()) {
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
    /// The rule's name, `tools:` list and `tool_action: strip`, when the list names function tools.
    tools: Option<(String, Vec<String>, bool)>,
    person: String,
    team: String,
    path: String,
    /// The rule's `buffer_stream`: a streamed answer is held whole and checked too.
    buffer_stream: bool,
    /// The rule's `check_stream_every`: a streamed answer is checked every this many characters as it comes.
    stream_every: Option<usize>,
    /// A cacheable answer waiting for these guardrails to pass it.
    gate: Option<spend::Gate>,
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
    if let (true, Some(every)) = (streamed, check.stream_every) {
        return Ok(windowed(state, check, decision, response, every));
    }
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
    let mut tools = gantry_core::fntools::Verdict::default();
    let mut tools_refusal = None;
    let mut transforms = Vec::new();
    let mut transforms_refusal: Option<Refusal> = None;
    let mut transformed_answer = false;
    let (mut answer, pointers, texts) = if streamed {
        let slots = stream_texts(&bytes).ok_or_else(unreadable)?;
        let texts = slots.into_iter().map(|(_, text)| text.into()).collect();
        (serde_json::Value::Null, Vec::new(), texts)
    } else {
        let mut answer: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| unreadable())?;
        let context = TransformContext {
            decision,
            person: &check.person,
            team: &check.team,
            route: &check.path,
        };
        let (found, refused) = transformed(
            state,
            &check.guards,
            &context,
            gantry_core::transform::Side::Answer,
            &mut answer,
        )
        .await;
        transformed_answer = found.iter().any(|s| s.outcome == "changed");
        transforms = found;
        if let Some(refusal) = refused {
            transforms_refusal = Some(refusal);
        }
        if let Some((rule, patterns, strip)) = &check.tools {
            tools = gantry_core::fntools::answer(&mut answer, patterns, *strip);
            if !tools.refused.is_empty() {
                tools_refusal = Some(gantry_core::fntools::refusal(
                    rule,
                    &tools.refused,
                    patterns,
                    true,
                ));
            }
        }
        let pointers = answer_texts(&answer);
        // Tool arguments given as a JSON object (Anthropic's tool_use input, Gemini's functionCall args) are read
        // as their JSON text.
        let texts: Vec<serde_json::Value> = pointers
            .iter()
            .map(|p| match answer.pointer(p) {
                Some(serde_json::Value::String(text)) => text.clone().into(),
                Some(other) => other.to_string().into(),
                None => serde_json::Value::Null,
            })
            .collect();
        (answer, pointers, texts)
    };
    let mut verdict = answer_verdict(state, &check, decision, &texts).await;
    let mut all = std::mem::take(&mut tools.audit);
    all.append(&mut verdict.audit);
    verdict.audit = all;
    if let Some(message) = &tools_refusal
        && verdict.blocked.is_none()
    {
        verdict.blocked = Some(guard::Blocked {
            guardrail: "tools".into(),
            message: message.clone(),
        });
    }
    let word = match (&verdict.blocked, verdict.changed || tools.changed) {
        (Some(_), _) => "block",
        (None, true) => "mask",
        (None, false) => "pass",
    };
    // Only a pass that is recorded lets the answer be cached: anything else drops the gate unopened.
    let word = if transforms_refusal.is_some() {
        "block"
    } else {
        word
    };
    let gate = check
        .gate
        .clone()
        .filter(|_| word == "pass" && !transformed_answer);
    if let Some(audit) = &state.audit {
        let mut record = record(
            serde_json::to_value(&verdict.audit).unwrap_or_default(),
            word,
        );
        if !transforms.is_empty() {
            record.insert(
                "transforms".into(),
                serde_json::to_value(&transforms).unwrap_or_default(),
            );
        }
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
    if let Some(gate) = gate {
        gate.passed(true);
    }
    if let Some(refusal) = transforms_refusal {
        return Err(refusal);
    }
    if let (Some(message), Some(blocked)) = (&tools_refusal, &verdict.blocked)
        && blocked.guardrail == "tools"
    {
        return Err(Refusal::new(
            StatusCode::FORBIDDEN,
            gantry_core::fntools::NOT_ALLOWED,
            message.clone(),
        ));
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
    if !verdict.changed && !tools.changed && !transformed_answer {
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
            if slot.is_string() {
                *slot = masked.clone();
            } else if let Some(text) = masked.as_str()
                && text != texts[i].as_str().unwrap_or_default()
            {
                // Masked JSON arguments must still be JSON; arguments that are not are withheld, never sent unmasked.
                *slot = serde_json::from_str(text).map_err(|_| unreadable())?;
            }
        }
    }
    let masked = serde_json::to_vec(&answer).map_err(|_| unreadable())?;
    parts.headers.remove(header::CONTENT_LENGTH);
    Ok(Response::from_parts(parts, Body::from(masked)))
}

/// One whole answer checked by `on: [answer]` guardrails away from a live request (a batch result line, read when
/// the caller downloads the results): the answer to pass on, masked where they masked it, or the message of the
/// guardrail that blocked it; and what they found.
pub(crate) async fn check_answer(
    state: &AppState,
    guards: &[Guardrail],
    person: &str,
    team: &str,
    path: &str,
    decision: &str,
    answer: &serde_json::Value,
) -> (Result<serde_json::Value, String>, Vec<guard::AuditEntry>) {
    let check = AnswerCheck {
        guards: guards.to_vec(),
        tools: None,
        person: person.to_string(),
        team: team.to_string(),
        path: path.to_string(),
        buffer_stream: false,
        stream_every: None,
        gate: None,
    };
    let pointers = answer_texts(answer);
    let texts: Vec<serde_json::Value> = pointers
        .iter()
        .map(|p| answer.pointer(p).cloned().unwrap_or_default())
        .collect();
    let verdict = answer_verdict(state, &check, decision, &texts).await;
    if let Some(blocked) = &verdict.blocked {
        let kinds: Vec<String> = verdict
            .audit
            .iter()
            .filter(|e| e.guardrail == blocked.guardrail && e.action == "block")
            .map(|e| format!("{} ({})", e.kind, e.count))
            .collect();
        let message = format!(
            "guardrail \"{}\" withheld the model's answer, which contained {}. The answer was produced and is counted in usage.",
            blocked.guardrail,
            kinds.join(", ")
        );
        return (Err(message), verdict.audit);
    }
    let mut out = answer.clone();
    if verdict.changed {
        for (i, pointer) in pointers.iter().enumerate() {
            if let (Some(slot), Some(masked)) = (
                out.pointer_mut(pointer),
                verdict.body.pointer(&format!("/messages/{i}/content")),
            ) {
                *slot = masked.clone();
            }
        }
    }
    (Ok(out), verdict.audit)
}

/// The answer guardrails' verdict on the model's texts: the built-in detectors, then each webhook in order until one
/// blocks.
async fn answer_verdict(
    state: &AppState,
    check: &AnswerCheck,
    decision: &str,
    texts: &[serde_json::Value],
) -> guard::Verdict {
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
    verdict
}

/// The end of the last whole event in a stream read so far: just after its blank line.
fn whole_events(bytes: &[u8]) -> usize {
    // Gemini ends its events with CRLF pairs.
    let lf = bytes
        .windows(2)
        .rposition(|w| w == b"\n\n")
        .map_or(0, |at| at + 2);
    let crlf = bytes
        .windows(4)
        .rposition(|w| w == b"\r\n\r\n")
        .map_or(0, |at| at + 4);
    lf.max(crlf)
}

/// The event that ends a stream a guardrail stopped, in the caller's API.
fn blocked_event(path: &str, message: &str) -> String {
    match path {
        _ if gemini_native(path).is_some() => format!(
            "data: {}\n\n",
            gemini_error(StatusCode::FORBIDDEN, guard::BLOCKED_CODE, message, "")
        ),
        MESSAGES => format!(
            "event: error\ndata: {}\n\n",
            serde_json::json!({"type": "error", "error": {"type": "permission_error", "message": message}})
        ),
        RESPONSES => format!(
            "event: error\ndata: {}\n\n",
            serde_json::json!({"type": "error", "code": guard::BLOCKED_CODE, "message": message})
        ),
        _ => format!(
            "data: {}\n\n",
            serde_json::json!({"error": {"message": message, "type": "gantry_error", "code": guard::BLOCKED_CODE}})
        ),
    }
}

/// The checked part of a streamed answer, released to the caller as it is checked.
struct Released(tokio::sync::mpsc::Receiver<Bytes>);

impl http_body::Body for Released {
    type Data = Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        self.0
            .poll_recv(cx)
            .map(|b| b.map(|b| Ok(http_body::Frame::data(b))))
    }
}

/// `check_stream_every`: passes a streamed answer on a window at a time. Each window is held until the answer
/// guardrails have read the whole text so far and let it through, so text a guardrail blocks never reaches the
/// caller: the stream ends there with an error event in the caller's API, and the provider's stream is dropped.
/// A guardrail that would rewrite the text stops it too, since what was sent cannot be rewritten (`gantry check`
/// refuses a masking answer guardrail on such a rule; a webhook may still answer mask).
fn windowed(
    state: &AppState,
    check: AnswerCheck,
    decision: &str,
    response: Response,
    every: usize,
) -> Response {
    let (mut parts, mut body) = response.into_parts();
    parts.headers.remove(header::CONTENT_LENGTH);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(8);
    let (state, decision) = (state.clone(), decision.to_string());
    tokio::spawn(async move {
        let mut seen: Vec<u8> = Vec::new();
        let (mut released, mut checked) = (0usize, 0usize);
        loop {
            let done = match body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        seen.extend_from_slice(&data);
                    }
                    false
                }
                // The provider's stream ended or broke: what is left is checked as the end.
                _ => true,
            };
            let end = if done {
                seen.len()
            } else {
                whole_events(&seen)
            };
            if end > released {
                let texts: Vec<serde_json::Value> = stream_texts(&seen[..end])
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(_, text)| text.into())
                    .collect();
                let chars: usize = texts
                    .iter()
                    .filter_map(|t| t.as_str())
                    .map(|t| t.chars().count())
                    .sum();
                if done || chars >= checked + every {
                    let verdict = answer_verdict(&state, &check, &decision, &texts).await;
                    if verdict.blocked.is_some() || verdict.changed {
                        let name = verdict
                            .blocked
                            .as_ref()
                            .map_or("a guardrail", |b| b.guardrail.as_str())
                            .to_string();
                        if let Some(audit) = &state.audit {
                            let mut record = serde_json::Map::new();
                            record.insert("event".into(), "answer_guardrails".into());
                            record.insert("id".into(), decision.as_str().into());
                            record.insert("time".into(), gantry_core::audit::timestamp().into());
                            record.insert("verdict".into(), "block".into());
                            record.insert(
                                "guardrails".into(),
                                serde_json::to_value(&verdict.audit).unwrap_or_default(),
                            );
                            record.insert("stopped_after_chars".into(), checked.into());
                            audit.log.append_record_then(&record, |_| {});
                        }
                        let message = format!(
                            "Refused: guardrail \"{name}\" stopped the model's answer partway. What came before was checked and sent; the rest was withheld. Ask in another way, or ask a Gantry admin about the guardrail."
                        );
                        let _ = tx
                            .send(Bytes::from(blocked_event(&check.path, &message)))
                            .await;
                        return;
                    }
                    checked = chars;
                    if tx
                        .send(Bytes::copy_from_slice(&seen[released..end]))
                        .await
                        .is_err()
                    {
                        // The caller left: the provider's stream is dropped with the body.
                        return;
                    }
                    released = end;
                }
            }
            if done {
                if let Some(audit) = &state.audit {
                    let mut record = serde_json::Map::new();
                    record.insert("event".into(), "answer_guardrails".into());
                    record.insert("id".into(), decision.as_str().into());
                    record.insert("time".into(), gantry_core::audit::timestamp().into());
                    record.insert("verdict".into(), "pass".into());
                    record.insert("guardrails".into(), serde_json::Value::Array(Vec::new()));
                    audit.log.append_record_then(&record, |_| {});
                }
                return;
            }
        }
    });
    Response::from_parts(parts, Body::new(Released(rx)))
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
    // Gemini: each candidate's text parts build one text, its thoughts another.
    for (i, candidate) in event["candidates"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
    {
        let n = candidate["index"].as_u64().unwrap_or(i as u64);
        for (j, part) in candidate["content"]["parts"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            if part["text"].is_string() {
                let slot = if part["thought"] == true { "gt" } else { "g" };
                found.push((
                    format!("{slot}{n}"),
                    format!("/candidates/{i}/content/parts/{j}/text"),
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
/// and tool call arguments), messages (`content[].text` and tool_use `input`), Responses (`output[].content[].text`
/// and function_call `arguments`) and Gemini (`candidates[].content.parts[].text` and functionCall `args`). A
/// pointer may lead to a JSON object (tool input or args), which the guardrails read as its JSON text.
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
            if block["type"] == "tool_use" && block["input"].is_object() {
                pointers.push(format!("/content/{i}/input"));
            }
        }
    }
    for (i, candidate) in list(&answer["candidates"]).iter().enumerate() {
        for (j, part) in list(&candidate["content"]["parts"]).iter().enumerate() {
            if part["text"].is_string() {
                pointers.push(format!("/candidates/{i}/content/parts/{j}/text"));
            }
        }
    }
    for (i, item) in list(&answer["output"]).iter().enumerate() {
        for (j, part) in list(&item["content"]).iter().enumerate() {
            if part["text"].is_string() {
                pointers.push(format!("/output/{i}/content/{j}/text"));
            }
        }
        if item["type"] == "function_call" && item["arguments"].is_string() {
            pointers.push(format!("/output/{i}/arguments"));
        }
    }
    for (i, candidate) in list(&answer["candidates"]).iter().enumerate() {
        for (j, part) in list(&candidate["content"]["parts"]).iter().enumerate() {
            if part["text"].is_string() {
                pointers.push(format!("/candidates/{i}/content/parts/{j}/text"));
            }
            if part["functionCall"]["args"].is_object() {
                pointers.push(format!(
                    "/candidates/{i}/content/parts/{j}/functionCall/args"
                ));
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
    // A Gemini Content: the text of each part, a tool call's arguments, a tool's result, and code and its output.
    fn content(value: &Value, at: &str, out: &mut Vec<String>) {
        for (j, part) in value["parts"].as_array().into_iter().flatten().enumerate() {
            let at = format!("{at}/parts/{j}");
            for field in [
                "text",
                "functionCall/args",
                "functionResponse/response",
                "executableCode/code",
                "codeExecutionResult/output",
            ] {
                if let Some(found) = part.pointer(&format!("/{field}")) {
                    strings(found, format!("{at}/{field}"), out);
                }
            }
        }
    }
    // The Contents of a Gemini request: generateContent's, countTokens' (also inside generateContentRequest), and
    // the embedding methods'.
    fn contents(body: &Value, at: &str, out: &mut Vec<String>) {
        for (i, item) in body["contents"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            content(item, &format!("{at}/contents/{i}"), out);
        }
        for field in ["systemInstruction", "system_instruction", "content"] {
            if body[field].is_object() {
                content(&body[field], &format!("{at}/{field}"), out);
            }
        }
        if body["generateContentRequest"].is_object() {
            contents(
                &body["generateContentRequest"],
                &format!("{at}/generateContentRequest"),
                out,
            );
        }
        for (i, item) in body["requests"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            contents(item, &format!("{at}/requests/{i}"), out);
        }
    }
    let mut pointers = Vec::new();
    match path {
        // A provider's own API has no shape Gantry knows: every string in the body is text.
        _ if is_passthrough(path) => strings(body, String::new(), &mut pointers),
        _ if gemini_native(path).is_some() => contents(body, "", &mut pointers),
        _ if path.starts_with("/v1/videos") => match &body["prompt"] {
            Value::String(_) => pointers.push("/prompt".into()),
            Value::Null => {}
            _ => return Err("prompt".into()),
        },
        IMAGES => match &body["prompt"] {
            Value::String(_) => pointers.push("/prompt".into()),
            Value::Null => {}
            _ => return Err("prompt".into()),
        },
        // A completion's prompt is a string or a list of strings; one given as token IDs cannot be read as text.
        COMPLETIONS => {
            for field in ["prompt", "suffix"] {
                match &body[field] {
                    Value::String(_) => pointers.push(format!("/{field}")),
                    Value::Null => {}
                    Value::Array(items) if items.iter().all(Value::is_string) => {
                        pointers.extend((0..items.len()).map(|i| format!("/{field}/{i}")));
                    }
                    _ => return Err(format!("{field} (send it as text, not token IDs)")),
                }
            }
        }
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
/// The refusal code when a transform fails closed or writes what Gantry cannot send.
const TRANSFORM_FAILED: &str = "transform_failed";

/// Runs the binary's transform, then each `transform` guardrail of the rule that reads this side, in order, on `body`.
/// Returns what each did, and the refusal when one failed closed. A transform in its shadow period (or observe mode)
/// is asked and recorded as `shadow`, and its body is not used.
async fn transformed(
    state: &AppState,
    guards: &[Guardrail],
    context: &TransformContext<'_>,
    side: gantry_core::transform::Side,
    body: &mut serde_json::Value,
) -> (Vec<gantry_core::transform::Summary>, Option<Refusal>) {
    use gantry_core::transform::{self as t, Side};
    let mut out = Vec::new();
    let refuse = |name: &str| {
        Refusal::new(
            StatusCode::BAD_GATEWAY,
            TRANSFORM_FAILED,
            format!(
                "Refused: transform \"{name}\" could not rewrite this {}, and it is set to fail closed, so nothing was sent on. Try again later; if it keeps failing, ask an administrator to check the transform.",
                if side == Side::Request {
                    "request"
                } else {
                    "answer"
                }
            ),
        )
    };
    let valid = |before: &serde_json::Value, after: &serde_json::Value| match side {
        Side::Request => t::request_ok(before, after),
        Side::Answer if after.is_object() => Ok(()),
        Side::Answer => Err("the transform's body is not a JSON object".into()),
    };
    if let Some(own) = &state.transform {
        let before = body.clone();
        let result = match side {
            Side::Request => own.request(context, body),
            Side::Answer => own.answer(context, body),
        }
        .and_then(|()| valid(&before, body));
        if let Err(cause) = result {
            eprintln!(
                "gantry: decision {}: the binary's transform: {cause}",
                context.decision
            );
            *body = before;
            return (out, Some(refuse("extension")));
        }
        out.push(t::summary("extension", side, &before, body));
    }
    for guard in guards {
        let guard::Check::Transform(hook) = &guard.check else {
            continue;
        };
        let reads = match side {
            Side::Request => guard.on.request,
            Side::Answer => guard.on.answer,
        };
        if !reads {
            continue;
        }
        let sent = t::TransformRequest {
            decision_id: context.decision,
            person: context.person,
            team: context.team,
            route: context.route,
            side,
            body,
        };
        let answer = async {
            let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
            for (name, variable) in &hook.headers_env {
                let value = std::env::var(variable)
                    .map_err(|_| format!("the environment variable {variable} is not set"))?;
                headers.push((name.clone(), value));
            }
            let call = gantry_core::vendors::Call {
                url: hook.url.clone(),
                headers,
                body: serde_json::to_vec(&sent).map_err(|e| e.to_string())?,
            };
            let bytes = tokio::time::timeout(hook.timeout, post(state, call))
                .await
                .map_err(|_| format!("gave no answer within {} ms", hook.timeout.as_millis()))??;
            let answer: t::TransformAnswer = serde_json::from_slice(&bytes)
                .map_err(|e| format!("the answer is not {{\"body\": ...}}: {e}"))?;
            valid(body, &answer.body)?;
            Ok::<_, String>(answer.body)
        }
        .await;
        match answer {
            Ok(new) => {
                let mut summary = t::summary(&guard.name, side, body, &new);
                if guard.shadowing() {
                    summary.outcome = guard::SHADOW;
                } else {
                    *body = new;
                }
                out.push(summary);
            }
            Err(cause) => {
                eprintln!(
                    "gantry: decision {}: transform \"{}\" at {}: {cause}",
                    context.decision, guard.name, hook.url
                );
                out.push(t::Summary {
                    transform: guard.name.clone(),
                    side,
                    outcome: "skipped",
                    changes: Vec::new(),
                    more: 0,
                });
                if hook.on_failure == guard::OnFailure::FailClosed && !guard.shadowing() {
                    return (out, Some(refuse(&guard.name)));
                }
            }
        }
    }
    (out, None)
}

pub(crate) async fn ask(
    state: &AppState,
    action: guard::Action,
    hook: &guard::Webhook,
    sent: &guard::WebhookRequest,
) -> Result<guard::WebhookAnswer, String> {
    // ponytail: credentials are read from the environment on each call. Start and reload refuse a policy whose
    // variables are unset, and a running process's environment does not change, so this is only a lookup.
    let env = |variable: &str| gantry_core::secrets::var(variable);
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
    let mut creator = parts.extensions.remove::<batch::Creator>();
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
                    // Proxy and CDN headers: the caller's address stays here, and a provider behind Cloudflare
                    // refuses a request that carries Cloudflare's own headers (error 1000).
                    || name.starts_with("cf-")
                    || name.starts_with("x-forwarded-")
                    || ["forwarded", "via", "cdn-loop", "x-real-ip", "true-client-ip"].contains(&name)
                    // The many names other proxies use for the caller's address (Fastly, Azure, Envoy, App Engine).
                    || name.ends_with("-ip")
                    || name.contains("client-ip")
                    || name.contains("clientip")
                    || name.contains("remote-addr")
                    || name.starts_with("x-envoy-")
                    || name.starts_with("x-original-forwarded")
                    // Gantry reads every answer (usage, guardrails, translation), so the provider must send plain
                    // bytes: a compressed answer cannot be read, and its tokens and cost would go unrecorded.
                    || name == "accept-encoding"
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
    let route = match plan.as_ref() {
        Some(Plan {
            passthrough: Some(native),
            ..
        }) => native.clone(),
        Some(Plan {
            sent_route: Some(route),
            ..
        }) => (*route).to_string(),
        _ => parts
            .uri
            .path_and_query()
            .map_or("/", |pq| pq.as_str())
            .to_string(),
    };
    let mut chain = plan.as_ref().map_or_else(
        || vec![Hop::plain(first, String::new())],
        |p| p.chain.clone(),
    );
    // A provider's own fallback takes the same model, and its fallback's fallback after it (A, then B, then C), each
    // provider once; an alias has its deployments and fallbacks instead. A passthrough path is that provider's own
    // API: another provider may not have it.
    if plan
        .as_ref()
        .is_some_and(|p| p.cooldown.is_none() && p.passthrough.is_none())
    {
        let model = chain
            .first()
            .map(|hop| hop.model.clone())
            .unwrap_or_default();
        let mut at = provider;
        while let Some(next) = at
            .fallback
            .as_ref()
            .and_then(|name| version.providers.iter().position(|p| p.name == *name))
            .filter(|next| !chain.iter().any(|hop| hop.provider == *next))
        {
            chain.push(Hop::plain(next, model.clone()));
            at = &version.providers[next];
        }
    }
    let mut attempts: Vec<Attempt> = Vec::new();
    let mut sent = None;
    let try_chain = Tries {
        state,
        version,
        parts: &parts,
        bytes: &bytes,
        route: &route,
        plan: plan.as_ref(),
    };
    let mut tried = try_chain
        .run(&chain, &mut attempts, &mut sent, &mut admitted)
        .await?;
    // A named fallback for a prompt too long for the model's context, or one refused under the provider's content
    // policy. The error answer is read whole only when the alias names a fallback for it.
    if let Some(plan) = plan
        .as_ref()
        .filter(|p| !p.context.is_empty() || !p.content.is_empty())
        && let Some(Ok(response)) = tried.last.as_mut()
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
            tried = try_chain
                .run(next, &mut attempts, &mut sent, &mut admitted)
                .await?;
        }
    }
    // An alias's fallbacks, in turn, while the last answer is a failure its `fallback_on` names.
    if let Some(plan) = plan.as_ref() {
        for next in &plan.fallbacks {
            let Some(why) = failure_of(&mut tried.last, &plan.fallback_on).await? else {
                break;
            };
            if !plan.fallback_on.contains(&why) {
                break;
            }
            tried = try_chain
                .run(next, &mut attempts, &mut sent, &mut admitted)
                .await?;
        }
    }
    let Tried {
        last,
        served,
        busy,
        view,
    } = tried;
    // An answer from a provider of the other API is not kept in the cache: a hit is handed back as the first
    // deployment's provider answers.
    if let (Some(admitted), Some(_)) = (admitted.as_mut(), &view) {
        admitted.not_cached();
    }
    let plan_used = view.as_ref().or(plan.as_ref());
    let (served, served_model) = served;
    let answered = Instant::now();
    if attempts.len() > 1 {
        record_attempts(state, decision, &attempts);
    }
    let response = match last {
        Some(Ok(response)) => response,
        // No provider answered: the upstream error record names the last one tried and how many tries there were,
        // so the request log and provider_errors alerts count it whether or not it was retried.
        Some(Err(mut failure)) => {
            failure.record = Some(Box::new(serde_json::json!({
                "provider": attempts.last().map(|a| a.who.as_str()).unwrap_or_default(),
                "tries": attempts.len(),
            })));
            return Err(failure);
        }
        None => return Err(unknown_route()),
    };
    let response = native(
        &state.client,
        &version.providers[served],
        plan_used,
        &served_model,
        parts.uri.path(),
        &bytes,
        response,
    )
    .await?;
    let price = version
        .policy
        .as_ref()
        .and_then(|p| gantry_core::usage::price_for(&served_model, p.prices()));
    // Usage is read in the provider's format (Bedrock's already decoded) before any translation, and settled with
    // the provider that answered, a fallback included.
    let response = match admitted {
        Some(mut admitted) => {
            admitted.served_by(
                &version.providers[served].name,
                &served_model,
                price.clone(),
            );
            if let Some(creator) = creator.as_mut() {
                creator.defer(&mut admitted);
            }
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
        plan_used,
        decision,
        response,
    )
    .await?;
    strip_hop_by_hop(response.headers_mut());
    let served_name = &version.providers[served].name;
    let named = [
        ("x-gantry-provider", served_name.clone()),
        ("x-gantry-model", served_model.clone()),
        (
            "x-gantry-deployment",
            alias::label(served_name, &served_model),
        ),
        ("x-gantry-attempts", attempts.len().max(1).to_string()),
    ];
    for (name, value) in named {
        if let Ok(value) = HeaderValue::from_str(&value)
            && !served_model.is_empty()
        {
            response
                .headers_mut()
                .insert(HeaderName::from_static(name), value);
        }
    }
    // Time from the request reaching Gantry's handler to it leaving for the provider, plus the time to hand the
    // answer back: identifying, deciding, recording. It does not cover reading the request off the socket or
    // streaming the answer, so the bench reads it as a breakdown and gates on what the client sees.
    let own = (sent.unwrap_or(answered) - arrived) + answered.elapsed();
    state.metrics.overhead(own);
    state
        .metrics
        .first_byte(&version.providers[served].name, arrived.elapsed());
    if let Ok(value) =
        HeaderValue::from_str(&format!("gantry;dur={:.3}", own.as_secs_f64() * 1000.0))
    {
        // Appended, not inserted: the provider's own timings stay.
        response
            .headers_mut()
            .append(HeaderName::from_static("server-timing"), value);
    }
    let mut response = match price {
        Some(price) => with_cost(response, &price, bytes.len()).await,
        None => response,
    };
    if let Some(check) = answer_check {
        response.extensions_mut().insert(check);
    }
    if let Some(mut creator) = creator {
        creator.served_by(
            &version.providers[served].name,
            plan.as_ref().is_some_and(|p| p.from_responses),
        );
        response.extensions_mut().insert(creator);
    }
    Ok(response)
}

/// The most of an answer read before its headers go, to name its exact cost in `x-gantry-cost-usd`.
const COST_READ_BYTES: u64 = MIB as u64;

/// The answer with `x-gantry-cost-usd`. A whole (not streamed) answer whose length is known, up to
/// `COST_READ_BYTES`, is read first, so the header is its cost by the usage it reports. A stream, an answer of
/// unknown length or a larger one is not held back: the header is then the prompt's cost alone, estimated as its bytes over four in tokens, and the exact cost is in the usage
/// record.
async fn with_cost(
    response: Response,
    price: &gantry_core::usage::Price,
    prompt: usize,
) -> Response {
    let (parts, mut body) = response.into_parts();
    let mut usd = None;
    let mut read: Vec<Bytes> = Vec::new();
    let streamed = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/event-stream"));
    let mut whole = false;
    // Only an answer that says its length is read: one that does not may be held open (a long poll, a slow
    // answer), and reading it would hold back its headers and end its holds on parallel limits early.
    let sized = http_body::Body::size_hint(&body)
        .exact()
        .is_some_and(|n| n <= COST_READ_BYTES);
    if !streamed && sized {
        let mut size = 0u64;
        loop {
            match body.frame().await {
                None => {
                    whole = true;
                    break;
                }
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        size += data.len() as u64;
                        read.push(data);
                    }
                    if size > COST_READ_BYTES {
                        break;
                    }
                }
                Some(Err(err)) => {
                    // The answer broke off: the caller gets what was read, then the same break.
                    eprintln!(
                        "gantry: the provider's answer broke off while it was read for its cost: {err}"
                    );
                    let failed = futures_util::stream::iter(
                        read.into_iter().map(Ok).chain(std::iter::once(Err(err))),
                    );
                    return Response::from_parts(parts, Body::from_stream(failed));
                }
            }
        }
        if whole {
            let bytes: Bytes = read.concat().into();
            usd = gantry_core::usage::Usage::from_body(&bytes).map(|u| price.cost_usd(&u));
            read = vec![bytes];
        }
    }
    let usd = usd.unwrap_or_else(|| {
        let tokens = u64::try_from(prompt / 4).unwrap_or(u64::MAX);
        price.cost_usd(&gantry_core::usage::Usage {
            input: tokens,
            ..gantry_core::usage::Usage::default()
        })
    });
    let mut response = if streamed {
        Response::from_parts(parts, body)
    } else if whole {
        Response::from_parts(parts, Body::from(read.concat()))
    } else {
        use futures_util::StreamExt;
        let rest =
            futures_util::stream::iter(read.into_iter().map(Ok)).chain(body.into_data_stream());
        Response::from_parts(parts, Body::from_stream(rest))
    };
    let text = format!("{usd:.9}");
    let text = text.trim_end_matches('0').trim_end_matches('.');
    if let Ok(value) = HeaderValue::from_str(text) {
        response
            .headers_mut()
            .insert(HeaderName::from_static("x-gantry-cost-usd"), value);
    }
    response
}

/// One attempt, for the attempts record: the deployment (an alias's) or provider tried, how it answered, and the
/// fingerprint of the pool key it was sent with.
struct Attempt {
    who: String,
    outcome: String,
    key: Option<String>,
}

/// Which failure `fallback_on` would name in the last outcome of a chain, if it is one. An error answer is read
/// whole only when a context window or content policy refusal is among those `fallback_on` names.
async fn failure_of(
    last: &mut Option<Result<Response, Refusal>>,
    on: &[gantry_core::config::FallbackOn],
) -> Result<Option<gantry_core::config::FallbackOn>, Refusal> {
    use gantry_core::config::FallbackOn;
    Ok(match last {
        None => None,
        Some(Err(refusal)) => match refusal.code {
            "upstream_timeout" => Some(FallbackOn::Timeout),
            "upstream_unreachable" | "upstream_failed" => Some(FallbackOn::Unreachable),
            _ => None,
        },
        Some(Ok(response)) => {
            let status = response.status();
            if status == StatusCode::TOO_MANY_REQUESTS {
                Some(FallbackOn::RateLimit)
            } else if status.is_server_error() {
                Some(FallbackOn::ServerError)
            } else if status.is_client_error()
                && on
                    .iter()
                    .any(|o| matches!(o, FallbackOn::ContextWindow | FallbackOn::ContentPolicy))
            {
                let body = whole(std::mem::take(response.body_mut())).await?;
                let why = match alias::refused(&body) {
                    Some(alias::Refused::ContextWindow) => Some(FallbackOn::ContextWindow),
                    Some(alias::Refused::ContentPolicy) => Some(FallbackOn::ContentPolicy),
                    None => None,
                };
                *response.body_mut() = Body::from(body);
                why
            } else {
                None
            }
        }
    })
}

/// The time limits of one attempt, from its deployment, alias, provider and the gateway, in that order.
#[derive(Clone, Copy, Debug)]
struct Limits {
    connect: Duration,
    first_byte: Duration,
    total: Duration,
    idle: Duration,
}

impl AppState {
    fn limits(&self, provider: &Upstream, hop: &Hop) -> Limits {
        let set = hop.timeouts.or(provider.timeouts);
        let ms =
            |value: Option<u64>, default: Duration| value.map_or(default, Duration::from_millis);
        let total = ms(set.total_ms, self.timeouts.total);
        Limits {
            connect: ms(set.connect_ms, self.timeouts.connect),
            first_byte: ms(set.first_byte_ms, self.timeouts.first_byte).min(total),
            total,
            idle: ms(set.idle_ms, self.timeouts.idle),
        }
    }

    /// The pooled client whose connections give up after `connect`. One per distinct setting, made on first use.
    fn client_for(&self, connect: Duration) -> Client<HttpsConnector<HttpConnector>, Body> {
        if connect == self.timeouts.connect {
            return self.client.clone();
        }
        let mut clients = self
            .clients
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        clients
            .entry(connect)
            .or_insert_with(|| client_with(connect))
            .clone()
    }
}

/// A client whose connections go through `proxy` (HTTP CONNECT), giving up after `connect`.
fn proxied_with(connect: Duration, proxy: &Proxy) -> Proxied {
    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(connect));
    connector.enforce_http(false);
    let mut tunnel =
        hyper_util::client::legacy::connect::proxy::Tunnel::new(proxy.uri.clone(), connector);
    if let Some(auth) = &proxy.auth {
        tunnel = tunnel.with_auth(auth.clone());
    }
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .wrap_connector(tunnel);
    Client::builder(TokioExecutor::new()).build(connector)
}

/// A client with its own connection pool, whose connections give up after `connect`.
fn client_with(connect: Duration) -> Client<HttpsConnector<HttpConnector>, Body> {
    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(connect));
    connector.enforce_http(false);
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .wrap_connector(connector);
    Client::builder(TokioExecutor::new()).build(connector)
}

/// "30 seconds", or "250 ms" for a limit that is not whole seconds.
fn wait_text(limit: Duration) -> String {
    if limit.subsec_millis() == 0 {
        format!("{} seconds", limit.as_secs())
    } else {
        format!("{} ms", limit.as_millis())
    }
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

/// The last outcome of a chain, which deployment gave it (provider position and model), for an alias the count
/// that keeps that deployment busy, and, when that deployment took the request translated differently from the
/// first (a fallback of the other API), the plan it was sent and is answered by.
struct Tried {
    last: Option<Result<Response, Refusal>>,
    served: (usize, String),
    busy: Option<alias::Busy>,
    view: Option<Plan>,
}

impl Tries<'_> {
    /// How this request goes to `provider`: as planned, or, for a provider of the other API (or a Google one behind
    /// a plain chat provider), its own plan, its body translated, and its route. `None` keeps the plan as it is.
    fn view(&self, provider: &Upstream) -> Result<Option<(Plan, Bytes, String)>, Refusal> {
        let Some(plan) = self.plan.filter(|p| p.passthrough.is_none()) else {
            return Ok(None);
        };
        let path = self.parts.uri.path();
        if path != CHAT && path != MESSAGES {
            return Ok(None);
        }
        let caller = if path == MESSAGES {
            Kind::Anthropic
        } else {
            Kind::OpenAi
        };
        let api = provider.kind.api();
        let translated =
            caller == Kind::OpenAi && (api == Kind::Anthropic || provider.kind.translates_chat());
        let from_messages = caller == Kind::Anthropic && api == Kind::OpenAi;
        if plan.body_api == api
            && plan.translated.is_some() == translated
            && plan.from_messages == from_messages
        {
            return Ok(None);
        }
        let bytes = match (plan.body_api == api, api) {
            (true, _) => self.bytes.clone(),
            (false, Kind::Anthropic) => to_messages(self.bytes)?.0,
            (false, _) => to_chat_request(self.bytes)?,
        };
        let mut view = plan.clone();
        view.translated = if translated {
            Some(plan.include_usage)
        } else if from_messages && provider.kind.translates_chat() {
            Some(true)
        } else {
            None
        };
        view.from_messages = from_messages;
        view.body_api = api;
        let route = if api == Kind::Anthropic {
            MESSAGES
        } else {
            CHAT
        };
        view.sent_route = Some(route);
        Ok(Some((view, bytes, route.to_string())))
    }

    /// Tries each deployment of `chain` in turn, each up to its provider's retries, until one answers with
    /// something other than a connection failure, a timeout, a 429 or a 5xx. A provider with a key pool moves to its
    /// next key on a 401, 403 or 429 before any of that counts.
    async fn run(
        &self,
        chain: &[Hop],
        attempts: &mut Vec<Attempt>,
        sent: &mut Option<Instant>,
        admitted: &mut Option<spend::Admitted>,
    ) -> Result<Tried, Refusal> {
        let mut tried = Tried {
            last: None,
            served: chain
                .first()
                .map(|hop| (hop.provider, hop.model.clone()))
                .unwrap_or_default(),
            busy: None,
            view: None,
        };
        let caller = self
            .plan
            .filter(|p| p.caller_key.is_some())
            .map(|p| p.provider);
        'providers: for hop in chain {
            // The caller's key is theirs for the provider they asked for: it never goes to a fallback elsewhere.
            if caller.is_some_and(|first| first != hop.provider) {
                continue;
            }
            let provider = &self.version.providers[hop.provider];
            let label = alias::label(&provider.name, &hop.model);
            let who = if hop.cooldown.is_some() {
                label.clone()
            } else {
                provider.name.clone()
            };
            // A body that cannot be carried to this provider's API skips it, recorded, and the chain goes on.
            let (view, bytes, route) = match self.view(provider) {
                Ok(Some((view, bytes, route))) => (Some(view), bytes, route),
                Ok(None) => (None, self.bytes.clone(), self.route.to_string()),
                Err(refusal) => {
                    attempts.push(Attempt {
                        who,
                        outcome: refusal.code.to_string(),
                        key: None,
                    });
                    tried.last.get_or_insert(Err(refusal));
                    continue;
                }
            };
            let plan = view.as_ref().or(self.plan);
            let limits = self.state.limits(provider, hop);
            let ids: Vec<String> = provider.pool.iter().map(|(_, id)| id.clone()).collect();
            for retry in 0..=provider.retries {
                if retry > 0 {
                    // ponytail: 200 ms doubling (100 << retry, from retry 1) with no jitter and no Retry-After; add
                    // both if providers ask for it.
                    tokio::time::sleep(Duration::from_millis(100 << retry.min(5))).await;
                }
                loop {
                    let key = if plan.is_some_and(|p| p.caller_key.is_some()) {
                        None
                    } else {
                        self.state.pool.key(
                            &provider.name,
                            &ids,
                            &provider.key_weights,
                            provider.least_used_key,
                        )
                    };
                    let request =
                        outbound(provider, self.parts, &bytes, &route, plan, &hop.model, key)?;
                    let started = Instant::now();
                    sent.get_or_insert(started);
                    let tokens = u64::try_from(bytes.len() / 4).unwrap_or(u64::MAX);
                    let busy = hop.cooldown.map(|_| self.state.pool.busy(&label, tokens));
                    // Dropped while waiting here (the caller hung up), the request is charged: the provider has it.
                    if let Some(admitted) = admitted.as_mut() {
                        admitted.forwarded(true);
                    }
                    let outcome = attempt_within(self.state, provider, request, &limits).await;
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
                    let key_id = key.and_then(|k| ids.get(k).cloned());
                    attempts.push(Attempt {
                        who: who.clone(),
                        outcome: outcome_word.clone(),
                        key: key_id.clone(),
                    });
                    // A pool key refused (401, 403) or out of quota (429) is set aside, and the next key is tried at
                    // once, before retries, cooldowns and fallbacks count it.
                    if let (Some(k), Some(id), Ok(response)) = (key, &key_id, &outcome) {
                        let retry_after = response
                            .headers()
                            .get(header::RETRY_AFTER)
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.trim().parse::<u64>().ok());
                        if self.state.pool.key_answered(
                            &provider.name,
                            &ids,
                            k,
                            response.status(),
                            retry_after,
                            provider.key_quarantine,
                        ) {
                            self.state
                                .metrics
                                .key_switched(&provider.name, &outcome_word);
                            eprintln!(
                                "gantry: provider \"{}\" answered {outcome_word} to key {id}; it is set aside and the next key of the pool is tried.",
                                provider.name
                            );
                            continue;
                        }
                    }
                    if let Some(cooldown) = hop.cooldown {
                        if let Ok(response) = &outcome {
                            self.state.pool.rate_limits(&label, response.headers());
                        }
                        if again {
                            self.state.pool.failed(&label, cooldown);
                        } else {
                            self.state.pool.answered(&label);
                            self.state.pool.observed(&label, started.elapsed());
                        }
                    }
                    // The rest of the answer is held to the total and idle limits; one that stalls counts as a
                    // failure of its deployment.
                    let stall = hop
                        .cooldown
                        .map(|cooldown| (self.state.pool.clone(), label.clone(), cooldown));
                    let outcome = outcome.map(|response| {
                        response.map(|body| {
                            Body::new(Deadline::new(body, started, &limits, stall, &provider.name))
                        })
                    });
                    tried = Tried {
                        last: Some(outcome),
                        served: (hop.provider, hop.model.clone()),
                        busy,
                        view: view.clone(),
                    };
                    if !again {
                        break 'providers;
                    }
                    break;
                }
            }
        }
        Ok(tried)
    }
}

/// An answer's body held to its total and idle limits. When one passes, the body ends in an error (the caller's
/// stream breaks, as a provider's broken stream would) and, for an alias's deployment, the deployment cools down.
struct Deadline {
    inner: Body,
    idle: Duration,
    until: tokio::time::Instant,
    timer: std::pin::Pin<Box<tokio::time::Sleep>>,
    stall: Option<(Arc<alias::Pool>, String, Duration)>,
    provider: String,
    done: bool,
}

impl Deadline {
    fn new(
        inner: Body,
        started: Instant,
        limits: &Limits,
        stall: Option<(Arc<alias::Pool>, String, Duration)>,
        provider: &str,
    ) -> Self {
        let until = tokio::time::Instant::from_std(started + limits.total);
        let next = until.min(tokio::time::Instant::now() + limits.idle);
        Deadline {
            inner,
            idle: limits.idle,
            until,
            timer: Box::pin(tokio::time::sleep_until(next)),
            stall,
            provider: provider.to_string(),
            done: false,
        }
    }
}

impl http_body::Body for Deadline {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, axum::Error>>> {
        use std::task::Poll;
        if self.done {
            return Poll::Ready(None);
        }
        if let Poll::Ready(frame) = std::pin::Pin::new(&mut self.inner).poll_frame(cx) {
            if frame.is_none() {
                self.done = true;
            } else {
                let next = self.until.min(tokio::time::Instant::now() + self.idle);
                self.timer.as_mut().reset(next);
            }
            return Poll::Ready(frame);
        }
        if self.timer.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        self.done = true;
        let which = if tokio::time::Instant::now() >= self.until {
            "its total time limit"
        } else {
            "its idle limit between two pieces of the answer"
        };
        eprintln!(
            "gantry: provider \"{}\" went past {which}; the answer was cut off.",
            self.provider
        );
        if let Some((pool, label, cooldown)) = self.stall.take() {
            pool.failed(&label, cooldown);
        }
        Poll::Ready(Some(Err(axum::Error::new(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("the provider went past {which}"),
        )))))
    }

    fn is_end_stream(&self) -> bool {
        self.done || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
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
    pool_key: Option<usize>,
) -> Result<axum::http::Request<Body>, Refusal> {
    // The body names the model the caller sent. Sent to another, it names that one.
    let rewritten;
    let native = gemini_native(route.split('?').next().unwrap_or_default());
    let bytes = match plan {
        // A Gemini API body has its model in the path; one it also names (countTokens' generateContentRequest) was
        // checked to be the path's, so it is sent as the same deployment.
        Some(plan) if plan.model != model && native.is_some() => {
            rewritten = gemini_with_model(bytes, model);
            &rewritten
        }
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
    let passthrough = plan.is_some_and(|p| p.passthrough.is_some());
    // What the request asks of the provider, whatever path its own API gives that.
    let op = [EMBEDDINGS, RERANK, COUNT_TOKENS, RESPONSES]
        .into_iter()
        .find(|r| route.split('?').next() == Some(*r))
        .unwrap_or(CHAT);
    let version = provider.api_version.as_deref().unwrap_or_default();
    let encoded = |name: &str| sigv4::uri_encode(name, false);
    let (url, body) = match provider.kind {
        // A provider's own API, as sent: signed below for Bedrock, with the Google token for Vertex AI, whose
        // native paths start at the host (/v1/projects/...).
        _ if passthrough && provider.kind.google_auth() => {
            let origin = provider
                .url
                .split_once("://")
                .map(|(scheme, rest)| {
                    format!("{scheme}://{}", rest.split('/').next().unwrap_or_default())
                })
                .unwrap_or_default();
            (format!("{origin}{route}"), bytes.clone())
        }
        // Each path segment encoded as the AWS SDKs send it (a model ID's colon as %3A), then signed below.
        _ if passthrough && provider.kind.aws() => {
            let (path, query) = route
                .split_once('?')
                .map_or((route, None), |(p, q)| (p, Some(q)));
            let path: Vec<String> = path
                .split('/')
                .map(|seg| sigv4::uri_encode(seg, false))
                .collect();
            let query = query.map(|q| format!("?{q}")).unwrap_or_default();
            // Batch inference jobs are Bedrock's control plane, at bedrock.<region> rather than bedrock-runtime.
            let base = if route.starts_with("/model-invocation-job") {
                provider
                    .url
                    .replacen("://bedrock-runtime.", "://bedrock.", 1)
            } else {
                provider.url.clone()
            };
            (format!("{base}{}{query}", path.join("/")), bytes.clone())
        }
        _ if passthrough => (
            gantry_core::config::join(&provider.url, route),
            bytes.clone(),
        ),
        Kind::OpenAi | Kind::Anthropic | Kind::VertexOpenAi => (
            gantry_core::config::join(&provider.url, route),
            bytes.clone(),
        ),
        // Google's own API, as sent: only the provider's base, the model it knows, and events for a stream.
        Kind::Gemini | Kind::Vertex if native.is_some() => {
            let (version, _, method) = native.unwrap_or_default();
            let has_path = provider
                .url
                .split_once("://")
                .is_some_and(|(_, rest)| rest.contains('/'));
            let base = if has_path {
                provider.url.clone()
            } else {
                format!("{}/{version}", provider.url)
            };
            let method = if method == "streamGenerateContent" {
                "streamGenerateContent?alt=sse"
            } else {
                method
            };
            (
                format!("{base}/models/{}:{method}", sigv4::uri_encode(model, false)),
                bytes.clone(),
            )
        }
        // The container takes the chat body as sent; the endpoint stands for the model.
        Kind::Sagemaker => {
            let stream = serde_json::from_slice::<serde_json::Value>(bytes)
                .is_ok_and(|b| b["stream"] == true);
            let action = if stream {
                "invocations-response-stream"
            } else {
                "invocations"
            };
            (
                format!("{}/{}/{action}", provider.url, encoded(mapped()?)),
                bytes.clone(),
            )
        }
        Kind::Replicate => {
            let id = provider
                .upstream_models
                .get(model)
                .map_or(model, String::as_str);
            let (body, _) = native_body(provider, model, bytes, op)?;
            if serde_json::from_slice::<serde_json::Value>(&body).is_ok_and(|b| b["stream"] == true)
            {
                // Created at once and read from its stream URL (`native`); cancelled by Replicate if it runs longer
                // than a stream should, so a caller who left does not keep it billing.
                headers.insert("cancel-after", HeaderValue::from_static("300s"));
            } else {
                // Waited for, and cancelled by Replicate if it runs longer, so nothing keeps billing after the answer.
                headers.insert("prefer", HeaderValue::from_static("wait=60"));
                headers.insert("cancel-after", HeaderValue::from_static("60s"));
            }
            let url = match id.split_once(':') {
                Some(_) => format!("{}/predictions", provider.url),
                None => {
                    let path: Vec<String> = id.split('/').map(&encoded).collect();
                    format!("{}/models/{}/predictions", provider.url, path.join("/"))
                }
            };
            (url, body)
        }
        Kind::Azure if azure_v1(&provider.url) => {
            // The v1 API takes OpenAI's paths and the deployment as the model; images and audio are in its preview.
            let deployment = mapped()?;
            let path = route.split('?').next().unwrap_or(route);
            let tail = path.strip_prefix("/v1").unwrap_or(path);
            let preview = if matches!(path, IMAGES | TRANSCRIPTIONS | SPEECH) {
                "?api-version=preview"
            } else {
                ""
            };
            let content_type = parts
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok());
            (
                format!("{}{tail}{preview}", provider.url.trim_end_matches('/')),
                alias::with_model(content_type, bytes, deployment),
            )
        }
        Kind::Azure => {
            let deployment = mapped()?;
            let on_deployment = |what: &str| {
                format!(
                    "{}/openai/deployments/{}/{what}?api-version={version}",
                    provider.url,
                    encoded(deployment)
                )
            };
            match (route.split('?').next().unwrap_or(route), op) {
                // The Responses API names the deployment in the body's model.
                (_, RESPONSES) => (
                    format!("{}/openai/responses?api-version={version}", provider.url),
                    alias::with_model(Some("application/json"), bytes, deployment),
                ),
                (_, EMBEDDINGS) => (on_deployment("embeddings"), bytes.clone()),
                (IMAGES, _) => (on_deployment("images/generations"), bytes.clone()),
                (TRANSCRIPTIONS, _) => (on_deployment("audio/transcriptions"), bytes.clone()),
                (SPEECH, _) => (on_deployment("audio/speech"), bytes.clone()),
                (COMPLETIONS, _) => (on_deployment("completions"), bytes.clone()),
                _ => (on_deployment("chat/completions"), bytes.clone()),
            }
        }
        Kind::Gemini | Kind::Vertex => {
            let (body, stream) = native_body(provider, model, bytes, op)?;
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
            let url = match (op, provider.kind) {
                (COUNT_TOKENS, _) => format!("{base}/models/{}:countTokens", encoded(model)),
                (EMBEDDINGS, Kind::Gemini) => {
                    format!("{base}/models/{}:batchEmbedContents", encoded(model))
                }
                (EMBEDDINGS, _) => format!("{base}/models/{}:predict", encoded(model)),
                (RERANK, _) => {
                    let project = vertex_project(&provider.url).unwrap_or_default();
                    // The Ranking API is Discovery Engine's, at its own host; a private or test URL keeps its host.
                    let host = if provider.url.contains("aiplatform.googleapis.com") {
                        "https://discoveryengine.googleapis.com".to_string()
                    } else {
                        base.split("/v1/").next().unwrap_or_default().to_string()
                    };
                    format!(
                        "{host}/v1/projects/{project}/locations/global/rankingConfigs/default_ranking_config:rank"
                    )
                }
                _ if stream => format!(
                    "{base}/models/{}:streamGenerateContent?alt=sse",
                    encoded(model)
                ),
                _ => format!("{base}/models/{}:generateContent", encoded(model)),
            };
            (url, body)
        }
        Kind::VertexAnthropic if op == COUNT_TOKENS => {
            // Vertex AI counts Claude's tokens at one endpoint for every model, named in the body.
            let mut body = json_of(bytes, "a messages request")?;
            body["anthropic_version"] = "vertex-2023-10-16".into();
            (
                format!("{}/models/count-tokens:rawPredict", provider.url),
                Bytes::from(body.to_string()),
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
                format!("{}/models/{}:{method}", provider.url, encoded(model)),
                body,
            )
        }
        Kind::Bedrock if op == COUNT_TOKENS => {
            let (body, _) = bedrock_body(bytes, &headers)?;
            let count = serde_json::json!({"input": {"invokeModel": {"body": eventstream::base64_encode(&body)}}});
            (
                format!("{}/model/{}/count-tokens", provider.url, encoded(mapped()?)),
                Bytes::from(count.to_string()),
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
                format!("{}/model/{}/{action}", provider.url, encoded(mapped()?)),
                body,
            )
        }
        Kind::BedrockConverse => {
            let (body, stream) = native_body(provider, model, bytes, op)?;
            let action = match (op, stream) {
                (EMBEDDINGS, _) => "invoke",
                (_, true) => "converse-stream",
                _ => "converse",
            };
            (
                format!("{}/model/{}/{action}", provider.url, encoded(mapped()?)),
                body,
            )
        }
        Kind::Cohere => match op {
            RERANK => (format!("{}/rerank", provider.url), bytes.clone()),
            EMBEDDINGS => (
                format!("{}/embed", provider.url),
                native_body(provider, model, bytes, op)?.0,
            ),
            _ => (
                format!("{}/chat", provider.url),
                native_body(provider, model, bytes, op)?.0,
            ),
        },
        Kind::Watsonx => {
            let version = Some(version)
                .filter(|v| !v.is_empty())
                .unwrap_or("2024-05-31");
            let (body, stream) = native_body(provider, model, bytes, op)?;
            let action = match (op, stream) {
                (EMBEDDINGS, _) => "text/embeddings",
                (_, true) => "text/chat_stream",
                _ => "text/chat",
            };
            (format!("{}/{action}?version={version}", provider.url), body)
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
    let key = match plan.and_then(|p| p.caller_key.as_ref()) {
        Some(caller) => Some(key_header(provider.kind, caller).map_err(|_| {
            Refusal::new(
                StatusCode::BAD_REQUEST,
                "caller_provider_key_invalid",
                "Refused: x-gantry-provider-key holds a character that cannot go in an HTTP header. Send your provider key alone.",
            )
        })?),
        None => match pool_key.and_then(|k| provider.pool.get(k)) {
            Some((header, _)) => Some(header.clone()),
            None => provider.key.clone(),
        },
    };
    if let Some((name, value)) = key {
        headers.insert(name, value);
    }
    // The caller's own key, when a rule allows it, goes in place of Gantry's token too.
    if let (Some(token), None) = (&provider.google, plan.and_then(|p| p.caller_key.as_ref())) {
        headers.insert(header::AUTHORIZATION, token.get());
    }
    // The provider's own headers (headers_env), before Bedrock signs, so its signature covers them.
    for (name, value) in &provider.headers {
        headers.insert(name.clone(), value.clone());
    }
    if provider.kind.aws() {
        sign_for_bedrock(provider, &parts.method, &uri, &body, &mut headers)?;
    }
    // The caller's own key, when a rule allows it, goes in place of the signature.
    if let (Some(signer), None) = (&provider.oci, plan.and_then(|p| p.caller_key.as_ref())) {
        signer
            .sign(&parts.method, &uri, &body, &mut headers)
            .map_err(|why| {
                Refusal::new(
                    StatusCode::BAD_GATEWAY,
                    "upstream_failed",
                    format!("Gantry could not sign the request for OCI: {why}. Tell your Gantry admin to check the provider's oci_signing key."),
                )
            })?;
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
    method: &Method,
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
    let (Some(credentials), Some(region), Some(host)) = (
        provider.aws.as_ref().map(cloud::Live::get),
        &provider.region,
        uri.authority(),
    ) else {
        return Err(failed());
    };
    // The betas went into the body. The other Anthropic headers mean nothing to Bedrock.
    headers.remove("anthropic-beta");
    headers.remove("anthropic-version");
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    // ponytail: a passthrough query is signed with its pairs sorted as the caller encoded them; one encoded other
    // than SigV4 encodes fails at Bedrock with a signature error naming the canonical request.
    let mut pairs: Vec<&str> = uri
        .query()
        .unwrap_or_default()
        .split('&')
        .filter(|p| !p.is_empty())
        .collect();
    pairs.sort_unstable();
    let query: Vec<String> = pairs
        .iter()
        .map(|p| {
            if p.contains('=') {
                (*p).to_string()
            } else {
                format!("{p}=")
            }
        })
        .collect();
    let signed = sigv4::sign(
        &credentials,
        region,
        if provider.kind == Kind::Sagemaker {
            "sagemaker"
        } else {
            "bedrock"
        },
        &sigv4::Request {
            method: method.as_str(),
            path: uri.path(),
            query: &query.join("&"),
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

/// Checks each deployment that has `probe:` on its turn, so one that is down cools down before a caller is sent to
/// it, and one that is back is used again. The cooldown is the alias's, shared through the store when there is one,
/// so every replica passes over a deployment any replica found down.
fn spawn_probes(state: std::sync::Weak<AppState>) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    runtime.spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            let Some(state) = state.upgrade() else {
                return;
            };
            let version = state.version();
            for alias in &version.aliases {
                for deployment in &alias.deployments {
                    let Some(probe) = &deployment.probe else {
                        continue;
                    };
                    let label = alias::label(&deployment.provider, &deployment.model);
                    if !state
                        .pool
                        .probe_due(&label, Duration::from_secs(probe.every_seconds))
                    {
                        continue;
                    }
                    let Some(provider) = version
                        .providers
                        .iter()
                        .position(|p| p.name == deployment.provider)
                    else {
                        continue;
                    };
                    // Marked as sent now, so a slow probe is not sent again on the next tick.
                    state.pool.probed(&label, true, "sent".into());
                    let hop = Hop {
                        provider,
                        model: deployment.model.clone(),
                        timeouts: deployment.timeouts.or(alias.timeouts),
                        cooldown: Some(Duration::from_secs(alias.cooldown_seconds)),
                    };
                    let (state, version, chat) = (state.clone(), version.clone(), probe.chat);
                    let every = Duration::from_secs(probe.every_seconds);
                    tokio::spawn(async move {
                        // With a store, one gateway probes each deployment at a time; the others take its
                        // outcome from the shared cooldowns.
                        if let Some(store) = state.pool.store() {
                            match store
                                .probe_lease(label.clone(), every + PROBE_LEASE_SLACK)
                                .await
                            {
                                Ok(true) => {}
                                Ok(false) => {
                                    state.pool.probed(
                                        &label,
                                        true,
                                        "probed by another gateway".into(),
                                    );
                                    return;
                                }
                                Err(err) => {
                                    eprintln!(
                                        "gantry: the health probe of {label} is skipped: {err}."
                                    );
                                    return;
                                }
                            }
                        }
                        probe_once(&state, &version, &hop, chat).await;
                    });
                }
            }
        }
    });
}

/// How much longer than its interval a gateway holds a deployment's probe lease: another takes it over once the
/// holder has missed a probe by this much.
const PROBE_LEASE_SLACK: Duration = Duration::from_secs(5);

/// The workload health probes are recorded and charged as.
pub const PROBE_WORKLOAD: &str = "gantry-probe";

/// One health probe of a deployment: its provider's model list, or a one-token request. Any answer under 500 other
/// than 429 means it is up (a 400 is still an answer); no answer, a 429 or a 5xx means it is down.
async fn probe_once(state: &AppState, version: &Snapshot, hop: &Hop, chat: bool) {
    let Some(provider) = version.providers.get(hop.provider) else {
        return;
    };
    let label = alias::label(&provider.name, &hop.model);
    let (method, route, body) = if !chat {
        (Method::GET, MODELS.to_string(), Bytes::new())
    } else if provider.kind.api() == Kind::Anthropic {
        (
            Method::POST,
            MESSAGES.to_string(),
            Bytes::from(
                serde_json::json!({"model": hop.model, "max_tokens": 1, "messages": [{"role": "user", "content": "ping"}]})
                    .to_string(),
            ),
        )
    } else {
        (
            Method::POST,
            CHAT.to_string(),
            Bytes::from(
                serde_json::json!({"model": hop.model, "max_tokens": 1, "messages": [{"role": "user", "content": "ping"}]})
                    .to_string(),
            ),
        )
    };
    let Ok(request) = axum::http::Request::builder()
        .method(method)
        .uri(route.as_str())
        .header(header::CONTENT_TYPE, "application/json")
        .header("anthropic-version", "2023-06-01")
        .body(())
    else {
        return;
    };
    let (parts, ()) = request.into_parts();
    let ids: Vec<String> = provider.pool.iter().map(|(_, id)| id.clone()).collect();
    let key = state.pool.key(
        &provider.name,
        &ids,
        &provider.key_weights,
        provider.least_used_key,
    );
    let outcome = match outbound(provider, &parts, &body, &route, None, &hop.model, key) {
        Ok(request) => attempt_within(state, provider, request, &state.limits(provider, hop)).await,
        Err(refusal) => Err(refusal),
    };
    let (up, word) = match &outcome {
        Ok(response) => {
            let status = response.status();
            (
                status != StatusCode::TOO_MANY_REQUESTS && !status.is_server_error(),
                status.as_u16().to_string(),
            )
        }
        Err(refusal) => (false, refusal.code.to_string()),
    };
    // A chat probe is a billed request: its usage is read off the answer and charged to the gantry-probe scope.
    let usage = match outcome {
        Ok(response) if chat => http_body_util::BodyExt::collect(response.into_body())
            .await
            .ok()
            .and_then(|body| gantry_core::usage::Usage::from_body(&body.to_bytes())),
        _ => None,
    };
    record_probe(
        state, version, provider, &route, &hop.model, &word, up, usage,
    )
    .await;
    state.pool.probed(&label, up, word.clone());
    if let Some(cooldown) = hop.cooldown {
        if up {
            state.pool.answered(&label);
        } else {
            eprintln!(
                "gantry: the health probe of {label} got {word}; it is passed over until it answers again."
            );
            state.pool.failed(&label, cooldown);
        }
    }
}

/// A probe in the audit log, as the workload `gantry-probe`: a decision record, and for a chat probe a usage record
/// whose cost is charged to the `gantry-probe` person and team scopes, so it shows on the spend page and counts
/// against a budget set for it.
#[allow(clippy::too_many_arguments)]
async fn record_probe(
    state: &AppState,
    version: &Snapshot,
    provider: &Upstream,
    route: &str,
    model: &str,
    outcome: &str,
    up: bool,
    usage: Option<gantry_core::usage::Usage>,
) {
    let Some(audit) = &state.audit else {
        return;
    };
    let decision = id::random_hex(16);
    let mut record = gantry_core::audit::record(&gantry_core::audit::Entry {
        id: &decision,
        person: Some(PROBE_WORKLOAD),
        team: Some(PROBE_WORKLOAD),
        user_agent: Some(PROBE_WORKLOAD),
        method: if route == MODELS { "GET" } else { "POST" },
        path: route,
        model: Some(model),
        allowed: true,
        provider: &provider.name,
        policy_sha256: &version.policy_sha256,
        keys_sha256: &version.keys_sha256,
        ..Default::default()
    });
    record.insert("workload".into(), PROBE_WORKLOAD.into());
    record.insert(
        "probe".into(),
        serde_json::json!({ "outcome": outcome, "up": up }),
    );
    let _ = audit.log.append_record(&record);
    if route == MODELS {
        return;
    }
    let price = version
        .policy
        .as_ref()
        .and_then(|p| gantry_core::usage::price_for(model, p.prices()));
    let (_, usage_record) = spend::charge(
        &state.spend,
        spend::Line {
            decision: &decision,
            person: PROBE_WORKLOAD,
            team: PROBE_WORKLOAD,
            key: "",
            org: "",
            customer: None,
            tags: &[],
            counted: &[],
            model,
            provider: &provider.name,
            version: (&version.policy_sha256, &version.keys_sha256),
            price,
            usage,
            share: 1.0,
            unreported: 0.0,
            succeeded: up,
            extra: serde_json::Map::new(),
        },
    );
    let _ = audit.log.append_record(&usage_record);
}

/// One attempt with the provider's own time limits, for requests that are not an alias's (batches).
async fn attempt(
    state: &AppState,
    provider: &Upstream,
    request: axum::http::Request<Body>,
) -> Result<Response, Refusal> {
    let limits = state.limits(provider, &Hop::default());
    attempt_within(state, provider, request, &limits).await
}

/// One attempt: sends the request and waits for the provider to start answering, within `limits`.
async fn attempt_within(
    state: &AppState,
    provider: &Upstream,
    request: axum::http::Request<Body>,
    limits: &Limits,
) -> Result<Response, Refusal> {
    let upstream = &provider.url;
    let outcome = match &provider.proxy {
        None => {
            let client = state.client_for(limits.connect);
            tokio::time::timeout(limits.first_byte, client.request(request)).await
        }
        Some(proxy) => {
            let client = state
                .proxied
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entry((limits.connect, proxy.id.clone()))
                .or_insert_with(|| proxied_with(limits.connect, proxy))
                .clone();
            tokio::time::timeout(limits.first_byte, client.request(request)).await
        }
    };
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
            let wait = wait_text(limits.first_byte);
            eprintln!("gantry: the provider at {upstream} sent nothing for {wait}");
            Err(Refusal::new(
                StatusCode::GATEWAY_TIMEOUT,
                "upstream_timeout",
                format!(
                    "The provider did not start answering within {wait}. Try again. If it keeps happening, tell your Gantry admin."
                ),
            ))
        }
    }
}

/// Writes which providers were tried and how each answered, after the request record that let it through.
/// That record is written before anything is forwarded, so it cannot know; this one follows it, with the same ID.
fn record_attempts(state: &AppState, decision: &str, attempts: &[Attempt]) {
    let Some(audit) = &state.audit else {
        return;
    };
    let list: Vec<serde_json::Value> = attempts
        .iter()
        .map(|a| {
            let mut entry = serde_json::json!({ "provider": a.who, "outcome": a.outcome });
            if let Some(key) = &a.key {
                entry["key"] = key.as_str().into();
            }
            entry
        })
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

/// Bedrock's event streams and errors as server-sent events and Anthropic-shaped errors, and the embeddings, rerank
/// and token count answers of providers that translate them in the caller's format, so that usage is read from one
/// shape and everything after this reads the same. A passthrough answer is the provider's own and left as it is.
async fn native(
    client: &Client<HttpsConnector<HttpConnector>, Body>,
    provider: &Upstream,
    plan: Option<&Plan>,
    model: &str,
    path: &str,
    request: &[u8],
    mut response: Response,
) -> Result<Response, Refusal> {
    if plan.is_some_and(|p| p.passthrough.is_some()) {
        return Ok(response);
    }
    if provider.kind == Kind::Sagemaker {
        if response.status().is_success()
            && is_type(&response, "application/vnd.amazon.eventstream")
        {
            let mut sse = eventstream::PayloadToSse::default();
            return Ok(map_body(
                response,
                "text/event-stream",
                move |input| match input {
                    Some(bytes) => sse.feed(bytes),
                    None => sse.finish(),
                },
            ));
        }
        return Ok(response);
    }
    if provider.kind == Kind::Replicate && response.status().is_success() {
        // A prediction becomes the chat answer here, before usage is read: whole, or as the stream asked for.
        let body = whole(std::mem::take(response.body_mut())).await?;
        let prediction: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        let created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let asked: serde_json::Value = serde_json::from_slice(request).unwrap_or_default();
        if asked["stream"] == true {
            let key = match plan.and_then(|p| p.caller_key.as_ref()) {
                Some(caller) => key_header(provider.kind, caller).ok(),
                None => provider.key.clone(),
            };
            return replicate_stream(client, provider, key, &prediction, model, created, response)
                .await;
        }
        let finished = matches!(
            prediction["status"].as_str(),
            Some("starting" | "processing")
        );
        let completion = gantry_core::replicate::prediction_to_openai(&prediction, model, created)
            .map_err(|err| {
                Refusal::new(
                    if finished {
                        StatusCode::GATEWAY_TIMEOUT
                    } else {
                        StatusCode::BAD_GATEWAY
                    },
                    "upstream_failed",
                    err.to_string(),
                )
            })?;
        return Ok(json_body(response, completion.to_string().into_bytes()));
    }
    if provider.kind.aws() {
        if !response.status().is_success() {
            let error_type = response
                .headers()
                .get("x-amzn-errortype")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let body = whole(std::mem::take(response.body_mut())).await?;
            let error = eventstream::anthropic_error(&error_type, &body);
            return Ok(json_body(response, error.to_string().into_bytes()));
        }
        if is_type(&response, "application/vnd.amazon.eventstream") {
            if provider.kind == Kind::BedrockConverse {
                let mut sse = eventstream::ConverseToSse::default();
                return Ok(map_body(
                    response,
                    "text/event-stream",
                    move |input| match input {
                        Some(bytes) => sse.feed(bytes),
                        None => sse.finish(),
                    },
                ));
            }
            let mut sse = eventstream::BedrockToSse::default();
            return Ok(map_body(
                response,
                "text/event-stream",
                move |input| match input {
                    Some(bytes) => sse.feed(bytes),
                    None => sse.finish(),
                },
            ));
        }
    }
    if !response.status().is_success() {
        return Ok(response);
    }
    use gantry_core::embed::Target;
    let target = match (path, provider.kind) {
        (EMBEDDINGS, Kind::Gemini) => Some(Target::Gemini),
        (EMBEDDINGS, Kind::Vertex) => Some(Target::Vertex),
        (EMBEDDINGS, Kind::Cohere) => Some(Target::Cohere),
        (EMBEDDINGS, Kind::Watsonx) => Some(Target::Watsonx),
        (EMBEDDINGS, Kind::BedrockConverse) => Target::bedrock(
            provider
                .upstream_models
                .get(model)
                .map_or(model, String::as_str),
        ),
        _ => None,
    };
    let reshaped = match (path, provider.kind, target) {
        (EMBEDDINGS, _, Some(target)) => {
            // Bedrock counts Cohere's tokens in a header; the Gemini API counts none, so its texts' bytes stand in.
            let tokens = match target {
                Target::Gemini => Some(gantry_core::embed::bytes_of(
                    &serde_json::from_slice(request).unwrap_or_default(),
                )),
                _ => response
                    .headers()
                    .get("x-amzn-bedrock-input-token-count")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse().ok()),
            };
            let body = whole(std::mem::take(response.body_mut())).await?;
            let answer = serde_json::from_slice(&body).unwrap_or_default();
            gantry_core::embed::answer(target, model, &answer, tokens).map_err(|err| {
                Refusal::new(
                    StatusCode::BAD_GATEWAY,
                    "untranslatable",
                    format!("The provider's embeddings answer could not be translated: {err}"),
                )
            })?
        }
        (RERANK, Kind::Vertex, _) => {
            let body = whole(std::mem::take(response.body_mut())).await?;
            let answer: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            let results: Vec<serde_json::Value> = answer["records"]
                .as_array()
                .map_or(&[][..], Vec::as_slice)
                .iter()
                .filter_map(|r| {
                    Some(serde_json::json!({
                        "index": r["id"].as_str()?.parse::<u64>().ok()?,
                        "relevance_score": r["score"],
                    }))
                })
                .collect();
            serde_json::json!({"object": "list", "model": model, "results": results})
        }
        (COUNT_TOKENS, Kind::Gemini | Kind::Vertex, _) => {
            let body = whole(std::mem::take(response.body_mut())).await?;
            let answer: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            serde_json::json!({"input_tokens": answer["totalTokens"]})
        }
        (COUNT_TOKENS, Kind::Bedrock, _) => {
            let body = whole(std::mem::take(response.body_mut())).await?;
            let answer: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            serde_json::json!({"input_tokens": answer["inputTokens"]})
        }
        _ => return Ok(response),
    };
    Ok(json_body(response, reshaped.to_string().into_bytes()))
}

/// A streaming prediction read from its `urls.stream` (server-sent events) and passed on as chat chunks while the
/// model writes. When the stream is done, the prediction (`urls.get`) is read once for its token counts, which end
/// the stream as its usage chunk. The key goes only to Replicate's own hosts (or the provider's).
async fn replicate_stream(
    client: &Client<HttpsConnector<HttpConnector>, Body>,
    provider: &Upstream,
    key: Option<(HeaderName, HeaderValue)>,
    prediction: &serde_json::Value,
    model: &str,
    created: u64,
    mut response: Response,
) -> Result<Response, Refusal> {
    let failed =
        |message: String| Refusal::new(StatusCode::BAD_GATEWAY, "upstream_failed", message);
    let host_of = |url: &str| {
        url.parse::<Uri>()
            .ok()
            .and_then(|u| u.host().map(String::from))
    };
    let ours = host_of(&provider.url);
    let trusted = |url: &str| {
        host_of(url).is_some_and(|host| {
            host == "replicate.com"
                || host.ends_with(".replicate.com")
                || Some(&host) == ours.as_ref()
        })
    };
    let Some(stream_url) = prediction["urls"]["stream"].as_str().filter(|u| trusted(u)) else {
        return Err(failed(format!(
            "Replicate gave no stream URL for model \"{model}\": the model does not stream. Send the request without \"stream\": true."
        )));
    };
    let get_url = prediction["urls"]["get"]
        .as_str()
        .filter(|u| trusted(u))
        .map(String::from);
    let request = |url: &str, accept: &'static str| {
        let mut request = axum::http::Request::new(Body::empty());
        *request.uri_mut() = url
            .parse::<Uri>()
            .map_err(|_| failed("Replicate gave a URL that cannot be read.".into()))?;
        request
            .headers_mut()
            .insert(header::ACCEPT, HeaderValue::from_static(accept));
        if let Some((name, value)) = &key {
            request.headers_mut().insert(name.clone(), value.clone());
        }
        Ok::<_, Refusal>(request)
    };
    let events = client
        .request(request(stream_url, "text/event-stream")?)
        .await
        .map_err(|err| {
            failed(format!(
                "Replicate's stream could not be reached: {err}. Try again."
            ))
        })?;
    if !events.status().is_success() {
        return Err(failed(format!(
            "Replicate's stream answered {}. Try again.",
            events.status()
        )));
    }
    let metrics = get_url.map(|url| (client.clone(), request(&url, "application/json")));
    let converter = gantry_core::replicate::PredictionStream::new(
        prediction["id"].as_str().unwrap_or("replicate"),
        model,
        created,
    );
    let state = (Some(Body::new(events.into_body())), converter, metrics);
    let body =
        futures_util::stream::unfold(state, |(upstream, mut converter, metrics)| async move {
            let mut upstream = upstream?;
            let mut pending = Vec::new();
            while let Some(Ok(frame)) = upstream.frame().await {
                let Ok(data) = frame.into_data() else {
                    continue;
                };
                let out = converter.feed(&data);
                // Replicate keeps the connection open a while after `done`: the answer ends here, with
                // the text that came in the same frame.
                if converter.done() {
                    pending = out;
                    break;
                }
                if !out.is_empty() {
                    return Some((
                        Ok::<_, std::convert::Infallible>(Bytes::from(out)),
                        (Some(upstream), converter, metrics),
                    ));
                }
            }
            let mut usage = None;
            if converter.done() {
                if let Some((client, Ok(request))) = metrics {
                    if let Ok(answer) = client.request(request).await {
                        if let Ok(body) = answer.into_body().collect().await {
                            let prediction: serde_json::Value =
                                serde_json::from_slice(&body.to_bytes()).unwrap_or_default();
                            usage = gantry_core::replicate::usage(&prediction);
                        }
                    }
                }
            }
            let mut last = pending;
            last.extend(converter.finish(usage));
            Some((Ok(Bytes::from(last)), (None, converter, None)))
        });
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    response.headers_mut().remove(header::CONTENT_LENGTH);
    *response.body_mut() = Body::from_stream(body);
    Ok(response)
}

/// A Replicate stream for a client that did not ask for usage: the usage chunk Gantry metered is dropped.
fn without_usage_chunk(response: Response) -> Response {
    let mut line = Vec::new();
    map_body(response, "text/event-stream", move |input| {
        let mut out = Vec::new();
        let keep = |line: &[u8], out: &mut Vec<u8>| {
            let usage_only = line.starts_with(b"data: {")
                && serde_json::from_slice::<serde_json::Value>(&line[6..])
                    .is_ok_and(|e| e["usage"].is_object() && e["choices"] == serde_json::json!([]));
            if !usage_only {
                out.extend_from_slice(line);
                out.push(b'\n');
            }
        };
        match input {
            Some(mut bytes) => {
                while let Some(end) = bytes.iter().position(|&b| b == b'\n') {
                    line.extend_from_slice(&bytes[..end]);
                    bytes = &bytes[end + 1..];
                    keep(&std::mem::take(&mut line), &mut out);
                }
                line.extend_from_slice(bytes);
            }
            None if !line.is_empty() => keep(&std::mem::take(&mut line), &mut out),
            None => {}
        }
        Ok(out)
    })
}

/// An answer in the provider's own format (by the `kind` of provider that gave it: messages, Gemini, Converse,
/// Cohere, watsonx) as a chat completions one, when the request was translated. `include_usage` is set then: whether
/// the client asked for usage in its stream. `model` is the caller's name for the model, for answers that carry none.
async fn to_chat(
    kind: Kind,
    include_usage: Option<bool>,
    decision: &str,
    model: &str,
    mut response: Response,
) -> Result<Response, Refusal> {
    // Gemini may send no responseId; a strict chat client refuses "id": null, and the decision ID is unique.
    let fallback_id = format!("chatcmpl-{decision}");
    // A Replicate prediction was made a chat answer already (`native`), its stream with the usage it metered.
    if kind == Kind::Replicate {
        return Ok(
            if include_usage == Some(false) && is_type(&response, "text/event-stream") {
                without_usage_chunk(response)
            } else {
                response
            },
        );
    }
    let Some(include_usage) = include_usage else {
        return Ok(response);
    };
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    if response.status().is_success() && is_type(&response, "text/event-stream") {
        type Feed =
            Box<dyn FnMut(Option<&[u8]>) -> Result<Vec<u8>, translate::TranslateError> + Send>;
        let mut step: Feed = match kind {
            _ if kind.google() => {
                let mut s =
                    gemini::GeminiToOpenAiStream::new(include_usage, created).with_id(fallback_id);
                Box::new(move |input| match input {
                    Some(bytes) => s.feed(bytes),
                    None => s.finish(),
                })
            }
            Kind::BedrockConverse => {
                let mut s = gantry_core::converse::ConverseToOpenAiStream::new(
                    include_usage,
                    fallback_id,
                    model.to_string(),
                    created,
                );
                Box::new(move |input| match input {
                    Some(bytes) => s.feed(bytes),
                    None => s.finish(),
                })
            }
            Kind::Cohere => {
                let mut s = gantry_core::cohere::CohereToOpenAiStream::new(
                    include_usage,
                    model.to_string(),
                    created,
                );
                Box::new(move |input| match input {
                    Some(bytes) => s.feed(bytes),
                    None => s.finish(),
                })
            }
            Kind::Watsonx => {
                let mut s = gantry_core::cohere::WatsonxToOpenAiStream::new(include_usage);
                Box::new(move |input| match input {
                    Some(bytes) => s.feed(bytes),
                    None => s.finish(),
                })
            }
            _ => {
                let mut s = translate::AnthropicToOpenAiStream::new(include_usage, created);
                Box::new(move |input| match input {
                    Some(bytes) => s.feed(bytes),
                    None => s.finish(),
                })
            }
        };
        return Ok(map_body(response, "text/event-stream", move |input| {
            step(input).map_err(|err| err.to_string())
        }));
    }
    let body = whole(std::mem::take(response.body_mut())).await?;
    let answer: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    let out = if response.status().is_success() {
        let translated = match kind {
            _ if kind.google() => gemini::gemini_to_openai_response(&answer, created),
            Kind::BedrockConverse => gantry_core::converse::converse_to_openai_response(
                &answer,
                &fallback_id,
                model,
                created,
            ),
            Kind::Cohere => gantry_core::cohere::cohere_to_openai_response(&answer, model, created),
            Kind::Watsonx => {
                let mut answer = answer.clone();
                gantry_core::cohere::watsonx_to_openai(&mut answer, false);
                Ok(answer)
            }
            _ => translate::anthropic_to_openai_response(&answer, created),
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
        // An error in the shape OpenAI's clients read, with the provider's own type and message: Anthropic, Bedrock
        // and Gemini put it in error.message, Cohere in message, watsonx in errors[0].message.
        let error = &answer["error"];
        let message = error["message"]
            .as_str()
            .or(answer["message"].as_str())
            .or(answer["errors"][0]["message"].as_str())
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

/// A chat completions answer as a Responses one, streamed or whole. An error stays in OpenAI's error shape, which
/// Responses clients read too.
async fn to_responses(decision: &str, mut response: Response) -> Result<Response, Refusal> {
    let id = format!("resp_{decision}");
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    if !response.status().is_success() {
        return Ok(response);
    }
    if is_type(&response, "text/event-stream") {
        let mut stream = gantry_core::responses::ChatToResponsesStream::new(id, created);
        return Ok(map_body(response, "text/event-stream", move |input| {
            match input {
                Some(bytes) => stream.feed(bytes),
                None => stream.finish(),
            }
            .map_err(|err| err.to_string())
        }));
    }
    let body = whole(std::mem::take(response.body_mut())).await?;
    let chat: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    let out =
        gantry_core::responses::chat_to_responses_response(&chat, &id, created).map_err(|err| {
            Refusal::new(
                StatusCode::BAD_GATEWAY,
                "untranslatable",
                format!(
                    "The provider's answer could not be translated to the Responses format: {err}"
                ),
            )
        })?;
    Ok(json_body(response, out.to_string().into_bytes()))
}

/// A Responses answer as a chat completions one, for a chat request sent to a model served through Responses.
async fn from_responses(include_usage: bool, mut response: Response) -> Result<Response, Refusal> {
    if !response.status().is_success() {
        return Ok(response);
    }
    if is_type(&response, "text/event-stream") {
        let mut stream = gantry_core::responses::ResponsesToChatStream::new(include_usage);
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
    let out = gantry_core::responses::responses_to_chat_response(&answer).map_err(|err| {
        Refusal::new(
            StatusCode::BAD_GATEWAY,
            "untranslatable",
            format!("The provider's answer could not be translated to the chat completions format: {err}"),
        )
    })?;
    Ok(json_body(response, out.to_string().into_bytes()))
}

/// The answer in the format the caller asked in: as sent, as chat completions (`to_chat`), as messages for a
/// messages request translated to chat, or as a response for a Responses request translated to chat.
async fn for_caller(
    kind: Kind,
    provider: &str,
    plan: Option<&Plan>,
    decision: &str,
    response: Response,
) -> Result<Response, Refusal> {
    let model = plan.map_or("", |p| p.model.as_str());
    match plan {
        Some(plan) if plan.from_messages => {
            // An answer in a provider's own format becomes chat first, which the step below reads.
            let response = if kind.translates_chat() {
                to_chat(kind, Some(true), decision, model, response).await?
            } else {
                response
            };
            to_anthropic(provider, decision, response).await
        }
        Some(plan) if plan.from_responses => {
            let response = to_chat(kind, plan.translated, decision, model, response).await?;
            to_responses(decision, response).await
        }
        Some(Plan {
            as_responses: Some(include_usage),
            ..
        }) => from_responses(*include_usage, response).await,
        _ => {
            to_chat(
                kind,
                plan.and_then(|p| p.translated),
                decision,
                model,
                response,
            )
            .await
        }
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
    let draining = Draining(Arc::default());
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
                let draining = draining.clone();
                let service = app.clone().map_request(move |mut request: axum::http::Request<_>| {
                    request.extensions_mut().insert(ClientAddr(peer));
                    request.extensions_mut().insert(draining.clone());
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
    // Draining: no new connection is taken, `/readyz` says 503 to any that asks on a connection still open, and the
    // requests in flight finish below.
    draining.0.store(true, std::sync::atomic::Ordering::Relaxed);
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
    serve_policy_with(name, policy_path, keys_path, listen, metrics, tls, &|_| {
        Ok(Extension::default())
    })
    .await
}

/// `serve_policy`, with what an embedding binary adds: `extend` runs once the files are checked and the store is
/// open, and its `Err` stops the start with that message.
pub async fn serve_policy_with(
    name: &str,
    policy_path: &Path,
    keys_path: Option<&Path>,
    listen: Option<&str>,
    metrics: Option<&str>,
    tls: Option<(&Path, &Path)>,
    extend: &(dyn Fn(Host<'_>) -> Result<Extension, String> + Sync),
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
    // A variable that points at a secret manager is read now: a start that cannot read one says which, and stops.
    let read = gantry_core::secrets::load()?;
    if read > 0 {
        println!(
            "{name}: read {} from secret managers.",
            gantry_core::count(read, "secret")
        );
    }
    let started = governed_with(policy_path, keys_path, &gantry_core::secrets::var, extend)?;
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
    if let Some(token) = &started.setup {
        // A wildcard address is not one a browser can open: show the same port on this machine.
        let shown = if addr.ip().is_unspecified() {
            SocketAddr::from(([127, 0, 0, 1], addr.port()))
        } else {
            addr
        };
        println!(
            "First run: no admin key yet. Open {scheme}://{shown}/console/setup/{token} to make the first one. The link works once."
        );
    }
    println!(
        "Console: {scheme}://{addr}/console (sign in with an admin key{})",
        if loaded.sso.is_some() || loaded.saml.is_some() {
            " or single sign-on"
        } else {
            ""
        }
    );
    // Without the secret every single sign-on fails at the identity provider, long after this start looked fine.
    if let Some(sso) = &loaded.sso
        && gantry_core::secrets::var(&sso.client_secret_env).is_none_or(|v| v.is_empty())
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
    // With a store, keys come from the database and the keys file is not read.
    let keys_from = match &loaded.store {
        Some(store) => format!("the store named by {}", store.postgres_url_env),
        None => loaded.keys_path.display().to_string(),
    };
    if loaded.store.is_some() {
        println!(
            "Keys, kill switches and budgets are shared through {keys_from} with every Gantry on that database."
        );
    }
    println!(
        "Changes to {} and {keys_from} are used within 2 seconds, or at once on SIGHUP.",
        policy_path.display(),
    );
    if loaded.policy.keys() == 0 {
        eprintln!(
            "warning: no keys in {keys_from}, so every request will be refused. Add one with `gantry key new <name> --team <team>`: it is used within 2 seconds.",
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

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    #[tokio::test]
    async fn a_draining_gateway_is_not_ready_and_still_alive()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = app(Config::default())?;
        let flag = Draining(Arc::default());
        let ask = |path: &str| -> Result<Request, axum::http::Error> {
            let mut request = Request::get(path).body(Body::empty())?;
            request.extensions_mut().insert(flag.clone());
            Ok(request)
        };
        assert_eq!(
            app.clone().oneshot(ask("/readyz")?).await?.status(),
            StatusCode::OK
        );
        flag.0.store(true, std::sync::atomic::Ordering::Relaxed);
        let response = app.clone().oneshot(ask("/readyz")?).await?;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await?
            .to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(body["checks"]["draining"]["ready"], false);
        assert_eq!(
            app.oneshot(ask("/healthz")?).await?.status(),
            StatusCode::OK
        );
        Ok(())
    }
}
