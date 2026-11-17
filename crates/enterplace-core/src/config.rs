//! Reads the policy file and the keys file, and says exactly what is wrong with them.
//! `enterplace check` and `enterplace serve` both go through `load`, so a file that passes one is accepted by the other.

use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
    path::{Path, PathBuf},
};

use serde::Deserialize;

use crate::{
    guard::{self, Guardrail, GuardrailFile},
    id::sha256_hex,
    policy::{
        Budget, CacheScope, CallerKey, Cap, Capture, Cidr, JwtTrust, KeyOptions, Limits, Mode,
        Models, Period, Permission, Policy, Principal, Role, Rule, ScopeKind, ScopeLimit, Semantic,
        Team, Who,
    },
    usage::{PriceOverrides, price_for},
};

/// Every word a policy or keys file may contain as a key, for "did you mean".
const KNOWN: &[&str] = &[
    "version",
    "providers",
    "rules",
    "audit",
    "name",
    "url",
    "key_env",
    "key_file",
    "kind",
    "preset",
    "allow_private",
    "principals",
    "models",
    "team",
    "any",
    "path",
    "keys",
    "sha256",
    "admin",
    "deployments",
    "model_ids",
    "api_version",
    "region",
    "role_arn",
    "fallback",
    "retries",
    "accept_chat",
    "accept_messages",
    "guardrails",
    "type",
    "action",
    "timeout_ms",
    "on_failure",
    "on",
    "budget",
    "usd",
    "per",
    "sliding",
    "per_org",
    "rate",
    "batch",
    "rpm",
    "cache",
    "ttl_seconds",
    "scope",
    "semantic",
    "threshold",
    "prompt_cache",
    "buffer_stream",
    "budget_headers",
    "check_stream_every",
    "file_retention_days",
    "containers",
    "sizes",
    "passthrough",
    "provider",
    "paths",
    "prices",
    "input",
    "output",
    "cache_read",
    "cache_write",
    "cache_write_1h",
    "long_context",
    "max_output",
    "max_context",
    "per_image",
    "input_audio",
    "output_audio",
    "cache_read_audio",
    "batch_input",
    "batch_output",
    "batch_cache_read",
    "max_lines",
    "max_open",
    "bucket",
    "storage_url",
    "per_second",
    "per_call",
    "per_page",
    "above_prompt_tokens",
    "price",
    "console",
    "sso",
    "issuer",
    "client_id",
    "client_secret_env",
    "redirect_url",
    "allowed_domains",
    "allowed_emails",
    "role_claim",
    "admin_values",
    "read_only_values",
    "self_issue",
    "scopes",
    "expires_days",
    "saml",
    "idp_entity_id",
    "idp_sso_url",
    "idp_certificate",
    "sp_entity_id",
    "acs_url",
    "email_attribute",
    "role_attribute",
    "owner",
    "members",
    "expires",
    "headers_env",
    "model",
    "prompt",
    "guardrail_id",
    "guardrail_version",
    "threshold",
    "anonymizer_url",
    "project_id",
    "oci_signing",
    "tenancy",
    "user",
    "fingerprint",
    "template_id",
    "pack",
    "recipe",
    "config_id",
    "guard_name",
    "profile_name",
    "policy_id",
    "rubric",
    "cache_seconds",
    "case_sensitive",
    "whole_word",
    "shadow_until",
    "applications",
    "intent",
    "mode",
    "history",
    "stream",
    "chunk_chars",
    "hold",
    "session_end_seconds",
    "secret_env",
    "batch_url",
    "queue",
    "batch_size",
    // An alias's deployments sit under `deployments`, a free map, so provider, model and weight are not listed: as
    // known words they would be the nearest match for a misspelled "models".
    "aliases",
    "balance",
    "cooldown_seconds",
    "context_window_fallback",
    "content_policy_fallback",
    "tpm",
    "mcp",
    "tools",
    "prompts",
    "resources",
    "approve_tools",
    "tool_action",
    "approval_timeout_seconds",
    "mcp_clients",
    "transport",
    "command",
    "args",
    "env",
    "resource",
    "call_price_usd",
    "tool_prices",
    "token_url",
    "audience",
    "user_auth",
    "user_headers",
    "oauth_client_id",
    "oauth_client_secret_env",
    "oauth_scopes",
    "tool_changes",
    "mcp_bundles",
    "teams",
    "store",
    "postgres_url_env",
    "policy_from",
    "approval",
    "credential",
    "caller_provider_key",
    "orgs",
    "org",
    "limits",
    "global",
    // A `limits:` entry for one key, by the first 8 hex characters of its hash.
    "key",
    "person",
    "customer",
    "customers",
    "tag",
    "tags",
    "parallel",
    "tz",
    "profiles",
    "roles",
    "role",
    "permissions",
    "sso_values",
    "jwt",
    "audience",
    "jwks_url",
    "person_claim",
    "team_claim",
    "trusted_proxies",
    "cors",
    "allowed_origins",
    "from",
    "regions",
    "session_affinity",
    "routes",
    "mcp_tools",
    "replaced_by",
    "capture",
    "to",
    "days",
    "viewers",
    "timeouts",
    "connect_ms",
    "first_byte_ms",
    "total_ms",
    "idle_ms",
    "key_balance",
    "key_quarantine_seconds",
    "weight",
    "headers_env",
    "proxy_env",
    "max_parallel",
    "rpm",
    "tpm",
    "rate_limit_headroom_percent",
    "fallbacks",
    "fallback_on",
    "weights",
    "latency",
    "errors",
    "cost",
    "default_guardrails",
    "model_groups",
    "model_group",
    "key_bounds",
    "max_days",
    "max_budget",
    "require",
    "headers",
    "body",
    "rph",
    "rpd",
    "tpd",
    "budget_basis",
    "auth",
    "identity",
    "session_requests",
    "answer_cache",
    // Last, so a misspelled "models" (one letter off both) is still offered "models", the word far more often meant.
    "mode",
];
/// Keys whose value is a map whose keys the user chooses: model names, or header names under `headers_env`.
/// Those names are not Enterplace keys, so the unknown-key scan never reads them.
/// A regex guardrail's `patterns` and a keywords guardrail's `keywords` are maps of entry names the user chooses, and
/// a key's `metadata` is the admin's own notes.
const FREE_MAPS: &[&str] = &[
    "deployments",
    "model_ids",
    "headers_env",
    "patterns",
    "keywords",
    "metadata",
    "model_groups",
    // An MCP server's priced tools by name, and a stdio server's variables.
    "tool_prices",
    "env",
];
/// The most retries a provider may ask for. Each one can wait the whole first-byte timeout.
pub const MAX_RETRIES: u32 = 5;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    version: u32,
    /// `observe` forwards what the policy would refuse and records it; `enforce`, the default, refuses it.
    #[serde(default)]
    mode: Option<String>,
    providers: Vec<ProviderFile>,
    rules: Vec<RuleFile>,
    #[serde(default)]
    audit: Option<AuditFile>,
    #[serde(default)]
    guardrails: Vec<GuardrailFile>,
    #[serde(default)]
    prices: PriceOverrides,
    #[serde(default)]
    console: Option<ConsoleFile>,
    #[serde(default)]
    aliases: Vec<AliasFile>,
    #[serde(default)]
    mcp: Vec<crate::mcp::ServerFile>,
    #[serde(default)]
    mcp_bundles: Vec<crate::mcp::BundleFile>,
    #[serde(default)]
    store: Option<StoreFile>,
    /// The organizations of a multi-tenant install. Keys, rules, limits and roles that name one must name one here.
    #[serde(default)]
    orgs: Vec<String>,
    #[serde(default)]
    limits: Vec<LimitFile>,
    #[serde(default)]
    profiles: Vec<ProfileFile>,
    #[serde(default)]
    roles: Vec<RoleFile>,
    #[serde(default)]
    teams: Vec<TeamFile>,
    #[serde(default)]
    jwt: Vec<JwtFile>,
    #[serde(default)]
    trusted_proxies: Vec<String>,
    #[serde(default)]
    cors: Option<CorsFile>,
    /// The applications rules name in `applications:`, each with what it is for.
    #[serde(default)]
    applications: Vec<ApplicationFile>,
    /// Guardrails every rule runs, before its own.
    #[serde(default)]
    default_guardrails: Vec<String>,
    /// Named groups of models: `group:<name>` in a rule's, a key's or a budget's `models`, and `model_group:` in
    /// a `limits:` entry.
    #[serde(default)]
    model_groups: BTreeMap<String, Vec<String>>,
    /// What every role may grant when it issues a key, unless the role has its own.
    #[serde(default)]
    key_bounds: Option<KeyBoundsFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyBoundsFile {
    #[serde(default)]
    max_days: Option<i64>,
    #[serde(default)]
    max_budget: Option<BudgetFile>,
    #[serde(default)]
    models: Vec<String>,
}

/// `require:` on a rule: what every request must carry.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequireFile {
    #[serde(default)]
    headers: Vec<String>,
    #[serde(default)]
    body: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplicationFile {
    name: String,
    #[serde(default)]
    intent: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CorsFile {
    allowed_origins: Vec<String>,
}

/// `cors:` checked: each origin a scheme and a host (and a port), as a browser sends it in `Origin`, or `*`.
fn cors_of(file: &CorsFile) -> Result<crate::policy::Cors, String> {
    if file.allowed_origins.is_empty() {
        return Err("cors lists no origin. List the origins of the pages that call Enterplace, such as allowed_origins: [https://pivot.claude.ai], or remove cors: to answer none.".into());
    }
    let mut origins = Vec::new();
    for origin in &file.allowed_origins {
        let origin = origin.trim().to_ascii_lowercase();
        let host = origin
            .strip_prefix("https://")
            .or_else(|| origin.strip_prefix("http://"));
        let fits = origin == "*"
            || host.is_some_and(|h| {
                !h.is_empty()
                    && h.chars().all(|c| {
                        c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']')
                    })
            });
        if !fits {
            return Err(format!(
                "cors: \"{origin}\" is not an origin. Write the scheme and host the page is served from, such as https://pivot.claude.ai or http://localhost:3000, with no path and no trailing slash; or \"*\" for any origin."
            ));
        }
        origins.push(origin);
    }
    Ok(crate::policy::Cors {
        allowed_origins: origins,
    })
}

/// One entry of `limits:`: one kind of scope (`global: true`, or a name or `*`), its organization, and its limits.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitFile {
    #[serde(default)]
    global: Option<bool>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    team: Option<String>,
    #[serde(default)]
    person: Option<String>,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    customer: Option<String>,
    #[serde(default)]
    tag: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    model_group: Option<String>,
    #[serde(default)]
    budget: Option<BudgetsFile>,
    #[serde(default)]
    rate: Option<RateFile>,
    #[serde(default)]
    parallel: Option<i64>,
    #[serde(default)]
    shadow_until: Option<String>,
}

/// A named set of models, guardrails, tools and limits that rules include with `profiles:`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileFile {
    name: String,
    #[serde(default)]
    models: Vec<String>,
    #[serde(default)]
    guardrails: Vec<String>,
    #[serde(default)]
    tools: Vec<String>,
    #[serde(default)]
    budget: Option<BudgetsFile>,
    #[serde(default)]
    rate: Option<RateFile>,
    #[serde(default)]
    parallel: Option<i64>,
}

/// A console role: what its holders may do.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleFile {
    name: String,
    permissions: Vec<String>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    teams: Vec<String>,
    #[serde(default)]
    customers: Vec<String>,
    #[serde(default)]
    sso_values: Vec<String>,
    /// What its holders may grant when they issue a key.
    #[serde(default)]
    key_bounds: Option<KeyBoundsFile>,
}

/// A team: its owner, its members by email, and the identity provider groups that put people in it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TeamFile {
    name: String,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    members: Vec<String>,
    #[serde(default)]
    sso_values: Vec<String>,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
}

/// One budget, or a list of them (a daily and a monthly one).
#[derive(Deserialize)]
#[serde(untagged)]
enum BudgetsFile {
    One(BudgetFile),
    Many(Vec<BudgetFile>),
}

impl BudgetsFile {
    fn list(&self) -> &[BudgetFile] {
        match self {
            BudgetsFile::One(one) => std::slice::from_ref(one),
            BudgetsFile::Many(many) => many,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JwtFile {
    issuer: String,
    audience: String,
    jwks_url: String,
    #[serde(default)]
    person_claim: Option<String>,
    #[serde(default)]
    team_claim: Option<String>,
    #[serde(default)]
    team: Option<String>,
    #[serde(default)]
    role_claim: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreFile {
    postgres_url_env: String,
    #[serde(default)]
    policy_from: Option<String>,
    #[serde(default)]
    approval: bool,
    #[serde(default)]
    answer_cache: bool,
}

/// Where several gateways keep what they share while they run, as `store:` in the policy sets it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreSetting {
    /// The environment variable that holds the Postgres connection string. The string never goes in the file: it
    /// carries a password.
    pub postgres_url_env: String,
    /// Where the policy is read from while Enterplace runs: the file (the default, for GitOps) or the store's live
    /// version (edited in the console and the admin API).
    pub policy_from: PolicyFrom,
    /// A new policy version waits for a second admin to approve it before it goes live. Read from the live version,
    /// so turning it off is itself a change that needs an approval.
    pub approval: bool,
    /// Cached answers are kept in the store too, so every gateway serves them. Off unless set: answers are then
    /// written to the database.
    pub answer_cache: bool,
}

/// Which one is the source of the policy when the store is set. Never both: see `store.policy_from`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PolicyFrom {
    /// The policy file decides, and the console and the admin API cannot change it.
    #[default]
    File,
    /// The store's live version decides. The file names the store and is otherwise not read.
    Store,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AliasFile {
    name: String,
    deployments: Vec<DeploymentFile>,
    #[serde(default)]
    timeouts: Option<TimeoutsFile>,
    #[serde(default)]
    fallbacks: Vec<String>,
    #[serde(default)]
    fallback_on: Option<Vec<String>>,
    #[serde(default)]
    weights: Option<WeightsFile>,
    #[serde(default)]
    balance: Option<String>,
    #[serde(default)]
    cooldown_seconds: Option<u64>,
    #[serde(default)]
    context_window_fallback: Option<String>,
    #[serde(default)]
    content_policy_fallback: Option<String>,
    #[serde(default)]
    session_affinity: bool,
    #[serde(default)]
    rate_limit_headroom_percent: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentFile {
    provider: String,
    model: String,
    #[serde(default)]
    weight: Option<u32>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default, rename = "for")]
    for_: Option<ForFile>,
    #[serde(default)]
    when: Option<WhenFile>,
    #[serde(default)]
    timeouts: Option<TimeoutsFile>,
    #[serde(default)]
    probe: Option<ProbeFile>,
    #[serde(default)]
    max_parallel: Option<u32>,
    #[serde(default)]
    rpm: Option<u32>,
    #[serde(default)]
    tpm: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TimeoutsFile {
    #[serde(default)]
    connect_ms: Option<u64>,
    #[serde(default)]
    first_byte_ms: Option<u64>,
    #[serde(default)]
    total_ms: Option<u64>,
    #[serde(default)]
    idle_ms: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WhenFile {
    #[serde(default)]
    team: Option<String>,
    #[serde(default)]
    tag: Option<String>,
    #[serde(default)]
    customer: Option<String>,
    #[serde(default)]
    min_prompt_tokens: Option<u64>,
    #[serde(default)]
    max_prompt_tokens: Option<u64>,
    #[serde(default)]
    tools: Option<bool>,
    #[serde(default)]
    images: Option<bool>,
    #[serde(default)]
    header: Option<BTreeMap<String, String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeFile {
    every_seconds: u64,
    #[serde(default)]
    with: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WeightsFile {
    #[serde(default)]
    latency: Option<f64>,
    #[serde(default)]
    errors: Option<f64>,
    #[serde(default)]
    cost: Option<f64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolKeyFile {
    #[serde(default)]
    key_env: Option<String>,
    #[serde(default)]
    credential: Option<String>,
    #[serde(default)]
    weight: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ForFile {
    #[serde(default)]
    team: Option<String>,
    #[serde(default)]
    tag: Option<String>,
}

/// How an alias picks among its deployments.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Balance {
    /// In turn, each as often as its weight says.
    #[default]
    RoundRobin,
    /// The one with the fewest requests in flight through this Enterplace.
    LeastBusy,
    /// The one with the lowest 90th percentile time to first byte over its recent answers on this Enterplace.
    LowestLatency,
    /// The one whose model is cheapest by its price (input plus output per million tokens).
    LowestCost,
    /// The lowest score of latency, error rate and cost, each scaled against the others and weighted.
    Adaptive,
}

impl Balance {
    pub fn word(self) -> &'static str {
        match self {
            Balance::RoundRobin => "round_robin",
            Balance::LeastBusy => "least_busy",
            Balance::LowestLatency => "lowest_latency",
            Balance::LowestCost => "lowest_cost",
            Balance::Adaptive => "adaptive",
        }
    }
}

/// Who a deployment is kept for: requests of one team, or requests that carry one tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum For {
    Team(String),
    Tag(String),
}

/// Time limits on one request to a provider, in milliseconds. `None` takes the next level's: a deployment's, then
/// its alias's, then its provider's, then the gateway's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timeouts {
    /// For the TCP connection.
    pub connect_ms: Option<u64>,
    /// For the answer's headers, from sending.
    pub first_byte_ms: Option<u64>,
    /// For the whole answer, body included, from sending.
    pub total_ms: Option<u64>,
    /// Between two pieces of a streamed answer.
    pub idle_ms: Option<u64>,
}

impl Timeouts {
    /// Each field of `self`, or of `other` where `self` has none.
    pub fn or(self, other: Timeouts) -> Timeouts {
        Timeouts {
            connect_ms: self.connect_ms.or(other.connect_ms),
            first_byte_ms: self.first_byte_ms.or(other.first_byte_ms),
            total_ms: self.total_ms.or(other.total_ms),
            idle_ms: self.idle_ms.or(other.idle_ms),
        }
    }
}

/// What a request must have for a deployment kept for it. Every condition set must hold.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct When {
    pub team: Option<String>,
    pub tag: Option<String>,
    pub customer: Option<String>,
    /// The prompt's size in tokens, estimated as its body's bytes over four.
    pub min_prompt_tokens: Option<u64>,
    pub max_prompt_tokens: Option<u64>,
    /// Whether the request offers tools.
    pub tools: Option<bool>,
    /// Whether the request holds an image.
    pub images: Option<bool>,
    /// A request header and the value it must have.
    pub header: Option<(String, String)>,
}

/// How a deployment is checked in the background, so a dead one is passed over before a caller finds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probe {
    pub every_seconds: u64,
    /// `models` lists the provider's models; `chat` sends a one-token request.
    pub chat: bool,
}

/// The weights of `balance: adaptive`. Each part of the score is scaled to 0..1 against the other deployments.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Weights {
    pub latency: f64,
    pub errors: f64,
    pub cost: f64,
}

impl Default for Weights {
    fn default() -> Self {
        Weights {
            latency: 1.0,
            errors: 1.0,
            cost: 1.0,
        }
    }
}

impl Eq for Weights {}

/// Which failures of an alias's deployments send a request on to its `fallbacks`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FallbackOn {
    RateLimit,
    ServerError,
    Timeout,
    Unreachable,
    ContextWindow,
    ContentPolicy,
}

impl FallbackOn {
    pub const ALL: [(&'static str, FallbackOn); 6] = [
        ("rate_limit", FallbackOn::RateLimit),
        ("server_error", FallbackOn::ServerError),
        ("timeout", FallbackOn::Timeout),
        ("unreachable", FallbackOn::Unreachable),
        ("context_window", FallbackOn::ContextWindow),
        ("content_policy", FallbackOn::ContentPolicy),
    ];
    /// What `fallbacks` are taken on when `fallback_on` is not written: every failure that may clear elsewhere.
    pub const DEFAULT: [FallbackOn; 4] = [
        FallbackOn::RateLimit,
        FallbackOn::ServerError,
        FallbackOn::Timeout,
        FallbackOn::Unreachable,
    ];
}

/// Where one key of a provider's key pool is read from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeySource {
    Env(String),
    Credential(String),
}

/// One place an alias can send a request: a provider and the model it is known by there.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Deployment {
    pub provider: String,
    pub model: String,
    pub weight: u32,
    /// Where it runs, as the admin labels it (eu, us, eu-west-1). A rule with `regions:` reaches only these.
    pub region: Option<String>,
    /// Kept for one team or tag. A request that matches some kept deployments goes only to those; one that
    /// matches none goes to the deployments kept for nobody.
    pub for_: Option<For>,
    /// Kept for requests that meet every condition here, as `for_` is.
    pub when: Option<When>,
    pub timeouts: Timeouts,
    pub probe: Option<Probe>,
    /// Most requests in flight at it through this Enterplace; one at its most is passed over.
    pub max_parallel: Option<u32>,
    /// Most requests and tokens a minute it is sent through this Enterplace; one at its limit is passed over.
    pub rpm: Option<u32>,
    pub tpm: Option<u64>,
}

/// A model name callers send that Enterplace serves from one or more deployments.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Alias {
    pub name: String,
    pub deployments: Vec<Deployment>,
    pub balance: Balance,
    /// How long a deployment that failed is passed over.
    pub cooldown_seconds: u64,
    /// The model or alias a request goes to when the provider says its prompt is longer than the model's context.
    pub context_window_fallback: Option<String>,
    /// The model or alias a request goes to when the provider refuses it under its content policy.
    pub content_policy_fallback: Option<String>,
    /// One session of one person (a coding agent's conversation) stays on one deployment while it answers.
    pub session_affinity: bool,
    /// For each of its deployments, unless the deployment says otherwise.
    pub timeouts: Timeouts,
    /// Models or aliases tried in turn when every deployment failed in a way `fallback_on` names.
    pub fallbacks: Vec<String>,
    pub fallback_on: Vec<FallbackOn>,
    /// For `balance: adaptive`.
    pub weights: Weights,
    /// A deployment whose provider says less than this share of a rate limit is left (in percent) goes after the
    /// others. `None` is 5.
    pub rate_limit_headroom_percent: Option<u32>,
}

/// How long a failed deployment is passed over when its alias does not say.
pub const DEFAULT_COOLDOWN_SECONDS: u64 = 30;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderFile {
    name: String,
    // A catalog id that fills in url and kind when they are not written.
    #[serde(default)]
    preset: Option<String>,
    // Optional here only so a file written for the previous version gets a message that says what to add.
    #[serde(default)]
    kind: Option<String>,
    // Optional for bedrock, whose URL follows from its region. Every other kind needs one.
    #[serde(default)]
    url: Option<String>,
    // Bedrock finds AWS credentials itself, and vertex Google ones when it is left out. Every other kind needs one.
    #[serde(default)]
    key_env: Option<String>,
    // Instead of key_env, for a key that changes while Enterplace runs: the file is read again once a second.
    #[serde(default)]
    key_file: Option<String>,
    // Instead of key_env or key_file: a provider credential kept sealed in the store, by its name.
    #[serde(default)]
    credential: Option<String>,
    #[serde(default)]
    allow_private: bool,
    #[serde(default)]
    models: Option<Vec<String>>,
    #[serde(default)]
    deployments: Option<BTreeMap<String, String>>,
    #[serde(default)]
    model_ids: Option<BTreeMap<String, String>>,
    #[serde(default)]
    api_version: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    role_arn: Option<String>,
    #[serde(default)]
    fallback: Option<String>,
    #[serde(default)]
    retries: Option<u32>,
    #[serde(default)]
    accept_chat: Option<bool>,
    #[serde(default)]
    accept_messages: Option<bool>,
    #[serde(default)]
    timeouts: Option<TimeoutsFile>,
    #[serde(default)]
    keys: Vec<PoolKeyFile>,
    #[serde(default)]
    key_balance: Option<String>,
    #[serde(default)]
    key_quarantine_seconds: Option<u64>,
    #[serde(default)]
    headers_env: BTreeMap<String, String>,
    #[serde(default)]
    proxy_env: Option<String>,
    #[serde(default)]
    batch: Option<ProviderBatchFile>,
    // watsonx.ai: the project its requests are made in.
    #[serde(default)]
    project_id: Option<String>,
    // openai or azure: chat completions requests for its models are sent to the Responses API, translated.
    #[serde(default)]
    chat_as_responses: Option<bool>,
    // openai (OCI Generative AI): requests are signed with an OCI API signing key instead of carrying a key.
    #[serde(default)]
    oci_signing: Option<OciSigningFile>,
    // `passthrough`: each caller's own login (a Claude or ChatGPT subscription) is sent on unchanged, and Enterplace holds no key.
    #[serde(default)]
    auth: Option<String>,
    // With `auth: passthrough`: whether a request must name its person in x-enterplace-user (`required`, the default).
    #[serde(default)]
    identity: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderBatchFile {
    bucket: String,
    #[serde(default)]
    role_arn: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    storage_url: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OciSigningFile {
    tenancy: String,
    user: String,
    fingerprint: String,
    #[serde(default)]
    key_file: Option<String>,
    #[serde(default)]
    key_env: Option<String>,
}

/// An OCI API signing key: the IDs that make its keyId, and where its private key (PEM) is. Requests are signed
/// with OCI's HTTP signature (version 1, rsa-sha256).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OciSigning {
    pub tenancy: String,
    pub user: String,
    pub fingerprint: String,
    /// The private key's file, read at start; or, when None, the environment variable in `key_env`.
    pub key_file: Option<PathBuf>,
    pub key_env: Option<String>,
}

impl OciSigning {
    /// `<tenancy OCID>/<user OCID>/<key fingerprint>`, as OCI's Authorization header names the key.
    pub fn key_id(&self) -> String {
        format!("{}/{}/{}", self.tenancy, self.user, self.fingerprint)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    name: String,
    principals: PrincipalsFile,
    /// Optional only for a rule that takes its models from profiles.
    #[serde(default)]
    models: Option<Vec<String>>,
    #[serde(default)]
    guardrails: Vec<String>,
    #[serde(default)]
    budget: Option<BudgetsFile>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    profiles: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    customers: Vec<String>,
    #[serde(default)]
    applications: Vec<String>,
    #[serde(default)]
    parallel: Option<i64>,
    #[serde(default)]
    rate: Option<RateFile>,
    #[serde(default)]
    cache: Option<CacheFile>,
    #[serde(default)]
    prompt_cache: Option<String>,
    #[serde(default)]
    buffer_stream: bool,
    #[serde(default)]
    budget_headers: bool,
    #[serde(default)]
    check_stream_every: Option<i64>,
    #[serde(default)]
    passthrough: Vec<PassthroughFile>,
    #[serde(default)]
    tools: Vec<String>,
    #[serde(default)]
    tool_action: Option<String>,
    #[serde(default)]
    prompts: Vec<String>,
    #[serde(default)]
    resources: Vec<String>,
    #[serde(default)]
    approve_tools: Vec<String>,
    #[serde(default)]
    approval_timeout_seconds: Option<i64>,
    #[serde(default)]
    mcp_clients: Vec<String>,
    #[serde(default)]
    caller_provider_key: Option<String>,
    #[serde(default)]
    budget_basis: Option<String>,
    #[serde(default)]
    from: Vec<String>,
    #[serde(default)]
    regions: Option<Vec<String>>,
    #[serde(default)]
    capture: Option<CaptureFile>,
    #[serde(default)]
    file_retention_days: Option<i64>,
    #[serde(default)]
    batch: Option<RuleBatchFile>,
    containers: Option<ContainersFile>,
    #[serde(default)]
    shadow_until: Option<String>,
    #[serde(default)]
    require: Option<RequireFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleBatchFile {
    #[serde(default)]
    max_lines: Option<i64>,
    #[serde(default)]
    max_open: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContainersFile {
    sizes: Vec<String>,
}

/// The memory sizes OpenAI offers for a code interpreter container.
pub const CONTAINER_SIZES: [&str; 4] = ["1g", "4g", "16g", "64g"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureFile {
    to: String,
    days: i64,
    viewers: Vec<String>,
}

/// The longest a kept body may be kept: 90 days.
const MAX_CAPTURE_DAYS: i64 = 90;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PassthroughFile {
    provider: String,
    paths: Vec<String>,
}

// Numbers are read wide and checked by hand, so a wrong one gets a message with the fix, not a parser's.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BudgetFile {
    usd: f64,
    per: PerFile,
    #[serde(default)]
    tz: Option<String>,
    /// In a rule or a profile: count only these models.
    #[serde(default)]
    models: Vec<String>,
    /// In a rule or a profile: until then the budget records what it would refuse and refuses nothing.
    #[serde(default)]
    shadow_until: Option<String>,
}

/// A budget's `per`: a calendar period (`month`, `6h`), or `{ sliding: 24h }` for a sliding window.
#[derive(Deserialize)]
#[serde(untagged)]
enum PerFile {
    Calendar(String),
    Sliding(SlidingFile),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SlidingFile {
    sliding: String,
}

impl PerFile {
    /// As [`Period::parse`] reads it.
    fn text(&self) -> String {
        match self {
            PerFile::Calendar(per) => per.clone(),
            PerFile::Sliding(s) => format!("sliding {}", s.sliding),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RateFile {
    #[serde(default)]
    rpm: Option<i64>,
    #[serde(default)]
    tpm: Option<i64>,
    /// Requests per calendar hour and per calendar day, UTC.
    #[serde(default)]
    rph: Option<i64>,
    #[serde(default)]
    rpd: Option<i64>,
    /// Tokens per calendar day, UTC.
    #[serde(default)]
    tpd: Option<i64>,
    /// In a rule: the most requests one session may send.
    #[serde(default)]
    session_requests: Option<i64>,
}

/// A count of requests (`rph`, `rpd`, `session_requests`), or what is wrong with it.
fn requests_of(n: Option<i64>, name: &str, at: &str, errors: &mut Vec<String>) -> Option<u32> {
    match u32::try_from(n?) {
        Ok(n) if (1..=1_000_000_000).contains(&n) => Some(n),
        _ => {
            errors.push(format!(
                "{at}: {name} is a number of requests, 1 to 1000000000, for example rate: {{ {name}: 500 }}. To set no limit, remove it."
            ));
            None
        }
    }
}

/// `group:<name>` entries of a model list replaced by the group's models; every other entry as written.
fn with_groups(
    models: &[String],
    groups: &BTreeMap<String, Vec<String>>,
    at: &str,
    errors: &mut Vec<String>,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for model in models {
        let members = match model.strip_prefix("group:") {
            None => std::slice::from_ref(model),
            Some(name) => match groups.get(name) {
                Some(members) => members.as_slice(),
                None => {
                    errors.push(format!(
                        "{at}: \"{model}\" names a model group that model_groups does not define. Define it there (model_groups: {{ {name}: [<model>, ...] }}), or check the spelling. The groups are: {}.",
                        names_or_none(groups.keys().map(String::as_str))
                    ));
                    continue;
                }
            },
        };
        for member in members {
            if !out.contains(member) {
                out.push(member.clone());
            }
        }
    }
    out
}

/// `key_bounds:` checked.
fn key_bounds_of(
    file: &KeyBoundsFile,
    groups: &BTreeMap<String, Vec<String>>,
    at: &str,
    errors: &mut Vec<String>,
) -> crate::policy::KeyBounds {
    let max_days = match file.max_days.map(u32::try_from) {
        None => None,
        Some(Ok(days @ 1..=3660)) => Some(days),
        Some(_) => {
            errors.push(format!(
                "{at}: max_days is the longest a key may work, 1 to 3660 days, for example key_bounds: {{ max_days: 90 }}."
            ));
            None
        }
    };
    if file.max_days.is_none() && file.max_budget.is_none() && file.models.is_empty() {
        errors.push(format!(
            "{at}: key_bounds sets no bound. Give max_days, max_budget or models, for example key_bounds: {{ max_days: 90, max_budget: {{ usd: 100, per: month }} }}, or remove it."
        ));
    }
    crate::policy::KeyBounds {
        max_days,
        max_budget: file
            .max_budget
            .as_ref()
            .and_then(|b| budget_of(b, at, errors)),
        models: with_groups(&file.models, groups, at, errors),
    }
}

/// Holds a key about to be issued by a holder of `role` (or by `enterplace login`, with none) to the policy's
/// `key_bounds`: what it leaves unset is set to the bound, and what passes a bound is refused, naming the fix.
pub fn bound_key(
    policy: &Policy,
    role: Option<&str>,
    expires: &mut Option<String>,
    budget: &mut Option<Budget>,
    models: &mut Option<Vec<String>>,
) -> Result<(), String> {
    let Some(bounds) = policy.key_bounds(role) else {
        return Ok(());
    };
    let by = match role {
        Some(role) => format!("key_bounds allows role \"{role}\""),
        None => "key_bounds allows".to_string(),
    };
    if let Some(days) = bounds.max_days {
        let later =
            std::time::SystemTime::now() + std::time::Duration::from_secs(u64::from(days) * 86_400);
        let last = format!("{}Z", &crate::audit::rfc3339(later)[..19]);
        match &*expires {
            None => *expires = Some(last),
            // A bare date starts at 00:00 UTC, and compares as text with a time on the same day.
            Some(expires) if expires.as_str() > last.as_str() => {
                return Err(format!(
                    "expires is {expires}, and {by} a key at most {days} days, until {}. Give an earlier expires, or leave it out to get the longest allowed",
                    &last[..10]
                ));
            }
            Some(_) => {}
        }
    }
    if let Some(most) = bounds.max_budget {
        let rate = |b: Budget| b.usd / b.per.minutes() as f64;
        match *budget {
            None => *budget = Some(most),
            Some(budget) if rate(budget) > rate(most) * (1.0 + 1e-9) => {
                return Err(format!(
                    "the budget is ${} a {}, and {by} a key at most ${} a {}. Give a smaller budget, or leave it out to get the largest allowed",
                    budget.usd,
                    budget.per.describe(),
                    most.usd,
                    most.per.describe()
                ));
            }
            Some(_) => {}
        }
    }
    if !bounds.models.is_empty() {
        match &*models {
            None => *models = Some(bounds.models.clone()),
            Some(models) => {
                if let Some(over) = models.iter().find(|m| {
                    !bounds
                        .models
                        .iter()
                        .any(|allowed| model_matches(allowed, m))
                }) {
                    return Err(format!(
                        "models names \"{over}\", and {by} only {}. Remove it, or leave models out to get every one allowed",
                        bounds.models.join(", ")
                    ));
                }
            }
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheFile {
    ttl_seconds: i64,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    semantic: Option<SemanticFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticFile {
    model: String,
    threshold: f64,
}

/// The longest an answer may be served from the cache: a day.
const MAX_CACHE_TTL: i64 = 86_400;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalsFile {
    team: Option<String>,
    name: Option<String>,
    #[serde(default)]
    tag: Option<String>,
    any: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditFile {
    #[serde(default)]
    path: Option<PathBuf>,
    /// Each organization's records in a chain of its own, beside the install's.
    #[serde(default)]
    per_org: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsoleFile {
    #[serde(default)]
    sso: Option<SsoFile>,
    #[serde(default)]
    saml: Option<SamlFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SamlFile {
    idp_entity_id: String,
    idp_sso_url: String,
    idp_certificate: String,
    sp_entity_id: String,
    acs_url: String,
    #[serde(default)]
    email_attribute: Option<String>,
    role_attribute: String,
    #[serde(default)]
    admin_values: Vec<String>,
    #[serde(default)]
    read_only_values: Vec<String>,
    #[serde(default)]
    allowed_domains: Vec<String>,
    #[serde(default)]
    allowed_emails: Vec<String>,
    #[serde(default)]
    self_issue: Option<SelfIssueFile>,
}

/// Console sign-in through a SAML 2.0 identity provider, as checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Saml {
    /// The `Issuer` of the identity provider's responses, exactly as written.
    pub idp_entity_id: String,
    /// Where the browser is sent with the request to sign in (HTTP-Redirect binding).
    pub idp_sso_url: String,
    /// The identity provider's signing certificates, DER, from the PEM blocks of `idp_certificate`. An assertion
    /// signed by any of them is accepted, so a certificate can be rotated without a gap.
    pub idp_certificates: Vec<Vec<u8>>,
    /// Enterplace's entity ID: the audience every assertion must name.
    pub sp_entity_id: String,
    /// The console's `/console/saml/acs` at its public address: where assertions are posted, and their recipient.
    pub acs_url: String,
    /// The attribute that holds the email. None: the subject's NameID, which must then be an email.
    pub email_attribute: Option<String>,
    pub role_attribute: String,
    pub admin_values: Vec<String>,
    pub read_only_values: Vec<String>,
    pub allowed_domains: Vec<String>,
    pub allowed_emails: Vec<String>,
    /// `enterplace login` issues keys over SAML only when this is set.
    pub self_issue: Option<SelfIssue>,
}

/// The DER of each `CERTIFICATE` PEM block in `text`.
pub fn pem_certificates(text: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
        let body = &rest[start + "-----BEGIN CERTIFICATE-----".len()..];
        let Some(end) = body.find("-----END CERTIFICATE-----") else {
            break;
        };
        let b64: String = body[..end].split_whitespace().collect();
        if let Some(der) = crate::x509::base64_decode(&b64) {
            out.push(der);
        }
        rest = &body[end..];
    }
    out
}

fn console_saml(
    file: &Path,
    text: &str,
    parsed: &PolicyFile,
    errors: &mut Vec<String>,
) -> Option<Saml> {
    let saml = parsed.console.as_ref()?.saml.as_ref()?;
    let before = errors.len();
    let start = line_of_key(text, "saml", 1, usize::MAX);
    let at = |key: &str| {
        format!(
            "{}:{}",
            file.display(),
            line_of_key(text, key, start, usize::MAX)
        )
    };
    if saml.idp_entity_id.trim().is_empty() {
        errors.push(format!(
            "{}: idp_entity_id is empty. Copy the identity provider's entity ID (its Issuer) exactly as its SAML setup page shows it.",
            at("idp_entity_id")
        ));
    }
    if !secure_url(&saml.idp_sso_url) {
        errors.push(format!(
            "{}: idp_sso_url must be the identity provider's https single sign-on URL for the HTTP-Redirect binding. Plain http is accepted only for a provider on this machine.",
            at("idp_sso_url")
        ));
    }
    let idp_certificates = pem_certificates(&saml.idp_certificate);
    if idp_certificates.is_empty()
        || idp_certificates
            .iter()
            .any(|der| crate::x509::public_key(der).is_err())
    {
        errors.push(format!(
            "{}: idp_certificate must be the identity provider's signing certificate in PEM, from -----BEGIN CERTIFICATE----- to -----END CERTIFICATE-----, with an RSA or P-256 key. Download it from the provider's SAML setup page and paste it under idp_certificate: |",
            at("idp_certificate")
        ));
    }
    if saml.sp_entity_id.trim().is_empty() {
        errors.push(format!(
            "{}: sp_entity_id is empty. Use the console's metadata address, for example https://enterplace.example.com/console/saml/metadata, and enter the same value as the audience (SP entity ID) at the identity provider.",
            at("sp_entity_id")
        ));
    }
    if !secure_url(&saml.acs_url) || !saml.acs_url.ends_with("/console/saml/acs") {
        errors.push(format!(
            "{}: acs_url must be the console's assertion consumer service at its public https address, for example https://enterplace.example.com/console/saml/acs, and be entered as the ACS (reply) URL at the identity provider.",
            at("acs_url")
        ));
    }
    if saml.allowed_domains.is_empty() && saml.allowed_emails.is_empty() {
        errors.push(format!(
            "{}:{start}: saml lets nobody in. Add allowed_domains (for example [example.com]) or allowed_emails, so only your people can sign in.",
            file.display()
        ));
    }
    if saml.role_attribute.trim().is_empty()
        || (saml.admin_values.is_empty() && saml.read_only_values.is_empty())
    {
        errors.push(format!(
            "{}: saml gives nobody a role. Set role_attribute to the assertion attribute that holds groups (for example groups), and list the values that make a console admin in admin_values and read-only viewers in read_only_values.",
            at("role_attribute")
        ));
    }
    let lower = |list: &[String]| -> Vec<String> {
        list.iter().map(|v| v.trim().to_ascii_lowercase()).collect()
    };
    let self_issue = saml
        .self_issue
        .as_ref()
        .map(|si| self_issue(si, &at, errors));
    (errors.len() == before).then(|| Saml {
        idp_entity_id: saml.idp_entity_id.clone(),
        idp_sso_url: saml.idp_sso_url.clone(),
        idp_certificates,
        sp_entity_id: saml.sp_entity_id.clone(),
        acs_url: saml.acs_url.clone(),
        email_attribute: saml
            .email_attribute
            .clone()
            .filter(|a| !a.trim().is_empty()),
        role_attribute: saml.role_attribute.clone(),
        admin_values: saml.admin_values.clone(),
        read_only_values: saml.read_only_values.clone(),
        allowed_domains: lower(&saml.allowed_domains),
        allowed_emails: lower(&saml.allowed_emails),
        self_issue,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SsoFile {
    issuer: String,
    client_id: String,
    client_secret_env: String,
    redirect_url: String,
    #[serde(default)]
    allowed_domains: Vec<String>,
    #[serde(default)]
    allowed_emails: Vec<String>,
    role_claim: String,
    #[serde(default)]
    admin_values: Vec<String>,
    #[serde(default)]
    read_only_values: Vec<String>,
    #[serde(default)]
    self_issue: Option<SelfIssueFile>,
    /// Space separated, as OpenID Connect writes it.
    #[serde(default)]
    scopes: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelfIssueFile {
    #[serde(default)]
    allowed_domains: Vec<String>,
    #[serde(default)]
    allowed_emails: Vec<String>,
    #[serde(default)]
    team: Option<String>,
    #[serde(default)]
    expires_days: Option<u32>,
}

/// Who may get a personal key of their own with `enterplace login`, as checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelfIssue {
    /// Lower case, as `Sso::allowed_domains`.
    pub allowed_domains: Vec<String>,
    pub allowed_emails: Vec<String>,
    /// The team the keys are in when `teams:` puts the person in none. `developers` unless set.
    pub team: String,
    /// Whether `team` was written. When the policy's `teams:` place people by email or group, a person they place
    /// nowhere gets a key only in a team written here.
    pub team_set: bool,
    /// Days a key works. 30 unless set.
    pub expires_days: u32,
}

/// Console sign-in through an OpenID Connect provider, as checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sso {
    /// Exactly as written: the ID token's `iss` must equal it.
    pub issuer: String,
    pub client_id: String,
    /// The name of the environment variable that holds the client secret. The secret never goes in the file.
    pub client_secret_env: String,
    /// Where the provider sends the browser back: the console's `/console/sso/callback` at its public address.
    pub redirect_url: String,
    /// Lower case. An email is let in when its domain is here or the whole address is in `allowed_emails`.
    pub allowed_domains: Vec<String>,
    pub allowed_emails: Vec<String>,
    /// The ID token claim, a string or a list of strings, whose values give the console role.
    pub role_claim: String,
    pub admin_values: Vec<String>,
    pub read_only_values: Vec<String>,
    /// `enterplace login` issues keys only when this is set.
    pub self_issue: Option<SelfIssue>,
    /// The scopes asked for at the authorization endpoint. `openid email profile` unless set; some providers send
    /// a groups claim only when `groups` is asked for too.
    pub scopes: Vec<String>,
}

/// An address Enterplace may send a secret or trust a key from: https, or http to this machine for a provider run beside it.
pub fn secure_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return url.starts_with("https://") && url.len() > "https://".len();
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => authority.rsplit_once(':').map_or(authority, |(h, _)| h),
    };
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn console_sso(
    file: &Path,
    text: &str,
    parsed: &PolicyFile,
    errors: &mut Vec<String>,
) -> Option<Sso> {
    let sso = parsed.console.as_ref()?.sso.as_ref()?;
    let before = errors.len();
    let start = line_of_key(text, "sso", 1, usize::MAX);
    let at = |key: &str| {
        format!(
            "{}:{}",
            file.display(),
            line_of_key(text, key, start, usize::MAX)
        )
    };
    if !secure_url(&sso.issuer) {
        errors.push(format!(
            "{}: the sso issuer must be an https URL, for example https://login.example.com. Plain http is accepted only for a provider on this machine (localhost or 127.0.0.1).",
            at("issuer")
        ));
    }
    if sso.client_id.trim().is_empty() {
        errors.push(format!(
            "{}: client_id is empty. Copy the client ID of the console's app registration at the identity provider.",
            at("client_id")
        ));
    }
    let env = &sso.client_secret_env;
    if env.is_empty() || !env.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        errors.push(format!(
            "{}: client_secret_env is the name of an environment variable, for example ENTERPLACE_SSO_SECRET. The secret itself never goes in this file.",
            at("client_secret_env")
        ));
    }
    if !secure_url(&sso.redirect_url) || !sso.redirect_url.ends_with("/console/sso/callback") {
        errors.push(format!(
            "{}: redirect_url must be the console's callback at its public https address, for example https://enterplace.example.com/console/sso/callback, and be registered as a redirect URI at the identity provider.",
            at("redirect_url")
        ));
    }
    if sso.allowed_domains.is_empty() && sso.allowed_emails.is_empty() {
        errors.push(format!(
            "{}:{start}: sso lets nobody in. Add allowed_domains (for example [example.com]) or allowed_emails, so only your people can sign in.",
            file.display()
        ));
    }
    if sso.role_claim.trim().is_empty()
        || (sso.admin_values.is_empty() && sso.read_only_values.is_empty())
    {
        errors.push(format!(
            "{}: sso gives nobody a role. Set role_claim to the ID token claim that holds groups or roles (for example groups), and list the values that make a console admin in admin_values and read-only viewers in read_only_values.",
            at("role_claim")
        ));
    }
    let lower = |list: &[String]| -> Vec<String> {
        list.iter().map(|v| v.trim().to_ascii_lowercase()).collect()
    };
    let self_issue = sso
        .self_issue
        .as_ref()
        .map(|si| self_issue(si, &at, errors));
    let scopes: Vec<String> = sso
        .scopes
        .as_deref()
        .unwrap_or("openid email profile")
        .split_whitespace()
        .map(str::to_string)
        .collect();
    // RFC 6749 section 3.3: a scope token is printable ASCII without space, double quote or backslash.
    if !scopes.iter().any(|s| s == "openid")
        || scopes.iter().any(|s| {
            !s.bytes()
                .all(|b| (0x21..=0x7e).contains(&b) && b != b'"' && b != b'\\')
        })
    {
        errors.push(format!(
            "{}: scopes must be space separated scope names that include openid, for example \"openid email profile groups\".",
            at("scopes")
        ));
    }
    (errors.len() == before).then(|| Sso {
        issuer: sso.issuer.clone(),
        client_id: sso.client_id.clone(),
        client_secret_env: env.clone(),
        redirect_url: sso.redirect_url.clone(),
        allowed_domains: lower(&sso.allowed_domains),
        allowed_emails: lower(&sso.allowed_emails),
        role_claim: sso.role_claim.clone(),
        admin_values: sso.admin_values.clone(),
        read_only_values: sso.read_only_values.clone(),
        self_issue,
        scopes,
    })
}

/// `self_issue` under `console.sso` or `console.saml`, as checked.
fn self_issue(
    si: &SelfIssueFile,
    at: &dyn Fn(&str) -> String,
    errors: &mut Vec<String>,
) -> SelfIssue {
    let lower = |list: &[String]| -> Vec<String> {
        list.iter().map(|v| v.trim().to_ascii_lowercase()).collect()
    };
    if si.allowed_domains.is_empty() && si.allowed_emails.is_empty() {
        errors.push(format!(
            "{}: self_issue lets nobody get a key. Add allowed_domains (for example [example.com]) or allowed_emails.",
            at("self_issue")
        ));
    }
    let team = si.team.clone().unwrap_or_else(|| "developers".into());
    if !valid_name(&team) {
        errors.push(format!(
            "{}: self_issue team \"{team}\" uses letters, digits, dots, dashes, underscores and @ only.",
            at("self_issue")
        ));
    }
    let expires_days = si.expires_days.unwrap_or(30);
    if !(1..=365).contains(&expires_days) {
        errors.push(format!(
            "{}: expires_days is {expires_days}. A key from enterplace login works 1 to 365 days; 30 is usual.",
            at("expires_days")
        ));
    }
    SelfIssue {
        allowed_domains: lower(&si.allowed_domains),
        allowed_emails: lower(&si.allowed_emails),
        team_set: si.team.is_some(),
        team,
        expires_days,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeysFile {
    #[serde(default)]
    keys: Vec<KeyFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    name: String,
    team: String,
    sha256: String,
    /// May sign in to the console. Optional so every keys file written before it still loads.
    #[serde(default)]
    admin: bool,
    /// The key stops working from this UTC date or time on.
    #[serde(default)]
    expires: Option<String>,
    /// Most this one key may spend, apart from any budget of its rule.
    #[serde(default)]
    budget: Option<BudgetFile>,
    /// The models this key may use, within its rule's.
    #[serde(default)]
    models: Option<Vec<String>>,
    /// Most tokens this key may use per minute.
    #[serde(default)]
    tpm: Option<i64>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    customer: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    parallel: Option<i64>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    rpm: Option<i64>,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
    #[serde(default)]
    routes: Vec<String>,
    #[serde(default)]
    from: Vec<String>,
    #[serde(default)]
    replaced_by: Option<String>,
    #[serde(default)]
    mcp_tools: Vec<String>,
    /// Guardrails this key adds to its rule's, by name.
    #[serde(default)]
    guardrails: Vec<String>,
}

/// One entry of a keys file, as checked.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyEntry {
    pub name: String,
    pub team: String,
    /// The SHA-256 of the key, in hex.
    pub sha256: String,
    pub admin: bool,
    /// `2026-12-31` or `2026-12-31T18:00:00Z`, UTC: the key is refused from then on.
    pub expires: Option<String>,
    pub budget: Option<Budget>,
    pub models: Option<Vec<String>>,
    pub tpm: Option<u32>,
    /// The key's organization, empty in an install without organizations.
    pub org: String,
    /// The end customer every request with the key is for.
    pub customer: Option<String>,
    /// Tags every request with the key carries.
    pub tags: Vec<String>,
    /// Most requests the key may have in flight at once.
    pub parallel: Option<u32>,
    /// The console role the key signs in with.
    pub role: Option<String>,
    pub options: KeyOptions,
}

/// Most routes or address ranges on one key or rule, and most metadata entries on one key: enough for any real
/// use, and small enough that a key entry stays readable and its record small.
pub const MAX_LIST: usize = 32;

/// The longest metadata value: a ticket link or a cost center, not a document.
pub const MAX_METADATA_VALUE: usize = 256;

/// What is wrong with a key's options, or `None`. Shared by the keys file loader and the admin API, so both refuse
/// the same things with the same words.
pub fn key_options_problem(options: &KeyOptions) -> Option<String> {
    if options.rpm.is_some_and(|n| !(1..=1_000_000).contains(&n)) {
        return Some(
            "rpm is the requests this key may send per minute, 1 to 1000000, for example rpm: 60"
                .into(),
        );
    }
    if options.routes.len() > MAX_LIST
        || options.routes.iter().any(|r| {
            !r.starts_with('/')
                || r.contains("..")
                || r.chars().any(|c| c.is_whitespace() || c.is_control())
        })
    {
        return Some(format!(
            "routes lists at most {MAX_LIST} path prefixes, each starting with /, for example routes: [/v1/chat/completions, /v1/messages]"
        ));
    }
    if options.from.len() > MAX_LIST {
        return Some(format!("from lists at most {MAX_LIST} address ranges"));
    }
    if options.mcp_tools.len() > MAX_LIST
        || options
            .mcp_tools
            .iter()
            .any(|t| !crate::mcp::narrowing_entry(t))
    {
        return Some(format!(
            "mcp_tools lists at most {MAX_LIST} MCP tools, each <server>.<tool>, <server>.* or *, or !<server>.<tool> to deny one, for example mcp_tools: [github.*, \"!github.delete_repo\"]"
        ));
    }
    if options.guardrails.len() > MAX_LIST || options.guardrails.iter().any(|g| !valid_name(g)) {
        return Some(format!(
            "guardrails lists at most {MAX_LIST} guardrails this key adds to its rule's, each by the name it has under guardrails in the policy, for example guardrails: [no-secrets]"
        ));
    }
    if options.metadata.len() > MAX_LIST
        || options.metadata.iter().any(|(k, v)| {
            !valid_name(k)
                || v.chars().count() > MAX_METADATA_VALUE
                || v.chars().any(char::is_control)
        })
    {
        return Some(format!(
            "metadata holds at most {MAX_LIST} entries, each name in letters, digits, '.', '-', '_' and '@' and each value at most {MAX_METADATA_VALUE} characters on one line, for example metadata: {{ owner: maya, ticket: OPS-12 }}"
        ));
    }
    if options
        .replaced_by
        .as_ref()
        .is_some_and(|p| p.len() != 8 || !p.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Some("replaced_by is the 8 hex characters of the key that replaced this one; `enterplace key rotate` writes it. Remove it to end the rotation".into());
    }
    None
}

/// Address ranges as written, or what is wrong with the first that is not one.
pub fn cidrs(list: &[String]) -> Result<Vec<Cidr>, String> {
    list.iter().map(|c| c.parse::<Cidr>()).collect()
}

/// The most requests in flight a `parallel:` may allow.
const MAX_PARALLEL: i64 = 100_000;

/// A `parallel:` value, or what is wrong with it.
fn parallel_of(n: i64, at: &str, errors: &mut Vec<String>) -> Option<u32> {
    match u32::try_from(n) {
        Ok(n) if (1..=MAX_PARALLEL).contains(&i64::from(n)) => Some(n),
        _ => {
            errors.push(format!(
                "{at}: parallel is the most requests that may be in flight at once, 1 to {MAX_PARALLEL}, for example parallel: 10. To set no limit, remove it."
            ));
            None
        }
    }
}

/// The most tags one request may carry, from its key and its header together.
pub const MAX_TAGS: usize = 16;

/// The tokens-per-minute limit `tpm` names, or what is wrong with it. `at` names where it is written.
/// A provider's `auth` and `identity`, checked. Returns whether it is a passthrough provider.
fn provider_auth(
    entry: &ProviderFile,
    kind: Option<Kind>,
    at: &dyn Fn(&str) -> String,
    errors: &mut Vec<String>,
) -> bool {
    let passthrough = match entry.auth.as_deref() {
        None | Some("key") => false,
        Some("passthrough") => true,
        Some(other) => {
            errors.push(format!(
                "{}: auth is \"{other}\". It is key (the default: Enterplace sends the provider key the policy names) or passthrough (each caller's own login, such as a Claude or ChatGPT subscription, is sent on unchanged and Enterplace holds no key).",
                at("auth")
            ));
            false
        }
    };
    if passthrough {
        if kind.is_some_and(|k| !matches!(k, Kind::Anthropic | Kind::OpenAi)) {
            errors.push(format!(
                "{}: auth: passthrough is for a provider of kind anthropic (Claude Code on a Claude subscription, url https://api.anthropic.com) or kind openai (Codex on a ChatGPT subscription, url https://chatgpt.com/backend-api/codex). Use one of those, or remove auth.",
                at("auth")
            ));
        }
        if entry.key_env.is_some()
            || entry.key_file.is_some()
            || entry.credential.is_some()
            || !entry.keys.is_empty()
            || entry.oci_signing.is_some()
        {
            errors.push(format!(
                "{}: provider \"{}\" has auth: passthrough, so it sends each caller's own login and never a key of Enterplace's. Remove key_env, key_file, credential and keys from it, or remove auth: passthrough and keep the key.",
                at("auth"),
                entry.name
            ));
        }
    }
    match (entry.identity.as_deref(), passthrough) {
        (None, _) | (Some("required" | "optional"), true) => {}
        (Some(_), false) => errors.push(format!(
            "{}: identity applies only to a provider with auth: passthrough, where it says whether a request must name its person in x-enterplace-user. Remove it, or add auth: passthrough.",
            at("identity")
        )),
        (Some(other), true) => errors.push(format!(
            "{}: identity is \"{other}\". It is required (the default: a request must name its person with a Enterplace person token in x-enterplace-user) or optional (a request without one is recorded as an unknown person, by its session).",
            at("identity")
        )),
    }
    passthrough
}

fn tpd_of(tpd: i64, at: &str, errors: &mut Vec<String>) -> Option<u32> {
    match u32::try_from(tpd) {
        Ok(tpd) if tpd >= 1 => Some(tpd),
        _ => {
            errors.push(format!(
                "{at}: tpd is the number of tokens (prompt and answer) that may be used per calendar day (UTC), 1 to 4294967295, for example tpd: 2000000. To set no limit, remove it."
            ));
            None
        }
    }
}

fn tpm_of(tpm: i64, at: &str, errors: &mut Vec<String>) -> Option<u32> {
    match u32::try_from(tpm) {
        Ok(tpm) if (1..=1_000_000_000).contains(&tpm) => Some(tpm),
        _ => {
            errors.push(format!(
                "{at}: tpm is the number of tokens (prompt and answer) that may be used per minute, 1 to 1000000000, for example tpm: 200000. To set no limit, remove it."
            ));
            None
        }
    }
}

/// Whether `text` is a UTC date (`2026-12-31`) or time (`2026-12-31T18:00:00Z`) that `expires` takes. Written this
/// way, it compares with the audit log's timestamps as text, so the hot path needs no date arithmetic.
fn expiry_shape(text: &str) -> bool {
    let b = text.as_bytes();
    let digits = |r: std::ops::Range<usize>| {
        b.get(r.clone())
            .is_some_and(|d| d.iter().all(u8::is_ascii_digit))
            && text[r].parse::<u32>().is_ok()
    };
    let num = |r: std::ops::Range<usize>| text[r].parse::<u32>().unwrap_or(99);
    let date = b.len() >= 10
        && digits(0..4)
        && b[4] == b'-'
        && digits(5..7)
        && b[7] == b'-'
        && digits(8..10)
        && (1..=12).contains(&num(5..7))
        && (1..=31).contains(&num(8..10));
    let time = b.len() == 20
        && b[10] == b'T'
        && digits(11..13)
        && b[13] == b':'
        && digits(14..16)
        && b[16] == b':'
        && digits(17..19)
        && b[19] == b'Z'
        && num(11..13) < 24
        && num(14..16) < 60
        && num(17..19) < 60;
    date && (b.len() == 10 || time)
}

/// Whether `text` is an expiry a keys file may hold: the shape of a UTC date or time, on a day its month has.
pub fn valid_expiry(text: &str) -> bool {
    expiry_shape(text) && missing_day(text).is_none()
}

/// "2026-02-30 is not a date: February 2026 has 28 days", for a day the month does not have.
fn missing_day(text: &str) -> Option<String> {
    const MONTHS: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    let (year, month, day) = (
        text.get(0..4)?.parse::<u32>().ok()?,
        text.get(5..7)?.parse::<usize>().ok()?,
        text.get(8..10)?.parse::<u32>().ok()?,
    );
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let last = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    let name = MONTHS.get(month.checked_sub(1)?)?;
    (day > last).then(|| {
        format!(
            "{} is not a date: {name} {year} has {last} days",
            &text[..10]
        )
    })
}

/// Whether a key may be issued with this expiry now: a date that exists and has not passed. A past one would make a
/// key that is refused on its first request. The message names the cause and the fix, without a leading option name.
pub fn issuable_expiry(text: &str) -> Result<(), String> {
    if !expiry_shape(text) {
        return Err(format!(
            "expires is \"{text}\". It takes a UTC date or time, for example 2026-12-31 or 2026-12-31T18:00:00Z"
        ));
    }
    if let Some(missing) = missing_day(text) {
        return Err(format!("expires {missing}. Write a day that exists"));
    }
    let now = crate::audit::timestamp();
    if crate::policy::expiry_passed(text, &now) {
        return Err(format!(
            "expires {text} has passed (it is {} UTC now), so the key would be refused on its first request. Give a later date",
            &now[..now.len().min(19)]
        ));
    }
    Ok(())
}

/// Reads a budget's `per`, `tz` and `usd`, or says what is wrong with them. `at` names where the budget is written.
fn budget_of(budget: &BudgetFile, at: &str, errors: &mut Vec<String>) -> Option<Budget> {
    let per = match Period::parse(&budget.per.text(), budget.tz.as_deref()) {
        Ok(per) => Some(per),
        Err(problem) => {
            errors.push(format!("{at}: {problem}"));
            None
        }
    };
    if !budget.usd.is_finite() || budget.usd <= 0.0 {
        errors.push(format!(
            "{at}: usd must be a number of US dollars above 0, for example budget: {{ usd: 2000, per: month }}. To set no budget, remove the line."
        ));
        return None;
    }
    per.map(|per| Budget {
        usd: budget.usd,
        per,
    })
}

/// The budgets of a rule or profile, with their model lists. Two that count the same models over the same period
/// would be one counter with two limits: refused.
fn caps_of(
    budgets: &BudgetsFile,
    groups: &BTreeMap<String, Vec<String>>,
    at: &str,
    path: &str,
    from: Option<&str>,
    errors: &mut Vec<String>,
) -> Vec<Cap> {
    let mut caps: Vec<Cap> = Vec::new();
    for (j, file) in budgets.list().iter().enumerate() {
        let path = match budgets {
            BudgetsFile::One(_) => format!("{path}.shadow_until"),
            BudgetsFile::Many(_) => format!("{path}[{j}].shadow_until"),
        };
        if file.per.text() == "session" {
            // A rule's session budget is read by `limits`. Anywhere else it has no session to count.
            if !path.starts_with("rules[") {
                errors.push(format!(
                    "{at}: per: session belongs on a rule's budget: it counts each session of the rule's callers. Move it to the rule."
                ));
            }
            continue;
        }
        let shadow_until = shadow_of(&file.shadow_until, at, &path, errors);
        let Some(budget) = budget_of(file, at, errors) else {
            continue;
        };
        let mut models = with_groups(&file.models, groups, at, errors);
        models.sort();
        if caps
            .iter()
            .any(|c| c.budget.per == budget.per && c.models == models)
        {
            errors.push(format!(
                "{at}: two budgets count the same models over the same period ({}). Keep one, or give one of them other models.",
                budget.per.describe()
            ));
            continue;
        }
        caps.push(Cap {
            budget,
            models,
            from: from.map(str::to_string),
            shadow_until,
        });
    }
    caps
}

/// A `shadow_until`, checked: a UTC date or time. `path` names it in the policy, as `rules[0].budget.shadow_until`.
fn shadow_of(
    until: &Option<String>,
    at: &str,
    path: &str,
    errors: &mut Vec<String>,
) -> Option<String> {
    match until {
        Some(text) if !valid_expiry(text) => {
            errors.push(format!(
                "{at}: {path} is \"{text}\". Write a UTC date or time, for example 2026-12-31 or 2026-12-31T18:00:00Z: until then what it would refuse is forwarded and recorded as would_refuse."
            ));
            None
        }
        other => other.clone(),
    }
}

/// Budgets of a scope, where model lists have no place: the scope says what counts.
fn scope_budgets(budgets: &BudgetsFile, at: &str, errors: &mut Vec<String>) -> Vec<Budget> {
    let mut out: Vec<Budget> = Vec::new();
    for file in budgets.list() {
        if file.shadow_until.is_some() {
            errors.push(format!(
                "{at}: shadow_until on a budget of a limits entry shadows only that budget, and the entry's other limits would still refuse. Write shadow_until on the entry itself, next to budget."
            ));
        }
        if !file.models.is_empty() {
            errors.push(format!(
                "{at}: models on a budget belongs in a rule or a profile. Here, add an entry with model: <name> to the limits list instead."
            ));
        }
        if let Some(budget) = budget_of(file, at, errors) {
            if out.iter().any(|b| b.per == budget.per) {
                errors.push(format!(
                    "{at}: two budgets over the same period ({}). Keep one.",
                    budget.per.describe()
                ));
                continue;
            }
            out.push(budget);
        }
    }
    out
}

/// Which API a provider speaks, and so which routes reach it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Kind {
    /// The chat completions API.
    #[default]
    OpenAi,
    /// The messages API.
    Anthropic,
    /// Azure OpenAI: the chat completions API, one deployment per model, keyed by `api-key`.
    Azure,
    /// Amazon Bedrock's InvokeModel for Anthropic models: the messages API, signed with AWS Signature Version 4.
    Bedrock,
    /// Google's Gemini API (generateContent), keyed by `x-goog-api-key`. Callers use the chat completions route,
    /// translated both ways.
    Gemini,
    /// Gemini on Google Cloud Vertex AI: the same body as `Gemini`, with an OAuth access token as a Bearer token.
    Vertex,
    /// Claude on Google Cloud Vertex AI: the messages body sent to rawPredict or streamRawPredict, with an OAuth
    /// access token as a Bearer token.
    VertexAnthropic,
    /// Amazon Bedrock's Converse and ConverseStream for every model family Bedrock serves through them (Anthropic,
    /// Meta, Mistral, Cohere, Amazon Nova, AI21, DeepSeek, Qwen, OpenAI gpt-oss), signed with AWS Signature Version 4.
    /// Callers use the chat completions route, translated both ways; embeddings go to InvokeModel (Titan, Cohere).
    BedrockConverse,
    /// Cohere's own API (v2 chat, embed and rerank), keyed by a Bearer token. Chat is translated both ways.
    Cohere,
    /// IBM watsonx.ai (text/chat and text/embeddings), with an IAM token Enterplace trades the API key for.
    Watsonx,
    /// Model Garden models on Vertex AI behind its OpenAI-compatible endpoint (`.../endpoints/openapi`), with an
    /// OAuth access token as a Bearer token.
    VertexOpenAi,
    /// An Amazon SageMaker real-time endpoint whose container takes the chat completions body (LMI, TGI's Messages
    /// API), reached at InvokeEndpoint and signed with AWS Signature Version 4. Each model maps to an endpoint name.
    Sagemaker,
    /// Replicate's predictions API, keyed by a Bearer token. Chat is translated to a model's `input` and the
    /// prediction is waited for.
    Replicate,
    /// Enterplace's own demo model: answered inside the gateway with a short sample text, never sent anywhere, priced at
    /// zero. It speaks every chat API (chat completions, responses, messages), so a first request works with no key.
    Demo,
}

impl Kind {
    pub fn word(self) -> &'static str {
        match self {
            Kind::OpenAi => "openai",
            Kind::Anthropic => "anthropic",
            Kind::Azure => "azure",
            Kind::Bedrock => "bedrock",
            Kind::Gemini => "gemini",
            Kind::Vertex => "vertex",
            Kind::VertexAnthropic => "vertex_anthropic",
            Kind::BedrockConverse => "bedrock_converse",
            Kind::Cohere => "cohere",
            Kind::Watsonx => "watsonx",
            Kind::VertexOpenAi => "vertex_openai",
            Kind::Sagemaker => "sagemaker",
            Kind::Replicate => "replicate",
            Kind::Demo => "demo",
        }
    }

    /// The kind a policy file names with `word`.
    pub fn from_word(word: &str) -> Option<Kind> {
        [
            Kind::OpenAi,
            Kind::Anthropic,
            Kind::Azure,
            Kind::Bedrock,
            Kind::Gemini,
            Kind::Vertex,
            Kind::VertexAnthropic,
            Kind::BedrockConverse,
            Kind::Cohere,
            Kind::Watsonx,
            Kind::VertexOpenAi,
            Kind::Sagemaker,
            Kind::Replicate,
            Kind::Demo,
        ]
        .into_iter()
        .find(|kind| kind.word() == word)
    }

    /// Google's generateContent body, which chat completions requests are translated to.
    pub fn google(self) -> bool {
        matches!(self, Kind::Gemini | Kind::Vertex)
    }

    /// The API its callers speak, which decides the routes that reach it: `OpenAi` or `Anthropic`.
    pub fn api(self) -> Kind {
        match self {
            Kind::OpenAi
            | Kind::Azure
            | Kind::Gemini
            | Kind::Vertex
            | Kind::BedrockConverse
            | Kind::Cohere
            | Kind::Watsonx
            | Kind::VertexOpenAi
            | Kind::Sagemaker
            | Kind::Replicate
            | Kind::Demo => Kind::OpenAi,
            Kind::Anthropic | Kind::Bedrock | Kind::VertexAnthropic => Kind::Anthropic,
        }
    }

    /// A chat completions request is translated to the provider's own body as it is sent, and its answer back.
    pub fn translates_chat(self) -> bool {
        matches!(
            self,
            Kind::Gemini
                | Kind::Vertex
                | Kind::BedrockConverse
                | Kind::Cohere
                | Kind::Watsonx
                | Kind::Replicate
        )
    }

    /// Signed with AWS Signature Version 4, from the provider's region and model IDs.
    pub fn aws(self) -> bool {
        matches!(
            self,
            Kind::Bedrock | Kind::BedrockConverse | Kind::Sagemaker
        )
    }

    /// Amazon Bedrock, either API: what `/bedrock/` passes through to.
    pub fn bedrock(self) -> bool {
        matches!(self, Kind::Bedrock | Kind::BedrockConverse)
    }

    /// Takes a Google OAuth access token: from key_env, or from Application Default Credentials without one.
    pub fn google_auth(self) -> bool {
        matches!(
            self,
            Kind::Vertex | Kind::VertexAnthropic | Kind::VertexOpenAi
        )
    }
}

/// The one rule for a provider URL, used by `enterplace check` and `enterplace serve` alike: http or https, a host, an
/// optional port and an optional path, and no login, query, fragment or spaces. Returns it without a trailing slash.
pub fn base_url(raw: &str) -> Result<String, String> {
    let fix = "Write it like https://api.openai.com, or with the vendor's path, like https://api.groq.com/openai/v1.";
    // A login, a query or a fragment would be glued onto every request path or leak into error messages.
    if raw.is_empty() || raw.contains(['?', '#', '@', ';']) || raw.contains(char::is_whitespace) {
        return Err(format!(
            "the provider url must be a plain URL, with no login, query, fragment or spaces. {fix}"
        ));
    }
    let url = raw.trim_end_matches('/');
    let not_a_url = || format!("the provider url \"{url}\" is not an http or https URL. {fix}");
    let (scheme, rest) = url.split_once("://").ok_or_else(not_a_url)?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err(not_a_url());
    }
    let authority = rest.split('/').next().unwrap_or_default();
    let (host, port) = match authority.strip_prefix('[') {
        Some(v6) => match v6.split_once(']') {
            Some((host, after)) => (host, after.strip_prefix(':')),
            None => return Err(not_a_url()),
        },
        None => match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        },
    };
    if host.is_empty() {
        return Err(not_a_url());
    }
    if let Some(port) = port
        && !port.parse::<u16>().is_ok_and(|p| p > 0)
    {
        return Err(format!(
            "the provider url \"{url}\" has a port no server can listen on. Use a number from 1 to 65535."
        ));
    }
    Ok(url.to_string())
}

/// Where a request on `route` (such as `/v1/chat/completions?x=1`) goes at `base`, a URL `base_url` accepted.
/// A URL without a path takes the route as it is. A URL with a path ends where the vendor's `/v1` would,
/// so it takes the route after `/v1`: `https://api.groq.com/openai/v1` reaches `/openai/v1/chat/completions`.
pub fn join(base: &str, route: &str) -> String {
    let has_path = base
        .split_once("://")
        .is_some_and(|(_, rest)| rest.contains('/'));
    let route = if has_path {
        route.strip_prefix("/v1").unwrap_or(route)
    } else {
        route
    };
    format!("{base}{route}")
}

/// A provider requests are forwarded to.
#[derive(Clone, Debug)]
pub struct Provider {
    pub name: String,
    pub kind: Kind,
    /// The exact model names this provider serves. A request for a model is sent to the one provider that lists it.
    pub models: Vec<String>,
    /// Base URL, without a trailing slash.
    pub url: String,
    /// Name of the environment variable that holds the provider key. The key itself is never in a file.
    /// Empty for bedrock, which finds AWS credentials through the AWS default chain, and for a vertex provider
    /// that signs in with Google's Application Default Credentials.
    pub key_env: String,
    /// A file that holds the provider key, in place of `key_env`. Enterplace reads it at start and again whenever it
    /// changes, so the key can be rotated without a restart. A relative path is read from where Enterplace runs.
    pub key_file: Option<PathBuf>,
    /// The name of a provider credential kept in the store, sealed under the master key, in place of `key_env`.
    /// A rotation in the console or the admin API reaches every gateway without a restart.
    pub credential: Option<String>,
    pub allow_private: bool,
    /// The name the provider knows each model by: the Azure deployment or the Bedrock model ID.
    pub upstream_models: BTreeMap<String, String>,
    /// Azure's api-version.
    pub api_version: Option<String>,
    /// Bedrock's AWS region.
    pub region: Option<String>,
    /// An IAM role Bedrock requests are signed as, assumed with the credentials Enterplace finds.
    pub role_arn: Option<String>,
    /// The provider a request goes to when this one fails before answering.
    pub fallback: Option<String>,
    /// How many times a failure before the answer starts is tried again on this provider.
    pub retries: u32,
    /// Whether chat completions requests for its models are translated to the messages API.
    pub accept_chat: bool,
    /// Whether messages requests (Claude Code) for its models are translated to the chat completions API.
    pub accept_messages: bool,
    /// For every request to it, unless an alias or deployment says otherwise.
    pub timeouts: Timeouts,
    /// A pool of keys used in turn, in place of `key_env`, `key_file` or `credential`.
    pub keys: Vec<KeySource>,
    /// Picks the key with the fewest requests sent, not the next in turn.
    pub least_used_key: bool,
    /// Each key's share of the pool's requests, by position in `keys`: a key of weight 2 is sent twice as many.
    pub key_weights: Vec<u32>,
    /// How long a key answered 401 or 403 is set aside. `None` is an hour.
    pub key_quarantine_seconds: Option<u64>,
    /// Headers sent with every request to it, each with the environment variable that holds its value.
    pub headers_env: Vec<(String, String)>,
    /// The environment variable that holds the HTTP proxy its requests go through (`http://[user:pass@]host:port`).
    pub proxy_env: Option<String>,
    /// Where the provider's own batch jobs keep their files: Bedrock batch inference and Vertex AI batch prediction.
    pub batch: Option<ProviderBatch>,
    /// watsonx.ai's project.
    pub project_id: Option<String>,
    /// Whether chat completions requests for its models are sent to the Responses API, translated both ways.
    pub chat_as_responses: bool,
    /// Signs requests with an OCI API signing key, in place of a provider key.
    pub oci_signing: Option<OciSigning>,
    /// `auth: passthrough`: Enterplace holds no key for it. Each request carries the caller's own login (a Claude
    /// subscription's OAuth token), sent on unchanged and never kept.
    pub passthrough: bool,
    /// `identity: optional`: a passthrough request without x-enterplace-user is recorded as an unknown person.
    pub identity_optional: bool,
}

/// How a Bedrock or Vertex AI provider runs batches through `/v1/batches`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderBatch {
    /// The bucket and prefix batch inputs and outputs are kept under: `s3://bucket/prefix/` for Bedrock,
    /// `gs://bucket/prefix/` for Vertex AI. Always ends in `/`.
    pub bucket: String,
    /// Bedrock: the service role Bedrock assumes to read and write the bucket.
    pub role_arn: Option<String>,
    /// The provider's batch API, when it is not the one the provider's URL implies.
    pub url: Option<String>,
    /// The S3 or Cloud Storage endpoint, when it is not the public one (a private endpoint or a test).
    pub storage_url: Option<String>,
}

impl ProviderBatch {
    /// The bucket and the prefix inside it, without the scheme.
    pub fn bucket_and_prefix(&self) -> (&str, &str) {
        let rest = self
            .bucket
            .split_once("://")
            .map_or(self.bucket.as_str(), |(_, rest)| rest);
        rest.split_once('/').unwrap_or((rest, ""))
    }
}

/// Everything `enterplace serve` needs from the two files.
#[derive(Clone, Debug)]
pub struct Loaded {
    pub policy: Policy,
    pub providers: Vec<Provider>,
    pub audit_path: PathBuf,
    /// `audit: { per_org: true }`: each organization's records go to a chain of its own (`<log>.orgs/<org>.jsonl`).
    pub audit_per_org: bool,
    pub keys_path: PathBuf,
    pub policy_sha256: String,
    pub keys_sha256: String,
    /// The policy file as it was read. It holds no secrets, so each version's text goes into its audit record.
    pub policy_text: String,
    /// Whether there was a keys file. A new setup may have none yet, which reads as no keys.
    pub keys_file_found: bool,
    /// Console sign-in through an identity provider, when the policy file sets `console.sso`.
    pub sso: Option<Sso>,
    /// Console sign-in through a SAML 2.0 identity provider, when the policy file sets `console.saml`.
    pub saml: Option<Saml>,
    /// Model names callers send that Enterplace serves from one or more deployments.
    pub aliases: Vec<Alias>,
    /// Upstream MCP servers whose tools Enterplace serves at `/mcp`.
    pub mcp: Vec<crate::mcp::Server>,
    /// The shared store, when the policy sets `store:`. Keys and kill switches are then read from it, not files.
    pub store: Option<StoreSetting>,
}

/// "1 provider: openai at https://api.openai.com", for messages.
pub fn describe(providers: &[Provider]) -> String {
    let list: Vec<String> = providers
        .iter()
        .map(|p| format!("{} ({}) at {}", p.name, p.kind.word(), p.url))
        .collect();
    format!(
        "{}: {}",
        crate::count(providers.len(), "provider"),
        list.join(", ")
    )
}

/// Where the keys file is when no path is given: beside the policy file.
pub fn keys_path_for(policy_path: &Path) -> PathBuf {
    policy_path.with_file_name("enterplace.keys.yaml")
}

/// Whether `model` is `pattern`, where each `*` in the pattern stands for any run of characters (`gpt-*`,
/// `claude-*-5`). A pattern with no `*` matches only itself.
pub fn model_matches(pattern: &str, model: &str) -> bool {
    let Some((head, rest)) = pattern.split_once('*') else {
        return pattern == model;
    };
    let Some(mut left) = model.strip_prefix(head) else {
        return false;
    };
    let mut pieces: Vec<&str> = rest.split('*').collect();
    let tail = pieces.pop().unwrap_or_default();
    for piece in pieces {
        match left.find(piece) {
            Some(at) => left = &left[at + piece.len()..],
            None => return false,
        }
    }
    left.len() >= tail.len() && left.ends_with(tail)
}

/// A name that is safe to write into a YAML file and an audit record without quoting.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-@".contains(&b))
}

fn distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut diagonal = row[0];
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let next = (diagonal + usize::from(ca != *cb))
                .min(row[j] + 1)
                .min(row[j + 1] + 1);
            diagonal = row[j + 1];
            row[j + 1] = next;
        }
    }
    row[b.len()]
}

/// Every YAML file Enterplace reads goes through here, so all of them refuse duplicate keys and bound alias
/// expansion (serde-saphyr's defaults), and an error is one plain line for `explain`, not a source snippet.
pub(crate) fn from_yaml<T: serde::de::DeserializeOwned>(
    text: &str,
) -> Result<T, serde_saphyr::Error> {
    serde_saphyr::from_str_with_options(
        text,
        serde_saphyr::options! { with_snippet: false, strict_booleans: true },
    )
}

/// Turns a YAML error into one line: where, what, and the nearest word Enterplace knows.
fn explain(file: &Path, source: &str, err: &serde_saphyr::Error) -> String {
    let at = err.location().map_or_else(
        || file.display().to_string(),
        |l| format!("{}:{}", file.display(), l.line()),
    );
    let full = err.to_string();
    // The parser ends its messages with the place, which is already in front.
    let text = full.split(" at line ").next().unwrap_or(&full);
    if let Some(word) = text
        .split("unknown field `")
        .nth(1)
        .and_then(|rest| rest.split('`').next())
    {
        if KNOWN.contains(&word) {
            // A real key in the wrong place: the parser lists the keys this place takes.
            let here = text
                .split("expected one of ")
                .nth(1)
                .map(|list| list.replace('`', ""))
                .unwrap_or_default();
            return format!(
                "{at}: \"{word}\" does not belong here. The keys here are {here}. Move it to where it belongs, or remove it."
            );
        }
        return unknown_key(&at, word);
    }
    if let Some(word) = text
        .split("missing field `")
        .nth(1)
        .and_then(|rest| rest.split('`').next())
    {
        return format!("{at}: \"{word}\" is missing here. Add it.");
    }
    if let Some(rest) = text.strip_prefix("duplicate mapping key: ") {
        let word = rest.split(',').next().unwrap_or(rest);
        return format!(
            "{at}: \"{word}\" is written twice in the same place. Keep one, so the file says one thing."
        );
    }
    // One budget or a list of them: the parser can only say neither shape matched.
    if text.contains("untagged enum BudgetsFile") {
        let given = err.location().map_or_else(
            || "another kind of value".to_string(),
            |l| {
                let line = usize::try_from(l.line()).unwrap_or(0);
                let column = usize::try_from(l.column()).unwrap_or(0);
                written_at(source, line, column).1
            },
        );
        return format!(
            "{at}: budget is {given}. Write it as budget: {{ usd: 20, per: month }} (tz and, in a rule or profile, models are optional), or a list of them such as budget: [{{ usd: 20, per: day }}, {{ usd: 300, per: month }}]."
        );
    }
    if let Some(wanted) = wanted_kind(text)
        && let Some(l) = err.location()
    {
        // The parser names neither the key nor the value, only where the value starts; both are read back from
        // the file as the person wrote them.
        let line = usize::try_from(l.line()).unwrap_or(0);
        let column = usize::try_from(l.column()).unwrap_or(0);
        let (key, given) = written_at(source, line, column);
        return match wanted_as_written(&key, wanted) {
            Wanted::Example(example) => {
                format!("{at}: {key} is {given}. Write it as {example}.")
            }
            Wanted::Kind(kind) => format!("{at}: {key} must be {kind}, and it is {given}."),
        };
    }
    format!("{at}: this is not valid YAML: {text}.")
}

/// The kind of value the parser wanted, from its message for a value of another kind.
fn wanted_kind(text: &str) -> Option<&'static str> {
    Some(match text {
        "expected mapping start" => "a map",
        "expected sequence start" => "a sequence",
        "expected string scalar" => "a string",
        t if t.starts_with("invalid boolean") => "a boolean",
        "invalid floating point" => "f64",
        "invalid u8" | "invalid u16" | "invalid u32" | "invalid u64" | "invalid usize"
        | "invalid i64" => "u64",
        _ => return None,
    })
}

/// The key that holds the value starting at `line`:`column` (both from 1), and that value described as a person
/// reads it: `integer 5`, `string "x"`, `a list`.
fn written_at(text: &str, line: usize, column: usize) -> (String, String) {
    let lines: Vec<&str> = text.lines().collect();
    let Some(here) = line.checked_sub(1).and_then(|i| lines.get(i)) else {
        return ("this value".into(), "another kind of value".into());
    };
    let start = here
        .char_indices()
        .nth(column.saturating_sub(1))
        .map_or(here.len(), |(i, _)| i);
    let (before, value) = here.split_at(start);
    let inline_key = before.trim_end().strip_suffix(':').and_then(|b| {
        b.rsplit(|c: char| !(c.is_ascii_alphanumeric() || "_-.@\"'".contains(c)))
            .next()
            .map(|k| k.trim_matches(['"', '\'']))
            .filter(|k| !k.is_empty())
    });
    if let Some(key) = inline_key {
        let value = value.split(" #").next().unwrap_or_default().trim_end();
        let value = if value.starts_with(['[', '{']) {
            value
        } else {
            value
                .split([',', '}', ']'])
                .next()
                .unwrap_or_default()
                .trim()
        };
        return (key.to_string(), described(value));
    }
    // A block written on the lines under its key: the key is the nearest line above that ends in a colon.
    let key = lines[..line - 1]
        .iter()
        .rev()
        .map(|l| l.trim_start().trim_start_matches("- "))
        .find(|l| {
            l.split(" #")
                .next()
                .unwrap_or_default()
                .trim_end()
                .ends_with(':')
        })
        .and_then(key_at)
        .unwrap_or("this value");
    let given = if here.trim_start().starts_with('-') {
        "a list"
    } else {
        "a map"
    };
    (key.to_string(), given.into())
}

fn described(value: &str) -> String {
    let unquoted = value.trim_matches(['"', '\'']);
    match value {
        "" | "~" | "null" => "empty".into(),
        "true" | "false" => format!("boolean {value}"),
        v if v.starts_with('[') => "a list".into(),
        v if v.starts_with('{') => "a map".into(),
        v if v.parse::<i128>().is_ok() => format!("integer {v}"),
        v if v.parse::<f64>().is_ok_and(f64::is_finite) => format!("floating point {v}"),
        _ => format!("string \"{unquoted}\""),
    }
}

enum Wanted {
    Example(&'static str),
    Kind(&'static str),
}

/// What the parser wanted, said as the file says it: never a Rust type name.
fn wanted_as_written(key: &str, wanted: &str) -> Wanted {
    match (wanted, key) {
        ("a map", "budget") => Wanted::Example("budget: { usd: 20, per: month }"),
        ("a map", "rate") => Wanted::Example("rate: { rpm: 60 }"),
        ("a map", "cache") => Wanted::Example("cache: { ttl_seconds: 300 }"),
        ("a map", "principals") => Wanted::Example("principals: { team: payments }"),
        ("a map", "audit") => Wanted::Example("audit: { path: enterplace-audit.jsonl }"),
        ("a map", "console") => {
            Wanted::Example("console: { sso: { issuer: ..., client_id: ... } }")
        }
        // A map under a key Enterplace does not know by name is a model's price under prices.
        ("a map", k) if !KNOWN.contains(&k) => {
            Wanted::Example("gpt-4o: { input: 2.5, output: 10 }")
        }
        ("a map", _) => {
            Wanted::Kind("a map of keys (key: value lines under it, or { key: value })")
        }
        ("a sequence", _) => Wanted::Kind("a list, such as [a, b]"),
        ("a string", _) => Wanted::Kind("text"),
        ("a boolean", _) => Wanted::Kind("true or false"),
        ("u64", _) => Wanted::Kind("a whole number"),
        ("f64", _) => Wanted::Kind("a number"),
        _ => Wanted::Kind("another kind of value"),
    }
}

fn unknown_key(at: &str, word: &str) -> String {
    let nearest = KNOWN
        .iter()
        .map(|known| (distance(word, known), known))
        // On a tie the word listed first wins: the common policy words come before the guardrail vendors' fields.
        .min_by_key(|(d, _)| *d)
        .filter(|(d, _)| *d <= 2);
    match nearest {
        Some((_, known)) => {
            format!("{at}: \"{word}\" is not a key Enterplace knows. Did you mean \"{known}\"?")
        }
        None => {
            format!(
                "{at}: \"{word}\" is not a key Enterplace knows. Remove it, or check the spelling."
            )
        }
    }
}

/// The key at the start of `text`, if it starts with one: a word, a colon, then a space or the end of the line.
/// `https://` is not a key.
fn key_at(text: &str) -> Option<&str> {
    let text = text.trim_start();
    // A key may be written in quotes. It is the same key.
    let (text, quote) = match text.chars().next() {
        Some(q @ ('"' | '\'')) => (&text[1..], Some(q)),
        _ => (text, None),
    };
    let end = text
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(text.len());
    let after = match quote {
        Some(q) => text[end..].strip_prefix(q)?,
        None => &text[end..],
    };
    let is_key =
        end > 0 && after.starts_with(':') && after[1..].chars().next().is_none_or(|c| c == ' ');
    is_key.then(|| &text[..end])
}

/// The keys written on one line: the one that starts it, and those inside `{ ... }`.
fn keys_on(line: &str) -> Vec<&str> {
    let line = match line.find(" #") {
        Some(at) => &line[..at],
        None => line,
    };
    let mut found = Vec::new();
    let mut start = line.trim_start();
    if start.starts_with('#') {
        return found;
    }
    while let Some(rest) = start.strip_prefix("- ") {
        start = rest.trim_start();
    }
    found.extend(key_at(start));
    let mut depth = 0;
    for (i, c) in line.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => depth -= 1,
            _ => {}
        }
        if c == '{' || (c == ',' && depth > 0) {
            found.extend(key_at(&line[i + 1..]));
        }
    }
    found
}

/// Finds every key Enterplace does not know or does not enforce, each with its line, in one pass over the text.
/// The parser stops at the first one, and a person fixing a file wants the whole list.
fn unknown_keys(file: &Path, text: &str, errors: &mut Vec<String>) -> bool {
    let before = errors.len();
    // The indent of a `FREE_MAPS` line while the lines under it are its map.
    let mut in_map: Option<usize> = None;
    // Under `prices:`, the first keys are model names, which can be any word.
    let (mut in_prices, mut model_depth) = (false, None);
    for (i, line) in text.lines().enumerate() {
        let at = format!("{}:{}", file.display(), i + 1);
        let trimmed = line.trim_start();
        let depth = line.len() - trimmed.len();
        if let Some(indent) = in_map {
            // YAML lets a list sit at its key's own indent (`deployments:` then `- provider: ...`).
            if trimmed.is_empty()
                || trimmed.starts_with('#')
                || depth > indent
                || (depth == indent && trimmed.starts_with("- "))
            {
                continue;
            }
            in_map = None;
        }
        let mut skip = 0;
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            if depth == 0 {
                in_prices = key_at(trimmed) == Some("prices");
                model_depth = None;
            } else if in_prices && *model_depth.get_or_insert(depth) == depth {
                skip = usize::from(key_at(trimmed).is_some());
            }
        }
        for key in keys_on(line).into_iter().skip(skip) {
            if FREE_MAPS.contains(&key) {
                // What follows on this line and under it are names the user chose, not keys.
                in_map = Some(depth);
                break;
            } else if !KNOWN.contains(&key) {
                errors.push(unknown_key(&at, key));
            }
        }
    }
    errors.len() > before
}

/// The text of a keys file, or `None` if there is none yet. Any other failure to read it is an error:
/// a file that exists and cannot be read must never be taken for an empty one.
pub fn read_keys(path: &Path) -> Result<Option<String>, String> {
    // With a store, the keys are in the database, and every reader of the keys file gets them from there.
    if let Some(store) = crate::store::attached(path) {
        return Ok(Some(store.keys_text()));
    }
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!(
            "{}: the keys file exists and cannot be read: {err}. Fix the file or its permissions. Nothing was changed.",
            path.display()
        )),
    }
}

/// The line of each item of the `rules:` list, and the line where the list ends.
// ponytail: found by reading the text, because the YAML parser does not report where a value sits.
// It holds for block lists, which is how the file is written. A span-aware parser replaces it when the console edits policies.
fn rule_lines(text: &str) -> (Vec<usize>, usize) {
    let mut lines = Vec::new();
    let mut inside = false;
    let mut indent = None;
    for (i, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let depth = line.len() - trimmed.len();
        if !inside {
            inside = depth == 0 && trimmed.starts_with("rules:");
            continue;
        }
        if depth == 0 && !trimmed.starts_with("- ") {
            return (lines, i + 1);
        }
        if trimmed.starts_with("- ") && *indent.get_or_insert(depth) == depth {
            lines.push(i + 1);
        }
    }
    (lines, text.lines().count() + 1)
}

pub(crate) fn line_of_key(text: &str, key: &str, from: usize, to: usize) -> usize {
    text.lines()
        .enumerate()
        .skip(from.saturating_sub(1))
        .take_while(|(i, _)| i + 1 < to)
        .find(|(_, line)| {
            line.trim_start()
                .trim_start_matches("- ")
                .strip_prefix(key)
                .is_some_and(|rest| rest.trim_start().starts_with(':'))
        })
        .map_or(from, |(i, _)| i + 1)
}

/// Whether a provider URL points at this machine or a private network, judged by what is written.
// ponytail: a public name that resolves to a private address is not caught here. That check belongs at connect time (package 1.2).
pub fn is_private(url: &str) -> bool {
    let authority = url
        .split("://")
        .nth(1)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or("");
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => authority
            .rsplit_once(':')
            .map_or(authority, |(host, _)| host),
    };
    // A name may end in a dot and still be the same host.
    let host = host.strip_suffix('.').unwrap_or(host);
    let v4 = |ip: std::net::Ipv4Addr| {
        let [a, b, ..] = ip.octets();
        ip.is_loopback()
            || ip.is_private()
            || ip.is_link_local()
            || ip.is_unspecified()
            // Shared address space, used by carrier NAT and some cloud networks.
            || (a == 100 && b & 0xc0 == 64)
    };
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => v4(ip),
        Ok(IpAddr::V6(ip)) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || (ip.segments()[0] & 0xfe00) == 0xfc00
                || (ip.segments()[0] & 0xffc0) == 0xfe80
                || ip.to_ipv4_mapped().is_some_and(v4)
        }
        Err(_) => {
            // `127.1`, `2130706433` and `0x7f.1` are addresses too, to the resolver. Enterplace does not work out which
            // one, and treats every such spelling as private.
            let numeric = !host.is_empty()
                && host.split('.').all(|part| {
                    !part.is_empty()
                        && (part.bytes().all(|b| b.is_ascii_digit())
                            || part
                                .strip_prefix("0x")
                                .or_else(|| part.strip_prefix("0X"))
                                .is_some_and(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit())))
                });
            numeric
                || host.eq_ignore_ascii_case("localhost")
                || host.to_ascii_lowercase().ends_with(".localhost")
        }
    }
}

fn read(path: &Path, what: &str) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map_err(|err| format!("{}: the {what} cannot be read: {err}.", path.display()))
}

fn policy_rules(
    file: &Path,
    text: &str,
    parsed: &PolicyFile,
    errors: &mut Vec<String>,
) -> Vec<Rule> {
    let (lines, end) = rule_lines(text);
    let mut rules = Vec::new();
    for (i, application) in parsed.applications.iter().enumerate() {
        let name = &application.name;
        if !valid_name(name) || parsed.applications[..i].iter().any(|a| a.name == *name) {
            errors.push(format!(
                "{}: applications names \"{name}\", which is defined twice or is not a name Enterplace accepts. Give each application its own name in letters, digits, dots, dashes, underscores and @, at most 100 characters.",
                file.display()
            ));
        }
        if application
            .intent
            .as_deref()
            .is_some_and(|i| !crate::events::intent_ok(i))
        {
            errors.push(format!(
                "{}: application \"{name}\": intent is one line of at most {} characters saying what the application is for. Shorten it, and take out line breaks.",
                file.display(),
                crate::events::MAX_INTENT
            ));
        }
    }
    for (i, rule) in parsed.rules.iter().enumerate() {
        let line = lines.get(i).copied().unwrap_or(0);
        let until = lines.get(i + 1).copied().unwrap_or(end);
        let at = |key: &str| format!("{}:{}", file.display(), line_of_key(text, key, line, until));
        if !valid_name(&rule.name) {
            errors.push(format!(
                "{}: a rule name uses letters, digits, dots, dashes, underscores and @ only, at most 100 characters.",
                at("name")
            ));
        }
        let p = &rule.principals;
        let who = match (&p.team, &p.name, &p.tag, p.any) {
            (Some(team), None, None, None) => Who::Team(team.clone()),
            (None, Some(name), None, None) => Who::Name(name.clone()),
            (None, None, Some(tag), None) => Who::Tag(tag.clone()),
            (None, None, None, Some(true)) => Who::Any,
            _ => {
                errors.push(format!(
                    "{}: principals must be exactly one of {{ team: <team> }}, {{ name: <person or workload> }}, {{ tag: <tag on the key> }} or {{ any: true }}.",
                    at("principals")
                ));
                continue;
            }
        };
        let own_models = match (&rule.models, rule.profiles.is_empty()) {
            (Some(models), _) => models.clone(),
            (None, false) => Vec::new(),
            (None, true) => {
                errors.push(format!(
                    "{}: \"models\" is missing here. Add it: the models the rule allows, [\"*\"] for all or [] for none, or include a profile that lists them.",
                    at("name")
                ));
                continue;
            }
        };
        let mut profiles = Vec::new();
        for name in &rule.profiles {
            match parsed.profiles.iter().find(|p| p.name == *name) {
                Some(profile) => profiles.push(profile),
                None => errors.push(format!(
                    "{}: rule \"{}\" includes profile \"{name}\", which is not defined under profiles. Define it there, or check the spelling. The profiles are: {}.",
                    at("profiles"),
                    rule.name,
                    names_or_none(parsed.profiles.iter().map(|p| p.name.as_str()))
                )),
            }
        }
        let own_models = with_groups(&own_models, &parsed.model_groups, &at("models"), errors);
        let mut all_models = own_models.clone();
        for profile in &profiles {
            for model in &with_groups(
                &profile.models,
                &parsed.model_groups,
                &at("profiles"),
                errors,
            ) {
                if !all_models.contains(model) {
                    all_models.push(model.clone());
                }
            }
        }
        let wildcard = all_models.iter().any(|m| m == "*");
        if own_models.iter().any(|m| m == "*") && own_models.len() > 1 {
            errors.push(format!(
                "{}: \"*\" already allows every model. List it alone, or list the models by name.",
                at("models")
            ));
        }
        let models = if wildcard {
            Models::Any
        } else {
            Models::Only(all_models)
        };
        let mut limits = limits(rule, i, &parsed.model_groups, &at, errors);
        let mut overrides = Vec::new();
        for profile in &profiles {
            merge_profile(
                profile,
                &parsed.model_groups,
                &mut limits,
                &mut overrides,
                &at("profiles"),
            );
        }
        let mut tools = rule.tools.clone();
        for profile in &profiles {
            for tool in &profile.tools {
                if !tools.contains(tool) {
                    tools.push(tool.clone());
                }
            }
        }
        crate::mcp::check_tools(&at("tools"), &tools, &parsed.mcp, errors);
        let tool_strip = match rule.tool_action.as_deref() {
            None | Some("block") => false,
            Some("strip") => true,
            Some(other) => {
                errors.push(format!(
                    "{}: tool_action is \"{other}\". Write block (refuse a request or answer with a function tool tools: does not allow) or strip (take the tool out and send the rest).",
                    at("tool_action")
                ));
                false
            }
        };
        let mcp = crate::mcp::rule(
            &at,
            &crate::mcp::RuleFields {
                prompts: &rule.prompts,
                resources: &rule.resources,
                approve_tools: &rule.approve_tools,
                approval_timeout_seconds: rule.approval_timeout_seconds,
                mcp_clients: &rule.mcp_clients,
            },
            &parsed.mcp,
            errors,
        );
        for (list, what) in [(&rule.tags, "tags"), (&rule.customers, "customers")] {
            if let Some(bad) = list.iter().find(|t| *t != "*" && !valid_name(t)) {
                errors.push(format!(
                    "{}: \"{bad}\" in {what} is not a name Enterplace accepts. Use letters, digits, dots, dashes, underscores and @, at most 100 characters, or \"*\" for any.",
                    at(what)
                ));
            }
        }
        if let Some(org) = &rule.org {
            check_org(&parsed.orgs, org, &at("org"), errors);
        }
        let mut applications = Vec::new();
        for name in &rule.applications {
            let defined = parsed.applications.iter().find(|a| a.name == *name);
            if name != "*" && defined.is_none() {
                errors.push(format!(
                    "{}: application \"{name}\" is not defined under applications. Define it there (- name: {name}, with an intent: line saying what it is for), or write \"*\" to take any name a caller sends in x-enterplace-application.",
                    at("applications")
                ));
            }
            applications.push(crate::events::Application {
                name: name.clone(),
                intent: defined.and_then(|a| a.intent.clone()),
            });
        }
        rules.push(Rule {
            name: rule.name.clone(),
            line,
            who,
            models,
            guardrails: Vec::new(),
            limits,
            passthrough: rule
                .passthrough
                .iter()
                .map(|p| crate::policy::Passthrough {
                    provider: p.provider.clone(),
                    paths: p.paths.clone(),
                })
                .collect(),
            tools,
            tool_strip,
            mcp,
            org: rule.org.clone(),
            profiles: rule.profiles.clone(),
            tags: rule.tags.clone(),
            customers: rule.customers.clone(),
            applications,
            overrides,
            shadow_until: shadow_of(
                &rule.shadow_until,
                &at("shadow_until"),
                &format!("rules[{i}].shadow_until"),
                errors,
            ),
        });
    }
    rules
}

/// "a, b" or "none", for messages that list what is defined.
fn names_or_none<'a>(names: impl Iterator<Item = &'a str>) -> String {
    let names: Vec<&str> = names.collect();
    if names.is_empty() {
        "none".into()
    } else {
        names.join(", ")
    }
}

/// An organization a rule, limit, role or key names must be one `orgs:` lists, so a misspelled one is caught here
/// rather than becoming a tenant of its own.
fn check_org(orgs: &[String], org: &str, at: &str, errors: &mut Vec<String>) {
    if !orgs.iter().any(|o| o == org) {
        errors.push(format!(
            "{at}: organization \"{org}\" is not listed under orgs. Add it to orgs: at the top of the policy, or check the spelling. The organizations are: {}.",
            names_or_none(orgs.iter().map(String::as_str))
        ));
    }
}

/// Adds what a profile sets and the rule does not. The rule's own value wins and the profile's is named as
/// overridden; between profiles, the first listed wins.
fn merge_profile(
    profile: &ProfileFile,
    groups: &BTreeMap<String, Vec<String>>,
    limits: &mut Limits,
    overrides: &mut Vec<String>,
    at: &str,
) {
    let of = format!("of profile \"{}\"", profile.name);
    // The profile's own values were checked once with it (check_profiles): a rule that includes it does not
    // repeat its problems, so they go nowhere here.
    let mut quiet = Vec::new();
    if let Some(budgets) = &profile.budget {
        for cap in caps_of(
            budgets,
            groups,
            at,
            "budget",
            Some(&profile.name),
            &mut quiet,
        ) {
            match limits
                .budgets
                .iter()
                .find(|c| c.budget.per == cap.budget.per && c.models == cap.models)
            {
                Some(kept) => overrides.push(format!(
                    "budget ${} a {} {of}, by {}",
                    cap.budget.usd,
                    cap.budget.per.describe(),
                    kept.from
                        .as_deref()
                        .map_or("the rule".to_string(), |p| format!("profile \"{p}\""))
                )),
                None => limits.budgets.push(cap),
            }
        }
    }
    let rate = profile.rate.as_ref();
    let values = [
        (
            "rpm",
            rate.and_then(|r| r.rpm).and_then(|n| {
                u32::try_from(n)
                    .ok()
                    .filter(|n| (1..=1_000_000).contains(n))
            }),
        ),
        (
            "tpm",
            rate.and_then(|r| r.tpm)
                .and_then(|n| tpm_of(n, at, &mut quiet)),
        ),
        (
            "parallel",
            profile
                .parallel
                .and_then(|n| parallel_of(n, at, &mut quiet)),
        ),
    ];
    for (field, value) in values {
        let Some(value) = value else { continue };
        let slot = match field {
            "rpm" => &mut limits.rpm,
            "tpm" => &mut limits.tpm,
            _ => &mut limits.parallel,
        };
        match slot {
            Some(kept) => {
                let by = limits
                    .inherited
                    .iter()
                    .find(|(f, _)| *f == field)
                    .map_or("the rule".to_string(), |(_, p)| format!("profile \"{p}\""));
                overrides.push(format!("{field} {value} {of}, by {by} ({kept})"));
            }
            None => {
                *slot = Some(value);
                limits.inherited.push((field, profile.name.clone()));
            }
        }
    }
}

/// The `profiles:` list: each name once and valid.
fn check_profiles(file: &Path, text: &str, parsed: &PolicyFile, errors: &mut Vec<String>) {
    let lines = list_lines(text, "profiles");
    for (i, profile) in parsed.profiles.iter().enumerate() {
        let at = format!("{}:{}", file.display(), lines.get(i).copied().unwrap_or(0));
        if !valid_name(&profile.name) {
            errors.push(format!(
                "{at}: a profile name uses letters, digits, dots, dashes, underscores and @ only, at most 100 characters."
            ));
        }
        if parsed.profiles[..i].iter().any(|p| p.name == profile.name) {
            errors.push(format!(
                "{at}: profile \"{}\" is defined twice. Give each profile its own name.",
                profile.name
            ));
        }
        if let Some(budgets) = &profile.budget {
            caps_of(
                budgets,
                &parsed.model_groups,
                &at,
                &format!("profiles[{i}].budget"),
                None,
                errors,
            );
        }
        if let Some(n) = profile.parallel {
            parallel_of(n, &at, errors);
        }
        if let Some(tpm) = profile.rate.as_ref().and_then(|r| r.tpm) {
            tpm_of(tpm, &at, errors);
        }
        if let Some(rate) = &profile.rate {
            if rate.rpm.is_some_and(|n| !(1..=1_000_000).contains(&n)) {
                errors.push(format!(
                    "{at}: rpm is the number of requests one person may send per minute, 1 to 1000000, for example rate: {{ rpm: 600 }}. To set no limit, remove the line."
                ));
            }
        }
    }
}

/// The `limits:` list, each entry checked: exactly one kind of scope, an organization `orgs:` lists, and at least
/// one limit.
fn scope_limits(
    file: &Path,
    text: &str,
    parsed: &PolicyFile,
    errors: &mut Vec<String>,
) -> Vec<ScopeLimit> {
    let lines = list_lines(text, "limits");
    let mut out: Vec<ScopeLimit> = Vec::new();
    for (i, entry) in parsed.limits.iter().enumerate() {
        let line = lines.get(i).copied().unwrap_or(0);
        let at = format!("{}:{line}", file.display());
        let kinds = [
            (ScopeKind::Team, &entry.team),
            (ScopeKind::Person, &entry.person),
            (ScopeKind::Key, &entry.key),
            (ScopeKind::Customer, &entry.customer),
            (ScopeKind::Tag, &entry.tag),
            (ScopeKind::Model, &entry.model),
            (ScopeKind::ModelGroup, &entry.model_group),
        ];
        let named: Vec<(ScopeKind, &String)> = kinds
            .iter()
            .filter_map(|(k, v)| v.as_ref().map(|v| (*k, v)))
            .collect();
        let global = entry.global == Some(true);
        let (kind, name, org) = match (global, named.as_slice(), &entry.org) {
            (true, [], None) => (ScopeKind::Global, String::new(), None),
            (false, [], Some(org)) => (ScopeKind::Org, org.clone(), None),
            (false, [(kind, name)], org) => (*kind, (*name).clone(), org.clone()),
            _ => {
                errors.push(format!(
                    "{at}: a limits entry names one scope: global: true, org: <org> (or \"*\" for each), or one of team, person, key, customer, tag or model (a name, or \"*\" for each), optionally with org: <org> to keep it to one organization."
                ));
                continue;
            }
        };
        if kind != ScopeKind::Global && name != "*" && !valid_name(&name) {
            errors.push(format!(
                "{at}: \"{name}\" is not a name Enterplace accepts. Use letters, digits, dots, dashes, underscores and @, at most 100 characters, or \"*\" for each one."
            ));
        }
        if kind == ScopeKind::Key
            && name != "*"
            && !(name.len() == 8 && name.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            errors.push(format!(
                "{at}: key names a key by the first 8 hex characters of its sha256, as enterplace key list shows them, for example key: 1a2b3c4d."
            ));
        }
        if kind == ScopeKind::Org && name != "*" {
            check_org(&parsed.orgs, &name, &at, errors);
        }
        if kind == ScopeKind::ModelGroup && !parsed.model_groups.contains_key(&name) {
            errors.push(format!(
                "{at}: model_group names \"{name}\", which model_groups does not define. Define it there, or check the spelling. The groups are: {}.",
                names_or_none(parsed.model_groups.keys().map(String::as_str))
            ));
        }
        if let Some(org) = &org {
            check_org(&parsed.orgs, org, &at, errors);
        }
        let budgets = entry
            .budget
            .as_ref()
            .map(|b| scope_budgets(b, &at, errors))
            .unwrap_or_default();
        let (mut rpm, mut tpm, mut rph, mut rpd, mut tpd) = (None, None, None, None, None);
        if let Some(rate) = &entry.rate {
            if let Some(n) = rate.rpm {
                match u32::try_from(n) {
                    Ok(n) if (1..=1_000_000).contains(&n) => rpm = Some(n),
                    _ => errors.push(format!(
                        "{at}: rpm is the number of requests the scope may send per minute, 1 to 1000000, for example rate: {{ rpm: 600 }}."
                    )),
                }
            }
            tpm = rate.tpm.and_then(|n| tpm_of(n, &at, errors));
            tpd = rate.tpd.and_then(|n| tpd_of(n, &at, errors));
            rph = requests_of(rate.rph, "rph", &at, errors);
            rpd = requests_of(rate.rpd, "rpd", &at, errors);
            if rate.session_requests.is_some() {
                errors.push(format!(
                    "{at}: session_requests belongs on a rule's rate: it counts each session of the rule's callers. Move it to the rule."
                ));
            }
        }
        let parallel = entry.parallel.and_then(|n| parallel_of(n, &at, errors));
        if entry.budget.is_none() && entry.rate.is_none() && entry.parallel.is_none() {
            errors.push(format!(
                "{at}: this limits entry sets no limit. Give it budget, rate or parallel, or remove it."
            ));
        }
        if kind == ScopeKind::Key && (rpm.is_some() || rph.is_some() || rpd.is_some()) {
            errors.push(format!(
                "{at}: a key's requests per minute are its person's: use person: <name> for rpm, and tpm, budget or parallel on the key."
            ));
        }
        if let Some(twin) = out
            .iter()
            .find(|e| e.kind == kind && e.name == name && e.org == org)
        {
            errors.push(format!(
                "{at}: the same scope is listed at line {} too. Put its limits in one entry.",
                twin.line
            ));
        }
        out.push(ScopeLimit {
            kind,
            name,
            org,
            line,
            budgets,
            rpm,
            rph,
            rpd,
            tpm,
            tpd,
            parallel,
            shadow_until: shadow_of(
                &entry.shadow_until,
                &at,
                &format!("limits[{i}].shadow_until"),
                errors,
            ),
        });
    }
    out
}

/// The `roles:` list, checked: known permissions, a name that is not a built-in one, an organization `orgs:` lists.
fn roles(file: &Path, text: &str, parsed: &PolicyFile, errors: &mut Vec<String>) -> Vec<Role> {
    let lines = list_lines(text, "roles");
    let mut out: Vec<Role> = Vec::new();
    for (i, role) in parsed.roles.iter().enumerate() {
        let line = lines.get(i).copied().unwrap_or(0);
        let at = format!("{}:{line}", file.display());
        if !valid_name(&role.name) {
            errors.push(format!(
                "{at}: a role name uses letters, digits, dots, dashes, underscores and @ only, at most 100 characters."
            ));
        }
        if crate::policy::builtin_role(&role.name).is_some() {
            errors.push(format!(
                "{at}: \"{}\" is a built-in role. Give yours another name.",
                role.name
            ));
        }
        if out.iter().any(|r| r.name == role.name) {
            errors.push(format!(
                "{at}: role \"{}\" is defined twice. Give each role its own name.",
                role.name
            ));
        }
        let mut permissions = Vec::new();
        for word in &role.permissions {
            match Permission::from_word(word) {
                Some(p) => permissions.push(p),
                None => errors.push(format!(
                    "{at}: \"{word}\" is not a permission. The permissions are: {}.",
                    Permission::ALL.map(Permission::word).join(", ")
                )),
            }
        }
        if let Some(org) = &role.org {
            check_org(&parsed.orgs, org, &at, errors);
        }
        for name in role.teams.iter().chain(&role.customers) {
            if !valid_name(name) || name == "*" {
                errors.push(format!(
                    "{at}: \"{name}\" in role \"{}\" is not a team or customer name: letters, digits, dots, dashes, underscores and @ only, at most 100 characters.",
                    role.name
                ));
            }
        }
        out.push(Role {
            name: role.name.clone(),
            permissions,
            org: role.org.clone(),
            teams: role.teams.clone(),
            customers: role.customers.clone(),
            sso_values: role.sso_values.clone(),
            line,
        });
    }
    out
}

/// The `teams:` list, checked: valid names, each once, members and owners that are emails.
fn teams(file: &Path, text: &str, parsed: &PolicyFile, errors: &mut Vec<String>) -> Vec<Team> {
    let lines = list_lines(text, "teams");
    let mut out: Vec<Team> = Vec::new();
    for (i, team) in parsed.teams.iter().enumerate() {
        let line = lines.get(i).copied().unwrap_or(0);
        let at = format!("{}:{line}", file.display());
        if !valid_name(&team.name) {
            errors.push(format!(
                "{at}: a team name uses letters, digits, dots, dashes, underscores and @ only, at most 100 characters."
            ));
        }
        if out.iter().any(|t| t.name == team.name) {
            errors.push(format!(
                "{at}: team \"{}\" is listed twice under teams. List it once, with all its members.",
                team.name
            ));
        }
        let email = |e: &String| e.trim().to_ascii_lowercase();
        for person in team.members.iter().chain(&team.owner) {
            let e = email(person);
            if !e.contains('@') || e.contains(char::is_whitespace) {
                errors.push(format!(
                    "{at}: \"{person}\" in team \"{}\" is not an email. Members and the owner are named by the email they sign in with.",
                    team.name
                ));
            }
        }
        if let Some(owner) = out
            .iter()
            .flat_map(|t| t.members.iter().map(move |m| (m, &t.name)))
            .find(|(m, _)| team.members.iter().any(|x| email(x) == **m))
        {
            errors.push(format!(
                "{at}: {} is a member of team \"{}\" and of team \"{}\". A person is in one team, so enterplace login knows which team their key is in.",
                owner.0, owner.1, team.name
            ));
        }
        if team.metadata.len() > MAX_LIST
            || team
                .metadata
                .iter()
                .any(|(k, v)| !valid_name(k) || v.len() > MAX_METADATA_VALUE || v.contains('\n'))
        {
            errors.push(format!(
                "{at}: metadata holds at most {MAX_LIST} entries, each name in letters, digits, '.', '-', '_' and '@' and each value at most {MAX_METADATA_VALUE} characters on one line."
            ));
        }
        out.push(Team {
            name: team.name.clone(),
            owner: team.owner.as_ref().map(email),
            members: team.members.iter().map(email).collect(),
            sso_values: team.sso_values.clone(),
            metadata: team.metadata.clone(),
            line,
        });
    }
    out
}

/// The `orgs:` list: valid names, each once.
fn check_orgs(file: &Path, text: &str, parsed: &PolicyFile, errors: &mut Vec<String>) {
    let line = line_of_key(text, "orgs", 1, usize::MAX);
    for (i, org) in parsed.orgs.iter().enumerate() {
        if !valid_name(org) || org == "*" {
            errors.push(format!(
                "{}:{line}: organization \"{org}\" uses letters, digits, dots, dashes, underscores and @ only, at most 100 characters.",
                file.display()
            ));
        }
        if parsed.orgs[..i].contains(org) {
            errors.push(format!(
                "{}:{line}: organization \"{org}\" is listed twice under orgs. List it once.",
                file.display()
            ));
        }
    }
}

/// Each rule's `passthrough:` entries must name a provider of a kind Enterplace can send to as is, and paths that
/// start with `/` and cannot climb out of the prefix.
fn rule_passthrough(
    file: &Path,
    text: &str,
    rules: &[Rule],
    providers: &[Provider],
    errors: &mut Vec<String>,
) {
    let (lines, end) = rule_lines(text);
    for (i, rule) in rules.iter().enumerate() {
        let line = lines.get(i).copied().unwrap_or(0);
        let until = lines.get(i + 1).copied().unwrap_or(end);
        let at = format!(
            "{}:{}",
            file.display(),
            line_of_key(text, "passthrough", line, until)
        );
        for entry in &rule.passthrough {
            if !providers.iter().any(|p| p.name == entry.provider) {
                errors.push(format!(
                    "{at}: passthrough names no provider named \"{}\". Use the name of one under providers:.",
                    entry.provider
                ));
            }
            if entry.paths.is_empty() {
                errors.push(format!(
                    "{at}: passthrough to \"{}\" needs at least one path, such as /v1/batches.",
                    entry.provider
                ));
            }
            for path in &entry.paths {
                let bad = if !path.starts_with('/') {
                    Some("starts with /")
                } else if path.split('/').any(|seg| seg == ".." || seg == ".") {
                    Some("has no . or .. segment")
                } else if path.contains(['?', '#', '%', '\\']) || path.contains("//") {
                    Some("is a plain path, with no query, fragment, escape or empty segment")
                } else {
                    None
                };
                if let Some(why) = bad {
                    errors.push(format!(
                        "{at}: the passthrough path \"{path}\" is refused: a path {why}. Write it as /v1/batches."
                    ));
                }
            }
        }
    }
}

/// The line of each item of a top-level list such as `guardrails:`. Same rule as `rule_lines`.
pub(crate) fn list_lines(text: &str, list: &str) -> Vec<usize> {
    let mut lines = Vec::new();
    let mut inside = false;
    let mut indent = None;
    for (i, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let depth = line.len() - trimmed.len();
        if !inside {
            inside = depth == 0
                && trimmed
                    .strip_prefix(list)
                    .is_some_and(|rest| rest.starts_with(':'));
            continue;
        }
        if depth == 0 && !trimmed.starts_with("- ") {
            break;
        }
        if trimmed.starts_with("- ") && *indent.get_or_insert(depth) == depth {
            lines.push(i + 1);
        }
    }
    lines
}

/// The `guardrails:` definitions, each problem with its line, then each rule's `guardrails: [...]` resolved
/// against them. A rule that names a guardrail nobody defined is an error, never a rule without the check.
fn rule_guardrails(
    file: &Path,
    text: &str,
    parsed: &PolicyFile,
    rules: &mut [Rule],
    errors: &mut Vec<String>,
) -> Vec<Guardrail> {
    let def_lines = list_lines(text, "guardrails");
    let line_of = |i: usize| def_lines.get(i).copied().unwrap_or(0);
    let before = errors.len();
    for (i, def) in parsed.guardrails.iter().enumerate() {
        if let Err(problems) = guard::guardrails(std::slice::from_ref(def)) {
            errors.extend(
                problems
                    .into_iter()
                    .map(|p| format!("{}:{}: {p}", file.display(), line_of(i))),
            );
        }
    }
    if errors.len() > before {
        return Vec::new();
    }
    // Each one alone is fine, so what is left is a name used twice.
    let defined: Vec<Guardrail> = match guard::guardrails(&parsed.guardrails) {
        Ok(defined) => defined,
        Err(problems) => {
            errors.extend(
                problems
                    .into_iter()
                    .map(|p| format!("{}: {p}", file.display())),
            );
            return Vec::new();
        }
    };
    let (lines, end) = rule_lines(text);
    for (i, rule) in parsed.rules.iter().enumerate() {
        // The policy's default guardrails run first, then a profile's, then the rule's own, each once.
        let mut names: Vec<String> = parsed.default_guardrails.clone();
        for profile in parsed
            .profiles
            .iter()
            .filter(|p| rule.profiles.contains(&p.name))
        {
            names.extend(profile.guardrails.iter().cloned());
        }
        names.extend(rule.guardrails.iter().cloned());
        let mut once: Vec<String> = Vec::new();
        for name in names {
            if !once.contains(&name) {
                once.push(name);
            }
        }
        if once.is_empty() {
            continue;
        }
        let line = lines.get(i).copied().unwrap_or(0);
        let until = lines.get(i + 1).copied().unwrap_or(end);
        match guard::for_rule(&rule.name, &once, &defined) {
            Ok(guards) => {
                if let Some(built) = rules.iter_mut().find(|r| r.line == line) {
                    built.guardrails = guards;
                }
            }
            Err(problem) => errors.push(format!(
                "{}:{}: {problem}",
                file.display(),
                line_of_key(text, "guardrails", line, until)
            )),
        }
    }
    for (i, rule) in rules.iter().enumerate() {
        if rule.limits.check_stream_every.is_some() {
            let until = lines.get(i + 1).copied().unwrap_or(end);
            let at = format!(
                "{}:{}",
                file.display(),
                line_of_key(text, "check_stream_every", rule.line, until)
            );
            let answers: Vec<&Guardrail> = rule.guardrails.iter().filter(|g| g.on.answer).collect();
            if answers.is_empty() {
                errors.push(format!(
                    "{at}: rule \"{}\" has check_stream_every, which checks streamed answers as they come, and none of its guardrails has on: [answer]. Add one with on: [answer], or remove the line.",
                    rule.name
                ));
            }
            if rule.limits.buffer_stream {
                errors.push(format!(
                    "{at}: rule \"{}\" has both check_stream_every and buffer_stream. buffer_stream holds the whole answer; check_stream_every lets it through as it is checked. Keep one.",
                    rule.name
                ));
            }
            if let Some(mask) = answers
                .iter()
                .find(|g| g.action == crate::guard::Action::Mask)
            {
                errors.push(format!(
                    "{at}: guardrail \"{}\" masks answers, and check_stream_every passes text on before the whole answer is known, so it cannot mask what was sent. Set it to action: block, or use buffer_stream: true.",
                    mask.name
                ));
            }
        }
        if rule.limits.buffer_stream && !rule.guardrails.iter().any(|g| g.on.answer) {
            let until = lines.get(i + 1).copied().unwrap_or(end);
            errors.push(format!(
                "{}:{}: rule \"{}\" has buffer_stream: true, which holds streamed answers for the answer guardrails, and none of its guardrails has on: [answer]. Add one with on: [answer], or remove the line.",
                file.display(),
                line_of_key(text, "buffer_stream", rule.line, until),
                rule.name
            ));
        }
    }
    defined
}

/// The budget, rate and cache of one rule, each checked. `at` gives the place of a key in the rule.
fn limits(
    rule: &RuleFile,
    i: usize,
    groups: &BTreeMap<String, Vec<String>>,
    at: &dyn Fn(&str) -> String,
    errors: &mut Vec<String>,
) -> Limits {
    let mut limits = Limits::default();
    if let Some(budgets) = &rule.budget {
        let path = format!("rules[{i}].budget");
        limits.budgets = caps_of(budgets, groups, &at("budget"), &path, None, errors);
        for file in budgets.list().iter().filter(|b| b.per.text() == "session") {
            if !file.usd.is_finite()
                || file.usd <= 0.0
                || !file.models.is_empty()
                || file.tz.is_some()
            {
                errors.push(format!(
                    "{}: a session budget is usd above 0 and per: session, with no models or tz, for example budget: {{ usd: 5, per: session }}.",
                    at("budget")
                ));
            } else if limits.session_budget.is_some() {
                errors.push(format!(
                    "{}: two budgets are per: session. Keep one.",
                    at("budget")
                ));
            } else {
                limits.session_budget = Some(Budget {
                    usd: file.usd,
                    per: Period::Session,
                });
            }
        }
    }
    if let Some(require) = &rule.require {
        let header_ok = |h: &String| {
            !h.is_empty()
                && h.len() <= 100
                && h.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        };
        let field_ok = |f: &String| {
            !f.is_empty()
                && f.len() <= 200
                && f.split('.').all(|part| {
                    !part.is_empty()
                        && part
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                })
        };
        if (require.headers.is_empty() && require.body.is_empty())
            || require.headers.len() + require.body.len() > MAX_LIST
            || !require.headers.iter().all(header_ok)
            || !require.body.iter().all(field_ok)
        {
            errors.push(format!(
                "{}: require lists the headers and the body fields every request under the rule must carry, at most {MAX_LIST} together: header names, and body fields as dotted paths, for example require: {{ headers: [X-Tenant-ID], body: [metadata.ticket] }}. To require nothing, remove it.",
                at("require")
            ));
        } else {
            limits.require_headers = require
                .headers
                .iter()
                .map(|h| h.to_ascii_lowercase())
                .collect();
            limits.require_body = require.body.clone();
        }
    }
    if let Some(n) = rule.parallel {
        limits.parallel = parallel_of(n, &at("parallel"), errors);
    }
    if let Some(rate) = &rule.rate {
        if rate.rpm.is_none()
            && rate.tpm.is_none()
            && rate.rph.is_none()
            && rate.rpd.is_none()
            && rate.tpd.is_none()
            && rate.session_requests.is_none()
        {
            errors.push(format!(
                "{}: rate sets no limit. Give rpm, tpm or both, for example rate: {{ rpm: 600, tpm: 200000 }}, or remove the line.",
                at("rate")
            ));
        }
        limits.rph = requests_of(rate.rph, "rph", &at("rate"), errors);
        limits.rpd = requests_of(rate.rpd, "rpd", &at("rate"), errors);
        limits.tpd = rate.tpd.and_then(|n| tpd_of(n, &at("rate"), errors));
        limits.session_requests = requests_of(
            rate.session_requests,
            "session_requests",
            &at("rate"),
            errors,
        );
        if let Some(rpm) = rate.rpm {
            match u32::try_from(rpm) {
                Ok(rpm) if (1..=1_000_000).contains(&rpm) => limits.rpm = Some(rpm),
                _ => errors.push(format!(
                    "{}: rpm is the number of requests one person may send per minute, 1 to 1000000, for example rate: {{ rpm: 600 }}. To set no limit, remove the line.",
                    at("rate")
                )),
            }
        }
        if let Some(tpm) = rate.tpm {
            limits.tpm = tpm_of(tpm, &at("rate"), errors);
        }
    }
    if let Some(cache) = &rule.cache {
        if (1..=MAX_CACHE_TTL).contains(&cache.ttl_seconds) {
            limits.cache_ttl_seconds = u64::try_from(cache.ttl_seconds).ok();
        } else {
            errors.push(format!(
                "{}: ttl_seconds is how long an answer is served again, 1 to 86400 seconds, for example cache: {{ ttl_seconds: 300 }}. To cache nothing, remove the line.",
                at("cache")
            ));
        }
        match cache.scope.as_deref() {
            None | Some("person") => {}
            Some("team") => limits.cache_scope = CacheScope::Team,
            Some(other) => errors.push(format!(
                "{}: scope is \"{other}\". It is person (the default: a cached answer is served only to the person it was made for) or team (to their team). No wider scope exists, so one team never reads another's answers.",
                at("cache")
            )),
        }
        if let Some(semantic) = &cache.semantic {
            if semantic.model.trim().is_empty() {
                errors.push(format!(
                    "{}: semantic needs the embeddings model to compare requests with, for example semantic: {{ model: text-embedding-3-small, threshold: 0.95 }}.",
                    at("cache")
                ));
            } else if !(semantic.threshold > 0.0 && semantic.threshold <= 1.0) {
                errors.push(format!(
                    "{}: threshold is the cosine similarity above which a cached answer is served again, above 0 and at most 1, for example 0.95. The lower it is, the looser the match.",
                    at("cache")
                ));
            } else if rule
                .models
                .as_ref()
                // Models a rule takes from its profiles are merged later; the call itself is still checked then.
                .is_some_and(|models| !models.iter().any(|m| m == "*" || *m == semantic.model))
            {
                errors.push(format!(
                    "{}: the semantic cache embeds each request with model \"{}\" as the person who sent it, and this rule does not allow that model, so every embedding would be refused. Add \"{}\" to the rule's models.",
                    at("cache"),
                    semantic.model,
                    semantic.model
                ));
            } else {
                limits.semantic = Some(Semantic {
                    model: semantic.model.clone(),
                    threshold: semantic.threshold,
                });
            }
        }
    }
    match rule.prompt_cache.as_deref() {
        None | Some("off") => {}
        Some("auto") => limits.prompt_cache = true,
        Some(other) => errors.push(format!(
            "{}: prompt_cache is \"{other}\". It is auto (Enterplace marks the system prompt, tools and conversation of a messages request with cache breakpoints when the caller placed none) or off (the default).",
            at("prompt_cache")
        )),
    }
    limits.buffer_stream = rule.buffer_stream;
    limits.budget_headers = rule.budget_headers;
    limits.caller_provider_key = match rule.caller_provider_key.as_deref() {
        None | Some("refused") => CallerKey::Refused,
        Some("allowed") => CallerKey::Allowed,
        Some("allowed_budgeted") => CallerKey::AllowedBudgeted,
        Some(other) => {
            errors.push(format!(
                "{}: caller_provider_key is \"{other}\". It is refused (the default: a request that carries x-enterplace-provider-key is refused), allowed (the caller's own provider key is sent, and what it spends is recorded but not counted against budgets) or allowed_budgeted (as allowed, and counted against budgets).",
                at("caller_provider_key")
            ));
            CallerKey::Refused
        }
    };
    match rule.budget_basis.as_deref() {
        None | Some("billed") => {}
        Some("api_equivalent") => limits.budget_api_equivalent = true,
        Some(other) => errors.push(format!(
            "{}: budget_basis is \"{other}\". It is billed (the default: dollar budgets count what the organization is billed per request, so subscription passthrough traffic does not count against them) or api_equivalent (subscription passthrough traffic counts at its estimated API price).",
            at("budget_basis")
        )),
    }
    match cidrs(&rule.from) {
        Ok(from) if from.len() <= MAX_LIST => limits.from = from,
        Ok(_) => errors.push(format!(
            "{}: from lists at most {MAX_LIST} address ranges.",
            at("from")
        )),
        Err(problem) => errors.push(format!("{}: from: {problem}.", at("from"))),
    }
    if let Some(regions) = &rule.regions {
        if regions.is_empty() || regions.iter().any(|r| !valid_name(r)) {
            errors.push(format!(
                "{}: regions lists the regions this rule's requests may be served in, at least one, each as an alias deployment's region: labels it, for example regions: [eu]. To set no residency, remove the line.",
                at("regions")
            ));
        }
        limits.regions = Some(regions.clone());
    }
    if let Some(capture) = &rule.capture {
        let mut ok = true;
        if capture.to != "console" {
            ok = false;
            errors.push(format!(
                "{}: capture keeps bodies to: console, which is the one place Enterplace keeps them; \"{}\" is not one. Write capture: {{ to: console, days: 7, viewers: [noa.bar] }}.",
                at("capture"),
                capture.to
            ));
        }
        if !(1..=MAX_CAPTURE_DAYS).contains(&capture.days) {
            ok = false;
            errors.push(format!(
                "{}: days is how long a redacted body is kept, 1 to 90, for example capture: {{ to: console, days: 7, viewers: [noa.bar] }}.",
                at("capture")
            ));
        }
        let viewers: Vec<String> = capture
            .viewers
            .iter()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .collect();
        if viewers.is_empty() {
            ok = false;
            errors.push(format!(
                "{}: viewers is empty, so no one could read what is kept. Name who may: a person (noa.bar), a team (team:security) or a console role (role:admin).",
                at("capture")
            ));
        }
        if ok {
            limits.capture = Some(Capture {
                days: u32::try_from(capture.days).unwrap_or(7),
                viewers,
            });
        }
    }
    if let Some(days) = rule.file_retention_days {
        match u32::try_from(days) {
            // OpenAI keeps an uploaded file at most 30 days when told to expire it.
            Ok(days @ 1..=30) => limits.file_retention_days = Some(days),
            _ => errors.push(format!(
                "{}: file_retention_days is how many days a file uploaded through Enterplace is kept before it is deleted at the provider, 1 to 30, for example file_retention_days: 7. To keep the provider's default, remove the line.",
                at("file_retention_days")
            )),
        }
    }
    if let Some(batch) = &rule.batch {
        let mut count = |value: Option<i64>, name: &str, example: &str| match value
            .map(u32::try_from)
        {
            None => None,
            Some(Ok(n @ 1..)) => Some(n),
            Some(_) => {
                errors.push(format!(
                    "{}: batch.{name} is a whole number, 1 or more, for example batch: {{ {name}: {example} }}. To set no limit, remove it.",
                    at("batch")
                ));
                None
            }
        };
        limits.batch_max_lines = count(batch.max_lines, "max_lines", "50000");
        limits.batch_max_open = count(batch.max_open, "max_open", "5");
        if batch.max_lines.is_none() && batch.max_open.is_none() {
            errors.push(format!(
                "{}: batch sets max_lines, max_open or both, for example batch: {{ max_lines: 50000, max_open: 5 }}. To set no batch limit, remove it.",
                at("batch")
            ));
        }
    }
    if let Some(containers) = &rule.containers {
        let sizes: Vec<String> = containers
            .sizes
            .iter()
            .map(|s| s.trim().to_string())
            .collect();
        if sizes.is_empty() || sizes.iter().any(|s| !CONTAINER_SIZES.contains(&s.as_str())) {
            errors.push(format!(
                "{}: containers lists the memory sizes of code interpreter containers this rule's callers may create, each one of 1g, 4g, 16g or 64g, for example containers: {{ sizes: [1g, 4g] }}. To allow no containers, remove the line.",
                at("containers")
            ));
        } else {
            limits.containers = sizes;
        }
    }
    if let Some(every) = rule.check_stream_every {
        match u32::try_from(every) {
            Ok(every @ 50..=100_000) => limits.check_stream_every = Some(every),
            _ => errors.push(format!(
                "{}: check_stream_every is how many characters of a streamed answer pass between checks, 50 to 100000, for example check_stream_every: 300.",
                at("check_stream_every")
            )),
        }
    }
    limits
}

/// Every price the file sets must be one that counts spend, and every model a budget reaches must have a price:
/// a budget cannot count what it cannot price.
fn check_prices(
    file: &Path,
    text: &str,
    parsed: &PolicyFile,
    rules: &[Rule],
    providers: &[Provider],
    errors: &mut Vec<String>,
) {
    let prices_line = line_of_key(text, "prices", 1, usize::MAX);
    for (model, price) in &parsed.prices {
        if let Err(problem) = price.check(model) {
            let line = line_of_key(text, model, prices_line, usize::MAX);
            errors.push(format!("{}:{line}: {problem}", file.display()));
        }
    }
    let (lines, end) = rule_lines(text);
    for (i, rule) in rules.iter().enumerate() {
        if rule.limits.budgets.is_empty() {
            continue;
        }
        let reached: Vec<&String> = match &rule.models {
            Models::Only(models) => models.iter().collect(),
            Models::Any => providers.iter().flat_map(|p| p.models.iter()).collect(),
        };
        // An alias is charged at the price of the model that served it.
        let reached: Vec<&String> = reached
            .into_iter()
            .flat_map(
                |model| match parsed.aliases.iter().find(|a| a.name == *model) {
                    Some(alias) => alias.deployments.iter().map(|d| &d.model).collect(),
                    None => vec![model],
                },
            )
            .collect();
        let until = lines.get(i + 1).copied().unwrap_or(end);
        let line = line_of_key(text, "budget", rule.line, until);
        // A pattern reaches models not known yet: one with no price is refused when it is asked for (`no_price`).
        for model in reached.into_iter().filter(|m| !m.contains('*')) {
            if price_for(model, &parsed.prices).is_none() {
                errors.push(format!(
                    "{}:{line}: rule \"{}\" has a budget in dollars, and model \"{model}\" has no price, so its spend could not be counted. Add its price in US dollars per million tokens under prices:, for example\nprices:\n  {model}: {{ input: 3, output: 15 }}\nor take the model out of the rule.",
                    file.display(),
                    rule.name
                ));
            }
        }
    }
}

/// Checks the `aliases:` list: each name is new, each deployment is a model its provider serves, all of one alias
/// speak one API, and each fallback names a model or alias Enterplace serves.
fn aliases(
    file: &Path,
    text: &str,
    parsed: &PolicyFile,
    providers: &[Provider],
    errors: &mut Vec<String>,
) -> Vec<Alias> {
    let mut out = Vec::new();
    let start = line_of_key(text, "aliases", 1, usize::MAX);
    for entry in &parsed.aliases {
        let line = line_of_key(text, &entry.name, start, usize::MAX);
        let at = format!("{}:{line}: alias \"{}\"", file.display(), entry.name);
        let before = errors.len();
        if let Some(provider) = providers.iter().find(|p| p.models.contains(&entry.name)) {
            errors.push(format!(
                "{at} has the name of a model provider \"{}\" serves, so a request for it would be ambiguous. Give the alias another name.",
                provider.name
            ));
        }
        if parsed
            .aliases
            .iter()
            .filter(|a| a.name == entry.name)
            .count()
            > 1
        {
            errors.push(format!("{at} is defined twice. Keep one."));
        }
        if entry.deployments.is_empty() {
            errors.push(format!(
                "{at} has no deployments. List at least one provider and model under deployments."
            ));
        }
        let mut api = None;
        let mut deployments = Vec::new();
        for d in &entry.deployments {
            let Some(provider) = providers.iter().find(|p| p.name == d.provider) else {
                errors.push(format!(
                    "{at} names provider \"{}\", and there is none. The providers are: {}.",
                    d.provider,
                    providers
                        .iter()
                        .map(|p| p.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
                continue;
            };
            // The model is the name sent to the provider, which need not be one callers may ask for by itself. Azure
            // and Bedrock know a model only by their map, so it must be in it.
            if let Some(map) = map_key(provider.kind)
                && !provider.upstream_models.contains_key(&d.model)
            {
                errors.push(format!(
                    "{at} sends to model \"{}\" on provider \"{}\", which has no entry for it in its {map}. Add `{}: <name>` under its {map}.",
                    d.model, d.provider, d.model
                ));
            }
            if *api.get_or_insert(provider.kind.api()) != provider.kind.api() {
                errors.push(format!(
                    "{at} mixes providers that speak different APIs. The deployments of one alias must take the same requests: openai and azure, anthropic and bedrock, or gemini and vertex."
                ));
            }
            let weight = d.weight.unwrap_or(1);
            if !(1..=1000).contains(&weight) {
                errors.push(format!("{at}: weight is how often a deployment is picked against the others, 1 to 1000."));
            }
            if d.region.as_deref().is_some_and(|r| !valid_name(r)) {
                errors.push(format!("{at}: region is a label such as eu, us or eu-west-1, in letters, digits, '.', '-' and '_'."));
            }
            let for_ = match d.for_.as_ref().map(|f| (&f.team, &f.tag)) {
                None => None,
                Some((Some(team), None)) if valid_name(team) => Some(For::Team(team.clone())),
                Some((None, Some(tag))) if valid_name(tag) => Some(For::Tag(tag.clone())),
                Some(_) => {
                    errors.push(format!("{at}: for keeps a deployment for exactly one of {{ team: <team> }} or {{ tag: <tag> }}."));
                    None
                }
            };
            let when = d.when.as_ref().map(|w| When {
                team: w.team.clone(),
                tag: w.tag.clone(),
                customer: w.customer.clone(),
                min_prompt_tokens: w.min_prompt_tokens,
                max_prompt_tokens: w.max_prompt_tokens,
                tools: w.tools,
                images: w.images,
                header: w
                    .header
                    .as_ref()
                    .and_then(|h| h.iter().next())
                    .map(|(name, value)| (name.to_ascii_lowercase(), value.clone())),
            });
            if let Some(w) = &d.when {
                let empty = w.team.is_none()
                    && w.tag.is_none()
                    && w.customer.is_none()
                    && w.min_prompt_tokens.is_none()
                    && w.max_prompt_tokens.is_none()
                    && w.tools.is_none()
                    && w.images.is_none()
                    && w.header.is_none();
                if empty {
                    errors.push(format!("{at}: when has no condition, so it would keep the deployment for every request. Add team, tag, customer, min_prompt_tokens, max_prompt_tokens, tools, images or header, or remove it."));
                }
                if w.header.as_ref().is_some_and(|h| h.len() != 1) {
                    errors.push(format!("{at}: when.header names one header and its value, for example `header: {{ x-tier: gold }}`."));
                }
                if let (Some(min), Some(max)) = (w.min_prompt_tokens, w.max_prompt_tokens)
                    && min > max
                {
                    errors.push(format!("{at}: when.min_prompt_tokens ({min}) is above max_prompt_tokens ({max}), so no request could match. Swap them."));
                }
                if d.for_.is_some() {
                    errors.push(format!("{at}: a deployment takes for or when, not both. Move the team or tag into when."));
                }
            }
            let probe = match &d.probe {
                None => None,
                Some(p) => {
                    if !(5..=3600).contains(&p.every_seconds) {
                        errors.push(format!("{at}: probe.every_seconds is how often the deployment is checked, 5 to 3600."));
                    }
                    let chat = match p.with.as_deref() {
                        None | Some("models") => {
                            if !matches!(provider.kind, Kind::OpenAi | Kind::Anthropic) {
                                errors.push(format!("{at}: probe with models lists the models of an openai or anthropic provider, and \"{}\" is of kind {}. Write `with: chat` to send it a one-token request instead.", provider.name, provider.kind.word()));
                            }
                            false
                        }
                        Some("chat") => true,
                        Some(other) => {
                            errors.push(format!("{at}: probe.with is \"{other}\". Write models (list the provider's models, free) or chat (a one-token request, billed by the provider)."));
                            false
                        }
                    };
                    Some(Probe {
                        every_seconds: p.every_seconds,
                        chat,
                    })
                }
            };
            if d.max_parallel == Some(0) || d.rpm == Some(0) || d.tpm == Some(0) {
                errors.push(format!("{at}: max_parallel, rpm and tpm are the most the deployment takes, each at least 1. Remove one to leave it unlimited."));
            }
            deployments.push(Deployment {
                provider: d.provider.clone(),
                model: d.model.clone(),
                weight,
                region: d.region.clone(),
                for_,
                when,
                timeouts: timeouts(d.timeouts.as_ref(), &at, errors),
                probe,
                max_parallel: d.max_parallel,
                rpm: d.rpm,
                tpm: d.tpm,
            });
        }
        let balance = match entry.balance.as_deref() {
            None | Some("round_robin") => Balance::RoundRobin,
            Some("least_busy") => Balance::LeastBusy,
            Some("lowest_latency") => Balance::LowestLatency,
            Some("lowest_cost") => Balance::LowestCost,
            Some("adaptive") => Balance::Adaptive,
            Some(other) => {
                errors.push(format!("{at}: balance is \"{other}\". Write round_robin (in turn, by weight), least_busy (fewest requests in flight), lowest_latency (fastest first byte lately), lowest_cost (cheapest by price) or adaptive (latency, error rate and cost, weighted)."));
                Balance::RoundRobin
            }
        };
        let cooldown_seconds = entry.cooldown_seconds.unwrap_or(DEFAULT_COOLDOWN_SECONDS);
        if cooldown_seconds > 3600 {
            errors.push(format!(
                "{at}: cooldown_seconds is how long a failed deployment is passed over, 0 to 3600."
            ));
        }
        for (word, target) in [
            ("context_window_fallback", &entry.context_window_fallback),
            ("content_policy_fallback", &entry.content_policy_fallback),
        ] {
            let Some(target) = target else { continue };
            let served = providers.iter().any(|p| p.models.contains(target))
                || parsed.aliases.iter().any(|a| a.name == *target);
            if *target == entry.name || !served {
                errors.push(format!(
                    "{at}: {word} is \"{target}\". Name another model a provider serves, or another alias."
                ));
            }
        }
        let served = |target: &String| {
            providers
                .iter()
                .any(|p| p.models.iter().any(|m| model_matches(m, target)))
                || parsed.aliases.iter().any(|a| a.name == *target)
        };
        for target in &entry.fallbacks {
            if *target == entry.name || !served(target) {
                errors.push(format!(
                    "{at}: fallbacks names \"{target}\". Name another model a provider serves, or another alias."
                ));
            }
        }
        let fallback_on = match &entry.fallback_on {
            None => FallbackOn::DEFAULT.to_vec(),
            Some(words) => words
                .iter()
                .filter_map(|word| {
                    let found = FallbackOn::ALL.iter().find(|(w, _)| w == word).map(|(_, on)| *on);
                    if found.is_none() {
                        errors.push(format!("{at}: fallback_on lists \"{word}\". Write any of rate_limit, server_error, timeout, unreachable, context_window and content_policy."));
                    }
                    found
                })
                .collect(),
        };
        if entry.fallback_on.is_some() && entry.fallbacks.is_empty() {
            errors.push(format!("{at}: fallback_on says when to take the fallbacks, and the alias has none. Add fallbacks: [<model or alias>, ...], or remove fallback_on."));
        }
        let weights = match &entry.weights {
            None => Weights::default(),
            Some(w) => {
                let weights = Weights {
                    latency: w.latency.unwrap_or(1.0),
                    errors: w.errors.unwrap_or(1.0),
                    cost: w.cost.unwrap_or(1.0),
                };
                let parts = [weights.latency, weights.errors, weights.cost];
                if parts.iter().any(|p| !(0.0..=100.0).contains(p))
                    || parts.iter().all(|p| *p == 0.0)
                {
                    errors.push(format!(
                        "{at}: weights are latency, errors and cost, each 0 to 100, not all 0."
                    ));
                }
                if balance != Balance::Adaptive {
                    errors.push(format!("{at}: weights apply to balance: adaptive only. Set balance: adaptive, or remove weights."));
                }
                weights
            }
        };
        let alias_timeouts = timeouts(entry.timeouts.as_ref(), &at, errors);
        let rate_limit_headroom_percent = entry.rate_limit_headroom_percent;
        if rate_limit_headroom_percent.is_some_and(|p| p > 100) {
            errors.push(format!("{at}: rate_limit_headroom_percent is the share of a provider's rate limit left under which a deployment goes after the others, 0 to 100 (default 5)."));
        }
        if errors.len() == before {
            out.push(Alias {
                name: entry.name.clone(),
                deployments,
                balance,
                cooldown_seconds,
                context_window_fallback: entry.context_window_fallback.clone(),
                content_policy_fallback: entry.content_policy_fallback.clone(),
                session_affinity: entry.session_affinity,
                timeouts: alias_timeouts,
                fallbacks: entry.fallbacks.clone(),
                fallback_on,
                weights,
                rate_limit_headroom_percent,
            });
        }
    }
    out
}

/// The line of each item of the `providers:` list. Same rule as `rule_lines`.
fn provider_lines(text: &str) -> Vec<usize> {
    let mut lines = Vec::new();
    let mut inside = false;
    let mut indent = None;
    for (i, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let depth = line.len() - trimmed.len();
        if !inside {
            inside = depth == 0 && trimmed.starts_with("providers:");
            continue;
        }
        if depth == 0 && !trimmed.starts_with("- ") {
            break;
        }
        if trimmed.starts_with("- ") && *indent.get_or_insert(depth) == depth {
            lines.push(i + 1);
        }
    }
    lines
}

/// The key that maps model names to the provider's own names, for the kinds that have one.
fn map_key(kind: Kind) -> Option<&'static str> {
    match kind {
        Kind::Azure => Some("deployments"),
        Kind::Bedrock | Kind::BedrockConverse | Kind::Sagemaker => Some("model_ids"),
        Kind::OpenAi
        | Kind::Anthropic
        | Kind::Gemini
        | Kind::Vertex
        | Kind::VertexAnthropic
        | Kind::Cohere
        | Kind::Watsonx
        | Kind::VertexOpenAi
        | Kind::Replicate
        | Kind::Demo => None,
    }
}

/// Checks the options that belong to one kind or that change routing. Returns the provider's model map.
fn provider_options(
    entry: &ProviderFile,
    kind: Option<Kind>,
    at: &dyn Fn(&str) -> String,
    errors: &mut Vec<String>,
) -> BTreeMap<String, String> {
    let word = kind.map_or("this", Kind::word);
    let only = |key: &str, owner: &str, errors: &mut Vec<String>| {
        errors.push(format!(
            "{}: {key} is for a provider of kind {owner}, and this one is of kind {word}. Remove the line.",
            at(key)
        ));
    };
    if entry.deployments.is_some() && kind != Some(Kind::Azure) {
        only("deployments", "azure", errors);
    }
    let aws = kind.is_some_and(Kind::aws);
    if entry.api_version.is_some() && !matches!(kind, Some(Kind::Azure | Kind::Watsonx)) {
        only("api_version", "azure or watsonx", errors);
    }
    if entry.model_ids.is_some() && !aws {
        only(
            "model_ids",
            "bedrock, bedrock_converse or sagemaker",
            errors,
        );
    }
    if entry.region.is_some() && !aws {
        only("region", "bedrock, bedrock_converse or sagemaker", errors);
    }
    if entry.role_arn.is_some() && !aws {
        only("role_arn", "bedrock, bedrock_converse or sagemaker", errors);
    }
    if entry.project_id.is_some() && kind != Some(Kind::Watsonx) {
        only("project_id", "watsonx", errors);
    }
    if entry.chat_as_responses.is_some() && !matches!(kind, Some(Kind::OpenAi | Kind::Azure)) {
        only("chat_as_responses", "openai or azure", errors);
    }
    if let Some(oci) = &entry.oci_signing {
        if kind != Some(Kind::OpenAi) {
            only("oci_signing", "openai (preset oci)", errors);
        }
        if entry.key_env.is_some() || entry.key_file.is_some() || entry.credential.is_some() {
            errors.push(format!(
                "{}: provider \"{}\" signs its requests with oci_signing, so it takes no key_env, key_file or credential. Keep oci_signing, or remove it and keep the API key.",
                at("oci_signing"),
                entry.name
            ));
        }
        match (&oci.key_file, &oci.key_env) {
            (Some(path), None) if !path.trim().is_empty() => {}
            (None, Some(env))
                if !env.is_empty()
                    && env.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') => {}
            _ => errors.push(format!(
                "{}: oci_signing takes one of key_file (the path of the API signing key's PEM file, for example ~/.oci/oci_api_key.pem written out in full) or key_env (an environment variable that holds the PEM). The key itself never goes in this file.",
                at("oci_signing")
            )),
        }
        let ocid = |id: &str, of: &str| id.starts_with(&format!("ocid1.{of}."));
        if !ocid(&oci.tenancy, "tenancy") || !ocid(&oci.user, "user") || oci.fingerprint.len() != 47
        {
            errors.push(format!(
                "{}: oci_signing needs tenancy (ocid1.tenancy...), user (ocid1.user...) and fingerprint (aa:bb:..., 16 pairs) as the OCI console shows them under the user's API keys. Copy them from there.",
                at("oci_signing")
            ));
        }
    }
    if let Some(project) = &entry.project_id
        && (project.is_empty()
            || !project
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'))
    {
        errors.push(format!(
            "{}: project_id is the ID of a watsonx.ai project, letters, digits and dashes, as shown under the project's Manage tab.",
            at("project_id")
        ));
    }
    if let Some(batch) = &entry.batch {
        let scheme = match kind {
            Some(Kind::Bedrock) => Some("s3"),
            Some(Kind::Vertex | Kind::VertexAnthropic) => Some("gs"),
            _ => None,
        };
        match scheme {
            None => errors.push(format!(
                "{}: batch is for a provider of kind bedrock, vertex or vertex_anthropic, whose batch jobs read and write a bucket. OpenAI and Anthropic batches need no batch: section. Remove it.",
                at("batch")
            )),
            Some(scheme) => {
                let rest = batch.bucket.strip_prefix(&format!("{scheme}://"));
                let bucket = rest.map(|r| r.split('/').next().unwrap_or_default());
                let plain = |text: &str| {
                    text.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_./".contains(&b))
                };
                if !bucket.is_some_and(|b| !b.is_empty() && plain(b))
                    || !rest.is_some_and(plain)
                {
                    errors.push(format!(
                        "{}: batch.bucket is where batch files are kept, as {scheme}://<bucket>/<prefix>/, for example {scheme}://my-bucket/enterplace-batches/, in letters, digits and -_./ only.",
                        at("batch")
                    ));
                }
                if scheme == "s3" {
                    match &batch.role_arn {
                        Some(role) if role.starts_with("arn:aws") && role.contains(":role/") => {}
                        _ => errors.push(format!(
                            "{}: a bedrock provider's batch needs role_arn, the service role Bedrock assumes to read and write the bucket, for example role_arn: arn:aws:iam::123456789012:role/bedrock-batch.",
                            at("batch")
                        )),
                    }
                } else if batch.role_arn.is_some() {
                    errors.push(format!(
                        "{}: batch.role_arn is for a bedrock provider. Vertex AI batch jobs run as the project's service agent. Remove it.",
                        at("batch")
                    ));
                }
                for url in [&batch.url, &batch.storage_url].into_iter().flatten() {
                    if !(url.starts_with("https://") || url.starts_with("http://")) {
                        errors.push(format!(
                            "{}: batch.url and batch.storage_url are base URLs, for example https://bedrock.us-east-1.amazonaws.com. Write the scheme.",
                            at("batch")
                        ));
                    } else if is_private(url) && !entry.allow_private {
                        errors.push(format!(
                            "{}: batch.url or batch.storage_url points at this machine or a private network. If that is intended, for example a private endpoint, add `allow_private: true` to the provider.",
                            at("batch")
                        ));
                    }
                }
            }
        }
    }
    if let Some(role) = &entry.role_arn
        && !(role.starts_with("arn:aws") && role.contains(":role/"))
    {
        errors.push(format!(
            "{}: role_arn is the ARN of an IAM role, for example arn:aws:iam::123456789012:role/enterplace-bedrock.",
            at("role_arn")
        ));
    }
    if entry.accept_chat.is_some() && kind.is_some_and(|k| k.api() != Kind::Anthropic) {
        errors.push(format!(
            "{}: accept_chat translates chat completions requests to the messages API, so it is for a provider of kind anthropic, bedrock or vertex_anthropic. Remove the line.",
            at("accept_chat")
        ));
    }
    if entry.accept_messages.is_some() && kind.is_some_and(|k| k.api() != Kind::OpenAi) {
        errors.push(format!(
            "{}: accept_messages translates messages requests (Claude Code) to the chat completions API, so it is for a provider of a kind that takes chat completions (openai, azure, gemini, vertex, vertex_openai, bedrock_converse, cohere, watsonx, sagemaker or replicate). Remove the line.",
            at("accept_messages")
        ));
    }
    if entry.retries.is_some_and(|n| n > MAX_RETRIES) {
        errors.push(format!(
            "{}: retries is at most {MAX_RETRIES}. Each retry can wait as long as the provider's whole timeout, so more would leave a caller waiting for many minutes.",
            at("retries")
        ));
    }
    match kind {
        Some(Kind::Watsonx) => {
            if entry.project_id.is_none() {
                errors.push(format!(
                    "{}: a watsonx provider needs project_id, the watsonx.ai project its requests are made in, for example `project_id: 0f6c1c3e-5d6a-4b4e-9b1e-2a7d1c9f0a11`.",
                    at("kind")
                ));
            }
            if let Some(version) = entry.api_version.as_deref()
                && !(version.len() == 10
                    && version.bytes().enumerate().all(|(i, b)| {
                        if i == 4 || i == 7 {
                            b == b'-'
                        } else {
                            b.is_ascii_digit()
                        }
                    }))
            {
                errors.push(format!(
                    "{}: api_version is the date of the watsonx.ai API version, as IBM writes it: 2024-05-31.",
                    at("api_version")
                ));
            }
        }
        Some(Kind::Azure) => {
            // The v1 API (a url ending in /openai/v1) takes no api_version.
            let v1 = entry
                .url
                .as_deref()
                .is_some_and(|u| u.trim_end_matches('/').ends_with("/openai/v1"));
            match entry.api_version.as_deref() {
                None if v1 => {}
                Some(_) if v1 => errors.push(format!(
                    "{}: a url ending in /openai/v1 is Azure's v1 API, which takes no api_version. Remove the line, or use the resource's url without /openai/v1 to keep a dated version.",
                    at("api_version")
                )),
                None => errors.push(format!(
                    "{}: an azure provider needs api_version, the Azure OpenAI REST API version, for example `api_version: 2024-10-21`, or a url ending in /openai/v1 for the v1 API.",
                    at("kind")
                )),
                Some(version) => {
                    let date = version.get(..10).unwrap_or_default();
                    let shaped = date.len() == 10
                        && date.bytes().enumerate().all(|(i, b)| {
                            if i == 4 || i == 7 {
                                b == b'-'
                            } else {
                                b.is_ascii_digit()
                            }
                        })
                        && matches!(&version[10..], "" | "-preview");
                    if !shaped {
                        errors.push(format!(
                            "{}: api_version is a date, as Azure writes it: 2024-10-21, or 2025-04-01-preview for a preview version.",
                            at("api_version")
                        ));
                    }
                }
            }
            if entry.deployments.is_none() {
                errors.push(format!(
                    "{}: an azure provider needs deployments, the deployment that serves each model, for example `deployments: {{ gpt-4o: my-gpt-4o }}`.",
                    at("kind")
                ));
            }
        }
        Some(Kind::Sagemaker) => {
            if entry.region.is_none() {
                errors.push(format!(
                    "{}: a sagemaker provider needs region, the AWS region its endpoints run in, for example `region: us-east-1`.",
                    at("kind")
                ));
            }
            if entry.model_ids.is_none() {
                errors.push(format!(
                    "{}: a sagemaker provider needs model_ids, the SageMaker endpoint that serves each model, for example `model_ids: {{ llama-3-70b: my-llama-endpoint }}`.",
                    at("kind")
                ));
            }
        }
        Some(Kind::Bedrock | Kind::BedrockConverse) => {
            if entry.region.is_none() {
                errors.push(format!(
                    "{}: a bedrock provider needs region, the AWS region it runs in, for example `region: us-east-1`.",
                    at("kind")
                ));
            }
            if entry.model_ids.is_none() {
                errors.push(format!(
                    "{}: a bedrock provider needs model_ids, the Bedrock model ID of each model, for example `model_ids: {{ claude-sonnet-5-5: us.anthropic.claude-sonnet-5-5-v1:0 }}`.",
                    at("kind")
                ));
            }
        }
        _ => {}
    }
    let map = entry
        .deployments
        .clone()
        .or_else(|| entry.model_ids.clone())
        .unwrap_or_default();
    for (model, name) in &map {
        // These names go into the request path. Bedrock's may be ARNs, with colons and slashes, which are encoded.
        let shaped = !name.is_empty()
            && name.len() <= 2048
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.:/".contains(&b));
        if !shaped {
            let key = kind.and_then(map_key).unwrap_or("deployments");
            errors.push(format!(
                "{}: the name for model \"{model}\" uses letters, digits and - _ . : / only.",
                at(key)
            ));
        }
    }
    map
}

/// Checks that `entry`'s fallback names another provider that speaks the same API and can serve each of its models.
/// The longest any timeout may be: a day.
const MAX_TIMEOUT_MS: u64 = 86_400_000;

/// A `timeouts:` block, each value checked.
fn timeouts(file: Option<&TimeoutsFile>, at: &str, errors: &mut Vec<String>) -> Timeouts {
    let Some(file) = file else {
        return Timeouts::default();
    };
    for (word, value) in [
        ("connect_ms", file.connect_ms),
        ("first_byte_ms", file.first_byte_ms),
        ("total_ms", file.total_ms),
        ("idle_ms", file.idle_ms),
    ] {
        if value.is_some_and(|ms| !(1..=MAX_TIMEOUT_MS).contains(&ms)) {
            errors.push(format!(
                "{at}: timeouts.{word} is in milliseconds, 1 to {MAX_TIMEOUT_MS} (a day)."
            ));
        }
    }
    if let (Some(first), Some(total)) = (file.first_byte_ms, file.total_ms)
        && total < first
    {
        errors.push(format!(
            "{at}: timeouts.total_ms ({total}) is shorter than first_byte_ms ({first}), so the first byte could never be waited for. Make total_ms at least first_byte_ms."
        ));
    }
    Timeouts {
        connect_ms: file.connect_ms,
        first_byte_ms: file.first_byte_ms,
        total_ms: file.total_ms,
        idle_ms: file.idle_ms,
    }
}

/// A provider's `keys:` pool, each entry checked: one source each, and never with `key_env`, `key_file` or
/// `credential` beside it.
fn key_pool(
    entry: &ProviderFile,
    bedrock: bool,
    store: bool,
    at: &dyn Fn(&str) -> String,
    errors: &mut Vec<String>,
) -> Vec<KeySource> {
    if entry.keys.is_empty() {
        return Vec::new();
    }
    if bedrock {
        errors.push(format!(
            "{}: a bedrock provider takes no keys. Enterplace signs its requests with AWS credentials. Remove the keys list.",
            at("keys")
        ));
        return Vec::new();
    }
    if entry.key_env.is_some() || entry.key_file.is_some() || entry.credential.is_some() {
        errors.push(format!(
            "{}: provider \"{}\" has a keys list and key_env, key_file or credential beside it. Put every key in the keys list and remove the others.",
            at("keys"),
            entry.name
        ));
    }
    let mut out = Vec::new();
    for key in &entry.keys {
        match (&key.key_env, &key.credential) {
            (Some(env), None)
                if !env.is_empty() && env.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') =>
            {
                out.push(KeySource::Env(env.clone()));
            }
            (None, Some(name)) if valid_name(name) && store => {
                out.push(KeySource::Credential(name.clone()));
            }
            (None, Some(_)) if !store => errors.push(format!(
                "{}: a key of provider \"{}\" names a credential, and credentials are kept in the store, which this policy does not name. Add `store: {{ postgres_url_env: DATABASE_URL }}`, or use `key_env:`.",
                at("keys"),
                entry.name
            )),
            _ => errors.push(format!(
                "{}: each entry of keys is `{{ key_env: <environment variable> }}` or `{{ credential: <name of a credential in the store> }}`, exactly one of them. The key itself never goes in this file.",
                at("keys")
            )),
        }
    }
    let mut seen = out.clone();
    seen.sort_by_key(|k| format!("{k:?}"));
    if seen.windows(2).any(|pair| pair[0] == pair[1]) {
        errors.push(format!(
            "{}: provider \"{}\" lists the same key twice. List each once.",
            at("keys"),
            entry.name
        ));
    }
    out
}

fn check_fallback(
    entry: &ProviderFile,
    kind: Kind,
    models: &[String],
    all: &[ProviderFile],
    at: &dyn Fn(&str) -> String,
    errors: &mut Vec<String>,
) {
    let Some(name) = &entry.fallback else {
        return;
    };
    if *name == entry.name {
        errors.push(format!(
            "{}: provider \"{name}\" names itself as its fallback. Name another provider, or use retries to try this one again.",
            at("fallback")
        ));
        return;
    }
    let Some(other) = all.iter().find(|p| p.name == *name) else {
        let names: Vec<&str> = all.iter().map(|p| p.name.as_str()).collect();
        errors.push(format!(
            "{}: fallback names provider \"{name}\", and there is none. The providers are: {}.",
            at("fallback"),
            names.join(", ")
        ));
        return;
    };
    // Its own entry reports a kind that is not one.
    let Some(other_kind) = other.kind.as_deref().and_then(Kind::from_word) else {
        return;
    };
    // A chat request for a kind that translates chat is translated as it is sent, so its fallback must translate too.
    if other_kind.api() != kind.api() || other_kind.translates_chat() != kind.translates_chat() {
        errors.push(format!(
            "{}: fallback \"{name}\" is of kind {}, which speaks another API than this provider ({}). A fallback must take the same requests: openai, azure and vertex_openai take chat completions as sent; gemini, vertex, bedrock_converse, cohere and watsonx take chat completions translated; anthropic, bedrock and vertex_anthropic take messages.",
            at("fallback"),
            other_kind.word(),
            kind.word()
        ));
        return;
    }
    let map = other.deployments.as_ref().or(other.model_ids.as_ref());
    if let (Some(key), Some(map)) = (map_key(other_kind), map) {
        let missing: Vec<&str> = models
            .iter()
            .filter(|m| !map.contains_key(*m))
            .map(String::as_str)
            .collect();
        if !missing.is_empty() {
            errors.push(format!(
                "{}: fallback \"{name}\" cannot serve {}: its {key} has no entry for it. Add `<model>: <name>` under its {key} for each.",
                at("fallback"),
                missing.join(", ")
            ));
        }
    }
}

/// Fills in the url and kind of each provider that names a catalog preset, before the providers are checked, so a
/// preset is held to every rule a hand-written provider is. What the file writes itself wins.
fn presets(file: &Path, text: &str, entries: &mut [ProviderFile], errors: &mut Vec<String>) {
    let lines = provider_lines(text);
    for (i, entry) in entries.iter_mut().enumerate() {
        let Some(id) = entry.preset.as_deref() else {
            continue;
        };
        let Some(preset) = crate::catalog::find(id) else {
            let line = lines.get(i).copied().unwrap_or(0);
            let until = lines.get(i + 1).copied().unwrap_or(usize::MAX);
            let closest = crate::catalog::PRESETS
                .iter()
                .min_by_key(|p| distance(id, p.id))
                .map_or(String::new(), |p| format!(" did you mean {}?", p.id));
            errors.push(format!(
                "{}:{}: preset \"{id}\" is not in Enterplace's provider catalog;{closest} `enterplace providers` lists every id. Or remove preset and write url and kind.",
                file.display(),
                line_of_key(text, "preset", line, until)
            ));
            continue;
        };
        if preset.needs_url() && entry.url.is_none() {
            let line = lines.get(i).copied().unwrap_or(0);
            let until = lines.get(i + 1).copied().unwrap_or(usize::MAX);
            errors.push(format!(
                "{}:{}: preset \"{id}\" holds a placeholder in its URL ({}). Write your own url next to the preset, with your workspace or account in place of the capitals.",
                file.display(),
                line_of_key(text, "preset", line, until),
                preset.url
            ));
        }
        // An AWS preset's URL follows from the provider's region, as a hand-written one's does.
        if !(preset.kind.aws() && entry.region.is_some()) {
            entry.url.get_or_insert_with(|| preset.url.to_string());
        }
        entry
            .kind
            .get_or_insert_with(|| preset.kind.word().to_string());
    }
}

fn providers(
    file: &Path,
    text: &str,
    parsed: &PolicyFile,
    errors: &mut Vec<String>,
) -> Vec<Provider> {
    let lines = provider_lines(text);
    let mut out = Vec::new();
    // Which provider, at which line, claimed each model: a model served by two providers would be ambiguous. A
    // passthrough provider and a keyed one may share a model: a request's credential picks between them.
    let mut claimed: HashMap<(String, bool), (String, usize)> = HashMap::new();
    if parsed.providers.is_empty() {
        errors.push(format!(
            "{}:{}: the file lists no provider, so no request could be forwarded. Add one under providers.",
            file.display(),
            line_of_key(text, "providers", 1, usize::MAX)
        ));
    }
    // The models the rules name, to write a concrete fix for a file from the previous version.
    let ruled: Vec<&str> = parsed
        .rules
        .iter()
        .flat_map(|rule| rule.models.iter().flatten().map(String::as_str))
        .filter(|model| *model != "*")
        .collect();
    for (i, entry) in parsed.providers.iter().enumerate() {
        let line = lines.get(i).copied().unwrap_or(0);
        let until = lines.get(i + 1).copied().unwrap_or(usize::MAX);
        let at = |key: &str| format!("{}:{}", file.display(), line_of_key(text, key, line, until));
        let kind = match entry.kind.as_deref() {
            Some(word) => {
                let kind = Kind::from_word(word);
                if kind.is_none() {
                    errors.push(format!(
                        "{}: kind is \"{word}\". It must be openai (the chat completions API), anthropic (the messages API), azure (Azure OpenAI), bedrock (Amazon Bedrock InvokeModel, Anthropic models), bedrock_converse (Amazon Bedrock Converse, every model family), gemini (Google's Gemini API), vertex (Gemini on Google Cloud Vertex AI), vertex_anthropic (Claude on Google Cloud Vertex AI), vertex_openai (Model Garden on Vertex AI), cohere (Cohere's own API), watsonx (IBM watsonx.ai), sagemaker (an Amazon SageMaker endpoint) or replicate (Replicate's predictions API).",
                        at("kind")
                    ));
                }
                kind
            }
            None => None,
        };
        let bedrock = kind.is_some_and(Kind::aws);
        let region = entry.region.as_deref();
        if let Some(region) = region {
            let shaped = !region.is_empty()
                && region
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
            if !shaped {
                errors.push(format!(
                    "{}: region is an AWS region code, for example us-east-1.",
                    at("region")
                ));
            }
        }
        // Bedrock's URL follows from its region. A url may still be given, for a private endpoint or a test.
        let url = match (&entry.url, bedrock, region) {
            (Some(url), _, _) => Some(url.clone()),
            (None, true, Some(region)) if kind == Some(Kind::Sagemaker) => Some(format!(
                "https://runtime.sagemaker.{region}.amazonaws.com/endpoints"
            )),
            (None, true, Some(region)) => {
                Some(format!("https://bedrock-runtime.{region}.amazonaws.com"))
            }
            (None, true, None) => None,
            (None, false, _) => {
                errors.push(format!(
                    "{}:{line}: provider \"{}\" has no url. Add the vendor's base URL, for example `url: https://api.openai.com`.",
                    file.display(),
                    entry.name
                ));
                None
            }
        };
        let url = match url.as_deref().map(base_url) {
            Some(Ok(url)) => {
                if kind == Some(Kind::Vertex) && !url.ends_with("/publishers/google") {
                    errors.push(format!(
                        "{}: a vertex provider's url ends in /publishers/google, for example https://us-central1-aiplatform.googleapis.com/v1/projects/my-project/locations/us-central1/publishers/google.",
                        at("url")
                    ));
                }
                if kind == Some(Kind::VertexAnthropic) && !url.ends_with("/publishers/anthropic") {
                    errors.push(format!(
                        "{}: a vertex_anthropic provider's url ends in /publishers/anthropic, for example https://us-east5-aiplatform.googleapis.com/v1/projects/my-project/locations/us-east5/publishers/anthropic.",
                        at("url")
                    ));
                }
                if kind == Some(Kind::VertexOpenAi) && !url.ends_with("/endpoints/openapi") {
                    errors.push(format!(
                        "{}: a vertex_openai provider's url ends in /endpoints/openapi, for example https://us-central1-aiplatform.googleapis.com/v1/projects/my-project/locations/us-central1/endpoints/openapi.",
                        at("url")
                    ));
                }
                if is_private(&url) && !entry.allow_private {
                    errors.push(format!(
                        "{}: the provider url points at this machine or a private network. If that is intended, for example a local model server, add `allow_private: true` to the provider.",
                        at("url")
                    ));
                }
                url
            }
            Some(Err(problem)) => {
                errors.push(format!("{}: {problem}", at("url")));
                String::new()
            }
            None => String::new(),
        };
        if let Some(name) = &entry.credential {
            if bedrock {
                errors.push(format!(
                    "{}: a bedrock provider takes no credential. Enterplace signs its requests with AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and, for temporary credentials, AWS_SESSION_TOKEN from its environment. Remove the line.",
                    at("credential")
                ));
            } else if entry.key_env.is_some() || entry.key_file.is_some() {
                errors.push(format!(
                    "{}: provider \"{}\" takes one of key_env, key_file or credential. Keep the one that holds its key and remove the others.",
                    at("credential"),
                    entry.name
                ));
            } else if !valid_name(name) {
                errors.push(format!(
                    "{}: credential is the name of a provider credential kept in the store, for example openai-prod: letters, digits, dots, dashes, underscores and @ only. The key itself never goes in this file.",
                    at("credential")
                ));
            } else if parsed.store.is_none() && !crate::store::credentials_file(file).exists() {
                errors.push(format!(
                    "{}: provider \"{}\" takes its key from credential \"{name}\", and credentials are kept in the store, which this policy does not name, or in enterplace-credentials.json beside the policy, which does not exist. Add the key in the console (Start here, Connect a model), add `store: {{ postgres_url_env: DATABASE_URL }}`, or keep the key in an environment variable with `key_env:`.",
                    at("credential"),
                    entry.name
                ));
            }
        }
        if let Some(path) = &entry.key_file {
            if bedrock {
                errors.push(format!(
                    "{}: a bedrock provider takes no key_file. Enterplace signs its requests with the AWS credentials it finds: the role of its pod, task or instance, or AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in its environment. Remove the line.",
                    at("key_file")
                ));
            } else if entry.key_env.is_some() {
                errors.push(format!(
                    "{}: provider \"{}\" takes key_env or key_file, not both. Keep the one that holds its key and remove the other.",
                    at("key_file"),
                    entry.name
                ));
            } else if path.trim().is_empty() {
                errors.push(format!(
                    "{}: key_file is the path of a file that holds the provider key, for example /run/secrets/openai.key. The key itself never goes in this file.",
                    at("key_file")
                ));
            }
        }
        match (&entry.key_env, bedrock) {
            (Some(_), true) => errors.push(format!(
                "{}: a bedrock provider takes no key_env. Enterplace signs its requests with the AWS credentials it finds: the role of its pod, task or instance, or AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in its environment. Remove the line.",
                at("key_env")
            )),
            (Some(env), false) => {
                let env_ok =
                    !env.is_empty() && env.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
                if !env_ok {
                    errors.push(format!(
                        "{}: key_env is the name of an environment variable, for example OPENAI_API_KEY. The key itself never goes in this file.",
                        at("key_env")
                    ));
                }
            }
            // A model server on this machine or a private network, such as Ollama or vLLM, often takes no key.
            (None, false) if entry.allow_private && kind == Some(Kind::OpenAi) => {}
            // The demo model is answered inside the gateway: there is no provider to send a key to.
            (None, false) if kind == Some(Kind::Demo) => {}
            // Each caller brings their own login.
            (None, false) if entry.auth.as_deref() == Some("passthrough") => {}
            (None, false)
                if entry.key_file.is_some()
                    || entry.credential.is_some()
                    || !entry.keys.is_empty()
                    || entry.oci_signing.is_some() => {}
            // Vertex AI signs in with Google's Application Default Credentials.
            (None, false) if kind.is_some_and(Kind::google_auth) => {}
            // Azure OpenAI signs in with Microsoft Entra ID without a key.
            (None, false) if kind == Some(Kind::Azure) => {}
            (None, false) => errors.push(format!(
                "{}:{line}: provider \"{}\" has no key_env. Add the name of the environment variable that holds its key, for example `key_env: OPENAI_API_KEY`, or `key_file:` with the path of a file that holds it, or `credential:` with the name of a provider credential kept in the store. A model server of kind openai on this machine with `allow_private: true` may leave it out.",
                file.display(),
                entry.name
            )),
            (None, true) => {}
        }
        if !valid_name(&entry.name) {
            errors.push(format!(
                "{}: a provider name uses letters, digits, dots, dashes, underscores and @ only, at most 100 characters.",
                at("name")
            ));
        }
        let passthrough = provider_auth(entry, kind, &at, errors);
        let upstream_models = provider_options(entry, kind, &at, errors);
        let models = entry.models.clone().unwrap_or_default();
        if entry.kind.is_none() || entry.models.is_none() {
            // Only the lines that are missing, and an example model of the kind the provider already says it is.
            let example = match (ruled.is_empty(), kind) {
                (false, _) => ruled.join(", "),
                (true, Some(Kind::Anthropic | Kind::Bedrock | Kind::VertexAnthropic)) => {
                    "claude-sonnet-5-5".to_string()
                }
                (true, _) => "gpt-4o-mini".to_string(),
            };
            let mut missing = Vec::new();
            if entry.kind.is_none() {
                missing.push("    kind: openai".to_string());
            }
            if entry.models.is_none() {
                missing.push(format!("    models: [{example}]"));
            }
            let what = if missing.len() == 2 {
                "these two lines"
            } else {
                "this line"
            };
            let other_kind = if entry.kind.is_none() {
                "\nUse kind: anthropic for a provider that speaks the messages API, such as Anthropic."
            } else {
                ""
            };
            errors.push(format!(
                "{}:{line}: provider \"{}\" must now say which API it speaks and which models it serves. Add {what} under its name:\n{}{other_kind}",
                file.display(),
                entry.name,
                missing.join("\n")
            ));
        } else if models.is_empty() {
            errors.push(format!(
                "{}: provider \"{}\" lists no models, so nothing would reach it. List the exact model names it serves.",
                at("models"),
                entry.name
            ));
        }
        for model in &models {
            if model.trim().is_empty() {
                errors.push(format!(
                    "{}: provider \"{}\" lists an empty model name. List the exact model names it serves, or remove the empty one.",
                    at("models"),
                    entry.name
                ));
                continue;
            }
            if model == "*" {
                errors.push(format!(
                    "{}: a provider lists exact model names. \"*\" belongs in a rule, where it means every model.",
                    at("models")
                ));
                continue;
            }
            let claim = (model.clone(), entry.auth.as_deref() == Some("passthrough"));
            match claimed.get(&claim) {
                Some((other, other_line)) => errors.push(format!(
                    "{}: model \"{model}\" is listed by provider \"{}\" and by provider \"{other}\" at line {other_line}. A model is served by one provider. Remove it from one of them.",
                    at("models"),
                    entry.name
                )),
                None => {
                    let model_line = line_of_key(text, "models", line, until);
                    claimed.insert(claim, (entry.name.clone(), model_line));
                }
            }
        }
        for model in &models {
            // A missing map is reported once, above, not once per model.
            if let Some(map) = kind.and_then(map_key)
                && (entry.deployments.is_some() || entry.model_ids.is_some())
                && !upstream_models.contains_key(model)
            {
                errors.push(format!(
                    "{}: model \"{model}\" has no entry in {map}, so Enterplace would not know what to call it at provider \"{}\". Add `{model}: <name>` under {map}.",
                    at(map),
                    entry.name
                ));
            }
        }
        let keys = key_pool(entry, bedrock, parsed.store.is_some(), &at, errors);
        let key_weights: Vec<u32> = entry.keys.iter().map(|k| k.weight.unwrap_or(1)).collect();
        if entry
            .keys
            .iter()
            .any(|k| k.weight.is_some_and(|w| !(1..=1000).contains(&w)))
        {
            errors.push(format!(
                "{}: a key's weight is its share of the pool's requests, 1 to 1000.",
                at("keys")
            ));
        }
        let key_quarantine_seconds = entry.key_quarantine_seconds;
        if key_quarantine_seconds.is_some_and(|s| !(1..=86_400).contains(&s)) {
            errors.push(format!(
                "{}: key_quarantine_seconds is how long a key answered 401 or 403 is set aside, 1 to 86400 (default 3600).",
                at("key_quarantine_seconds")
            ));
        }
        let env_name =
            |v: &str| !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        for (header, variable) in &entry.headers_env {
            let reserved = [
                "authorization",
                "x-api-key",
                "api-key",
                "x-goog-api-key",
                "host",
                "content-length",
            ]
            .contains(&header.to_ascii_lowercase().as_str());
            let token = !header.is_empty()
                && header
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
            if !token || reserved || !env_name(variable) {
                errors.push(format!(
                    "{}: headers_env maps a header name to the environment variable that holds its value, such as `x-team-id: TEAM_ID_HEADER`. \"{header}\" is not one Enterplace sends this way: keys go in key_env or keys, and Host and Content-Length are Enterplace's.",
                    at("headers_env")
                ));
            }
        }
        if entry.proxy_env.as_deref().is_some_and(|v| !env_name(v)) {
            errors.push(format!(
                "{}: proxy_env names the environment variable that holds the proxy URL, such as `proxy_env: OPENAI_PROXY`.",
                at("proxy_env")
            ));
        }
        let least_used_key = match entry.key_balance.as_deref() {
            None | Some("round_robin") => false,
            Some("least_used") => true,
            Some(other) => {
                errors.push(format!(
                    "{}: key_balance is \"{other}\". Write round_robin (each key in turn) or least_used (the key with the fewest requests sent).",
                    at("key_balance")
                ));
                false
            }
        };
        let timeouts = timeouts(entry.timeouts.as_ref(), &at("timeouts"), errors);
        if let Some(kind) = kind {
            check_fallback(entry, kind, &models, &parsed.providers, &at, errors);
            out.push(Provider {
                name: entry.name.clone(),
                kind,
                models,
                url,
                key_env: entry.key_env.clone().unwrap_or_default(),
                key_file: entry.key_file.as_ref().map(PathBuf::from),
                credential: entry.credential.clone(),
                allow_private: entry.allow_private,
                upstream_models,
                api_version: entry.api_version.clone(),
                region: entry.region.clone(),
                role_arn: entry.role_arn.clone(),
                fallback: entry.fallback.clone(),
                retries: entry.retries.unwrap_or(0),
                accept_chat: entry.accept_chat.unwrap_or(false),
                // The demo answers Claude Code too, so its first request works with no key: translated like any chat provider.
                accept_messages: entry.accept_messages.unwrap_or(kind == Kind::Demo),
                timeouts,
                keys,
                least_used_key,
                key_weights,
                key_quarantine_seconds,
                headers_env: entry
                    .headers_env
                    .iter()
                    .map(|(h, v)| (h.to_ascii_lowercase(), v.clone()))
                    .collect(),
                proxy_env: entry.proxy_env.clone(),
                batch: entry.batch.as_ref().map(|b| ProviderBatch {
                    bucket: if b.bucket.ends_with('/') {
                        b.bucket.clone()
                    } else {
                        format!("{}/", b.bucket)
                    },
                    role_arn: b.role_arn.clone(),
                    url: b.url.as_ref().map(|u| u.trim_end_matches('/').to_string()),
                    storage_url: b
                        .storage_url
                        .as_ref()
                        .map(|u| u.trim_end_matches('/').to_string()),
                }),
                project_id: entry.project_id.clone(),
                chat_as_responses: entry.chat_as_responses.unwrap_or(false),
                passthrough,
                identity_optional: passthrough && entry.identity.as_deref() == Some("optional"),
                oci_signing: entry.oci_signing.as_ref().map(|oci| OciSigning {
                    tenancy: oci.tenancy.clone(),
                    user: oci.user.clone(),
                    fingerprint: oci.fingerprint.clone(),
                    key_file: oci.key_file.as_ref().map(PathBuf::from),
                    key_env: oci.key_env.clone(),
                }),
            });
        }
    }
    let mut names: Vec<&str> = parsed.providers.iter().map(|p| p.name.as_str()).collect();
    names.sort_unstable();
    if names.windows(2).any(|pair| pair[0] == pair[1]) {
        errors.push(format!(
            "{}: two providers have the same name. Each provider needs its own name, because records name the provider that served each request.",
            file.display()
        ));
    }
    out
}

/// Every problem in the text of a keys file. Empty means `enterplace serve` will accept it.
pub fn keys_problems(file: &Path, text: &str) -> Vec<String> {
    key_entries(file, text).err().unwrap_or_default()
}

/// The entries of a keys file, or every problem in it.
pub fn key_entries(file: &Path, text: &str) -> Result<Vec<KeyEntry>, Vec<String>> {
    let mut errors = Vec::new();
    let entries = if unknown_keys(file, text, &mut errors) {
        Vec::new()
    } else {
        keys(file, text, &mut errors)
    };
    if errors.is_empty() {
        Ok(entries)
    } else {
        Err(errors)
    }
}

fn keys(file: &Path, text: &str, errors: &mut Vec<String>) -> Vec<KeyEntry> {
    let mut entries: Vec<KeyEntry> = Vec::new();
    let parsed: KeysFile = match from_yaml(text) {
        Ok(parsed) => parsed,
        Err(err) => {
            errors.push(explain(file, text, &err));
            return entries;
        }
    };
    for entry in parsed.keys {
        let line = text
            .lines()
            .position(|l| l.contains(&entry.sha256))
            .map_or(0, |i| i + 1);
        let at = format!("{}:{line}", file.display());
        let hex_ok = entry.sha256.len() == 64
            && entry
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b.to_ascii_lowercase()));
        if !hex_ok {
            errors.push(format!("{at}: sha256 must be 64 hex characters. Run `enterplace key new` to add a key instead of writing one by hand."));
            continue;
        }
        if !valid_name(&entry.name) || !valid_name(&entry.team) {
            errors.push(format!(
                "{at}: a name and a team use letters, digits, dots, dashes, underscores and @ only, at most 100 characters."
            ));
            continue;
        }
        if let Some(expires) = &entry.expires
            && !expiry_shape(expires)
        {
            errors.push(format!("{at}: expires is \"{expires}\". Write a UTC date or time, for example expires: 2026-12-31 (the key stops working when that day starts) or expires: 2026-12-31T18:00:00Z."));
            continue;
        }
        if let Some(missing) = entry.expires.as_deref().and_then(missing_day) {
            errors.push(format!("{at}: expires {missing}. Write a day that exists."));
            continue;
        }
        let budget = match &entry.budget {
            Some(budget) => match budget_of(budget, &at, errors) {
                Some(budget) => Some(budget),
                None => continue,
            },
            None => None,
        };
        let sha256 = entry.sha256.to_ascii_lowercase();
        if let Some(first) = entries.iter().find(|e| e.sha256 == sha256) {
            errors.push(format!("{at}: this key is listed twice, the first time for \"{}\". Remove one of the two entries.", first.name));
            continue;
        }
        let tpm = entry.tpm.and_then(|tpm| tpm_of(tpm, &at, errors));
        let parallel = entry.parallel.and_then(|n| parallel_of(n, &at, errors));
        for name in entry
            .org
            .iter()
            .chain(entry.customer.iter())
            .chain(entry.role.iter())
            .chain(entry.tags.iter())
        {
            if !valid_name(name) {
                errors.push(format!(
                    "{at}: \"{name}\" is not a name Enterplace accepts for org, customer, role or tags. Use letters, digits, dots, dashes, underscores and @ only, at most 100 characters."
                ));
            }
        }
        if entry.tags.len() > MAX_TAGS {
            errors.push(format!(
                "{at}: a key carries at most {MAX_TAGS} tags. Remove some."
            ));
        }
        if entry.models.as_ref().is_some_and(Vec::is_empty) {
            errors.push(format!("{at}: models is empty, so this key could use no model. List the models it may use, or remove the line to leave its rule's list."));
        }
        let from = match cidrs(&entry.from) {
            Ok(from) => from,
            Err(problem) => {
                errors.push(format!("{at}: from: {problem}."));
                continue;
            }
        };
        let wide = |n: Option<i64>| n.map(|n| u32::try_from(n).unwrap_or(0));
        let options = KeyOptions {
            rpm: wide(entry.rpm),
            metadata: entry.metadata,
            routes: entry.routes,
            from,
            replaced_by: entry.replaced_by.map(|p| p.to_ascii_lowercase()),
            mcp_tools: entry.mcp_tools,
            guardrails: entry.guardrails,
        };
        if let Some(problem) = key_options_problem(&options) {
            errors.push(format!("{at}: {problem}."));
            continue;
        }
        entries.push(KeyEntry {
            name: entry.name,
            team: entry.team,
            sha256,
            admin: entry.admin,
            expires: entry.expires,
            budget,
            models: entry.models,
            tpm,
            org: entry.org.unwrap_or_default(),
            customer: entry.customer,
            tags: entry.tags,
            parallel,
            role: entry.role,
            options,
        });
    }
    entries
}

fn principals(entries: Vec<KeyEntry>) -> HashMap<[u8; 32], Principal> {
    let mut keys = HashMap::new();
    for entry in entries {
        let mut hash = [0u8; 32];
        for (byte, pair) in hash.iter_mut().zip(entry.sha256.as_bytes().chunks(2)) {
            *byte = std::str::from_utf8(pair)
                .ok()
                .and_then(|p| u8::from_str_radix(p, 16).ok())
                .unwrap_or(0);
        }
        keys.insert(
            hash,
            Principal {
                name: entry.name,
                team: entry.team,
                admin: entry.admin,
                key: entry.sha256[..8].to_string(),
                expires: entry.expires,
                budget: entry.budget,
                models: entry.models,
                tpm: entry.tpm,
                org: entry.org,
                customer: entry.customer,
                tags: entry.tags,
                parallel: entry.parallel,
                role: entry.role,
                options: entry.options,
                jwt: None,
            },
        );
    }
    keys
}

/// Reads and checks both files. Returns every problem found, one per line, each with its file and line.
pub fn load(policy_path: &Path, keys_path: Option<&Path>) -> Result<Loaded, Vec<String>> {
    let policy_text = policy_text(policy_path).map_err(|e| vec![e])?;
    if names_store(&policy_text) {
        // The keys are in the store: a keys file left beside the policy is not read. `enterplace check` has no
        // connection, so it checks the policy alone.
        let keys_file = keys_path.map_or_else(|| keys_path_for(policy_path), Path::to_path_buf);
        let text = crate::store::attached(&keys_file)
            .map(|store| store.keys_text())
            .unwrap_or_default();
        return load_texts(policy_path, &policy_text, &keys_file, &text);
    }
    // The keys file may not exist yet: a new setup has a policy before it has its first key.
    let (keys_file, keys_text) = match keys_path {
        Some(path) => (
            path.to_path_buf(),
            Some(read(path, "keys file").map_err(|e| vec![e])?),
        ),
        None => {
            let default = keys_path_for(policy_path);
            let text = read_keys(&default).map_err(|e| vec![e])?;
            (default, text)
        }
    };
    let found = keys_text.is_some();
    let mut loaded = load_texts(
        policy_path,
        &policy_text,
        &keys_file,
        &keys_text.unwrap_or_default(),
    )?;
    loaded.keys_file_found = found;
    Ok(loaded)
}

/// The policy in force for `policy_path`: the store's live version when the policy is kept there
/// (`store.policy_from: store`), the file otherwise. Every reader of the policy comes here, so the console, the
/// admin API and the reload never read one while the gateway serves the other.
pub fn policy_text(policy_path: &Path) -> Result<String, String> {
    if let Some(live) = crate::store::policy_store(policy_path).and_then(|s| s.live_policy()) {
        return Ok(live.text);
    }
    read(policy_path, "policy file")
}

/// Whether a policy text sets `store:`. A text that does not parse says no here and gets its problems from
/// `load_texts`.
pub fn names_store(policy_text: &str) -> bool {
    #[derive(Deserialize)]
    struct Probe {
        #[serde(default)]
        store: Option<serde::de::IgnoredAny>,
    }
    // The console loads the policy on every page and sign-in: a policy without the word is not parsed twice.
    policy_text.contains("store")
        && from_yaml::<Probe>(policy_text).is_ok_and(|probe| probe.store.is_some())
}

/// The providers that name a credential, with its name, from the policy file as it is now. Empty when it does not
/// load: `enterplace check` says why.
pub fn credentials_named(policy_path: &Path) -> Vec<(String, String)> {
    policy_text(policy_path)
        .ok()
        .and_then(|text| load_texts(policy_path, &text, policy_path, "").ok())
        .map(|loaded| {
            loaded
                .providers
                .into_iter()
                .filter_map(|p| p.credential.map(|c| (p.name, c)))
                .collect()
        })
        .unwrap_or_default()
}

/// The `store:` section, checked: the name of the variable that holds the connection string.
fn store_setting(
    file: &Path,
    text: &str,
    parsed: &PolicyFile,
    errors: &mut Vec<String>,
) -> Option<StoreSetting> {
    let store = parsed.store.as_ref()?;
    let env = &store.postgres_url_env;
    if env.is_empty() || !env.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        errors.push(format!(
            "{}:{}: postgres_url_env is the name of an environment variable that holds the connection string, for example DATABASE_URL. The string itself carries a password and never goes in this file.",
            file.display(),
            line_of_key(text, "postgres_url_env", 1, usize::MAX)
        ));
        return None;
    }
    let policy_from = match store.policy_from.as_deref() {
        None | Some("file") => PolicyFrom::File,
        Some("store") => PolicyFrom::Store,
        Some(other) => {
            errors.push(format!(
                "{}:{}: policy_from is \"{other}\". It is file (the policy file decides, as in GitOps) or store (the console and the admin API edit versions kept in the store).",
                file.display(),
                line_of_key(text, "policy_from", 1, usize::MAX)
            ));
            return None;
        }
    };
    Some(StoreSetting {
        postgres_url_env: env.clone(),
        policy_from,
        approval: store.approval,
        answer_cache: store.answer_cache,
    })
}

/// The identity providers under `jwt:`, each checked.
fn jwt_trusts(
    file: &Path,
    text: &str,
    parsed: &PolicyFile,
    errors: &mut Vec<String>,
) -> Vec<JwtTrust> {
    let mut out = Vec::new();
    for entry in &parsed.jwt {
        let at = format!(
            "{}:{}: jwt issuer \"{}\"",
            file.display(),
            line_of_key(text, &entry.issuer, 1, usize::MAX),
            entry.issuer
        );
        let before = errors.len();
        if entry.issuer.trim().is_empty() || entry.audience.trim().is_empty() {
            errors.push(format!("{at}: issuer and audience are the iss and aud your identity provider writes in its tokens. Give both."));
        }
        if !secure_url(&entry.jwks_url) {
            errors.push(format!("{at}: jwks_url is where the issuer publishes its signing keys, over https (http only on this machine), for example https://login.example.com/.well-known/jwks.json."));
        }
        let person_claim = entry.person_claim.clone().unwrap_or_else(|| "sub".into());
        if person_claim.trim().is_empty() {
            errors.push(format!(
                "{at}: person_claim names the claim that holds the person, such as email or sub."
            ));
        }
        match (&entry.team_claim, &entry.team) {
            (Some(claim), None) if !claim.trim().is_empty() => {}
            (None, Some(team)) if valid_name(team) => {}
            _ => errors.push(format!("{at}: give exactly one of team_claim (the claim that names the caller's team, such as team) or team (one team for every caller of this issuer).")),
        }
        if entry
            .role_claim
            .as_ref()
            .is_some_and(|c| c.trim().is_empty())
        {
            errors.push(format!("{at}: role_claim names the claim (a string or a list) whose values sign in to the admin API with the role whose sso_values hold one, such as groups. Remove it to keep this issuer off the admin API."));
        }
        if parsed
            .jwt
            .iter()
            .filter(|j| j.issuer == entry.issuer)
            .count()
            > 1
        {
            errors.push(format!("{at} is listed twice. Keep one."));
        }
        if errors.len() == before {
            out.push(JwtTrust {
                issuer: entry.issuer.clone(),
                audience: entry.audience.clone(),
                jwks_url: entry.jwks_url.clone(),
                person_claim,
                team_claim: entry.team_claim.clone(),
                team: entry.team.clone(),
                role_claim: entry.role_claim.clone(),
            });
        }
    }
    out
}

/// Checks the text of both files, as read by the caller, with the same rules as `load`.
pub fn load_texts(
    policy_path: &Path,
    policy_text: &str,
    keys_file: &Path,
    keys_text: &str,
) -> Result<Loaded, Vec<String>> {
    let mut errors = Vec::new();
    let keys = if unknown_keys(keys_file, keys_text, &mut errors) {
        Vec::new()
    } else {
        keys(keys_file, keys_text, &mut errors)
    };
    if unknown_keys(policy_path, policy_text, &mut errors) {
        return Err(errors);
    }

    let mut parsed: PolicyFile = match from_yaml(policy_text) {
        Ok(parsed) => parsed,
        Err(err) => {
            errors.push(explain(policy_path, policy_text, &err));
            return Err(errors);
        }
    };
    if parsed.version != 1 {
        errors.push(format!(
            "{}:{}: version is {}. This version of Enterplace reads version 1.",
            policy_path.display(),
            line_of_key(policy_text, "version", 1, usize::MAX),
            parsed.version
        ));
    }
    presets(policy_path, policy_text, &mut parsed.providers, &mut errors);
    let providers = providers(policy_path, policy_text, &parsed, &mut errors);
    let mut rules = policy_rules(policy_path, policy_text, &parsed, &mut errors);
    let guardrail_defs =
        rule_guardrails(policy_path, policy_text, &parsed, &mut rules, &mut errors);
    for (name, members) in &parsed.model_groups {
        if !valid_name(name)
            || members.is_empty()
            || members
                .iter()
                .any(|m| m.trim().is_empty() || m.starts_with("group:"))
        {
            errors.push(format!(
                "{}:{}: model group \"{name}\" needs a name in letters, digits, dots, dashes, underscores and @, and a list of at least one model (a name, or a pattern such as gpt-*; not another group), for example model_groups: {{ cheap: [gpt-4o-mini, claude-haiku-*] }}.",
                policy_path.display(),
                line_of_key(policy_text, "model_groups", 1, usize::MAX)
            ));
        }
    }
    let mut key_bounds = Vec::new();
    if let Some(bounds) = &parsed.key_bounds {
        let at = format!(
            "{}:{}",
            policy_path.display(),
            line_of_key(policy_text, "key_bounds", 1, usize::MAX)
        );
        key_bounds.push((
            String::new(),
            key_bounds_of(bounds, &parsed.model_groups, &at, &mut errors),
        ));
    }
    let role_lines = list_lines(policy_text, "roles");
    for (i, role) in parsed.roles.iter().enumerate() {
        if let Some(bounds) = &role.key_bounds {
            let at = format!(
                "{}:{}",
                policy_path.display(),
                role_lines.get(i).copied().unwrap_or(0)
            );
            key_bounds.push((
                role.name.clone(),
                key_bounds_of(bounds, &parsed.model_groups, &at, &mut errors),
            ));
        }
    }
    rule_passthrough(policy_path, policy_text, &rules, &providers, &mut errors);
    check_prices(
        policy_path,
        policy_text,
        &parsed,
        &rules,
        &providers,
        &mut errors,
    );
    let sso = console_sso(policy_path, policy_text, &parsed, &mut errors);
    let aliases = aliases(policy_path, policy_text, &parsed, &providers, &mut errors);
    let mcp = crate::mcp::servers(policy_path, policy_text, &parsed.mcp, &mut errors);
    let bundles = crate::mcp::bundles(
        policy_path,
        policy_text,
        &parsed.mcp_bundles,
        &parsed.mcp,
        &mut errors,
    );
    let store = store_setting(policy_path, policy_text, &parsed, &mut errors);
    let mode = match parsed.mode.as_deref() {
        None | Some("enforce") => Mode::Enforce,
        Some("observe") => Mode::Observe,
        Some(other) => {
            errors.push(format!(
                "{}:{}: mode is \"{other}\". Write mode: observe to forward every request and record what the policy would refuse, or mode: enforce (the default) to refuse it.",
                policy_path.display(),
                line_of_key(policy_text, "mode", 1, usize::MAX)
            ));
            Mode::Enforce
        }
    };
    check_orgs(policy_path, policy_text, &parsed, &mut errors);
    check_profiles(policy_path, policy_text, &parsed, &mut errors);
    let scope_limits = scope_limits(policy_path, policy_text, &parsed, &mut errors);
    let roles = roles(policy_path, policy_text, &parsed, &mut errors);
    let teams = teams(policy_path, policy_text, &parsed, &mut errors);
    let saml = console_saml(policy_path, policy_text, &parsed, &mut errors);
    // A key's org and role must be ones the policy has: a misspelled org would be a tenant with no rules, and a
    // misspelled role a key that cannot sign in.
    let mut keys = keys;
    for entry in &mut keys {
        let line = keys_text
            .lines()
            .position(|l| l.contains(&entry.sha256))
            .map_or(0, |i| i + 1);
        let at = format!("{}:{line}", keys_file.display());
        if let Some(models) = &entry.models {
            entry.models = Some(with_groups(models, &parsed.model_groups, &at, &mut errors));
        }
        if let Some(missing) = entry
            .options
            .guardrails
            .iter()
            .find(|name| !guardrail_defs.iter().any(|g| g.name == **name))
        {
            errors.push(format!(
                "{at}: the key adds guardrail \"{missing}\", which is not defined under guardrails in the policy. Define it there, or check the spelling. The guardrails are: {}.",
                names_or_none(guardrail_defs.iter().map(|g| g.name.as_str()))
            ));
        }
        if !entry.org.is_empty() {
            check_org(&parsed.orgs, &entry.org, &at, &mut errors);
        }
        if let Some(role) = &entry.role
            && crate::policy::builtin_role(role).is_none()
            && !roles.iter().any(|r| r.name == *role)
        {
            errors.push(format!(
                "{at}: role \"{role}\" is not defined under roles in the policy, and is not a built-in role (admin, read_only). Define it, or check the spelling."
            ));
        }
    }
    let jwt = jwt_trusts(policy_path, policy_text, &parsed, &mut errors);
    let trusted_proxies = match cidrs(&parsed.trusted_proxies) {
        Ok(list) => list,
        Err(problem) => {
            errors.push(format!(
                "{}:{}: trusted_proxies: {problem}. List the addresses of the load balancers in front of Enterplace.",
                policy_path.display(),
                line_of_key(policy_text, "trusted_proxies", 1, usize::MAX)
            ));
            Vec::new()
        }
    };
    let cors = match parsed.cors.as_ref().map(cors_of).transpose() {
        Ok(cors) => cors,
        Err(problem) => {
            errors.push(format!(
                "{}:{}: {problem}",
                policy_path.display(),
                line_of_key(policy_text, "cors", 1, usize::MAX)
            ));
            None
        }
    };
    let audit_path = match parsed.audit.as_ref().and_then(|a| a.path.clone()) {
        Some(path) => path,
        None => policy_path.with_file_name("enterplace-audit.jsonl"),
    };
    let audit_per_org = parsed.audit.as_ref().is_some_and(|a| a.per_org);
    match providers {
        providers if errors.is_empty() => Ok(Loaded {
            policy: Policy::from_parts(principals(keys), rules)
                .with_prices(parsed.prices)
                .with_mcp_bundles(bundles)
                .with_scope_limits(scope_limits)
                .with_roles(roles)
                .with_teams(teams)
                .with_orgs(parsed.orgs.clone())
                .with_jwt(jwt)
                .with_trusted_proxies(trusted_proxies)
                .with_cors(cors)
                .with_guardrail_defs(guardrail_defs)
                .with_model_groups(parsed.model_groups.clone().into_iter().collect())
                .with_key_bounds(key_bounds)
                .with_mode(mode),
            providers,
            audit_path,
            audit_per_org,
            keys_path: keys_file.to_path_buf(),
            policy_sha256: sha256_hex(policy_text.as_bytes()),
            keys_sha256: sha256_hex(keys_text.as_bytes()),
            policy_text: policy_text.to_string(),
            keys_file_found: true,
            sso,
            saml,
            aliases,
            mcp,
            store,
        }),
        _ => Err(errors),
    }
}

/// Why a running Enterplace cannot change from `old` to `new` without a restart. Empty when it can.
/// The audit log is opened once, MCP servers' credentials and the store's connection are read once, at start.
/// Providers may be added, removed or pointed elsewhere: the reload builds the routes that changed.
pub fn needs_restart(old: &Loaded, new: &Loaded) -> Vec<String> {
    let mut reasons = Vec::new();
    if old.audit_path != new.audit_path {
        reasons.push(format!(
            "the audit log path changed from {} to {}. A running Enterplace keeps writing one chain: restart Enterplace to change it.",
            old.audit_path.display(),
            new.audit_path.display()
        ));
    }
    if old.audit_per_org != new.audit_per_org {
        reasons.push(
            "audit per_org changed. Which chain each organization's records go to is set when the audit log opens: restart Enterplace to change it.".to_string(),
        );
    }
    // The connection to the store is made once, at start, and the source of the policy is chosen then. Approval
    // may change while Enterplace runs.
    let connection = |s: &Option<StoreSetting>| {
        s.as_ref()
            .map(|s| (s.postgres_url_env.clone(), s.policy_from))
    };
    if connection(&old.store) != connection(&new.store) {
        reasons.push(
            "the store section changed. Enterplace connects to its store and picks the policy's source at start: restart Enterplace to apply it.".to_string(),
        );
    }
    reasons
}

/// Whether two versions of a provider reach it the same way: same kind, address, key and signing. A provider whose
/// connection changed gets a new route at the reload; one whose only change is its models keeps its route.
pub fn same_connection(a: &Provider, b: &Provider) -> bool {
    a.kind == b.kind
        && a.url == b.url
        && a.key_env == b.key_env
        && a.key_file == b.key_file
        && a.credential == b.credential
        && a.api_version == b.api_version
        && a.region == b.region
        && a.role_arn == b.role_arn
        && a.allow_private == b.allow_private
        && a.batch == b.batch
        && a.keys == b.keys
        && a.key_weights == b.key_weights
        && a.least_used_key == b.least_used_key
        && a.key_quarantine_seconds == b.key_quarantine_seconds
        && a.headers_env == b.headers_env
        && a.proxy_env == b.proxy_env
        && a.timeouts == b.timeouts
        && a.project_id == b.project_id
        && a.oci_signing == b.oci_signing
}

/// What `enterplace check` warns about in a policy that loads: observe mode, and models no provider serves.
pub fn warnings(policy_path: &Path, loaded: &Loaded) -> Vec<String> {
    let mut out = Vec::new();
    if loaded.policy.mode() == Mode::Observe {
        out.push(format!(
            "warning: {}:{}: mode: observe is on, so nothing is refused but a missing, bad or revoked key, an unknown model and a kill switch. What the policy would refuse is forwarded and recorded as would_refuse. Remove the line, or write mode: enforce, to enforce the policy.",
            policy_path.display(),
            line_of_key(&loaded.policy_text, "mode", 1, usize::MAX)
        ));
    }
    out.extend(unserved_models(policy_path, loaded));
    out
}

/// A warning for each model a rule names that no provider serves. Requests for it are refused, so it is
/// probably a typo or a provider not added yet, but it is not an error: the rule still decides correctly.
/// Whether `model` is `<provider>/<name>` for a provider that serves `<name>`, by name or pattern.
pub fn served_by_prefix(providers: &[Provider], model: &str) -> bool {
    model.split_once('/').is_some_and(|(provider, name)| {
        providers.iter().any(|p| {
            p.name == provider
                && p.models
                    .iter()
                    .any(|m| model_matches(m, name) || model_matches(name, m))
        })
    })
}

pub fn unserved_models(policy_path: &Path, loaded: &Loaded) -> Vec<String> {
    let mut warnings = Vec::new();
    for rule in loaded.policy.rule_list() {
        let Models::Only(models) = &rule.models else {
            continue;
        };
        let models_line = line_of_key(&loaded.policy_text, "models", rule.line, usize::MAX);
        for model in models {
            if !loaded.providers.iter().any(|p| {
                p.models
                    .iter()
                    .any(|m| model_matches(m, model) || model_matches(model, m))
            }) && !loaded.aliases.iter().any(|a| a.name == *model)
                && !served_by_prefix(&loaded.providers, model)
            {
                warnings.push(format!(
                    "warning: {}:{models_line}: rule \"{}\" names model \"{model}\", which no provider serves, so requests for it are refused with unknown_model. Add it to a provider's models, or check the spelling.",
                    policy_path.display(),
                    rule.name
                ));
            }
        }
    }
    // Model names are matched exactly, so a name that differs from another only in case or spaces, or that holds
    // a `*`, is most likely a mistake: requests for the other spelling go elsewhere or are refused.
    let mut spellings: HashMap<String, (&str, &str)> = HashMap::new();
    for provider in &loaded.providers {
        for model in &provider.models {
            let at = format!(
                "warning: {}: provider \"{}\"",
                policy_path.display(),
                provider.name
            );
            if model.trim() != model {
                warnings.push(format!(
                    "{at} lists model \"{model}\" with spaces at its start or end, and no client sends that name. Remove the spaces."
                ));
            }
            let folded = model.trim().to_lowercase();
            match spellings.get(&folded) {
                Some((other, other_provider)) if other != model => warnings.push(format!(
                    "{at} lists model \"{model}\", and provider \"{other_provider}\" lists \"{other}\". Names are matched exactly, so these are two models: check which spelling is meant."
                )),
                Some(_) => {}
                None => {
                    spellings.insert(folded, (model, &provider.name));
                }
            }
        }
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Budget, Decision, Limits, Period};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const GOOD: &str = "\
# Who may use which model.
version: 1
providers:
  - name: openai
    kind: openai
    url: https://api.openai.com
    key_env: OPENAI_API_KEY
    models: [gpt-4o-mini, gpt-4o]
rules:
  - name: payments-team
    principals: { team: payments }
    models: [gpt-4o-mini]
  - name: everyone-else
    principals: { any: true }
    models: [\"*\"]
";

    fn dir(name: &str) -> std::io::Result<PathBuf> {
        let dir =
            std::env::temp_dir().join(format!("enterplace-config-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    fn check(
        name: &str,
        policy: &str,
        keys: Option<&str>,
    ) -> Result<Result<Loaded, Vec<String>>, std::io::Error> {
        let dir = dir(name)?;
        let path = dir.join("enterplace.policy.yaml");
        std::fs::write(&path, policy)?;
        if let Some(keys) = keys {
            std::fs::write(dir.join("enterplace.keys.yaml"), keys)?;
        }
        Ok(load(&path, None))
    }

    fn errors(result: Result<Loaded, Vec<String>>) -> Result<String, &'static str> {
        result
            .err()
            .map(|e| e.join("\n"))
            .ok_or("the file was accepted")
    }

    #[test]
    fn groups_bounds_requirements_and_session_limits_load_and_their_mistakes_name_the_fix()
    -> TestResult {
        let good = format!(
            "{GOOD}guardrails:\n  - name: no-secrets\n    type: secrets\n    action: block\ndefault_guardrails: [no-secrets]\nmodel_groups:\n  small: [gpt-4o-mini]\nkey_bounds:\n  max_days: 90\n  models: [\"group:small\"]\nlimits:\n  - {{ model_group: small, rate: {{ rpd: 100, rph: 10 }} }}\n"
        )
        .replace(
            "    models: [gpt-4o-mini]\n",
            "    models: [\"group:small\"]\n    require: { headers: [X-Tenant-ID], body: [metadata.ticket] }\n    budget: { usd: 5, per: session }\n    rate: { session_requests: 20, rpd: 500 }\n",
        );
        let loaded = check("gov-good", &good, None)?.map_err(|e| e.join("\n"))?;
        let rules = loaded.policy.rule_list();
        let (first, second) = (&rules[0], &rules[1]);
        assert!(first.allows("gpt-4o-mini") && !first.allows("gpt-4o"));
        assert_eq!(first.limits.require_headers, ["x-tenant-id"]);
        assert_eq!(first.limits.require_body, ["metadata.ticket"]);
        assert_eq!(first.limits.session_budget.map(|b| b.usd), Some(5.0));
        assert_eq!(
            (first.limits.session_requests, first.limits.rpd),
            (Some(20), Some(500))
        );
        assert!(
            first.limits.budgets.is_empty(),
            "a session budget is no calendar budget"
        );
        // The default guardrail runs on a rule that lists none.
        assert_eq!(second.guardrails.len(), 1);
        let bounds = loaded.policy.key_bounds(Some("admin")).ok_or("no bounds")?;
        assert_eq!(
            (bounds.max_days, bounds.models.as_slice()),
            (Some(90), &["gpt-4o-mini".to_string()][..])
        );

        for (name, from, to, word) in [
            (
                "group",
                "[\"group:small\"]\n    require",
                "[\"group:tiny\"]\n    require",
                "model_groups does not define",
            ),
            (
                "limit-group",
                "model_group: small",
                "model_group: tiny",
                "model_groups does not define",
            ),
            (
                "guard",
                "default_guardrails: [no-secrets]",
                "default_guardrails: [nope]",
                "nope",
            ),
            (
                "require",
                "headers: [X-Tenant-ID]",
                "headers: [\"bad header\"]",
                "require lists the headers",
            ),
            (
                "session",
                "{ usd: 5, per: session }",
                "{ usd: 5, per: session, tz: UTC }",
                "a session budget is usd above 0",
            ),
            ("rpd", "rpd: 500", "rpd: 0", "rpd is a number of requests"),
            (
                "bounds",
                "max_days: 90",
                "max_days: 0",
                "max_days is the longest a key may work",
            ),
        ] {
            assert!(good.contains(from), "{from}");
            let found = errors(check(
                &format!("gov-{name}"),
                &good.replace(from, to),
                None,
            )?)?;
            assert!(found.contains(word), "{name}: {found}");
        }
        // A key may add only guardrails the policy defines.
        let keys = "keys:\n  - name: bot\n    team: payments\n    sha256: 0000000000000000000000000000000000000000000000000000000000000001\n    guardrails: [GUARD]\n";
        check("gov-key", &good, Some(&keys.replace("GUARD", "no-secrets")))?
            .map_err(|e| e.join("\n"))?;
        let found = errors(check(
            "gov-key-bad",
            &good,
            Some(&keys.replace("GUARD", "other")),
        )?)?;
        assert!(
            found.contains("adds guardrail \"other\", which is not defined"),
            "{found}"
        );
        Ok(())
    }

    #[test]
    fn a_key_is_held_to_its_issuer_s_bounds() -> TestResult {
        let policy = format!(
            "{GOOD}model_groups:\n  small: [gpt-4o-mini]\nkey_bounds:\n  max_days: 30\n  max_budget: {{ usd: 100, per: month }}\n  models: [\"group:small\"]\nroles:\n  - name: lead\n    permissions: [issue_keys]\n    key_bounds:\n      max_days: 7\n"
        );
        let loaded = check("bounds", &policy, None)?.map_err(|e| e.join("\n"))?;
        let day = Budget {
            usd: 5.0,
            per: Period::Day,
        };
        // Unset fields take the bound; the role's own bounds replace the policy's for its holders.
        let (mut expires, mut budget, mut models) = (None, None, None);
        bound_key(&loaded.policy, None, &mut expires, &mut budget, &mut models)?;
        assert_eq!(budget.map(|b| b.usd), Some(100.0));
        assert_eq!(models, Some(vec!["gpt-4o-mini".to_string()]));
        let month = expires.ok_or("no expiry")?;
        let (mut week, mut none, mut any) = (None, None, None);
        bound_key(&loaded.policy, Some("lead"), &mut week, &mut none, &mut any)?;
        assert!(week.ok_or("no expiry")? < month && none.is_none() && any.is_none());
        // $5 a day is $155 a month: faster than $100 a month.
        let over = bound_key(&loaded.policy, None, &mut None, &mut Some(day), &mut None);
        assert!(over.is_err_and(|e| e.contains("at most $100 a month")));
        let over = bound_key(
            &loaded.policy,
            None,
            &mut Some("2099-01-01".into()),
            &mut None,
            &mut None,
        );
        assert!(over.is_err_and(|e| e.contains("at most 30 days")));
        let over = bound_key(
            &loaded.policy,
            None,
            &mut None,
            &mut None,
            &mut Some(vec!["gpt-4o".into()]),
        );
        assert!(over.is_err_and(|e| e.contains("only gpt-4o-mini")));
        Ok(())
    }

    #[test]
    fn a_rule_names_the_provider_paths_it_may_reach_and_bad_ones_are_refused() -> TestResult {
        let with = |entry: &str| {
            format!(
                "version: 1\nproviders:\n  - name: openai\n    kind: openai\n    url: https://api.openai.com\n    key_env: K\n    models: [gpt-4o]\n  - name: bedrock\n    kind: bedrock\n    region: us-east-1\n    models: [m]\n    model_ids: {{ m: x }}\nrules:\n  - name: batch\n    principals: {{ team: data }}\n    models: [gpt-4o]\n    passthrough:\n{entry}"
            )
        };
        let loaded = check(
            "pt-good",
            &with("      - { provider: openai, paths: [/v1/batches, /v1/files] }\n"),
            None,
        )?
        .map_err(|e| e.join("\n"))?;
        let rule = loaded.policy.rule_list().first().ok_or("no rule")?;
        assert!(rule.reaches("openai", "/v1/batches"));
        assert!(rule.reaches("openai", "/v1/batches/batch_1/cancel"));
        assert!(
            !rule.reaches("openai", "/v1/batchesX"),
            "a prefix matches whole path segments"
        );
        assert!(!rule.reaches("openai", "/v1/organization/admin_api_keys"));
        assert!(!rule.reaches("anthropic", "/v1/batches"));
        // Bedrock and Vertex AI are signed on the way out, so a rule may pass through to them too.
        let signed = check(
            "pt-bedrock",
            &with("      - { provider: bedrock, paths: [/model/x/converse] }\n"),
            None,
        )?;
        assert!(signed.is_ok(), "{signed:?}");
        for (entry, expected) in [
            (
                "      - { provider: nope, paths: [/v1/x] }\n",
                "no provider named \"nope\"",
            ),
            (
                "      - { provider: openai, paths: [v1/x] }\n",
                "starts with /",
            ),
            (
                "      - { provider: openai, paths: [/v1/../admin] }\n",
                "..",
            ),
            (
                "      - { provider: openai, paths: [] }\n",
                "at least one path",
            ),
        ] {
            let found = errors(check("pt-bad", &with(entry), None)?)?;
            assert!(found.contains(expected), "{entry}: {found}");
            assert!(
                found.contains("enterplace.policy.yaml:"),
                "the error names file and line: {found}"
            );
        }
        Ok(())
    }

    #[test]
    fn the_example_file_loads_with_rule_lines() -> TestResult {
        let key = "enterplace_test";
        let keys = format!(
            "keys:\n  - name: maya.cohen\n    team: payments\n    sha256: {}\n",
            sha256_hex(key.as_bytes())
        );
        let loaded = check("good", GOOD, Some(&keys))?.map_err(|e| e.join("\n"))?;
        assert_eq!(loaded.providers[0].url, "https://api.openai.com");
        assert_eq!(loaded.providers[0].kind, Kind::OpenAi);
        let who = loaded
            .policy
            .identify(key)
            .ok_or("the key was not loaded")?;
        assert!(
            matches!(loaded.policy.decide(who, "gpt-4o-mini"), Decision::Allow(rule) if rule.line == 10)
        );
        assert!(
            matches!(loaded.policy.decide(who, "gpt-4o"), Decision::ModelNotAllowed(rule) if rule.name == "payments-team")
        );
        assert_eq!(loaded.policy.rules(), 2);
        Ok(())
    }

    #[test]
    fn a_misspelled_key_is_named_with_its_line_and_the_nearest_word() -> TestResult {
        let text = errors(check(
            "typo",
            &GOOD.replace("    models: [gpt-4o-mini]", "    modles: [gpt-4o-mini]"),
            None,
        )?)?;
        assert!(text.contains("enterplace.policy.yaml:12"), "{text}");
        assert!(
            text.contains("\"modles\"") && text.contains("Did you mean \"models\"?"),
            "{text}"
        );
        Ok(())
    }

    #[test]
    fn mcp_servers_and_rule_tools_load() -> TestResult {
        let text = format!(
            "{}{}",
            GOOD.replace(
                "    models: [gpt-4o-mini]\n",
                "    models: [gpt-4o-mini]\n    tools: [github.create_issue, docs.*]\n",
            ),
            "mcp:
  - name: github
    url: https://mcp.example.com/github/
    headers_env: { Authorization: GITHUB_MCP_TOKEN }
  - name: docs
    url: http://127.0.0.1:9000/mcp
    allow_private: true
"
        );
        let loaded = check("mcp-good", &text, None)?.map_err(|e| e.join("\n"))?;
        assert_eq!(loaded.mcp.len(), 2);
        assert_eq!(loaded.mcp[0].url, "https://mcp.example.com/github");
        assert_eq!(
            loaded.mcp[0].headers_env,
            [("Authorization".to_string(), "GITHUB_MCP_TOKEN".to_string())]
        );
        let rules = loaded.policy.rule_list();
        assert_eq!(rules[0].tools, ["github.create_issue", "docs.*"]);
        // A rule that says nothing about tools allows none.
        assert!(rules[1].tools.is_empty());
        Ok(())
    }

    #[test]
    fn mcp_mistakes_are_named_with_their_line() -> TestResult {
        let text = format!(
            "{}{}",
            GOOD.replace(
                "    models: [gpt-4o-mini]\n",
                "    models: [gpt-4o-mini]\n    tools: [gitlab.create_issue, search]\n",
            ),
            "mcp:
  - name: git.hub
    url: http://10.0.0.5/mcp
    headers_env: { Authorization: Bearer abc }
"
        );
        let text = errors(check("mcp-bad", &text, None)?)?;
        for expected in [
            "enterplace.policy.yaml:13: tool \"gitlab.create_issue\" is on MCP server \"gitlab\", which is not defined under mcp. The MCP servers are: git.hub.",
            "enterplace.policy.yaml:13: tool \"search\" names no server.",
            "enterplace.policy.yaml:18: an MCP server name uses letters",
            "enterplace.policy.yaml:19: the MCP server url points at this machine or a private network",
            "enterplace.policy.yaml:20: headers_env gives header Authorization the value \"Bearer abc\"",
        ] {
            assert!(text.contains(expected), "missing {expected}:\n{text}");
        }
        Ok(())
    }

    #[test]
    fn mcp_prompts_resources_approvals_and_bundles_load_and_are_checked() -> TestResult {
        let text = format!(
            "{}{}",
            GOOD.replace(
                "    models: [gpt-4o-mini]\n",
                "    models: [gpt-4o-mini]\n    tools: [docs.*]\n    prompts: [docs.*]\n    resources: [docs.file:///readme]\n    approve_tools: [docs.delete]\n    approval_timeout_seconds: 60\n",
            ),
            "mcp:
  - name: docs
    url: https://mcp.example.com/docs
mcp_bundles:
  - name: payments-tools
    tools: [docs.search]
    teams: [payments]
"
        );
        let loaded = check("mcp-more", &text, None)?.map_err(|e| e.join("\n"))?;
        let rule = &loaded.policy.rule_list()[0];
        assert_eq!(rule.mcp.prompts, ["docs.*"]);
        assert_eq!(rule.mcp.resources, ["docs.file:///readme"]);
        assert_eq!(rule.mcp.approve, ["docs.delete"]);
        assert_eq!(rule.mcp.approval_timeout_seconds, 60);
        let bundle = loaded
            .policy
            .mcp_bundle("payments-tools")
            .ok_or("no bundle")?;
        assert_eq!(bundle.tools, ["docs.search"]);
        assert_eq!(bundle.teams, ["payments"]);
        let bad = text
            .replace(
                "approval_timeout_seconds: 60",
                "approval_timeout_seconds: 5",
            )
            .replace("prompts: [docs.*]", "prompts: [wiki.*]")
            .replace("tools: [docs.search]", "tools: [nowhere.search]");
        let errors = errors(check("mcp-more-bad", &bad, None)?)?;
        for expected in [
            "approval_timeout_seconds is 5",
            "prompt \"wiki.*\" is on MCP server \"wiki\"",
            "tool \"nowhere.search\" is on MCP server \"nowhere\"",
        ] {
            assert!(errors.contains(expected), "missing {expected}:\n{errors}");
        }
        Ok(())
    }

    #[test]
    fn routing_residency_access_and_jwt_settings_load_and_wrong_ones_are_named() -> TestResult {
        let policy = "\
version: 1
providers:
  - name: eu
    kind: openai
    url: https://eu.example.com
    key_env: EU_KEY
    models: [gpt-4o]
  - name: us
    kind: openai
    url: https://us.example.com
    key_env: US_KEY
    models: [gpt-4o-mini]
trusted_proxies: [10.0.0.0/8]
jwt:
  - issuer: https://login.example.com
    audience: enterplace
    jwks_url: https://login.example.com/jwks
    person_claim: email
    team_claim: team
aliases:
  - name: smart
    balance: lowest_latency
    session_affinity: true
    deployments:
      - { provider: eu, model: gpt-4o, region: eu }
      - { provider: us, model: gpt-4o-mini, region: us, for: { tag: batch } }
rules:
  - name: everyone
    principals: { any: true }
    models: [smart]
    from: [203.0.113.0/24, 10.1.2.3]
    regions: [eu]
    tags: [batch]
";
        let loaded = check("routing", policy, None)?.map_err(|e| e.join("\n"))?;
        let alias = &loaded.aliases[0];
        assert_eq!(alias.balance, Balance::LowestLatency);
        assert!(alias.session_affinity);
        assert_eq!(alias.deployments[0].region.as_deref(), Some("eu"));
        assert_eq!(alias.deployments[1].for_, Some(For::Tag("batch".into())));
        let limits = &loaded.policy.rule_list()[0].limits;
        assert_eq!(limits.from.len(), 2);
        assert_eq!(limits.regions, Some(vec!["eu".to_string()]));
        assert_eq!(loaded.policy.rule_list()[0].tags, ["batch"]);
        let jwt = &loaded.policy.jwt()[0];
        assert_eq!(
            (jwt.person_claim.as_str(), jwt.team_claim.as_deref()),
            ("email", Some("team"))
        );
        assert_eq!(
            loaded
                .policy
                .client_ip("10.0.0.1".parse()?, &["198.51.100.4"]),
            "198.51.100.4".parse::<IpAddr>()?
        );
        for (from, to, expected) in [
            ("balance: lowest_latency", "balance: lowest_cost", ""),
            (
                "team_claim: team\n",
                "team_claim: team\n    role_claim: groups\n",
                "",
            ),
            (
                "team_claim: team\n",
                "team_claim: team\n    role_claim: \" \"\n",
                "role_claim names the claim",
            ),
            (
                "balance: lowest_latency",
                "balance: fastest",
                "lowest_latency (fastest",
            ),
            ("region: eu }", "region: \"e u\" }", "region is a label"),
            (
                "for: { tag: batch }",
                "for: { tag: batch, team: x }",
                "exactly one of",
            ),
            (
                "from: [203.0.113.0/24, 10.1.2.3]",
                "from: [203.0.113.0/33]",
                "is not an address range",
            ),
            ("regions: [eu]", "regions: []", "regions lists the regions"),
            (
                "tags: [batch]",
                "tags: [\"a b\"]",
                "\"a b\" in tags is not a name",
            ),
            (
                "trusted_proxies: [10.0.0.0/8]",
                "trusted_proxies: [lb]",
                "trusted_proxies:",
            ),
            (
                "jwks_url: https://login.example.com/jwks",
                "jwks_url: http://login.example.com/jwks",
                "jwks_url is where",
            ),
            (
                "    team_claim: team\n",
                "",
                "give exactly one of team_claim",
            ),
            (
                "    team_claim: team\n",
                "    team_claim: team\n    team: x\n",
                "give exactly one of team_claim",
            ),
        ] {
            let text = policy.replace(from, to);
            assert_ne!(text, policy, "{from}");
            let result = check("routing", &text, None)?;
            if expected.is_empty() {
                assert!(result.is_ok(), "{to}: {:?}", result.err());
            } else {
                let problems = errors(result)?;
                assert!(problems.contains(expected), "{to}: {problems}");
            }
        }
        Ok(())
    }

    #[test]
    fn a_keys_file_carries_every_key_option_and_a_wrong_one_is_named() -> TestResult {
        let policy = "version: 1\nproviders:\n  - name: openai\n    kind: openai\n    url: https://api.openai.com\n    key_env: K\n    models: [gpt-4o]\nrules:\n  - name: all\n    principals: { any: true }\n    models: [gpt-4o]\n";
        let keys = "keys:\n  - name: ci\n    team: t\n    sha256: aaaaaaaa00000000000000000000000000000000000000000000000000000000\n    rpm: 60\n    parallel: 2\n    tags: [batch]\n    metadata: { owner: maya, ticket: OPS-1 }\n    routes: [/v1/chat/completions]\n    from: [10.0.0.0/8]\n    replaced_by: \"bbbbbbbb\"\n";
        let loaded = check("key-options", policy, Some(keys))?.map_err(|e| e.join("\n"))?;
        let Some((_, who)) = loaded.policy.entries().next() else {
            return Err("no key loaded".into());
        };
        assert_eq!((who.options.rpm, who.parallel), (Some(60), Some(2)));
        assert_eq!(who.tags, ["batch"]);
        assert_eq!(
            who.options.metadata.get("ticket").map(String::as_str),
            Some("OPS-1")
        );
        assert_eq!(who.options.replaced_by.as_deref(), Some("bbbbbbbb"));
        for (from, to, expected) in [
            ("rpm: 60", "rpm: 0", "rpm is the requests"),
            ("parallel: 2", "parallel: -1", "parallel"),
            (
                "from: [10.0.0.0/8]",
                "from: [ten]",
                "is not an address range",
            ),
            (
                "routes: [/v1/chat/completions]",
                "routes: [v1]",
                "routes lists",
            ),
            (
                "replaced_by: \"bbbbbbbb\"",
                "replaced_by: \"zz\"",
                "replaced_by is",
            ),
        ] {
            let text = keys.replace(from, to);
            let problems = errors(check("key-options", policy, Some(&text))?)?;
            assert!(problems.contains(expected), "{to}: {problems}");
        }
        Ok(())
    }

    const LIMITED: &str = "\
version: 1
providers:
  - name: openai
    kind: openai
    url: https://api.openai.com
    key_env: OPENAI_API_KEY
    models: [gpt-4o-mini, o3]
prices:
  o3:
    input: 2
    output: 8
    cache_read: 0.5
rules:
  - name: payments-team
    principals: { team: payments }
    models: [gpt-4o-mini, o3]
    budget: { usd: 2000, per: month }
    rate: { rpm: 600 }
    cache: { ttl_seconds: 300 }
  - name: everyone-else
    principals: { any: true }
    models: [\"*\"]
    budget:
      usd: 12.5
      per: day
";

    #[test]
    fn aliases_and_token_limits_load_and_wrong_ones_are_named() -> TestResult {
        let policy = "\
version: 1
providers:
  - name: east
    kind: openai
    url: https://east.example.com
    key_env: EAST_KEY
    models: [gpt-4o]
  - name: west
    kind: openai
    url: https://west.example.com
    key_env: WEST_KEY
    models: [gpt-4o-mini]
aliases:
  - name: smart
    balance: least_busy
    cooldown_seconds: 10
    context_window_fallback: gpt-4o
    deployments:
      - { provider: east, model: gpt-4o, weight: 3 }
      - { provider: west, model: gpt-4o }
rules:
  - name: everyone
    principals: { any: true }
    models: [smart]
    rate: { tpm: 200000 }
";
        let loaded = check("aliases", policy, None)?.map_err(|e| e.join("\n"))?;
        let alias = &loaded.aliases[0];
        assert_eq!(alias.balance, Balance::LeastBusy);
        assert_eq!(alias.cooldown_seconds, 10);
        assert_eq!(alias.deployments[0].weight, 3);
        assert_eq!(alias.deployments[1].weight, 1);
        assert_eq!(loaded.policy.rule_list()[0].limits.tpm, Some(200_000));
        assert_eq!(loaded.policy.rule_list()[0].limits.rpm, None);
        // An alias a rule names is served: no warning.
        assert!(unserved_models(Path::new("p"), &loaded).is_empty());
        for (from, to, expected) in [
            (
                "- name: smart",
                "- name: gpt-4o-mini",
                "has the name of a model provider \"west\" serves",
            ),
            (
                "provider: west",
                "provider: north",
                "names provider \"north\", and there is none",
            ),
            (
                "balance: least_busy",
                "balance: random",
                "balance is \"random\"",
            ),
            ("weight: 3", "weight: 0", "weight is how often"),
            (
                "context_window_fallback: gpt-4o",
                "context_window_fallback: smart",
                "Name another model",
            ),
            ("tpm: 200000", "tpm: 0", "tpm is the number of tokens"),
            ("rate: { tpm: 200000 }", "rate: {}", "rate sets no limit"),
        ] {
            let text = policy.replace(from, to);
            let found = errors(check("aliases-bad", &text, None)?)?;
            assert!(found.contains(expected), "{to}: {found}");
        }
        Ok(())
    }

    #[test]
    fn capture_loads_and_a_wrong_one_names_the_fix() -> TestResult {
        let good = LIMITED.replace(
            "    cache: { ttl_seconds: 300 }\n",
            "    cache: { ttl_seconds: 300 }\n    capture: { to: console, days: 7, viewers: [noa.bar, \"team:security\"] }\n",
        );
        let loaded = check("capture", &good, None)?.map_err(|e| e.join("\n"))?;
        assert_eq!(
            loaded.policy.rule_list()[0].limits.capture,
            Some(Capture {
                days: 7,
                viewers: vec!["noa.bar".into(), "team:security".into()]
            })
        );
        for (from, expected) in [
            ("to: console", "to: console, which is the one place"),
            ("days: 7", "1 to 90"),
            ("viewers: [noa.bar, \"team:security\"]", "no one could read"),
        ] {
            let to = match from {
                "to: console" => "to: otlp",
                "days: 7" => "days: 365",
                _ => "viewers: []",
            };
            let found = errors(check("capture-bad", &good.replace(from, to), None)?)?;
            assert!(found.contains(expected), "{to}: {found}");
        }
        Ok(())
    }

    #[test]
    fn budget_rate_cache_and_prices_load_into_the_rules() -> TestResult {
        let loaded = check("limits", LIMITED, None)?.map_err(|e| e.join("\n"))?;
        let rules = loaded.policy.rule_list();
        assert_eq!(
            rules[0].limits,
            Limits {
                budgets: vec![crate::policy::Cap {
                    budget: Budget {
                        usd: 2000.0,
                        per: Period::Month
                    },
                    models: Vec::new(),
                    from: None,
                    shadow_until: None,
                }],
                parallel: None,
                inherited: Vec::new(),
                rpm: Some(600),
                tpm: None,
                cache_ttl_seconds: Some(300),
                buffer_stream: false,
                check_stream_every: None,
                caller_provider_key: CallerKey::Refused,
                ..Limits::default()
            }
        );
        assert_eq!(
            rules[1].limits.budget(),
            Some(Budget {
                usd: 12.5,
                per: Period::Day
            })
        );
        let o3 = loaded.policy.prices().get("o3").ok_or("no price for o3")?;
        assert_eq!((o3.input, o3.output, o3.cache_read), (2.0, 8.0, Some(0.5)));
        Ok(())
    }

    #[test]
    fn a_price_per_image_loads() -> TestResult {
        // QA14-3: the documented per_image key was refused as unknown.
        let text = LIMITED.replace(
            "    cache_read: 0.5\n",
            "    cache_read: 0.5\n    per_image: 0.04\n",
        );
        let loaded = check("per-image", &text, None)?.map_err(|e| e.join("\n"))?;
        let o3 = loaded.policy.prices().get("o3").ok_or("no price for o3")?;
        assert_eq!(o3.per_image, Some(0.04));
        Ok(())
    }

    #[test]
    fn cache_scope_semantic_and_prompt_cache_load_and_wrong_ones_are_named() -> TestResult {
        let text = LIMITED.replace(
            "    cache: { ttl_seconds: 300 }\n",
            "    cache: { ttl_seconds: 300, scope: team, semantic: { model: gpt-4o-mini, threshold: 0.95 } }\n    prompt_cache: auto\n",
        );
        let loaded = check("cache-options", &text, None)?.map_err(|e| e.join("\n"))?;
        let limits = &loaded.policy.rule_list()[0].limits;
        assert_eq!(limits.cache_scope, CacheScope::Team);
        assert_eq!(
            limits.semantic,
            Some(Semantic {
                model: "gpt-4o-mini".into(),
                threshold: 0.95
            })
        );
        assert!(limits.prompt_cache);
        // The default scope is the person, and prompt caching is off.
        let plain = check("cache-plain", LIMITED, None)?.map_err(|e| e.join("\n"))?;
        let limits = &plain.policy.rule_list()[0].limits;
        assert_eq!(
            (limits.cache_scope, limits.prompt_cache),
            (CacheScope::Person, false)
        );
        let cases = [
            (
                "scope: team",
                "scope: everyone",
                "one team never reads another's",
            ),
            ("threshold: 0.95", "threshold: 1.5", "above 0 and at most 1"),
            (
                "model: gpt-4o-mini",
                "model: emb",
                "Add \"emb\" to the rule's models",
            ),
            (
                "prompt_cache: auto",
                "prompt_cache: always",
                "auto (Enterplace marks",
            ),
        ];
        for (i, (from, to, fix)) in cases.into_iter().enumerate() {
            let problems = errors(check(
                &format!("cache-bad-{i}"),
                &text.replace(from, to),
                None,
            )?)?;
            assert!(problems.contains(fix), "{to}: {problems}");
        }
        Ok(())
    }

    #[test]
    fn bad_limits_are_named_with_their_line_and_the_fix() -> TestResult {
        let cases = [
            (
                "usd: 2000, per: month",
                "usd: 2000, per: fortnight",
                ":17",
                "per: day, per: month",
            ),
            (
                "usd: 2000, per: month",
                "usd: -5, per: month",
                ":17",
                "above 0",
            ),
            ("rpm: 600", "rpm: 0", ":18", "rpm: 600"),
            ("ttl_seconds: 300", "ttl_seconds: 0", ":19", "1 to 86400"),
            ("    output: 8\n", "    output: -8\n", ":9", "0 or more"),
            (
                "    cache_read: 0.5\n",
                "    cache_raed: 0.5\n",
                ":12",
                "Did you mean \"cache_read\"?",
            ),
            (
                "rate: { rpm: 600 }",
                "rate: { rmp: 600 }",
                ":18",
                "Did you mean \"rpm\"?",
            ),
        ];
        for (i, (from, to, line, fix)) in cases.into_iter().enumerate() {
            let text = errors(check(
                &format!("bad-limit-{i}"),
                &LIMITED.replace(from, to),
                None,
            )?)?;
            assert!(
                text.contains(&format!("enterplace.policy.yaml{line}:")),
                "{to}: {text}"
            );
            assert!(text.contains(fix), "{to}: {text}");
        }
        Ok(())
    }

    #[test]
    fn a_budget_on_a_model_with_no_price_is_refused() -> TestResult {
        // "*" reaches every model the providers serve, so each of them needs a price.
        let unpriced = LIMITED.replace(
            "[gpt-4o-mini, o3]\nprices",
            "[gpt-4o-mini, o3, my-model]\nprices",
        );
        let text = errors(check("unpriced", &unpriced, None)?)?;
        assert!(text.contains("enterplace.policy.yaml:23"), "{text}");
        assert!(
            text.contains("model \"my-model\" has no price") && text.contains("prices:"),
            "{text}"
        );
        // Without a budget, an unpriced model is fine: its spend is recorded as unknown.
        let no_budget = unpriced.replace("    budget:\n      usd: 12.5\n      per: day\n", "");
        assert!(check("unpriced-ok", &no_budget, None)?.is_ok());
        Ok(())
    }

    #[test]
    fn a_private_provider_needs_to_be_allowed_by_name() -> TestResult {
        let local = GOOD.replace("https://api.openai.com", "http://127.0.0.1:9000");
        let text = errors(check("private", &local, None)?)?;
        assert!(text.contains("allow_private: true"), "{text}");
        let allowed = local.replace("    key_env", "    allow_private: true\n    key_env");
        assert!(check("private-ok", &allowed, None)?.is_ok());
        for private in [
            "http://localhost",
            "http://10.1.2.3",
            "http://[::1]:8000",
            "http://192.168.0.5:1",
            // Other spellings of the same addresses.
            "http://2130706433",
            "http://127.1:8000",
            "http://0x7f.1",
            "http://127.0.0.1.",
            "http://[::ffff:127.0.0.1]",
            "http://[fe80::1]",
            "http://100.64.0.1",
        ] {
            assert!(is_private(private), "{private}");
        }
        for public in [
            "https://api.openai.com",
            "https://cafe.be",
            "https://8.8.8.8",
            "https://api.example.com.",
        ] {
            assert!(!is_private(public), "{public}");
        }
        Ok(())
    }

    #[test]
    fn principals_and_wildcards_must_be_unambiguous() -> TestResult {
        let both = GOOD.replace("{ team: payments }", "{ team: payments, any: true }");
        assert!(errors(check("both", &both, None)?)?.contains("exactly one of"));
        let mixed = GOOD.replace("[\"*\"]", "[\"*\", gpt-4o]");
        assert!(errors(check("mixed", &mixed, None)?)?.contains("already allows every model"));
        Ok(())
    }

    #[test]
    fn a_key_listed_twice_or_badly_is_refused() -> TestResult {
        let hash = sha256_hex(b"k");
        let twice = format!(
            "keys:\n  - name: a\n    team: t\n    sha256: {hash}\n  - name: b\n    team: t\n    sha256: {hash}\n"
        );
        assert!(errors(check("twice", GOOD, Some(&twice))?)?.contains("listed twice"));
        let short = "keys:\n  - name: a\n    team: t\n    sha256: abc\n";
        assert!(errors(check("short", GOOD, Some(short))?)?.contains("64 hex characters"));
        Ok(())
    }

    #[test]
    fn two_people_may_share_a_name_so_a_key_can_be_rotated() -> TestResult {
        let keys = format!(
            "keys:\n  - name: a\n    team: t\n    sha256: {}\n  - name: a\n    team: t\n    sha256: {}\n",
            sha256_hex(b"old"),
            sha256_hex(b"new")
        );
        let loaded = check("rotate", GOOD, Some(&keys))?.map_err(|e| e.join("\n"))?;
        assert_eq!(loaded.policy.keys(), 2);
        Ok(())
    }

    #[test]
    fn a_file_from_the_previous_version_gets_the_lines_to_add() -> TestResult {
        let old = GOOD
            .replace("    kind: openai\n", "")
            .replace("    models: [gpt-4o-mini, gpt-4o]\n", "");
        let text = errors(check("old", &old, None)?)?;
        assert!(
            text.contains("kind: openai") && text.contains("models: [gpt-4o-mini]"),
            "{text}"
        );
        Ok(())
    }

    #[test]
    fn a_provider_missing_one_line_is_told_that_line_in_its_own_kind() -> TestResult {
        let no_models = GOOD
            .replace("kind: openai", "kind: anthropic")
            .replace("    models: [gpt-4o-mini, gpt-4o]\n", "");
        let text = errors(check("no-models", &no_models, None)?)?;
        assert!(
            text.contains("Add this line") && text.contains("models: ["),
            "{text}"
        );
        assert!(
            !text.contains("kind: openai"),
            "a second, wrong kind line: {text}"
        );
        let no_kind = GOOD.replace("    kind: openai\n", "");
        let text = errors(check("no-kind", &no_kind, None)?)?;
        assert!(
            text.contains("Add this line") && text.contains("kind: openai"),
            "{text}"
        );
        assert!(!text.contains("    models: ["), "{text}");
        let empty = GOOD.replace("models: [gpt-4o-mini, gpt-4o]", "models: [gpt-4o, \"\"]");
        let text = errors(check("empty-name", &empty, None)?)?;
        assert!(text.contains("an empty model name"), "{text}");
        assert!(!text.contains("belongs in a rule"), "{text}");
        Ok(())
    }

    #[test]
    fn near_duplicate_model_names_are_warned_about_and_patterns_are_not() -> TestResult {
        let odd = GOOD.replace(
            "models: [gpt-4o-mini, gpt-4o]",
            "models: [gpt-4o-mini, gpt-4o, GPT-4o, \" gpt-x\", \"gpt-*\"]",
        );
        let dir = dir("near")?;
        let path = dir.join("enterplace.policy.yaml");
        std::fs::write(&path, &odd)?;
        let loaded = load(&path, None).map_err(|e| e.join("\n"))?;
        let warnings = unserved_models(&path, &loaded).join("\n");
        assert!(
            warnings.contains("\"GPT-4o\"") && warnings.contains("\"gpt-4o\""),
            "{warnings}"
        );
        assert!(
            warnings.contains("spaces at its start or end"),
            "{warnings}"
        );
        // `gpt-*` is a pattern now, not a mistake.
        assert!(!warnings.contains("gpt-*"), "{warnings}");
        let plain = unserved_models(
            &path,
            &check("plain", GOOD, None)?.map_err(|e| e.join("\n"))?,
        );
        assert!(plain.is_empty(), "{plain:?}");
        Ok(())
    }

    #[test]
    fn a_model_listed_by_two_providers_is_refused_with_both_lines() -> TestResult {
        let two = GOOD.replace(
            "rules:\n",
            "  - name: proxy\n    kind: openai\n    url: https://proxy.example.com\n    key_env: PROXY_KEY\n    models: [gpt-4o]\nrules:\n",
        );
        let text = errors(check("twice-model", &two, None)?)?;
        assert!(
            text.contains("enterplace.policy.yaml:13") && text.contains("at line 8"),
            "{text}"
        );
        assert!(
            text.contains("\"gpt-4o\" is listed by provider \"proxy\" and by provider \"openai\""),
            "{text}"
        );
        Ok(())
    }

    #[test]
    fn a_provider_needs_a_known_kind_and_exact_models() -> TestResult {
        let odd = GOOD.replace("kind: openai", "kind: palm");
        assert!(errors(check("kind", &odd, None)?)?.contains("must be openai"));
        let empty = GOOD.replace("models: [gpt-4o-mini, gpt-4o]", "models: []");
        assert!(errors(check("empty-models", &empty, None)?)?.contains("lists no models"));
        let wild = GOOD.replace("models: [gpt-4o-mini, gpt-4o]", "models: [\"*\"]");
        assert!(errors(check("wild-models", &wild, None)?)?.contains("belongs in a rule"));
        let named_twice = GOOD.replace(
            "rules:\n",
            "  - name: openai\n    kind: openai\n    url: https://proxy.example.com\n    key_env: PROXY_KEY\n    models: [o3]\nrules:\n",
        );
        assert!(errors(check("named-twice", &named_twice, None)?)?.contains("the same name"));
        Ok(())
    }

    #[test]
    fn a_key_may_be_marked_admin_and_still_loads() -> TestResult {
        let keys = format!(
            "keys:\n  - name: noa.bar\n    team: platform\n    sha256: {}\n    admin: true\n  - name: a\n    team: t\n    sha256: {}\n",
            sha256_hex(b"admin"),
            sha256_hex(b"plain")
        );
        assert!(check("admin", GOOD, Some(&keys))?.is_ok());
        let entries = key_entries(Path::new("k.yaml"), &keys).map_err(|e| e.join("\n"))?;
        assert!(entries[0].admin && !entries[1].admin);
        Ok(())
    }

    #[test]
    fn a_key_may_carry_an_expiry_and_a_budget_and_wrong_ones_are_named() -> TestResult {
        let entry = |extra: &str| {
            format!(
                "keys:\n  - name: ci\n    team: t\n    sha256: {}\n{extra}",
                sha256_hex(b"ci")
            )
        };
        let good = entry("    expires: 2026-12-31\n    budget: { usd: 5, per: month }\n");
        let entries = key_entries(Path::new("k.yaml"), &good).map_err(|e| e.join("\n"))?;
        assert_eq!(entries[0].expires.as_deref(), Some("2026-12-31"));
        assert_eq!(
            entries[0].budget,
            Some(Budget {
                usd: 5.0,
                per: Period::Month
            })
        );
        assert!(check("key-attrs", GOOD, Some(&good))?.is_ok());
        let timed = entry("    expires: 2026-12-31T18:00:00Z\n");
        assert!(key_entries(Path::new("k.yaml"), &timed).is_ok());
        let leap = entry("    expires: 2028-02-29\n");
        assert!(key_entries(Path::new("k.yaml"), &leap).is_ok());
        for (bad, says) in [
            ("    expires: 31/12/2026\n", "expires is \"31/12/2026\""),
            ("    expires: 2026-13-01\n", "Write a UTC date or time"),
            // UX11 n3: a day the month does not have.
            ("    expires: 2026-02-29\n", "2026-02-29 is not a date"),
            ("    expires: 2026-11-31T00:00:00Z\n", "is not a date"),
            (
                "    budget: { usd: 5, per: fortnight }\n",
                "per is \"fortnight\"",
            ),
            ("    budget: { usd: 0, per: day }\n", "above 0"),
        ] {
            let problems = key_entries(Path::new("k.yaml"), &entry(bad))
                .err()
                .ok_or(bad)?
                .join("\n");
            assert!(problems.contains(says), "{bad}: {problems}");
            assert!(problems.contains("k.yaml:4"), "{problems}");
        }
        Ok(())
    }

    const GUARDED: &str = "\
guardrails:
  - name: no-secrets
    type: secrets
    action: block
  - name: vendor
    type: webhook
    url: http://127.0.0.1:9100/check
    on_failure: fail_closed
";

    #[test]
    fn guardrails_are_defined_once_and_named_by_rules_in_order() -> TestResult {
        let text = format!(
            "{GUARDED}{}",
            GOOD.replace(
                "    models: [gpt-4o-mini]\n",
                "    models: [gpt-4o-mini]\n    guardrails: [vendor, no-secrets]\n"
            )
        );
        let loaded = check("guarded", &text, None)?.map_err(|e| e.join("\n"))?;
        let rules = loaded.policy.rule_list();
        let names: Vec<&str> = rules[0]
            .guardrails
            .iter()
            .map(|g| g.name.as_str())
            .collect();
        assert_eq!(names, ["vendor", "no-secrets"]);
        assert!(rules[1].guardrails.is_empty());
        Ok(())
    }

    #[test]
    fn containers_load_and_a_size_openai_does_not_offer_is_named() -> TestResult {
        let with = |extra: &str| {
            GOOD.replace(
                "    models: [gpt-4o-mini]\n",
                &format!("    models: [gpt-4o-mini]\n{extra}"),
            )
        };
        let loaded = check(
            "containers",
            &with("    containers: { sizes: [1g, 4g] }\n"),
            None,
        )?
        .map_err(|e| e.join("\n"))?;
        assert_eq!(
            loaded.policy.rule_list()[0].limits.containers,
            vec!["1g".to_string(), "4g".to_string()]
        );
        for bad in ["{ sizes: [] }", "{ sizes: [2g] }", "{ allow: true }"] {
            let refused = check(
                "containers-bad",
                &with(&format!("    containers: {bad}\n")),
                None,
            )?
            .err()
            .ok_or("a bad containers line loaded")?
            .join("\n");
            assert!(
                refused.contains("containers") || refused.contains("allow"),
                "{bad}: {refused}"
            );
        }
        Ok(())
    }

    #[test]
    fn file_retention_days_loads_and_a_bad_one_names_the_range() -> TestResult {
        let with = |extra: &str| {
            GOOD.replace(
                "    models: [gpt-4o-mini]\n",
                &format!("    models: [gpt-4o-mini]\n{extra}"),
            )
        };
        let loaded = check("retention", &with("    file_retention_days: 7\n"), None)?
            .map_err(|e| e.join("\n"))?;
        assert_eq!(
            loaded.policy.rule_list()[0].limits.file_retention_days,
            Some(7)
        );
        for days in ["0", "31", "-2"] {
            let refused = check(
                "retention-bad",
                &with(&format!("    file_retention_days: {days}\n")),
                None,
            )?
            .err()
            .ok_or("a bad file_retention_days loaded")?
            .join("\n");
            assert!(
                refused.contains("file_retention_days") && refused.contains("1 to 30"),
                "{days}: {refused}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_provider_batch_section_loads_for_bedrock_and_vertex_only() -> TestResult {
        let bedrock = |batch: &str| {
            GOOD.replace(
                "rules:\n",
                &format!("  - name: bedrock\n    kind: bedrock\n    region: us-east-1\n    models: [claude-b]\n    model_ids: {{ claude-b: anthropic.claude-b }}\n    batch: {batch}\nrules:\n"),
            )
        };
        let loaded = check(
            "provider-batch",
            &bedrock("{ bucket: s3://bkt/pre, role_arn: arn:aws:iam::123456789012:role/b }"),
            None,
        )?
        .map_err(|e| e.join("\n"))?;
        let batch = loaded
            .providers
            .iter()
            .find_map(|p| p.batch.clone())
            .ok_or("no batch")?;
        assert_eq!(batch.bucket, "s3://bkt/pre/");
        assert_eq!(batch.bucket_and_prefix(), ("bkt", "pre/"));
        for (bad, says) in [
            ("{ bucket: s3://bkt/ }", "role_arn"),
            (
                "{ bucket: gs://bkt/, role_arn: arn:aws:iam::1:role/b }",
                "s3://",
            ),
            (
                "{ bucket: s3://b k/, role_arn: arn:aws:iam::1:role/b }",
                "s3://",
            ),
        ] {
            let refused = check("provider-batch-bad", &bedrock(bad), None)?
                .err()
                .ok_or("a bad batch section loaded")?
                .join("\n");
            assert!(refused.contains(says), "{bad}: {refused}");
        }
        let openai = GOOD.replace(
            "    models: [gpt-4o-mini, gpt-4o]\n",
            "    models: [gpt-4o-mini, gpt-4o]\n    batch: { bucket: s3://bkt/ }\n",
        );
        let refused = check("provider-batch-openai", &openai, None)?
            .err()
            .ok_or("an openai batch section loaded")?
            .join("\n");
        assert!(
            refused.contains("bedrock, vertex or vertex_anthropic"),
            "{refused}"
        );
        Ok(())
    }

    #[test]
    fn a_rule_batch_limit_loads_and_a_bad_one_says_the_fix() -> TestResult {
        let with = |extra: &str| {
            GOOD.replace(
                "    models: [gpt-4o-mini]\n",
                &format!("    models: [gpt-4o-mini]\n{extra}"),
            )
        };
        let loaded = check(
            "batch-limits",
            &with("    batch: { max_lines: 100, max_open: 2 }\n"),
            None,
        )?
        .map_err(|e| e.join("\n"))?;
        let limits = &loaded.policy.rule_list()[0].limits;
        assert_eq!(
            (limits.batch_max_lines, limits.batch_max_open),
            (Some(100), Some(2))
        );
        for bad in ["{ max_lines: 0 }", "{ max_open: -1 }", "{}"] {
            let refused = check("batch-bad", &with(&format!("    batch: {bad}\n")), None)?
                .err()
                .ok_or("a bad batch limit loaded")?
                .join("\n");
            assert!(refused.contains("batch"), "{bad}: {refused}");
        }
        Ok(())
    }

    #[test]
    fn check_stream_every_needs_a_blocking_answer_guardrail_and_a_sane_window() -> TestResult {
        let rule = |guards: &str, extra: &str| {
            format!(
                "{GUARDED}  - name: answers\n    type: secrets\n    action: block\n    on: [answer]\n  - name: masks\n    type: pii\n    action: mask\n    on: [answer]\n{}",
                GOOD.replace(
                    "    models: [gpt-4o-mini]\n",
                    &format!("    models: [gpt-4o-mini]\n    guardrails: [{guards}]\n{extra}"),
                )
            )
        };
        let loaded = check(
            "window",
            &rule("answers, vendor", "    check_stream_every: 300\n"),
            None,
        )?
        .map_err(|e| e.join("\n"))?;
        assert_eq!(
            loaded.policy.rule_list()[0].limits.check_stream_every,
            Some(300)
        );
        for (guards, extra, expected) in [
            (
                "no-secrets",
                "    check_stream_every: 300\n",
                "on: [answer]",
            ),
            ("answers", "    check_stream_every: 5\n", "50 to 100000"),
            (
                "answers",
                "    check_stream_every: 300\n    buffer_stream: true\n",
                "buffer_stream",
            ),
            ("answers, masks", "    check_stream_every: 300\n", "mask"),
        ] {
            let refused = check("window-bad", &rule(guards, extra), None)?
                .err()
                .ok_or("a bad check_stream_every loaded")?
                .join("\n");
            assert!(
                refused.contains("check_stream_every") && refused.contains(expected),
                "{extra}: {refused}"
            );
        }
        Ok(())
    }

    #[test]
    fn buffer_stream_needs_an_answer_guardrail_on_its_rule() -> TestResult {
        let guarded = |guards: &str| {
            format!(
                "{GUARDED}  - name: answers\n    type: secrets\n    action: block\n    on: [answer]\n{}",
                GOOD.replace(
                    "    models: [gpt-4o-mini]\n",
                    &format!("    models: [gpt-4o-mini]\n    guardrails: [{guards}]\n    buffer_stream: true\n"),
                )
            )
        };
        let loaded = check("buffered", &guarded("answers"), None)?.map_err(|e| e.join("\n"))?;
        let rules = loaded.policy.rule_list();
        assert!(rules[0].limits.buffer_stream && !rules[1].limits.buffer_stream);
        let refused = check("unbuffered", &guarded("no-secrets"), None)?
            .err()
            .ok_or("buffer_stream without an answer guardrail loaded")?
            .join("\n");
        assert!(
            refused.contains("buffer_stream") && refused.contains("on: [answer]"),
            "{refused}"
        );
        Ok(())
    }

    #[test]
    fn a_key_written_twice_is_refused_with_its_line() -> TestResult {
        let twice = GOOD.replacen("version: 1\n", "version: 1\nversion: 1\n", 1);
        let problems = errors(check("dup-key", &twice, None)?)?;
        assert!(
            problems.contains("enterplace.policy.yaml:3: \"version\" is written twice"),
            "{problems}"
        );
        let nested = GOOD.replacen(
            "    models: [gpt-4o-mini]\n",
            "    models: [gpt-4o-mini]\n    models: [gpt-4o]\n",
            1,
        );
        let problems = errors(check("dup-key-nested", &nested, None)?)?;
        assert!(
            problems.contains("enterplace.policy.yaml:13: \"models\" is written twice"),
            "{problems}"
        );
        Ok(())
    }

    #[test]
    fn a_price_or_a_list_of_the_wrong_kind_is_explained() -> TestResult {
        let price = format!("{GOOD}prices:\n  gpt-4o: 5\n");
        let problems = errors(check("price-kind", &price, None)?)?;
        assert!(
            problems.contains("enterplace.policy.yaml:17: gpt-4o is integer 5. Write it as gpt-4o: { input: 2.5, output: 10 }"),
            "{problems}"
        );
        let block = GOOD.replacen("{ team: payments }", "\n      - team", 1);
        let problems = errors(check("block-kind", &block, None)?)?;
        assert!(
            problems.contains("principals is a list. Write it as principals: { team: payments }"),
            "{problems}"
        );
        Ok(())
    }

    #[test]
    fn yaml_1_1_words_read_as_yaml_1_2() -> TestResult {
        // `on`, `yes`, `no` and `off` are booleans in YAML 1.1 only. As a key, `on` stays the key `on`; as text they
        // stay text; where true or false is wanted, they are refused, not read as a boolean.
        let words = GOOD
            .replace("{ team: payments }", "{ team: off }")
            .replace("name: payments-team", "name: no");
        if let Err(problems) = check("yaml11-text", &words, None)? {
            return Err(problems.join("\n").into());
        }
        let yes = GOOD.replace("{ any: true }", "{ any: yes }");
        let problems = errors(check("yaml11-yes", &yes, None)?)?;
        assert!(
            problems.contains("enterplace.policy.yaml:14: any must be true or false"),
            "{problems}"
        );
        let guarded = format!(
            "{GOOD}guardrails:\n  - name: answers\n    type: secrets\n    action: block\n    on: [answer]\n"
        )
        .replace(
            "    models: [\"*\"]\n",
            "    models: [\"*\"]\n    guardrails: [answers]\n",
        );
        if let Err(problems) = check("yaml11-on", &guarded, None)? {
            return Err(problems.join("\n").into());
        }
        Ok(())
    }

    #[test]
    fn a_wrong_value_is_explained_without_rust_type_names() -> TestResult {
        // UX11 n4: "this value must be struct BudgetFile" names code, not the file.
        for (line, says) in [
            (
                "    budget: 5\n",
                "budget is integer 5. Write it as budget: { usd: 20, per: month }",
            ),
            (
                "    rate: 3\n",
                "rate is integer 3. Write it as rate: { rpm: 60 }",
            ),
            ("    cache: true\n", "cache: { ttl_seconds: 300 }"),
            ("    models: 7\n", "models must be a list"),
            // A key Enterplace knows, in a place it does not belong, is not a misspelling of itself.
            ("    retries: 2\n", "\"retries\" does not belong here"),
        ] {
            let text = GOOD.replacen(
                "    models: [gpt-4o-mini]\n",
                &format!("    models: [gpt-4o-mini]\n{line}"),
                1,
            );
            let text = if line.contains("models") {
                GOOD.replacen("    models: [gpt-4o-mini]\n", line, 1)
            } else {
                text
            };
            let problems = errors(check("types", &text, None)?)?;
            assert!(problems.contains(says), "{line}: {problems}");
            assert!(
                !problems.contains("struct") && !problems.contains("Did you mean"),
                "{problems}"
            );
        }
        Ok(())
    }

    #[test]
    fn header_names_under_headers_env_are_not_policy_keys() -> TestResult {
        // Authorization has no hyphen, so it looks like a key; under headers_env it is a header the user chose.
        for (style, extra) in [
            ("flow", "    headers_env: { Authorization: GUARD_TOKEN }\n"),
            (
                "block",
                "    headers_env:\n      Authorization: GUARD_TOKEN\n      Proxy_Token: OTHER\n",
            ),
        ] {
            let text = format!("{GUARDED}{extra}{GOOD}");
            check(style, &text, None)?.map_err(|e| format!("{style}: {}", e.join("\n")))?;
            // A misspelled key after the map is still caught.
            let typo = format!("{GUARDED}{extra}    timeout_mss: 5\n{GOOD}");
            let text = errors(check(&format!("{style}-typo"), &typo, None)?)?;
            assert!(text.contains("\"timeout_mss\""), "{style}: {text}");
        }
        Ok(())
    }

    #[test]
    fn a_bad_guardrail_is_refused_with_its_line() -> TestResult {
        let undefined = format!(
            "{GUARDED}{}",
            GOOD.replace(
                "    models: [gpt-4o-mini]\n",
                "    models: [gpt-4o-mini]\n    guardrails: [no-secret]\n"
            )
        );
        let text = errors(check("undefined-guard", &undefined, None)?)?;
        assert!(
            text.contains("enterplace.policy.yaml:21")
                && text.contains("\"no-secret\", which is not defined"),
            "{text}"
        );
        let no_failure = format!("{GUARDED}{GOOD}").replace("    on_failure: fail_closed\n", "");
        let text = errors(check("no-failure", &no_failure, None)?)?;
        assert!(
            text.contains("enterplace.policy.yaml:5: guardrail \"vendor\"")
                && text.contains("on_failure"),
            "{text}"
        );
        let typo = format!("{GUARDED}{GOOD}").replace(
            "    on_failure: fail_closed\n",
            "    on_failure: fail_closed\n    timeoutms: 5\n",
        );
        let text = errors(check("guard-typo", &typo, None)?)?;
        assert!(
            text.contains("enterplace.policy.yaml:9")
                && text.contains("Did you mean \"timeout_ms\""),
            "{text}"
        );
        let twice = format!("{GUARDED}{GOOD}").replace("name: vendor", "name: no-secrets");
        assert!(errors(check("guard-twice", &twice, None)?)?.contains("defined twice"));
        Ok(())
    }

    #[test]
    fn two_providers_of_two_kinds_load() -> TestResult {
        let both = GOOD.replace(
            "rules:\n",
            "  - name: anthropic\n    kind: anthropic\n    url: https://api.anthropic.com\n    key_env: ANTHROPIC_API_KEY\n    models: [claude-sonnet-5-5]\nrules:\n",
        );
        let loaded = check("two-kinds", &both, None)?.map_err(|e| e.join("\n"))?;
        assert_eq!(loaded.providers.len(), 2);
        assert_eq!(loaded.providers[1].kind, Kind::Anthropic);
        assert_eq!(loaded.providers[1].models, ["claude-sonnet-5-5"]);
        Ok(())
    }

    const MORE: &str = "\
version: 1
providers:
  - name: azure
    kind: azure
    url: https://acme.openai.azure.com
    key_env: AZURE_OPENAI_KEY
    api_version: 2024-10-21
    models: [gpt4o, gpt-4o-mini]
    deployments:
      gpt4o: prod-gpt-4o
      gpt-4o-mini: prod-mini
    retries: 2
    fallback: groq
  - name: groq
    kind: openai
    url: https://api.groq.com/openai/v1/
    key_env: GROQ_API_KEY
    models: [llama-4]
  - name: anthropic
    kind: anthropic
    url: https://api.anthropic.com
    key_env: ANTHROPIC_API_KEY
    models: [claude-sonnet-5-5]
    accept_chat: true
    fallback: bedrock
  - name: bedrock
    kind: bedrock
    region: us-east-1
    models: [claude-haiku-5-5]
    model_ids: { claude-haiku-5-5: us.anthropic.claude-haiku-5-5-v1:0, claude-sonnet-5-5: \"arn:aws:bedrock:us-east-1:123456789012:inference-profile/x\" }
rules:
  - name: everyone
    principals: { any: true }
    models: [\"*\"]
";

    #[test]
    fn a_sagemaker_preset_takes_its_url_from_the_region_and_needs_endpoints() -> TestResult {
        let policy = "version: 1\nproviders:\n  - name: sm\n    preset: sagemaker\n    region: eu-west-1\n    models: [llama]\n    model_ids: { llama: my-endpoint }\n  - name: rep\n    preset: replicate\n    key_env: REPLICATE_API_TOKEN\n    models: [meta/llama]\nrules:\n  - name: everyone\n    principals: { any: true }\n    models: [\"*\"]\n";
        let loaded = check("sagemaker", policy, None)?.map_err(|e| e.join("\n"))?;
        let [sm, rep] = &loaded.providers[..] else {
            return Err("two providers".into());
        };
        assert_eq!(sm.kind, Kind::Sagemaker);
        assert_eq!(
            sm.url,
            "https://runtime.sagemaker.eu-west-1.amazonaws.com/endpoints"
        );
        assert_eq!(sm.upstream_models["llama"], "my-endpoint");
        assert_eq!(
            (rep.kind, rep.url.as_str()),
            (Kind::Replicate, "https://api.replicate.com/v1")
        );
        let refused = check(
            "sagemaker-bad",
            &policy.replace("    model_ids: { llama: my-endpoint }\n", ""),
            None,
        )?
        .err()
        .ok_or("a sagemaker provider without endpoints loaded")?
        .join("\n");
        assert!(refused.contains("SageMaker endpoint"), "{refused}");
        Ok(())
    }

    #[test]
    fn an_oci_provider_signs_with_an_api_signing_key_instead_of_a_key() -> TestResult {
        let policy = "version: 1\nproviders:\n  - name: oci\n    preset: oci\n    oci_signing:\n      tenancy: ocid1.tenancy.oc1..aaaa\n      user: ocid1.user.oc1..bbbb\n      fingerprint: 20:3b:97:13:55:1c:5b:0d:d3:37:d8:50:4e:c5:3a:34\n      key_env: OCI_API_KEY_PEM\n    models: [meta.llama-3.3-70b-instruct]\nrules:\n  - name: everyone\n    principals: { any: true }\n    models: [\"*\"]\n";
        let loaded = check("oci-signing", policy, None)?.map_err(|e| e.join("\n"))?;
        let oci = loaded.providers[0]
            .oci_signing
            .as_ref()
            .ok_or("no oci_signing")?;
        assert_eq!(
            oci.key_id(),
            "ocid1.tenancy.oc1..aaaa/ocid1.user.oc1..bbbb/20:3b:97:13:55:1c:5b:0d:d3:37:d8:50:4e:c5:3a:34"
        );
        assert_eq!(loaded.providers[0].key_env, "");
        for (bad, says) in [
            ("      key_env: OCI_API_KEY_PEM\n", "key_file"),
            ("    preset: oci\n", "kind"),
            ("      user: ocid1.user.oc1..bbbb\n", "user"),
        ] {
            let text = match bad {
                "    preset: oci\n" => {
                    policy.replace(bad, "    preset: oci\n    key_env: OCI_KEY\n")
                }
                _ => policy.replace(bad, ""),
            };
            let refused = check("oci-signing-bad", &text, None)?
                .err()
                .ok_or("a bad oci_signing loaded")?
                .join("\n");
            assert!(
                refused.contains(says) || refused.contains("oci_signing"),
                "{refused}"
            );
        }
        Ok(())
    }

    #[test]
    fn an_azure_v1_url_takes_no_api_version() -> TestResult {
        let v1 = MORE.replace(
            "    url: https://acme.openai.azure.com\n    key_env: AZURE_OPENAI_KEY\n    api_version: 2024-10-21\n",
            "    url: https://acme.openai.azure.com/openai/v1\n    key_env: AZURE_OPENAI_KEY\n",
        );
        let loaded = check("azure-v1", &v1, None)?.map_err(|e| e.join("\n"))?;
        assert_eq!(loaded.providers[0].api_version, None);
        let both = v1.replace(
            "/openai/v1\n    key_env: AZURE_OPENAI_KEY\n",
            "/openai/v1\n    key_env: AZURE_OPENAI_KEY\n    api_version: 2024-10-21\n",
        );
        let refused = check("azure-v1-dated", &both, None)?
            .err()
            .ok_or("a v1 url with api_version loaded")?
            .join("\n");
        assert!(refused.contains("takes no api_version"), "{refused}");
        Ok(())
    }

    #[test]
    fn azure_bedrock_fallbacks_and_paths_load() -> TestResult {
        // A fallback to groq for gpt4o needs no map: groq takes the same name.
        let loaded = check("more", MORE, None)?.map_err(|e| e.join("\n"))?;
        let [azure, groq, anthropic, bedrock] = &loaded.providers[..] else {
            return Err("four providers".into());
        };
        assert_eq!(azure.kind, Kind::Azure);
        assert_eq!(azure.upstream_models["gpt4o"], "prod-gpt-4o");
        assert_eq!(azure.api_version.as_deref(), Some("2024-10-21"));
        assert_eq!(
            (azure.retries, azure.fallback.as_deref()),
            (2, Some("groq"))
        );
        assert_eq!(groq.url, "https://api.groq.com/openai/v1");
        assert!(anthropic.accept_chat && !azure.accept_chat);
        assert_eq!(
            bedrock.url,
            "https://bedrock-runtime.us-east-1.amazonaws.com"
        );
        assert_eq!(bedrock.key_env, "");
        assert_eq!(bedrock.region.as_deref(), Some("us-east-1"));
        Ok(())
    }

    #[test]
    fn a_provider_key_may_come_from_a_file() -> TestResult {
        let text = MORE.replace(
            "    key_env: GROQ_API_KEY\n",
            "    key_file: secrets/groq.key\n",
        );
        let loaded = check("key-file", &text, None)?.map_err(|e| e.join("\n"))?;
        let groq = loaded
            .providers
            .iter()
            .find(|p| p.name == "groq")
            .ok_or("groq")?;
        assert_eq!(groq.key_env, "");
        assert_eq!(
            groq.key_file.as_deref(),
            Some(Path::new("secrets/groq.key"))
        );
        // Moving the key to another file gives the provider a new route at the reload, with no restart.
        let moved = text.replace("secrets/groq.key", "other.key");
        let new = check("key-file-moved", &moved, None)?.map_err(|e| e.join("\n"))?;
        assert!(!needs_restart(&loaded, &new).join("\n").contains("provider"));
        let (Some(was), Some(now)) = (
            loaded.providers.iter().find(|p| p.name == "groq"),
            new.providers.iter().find(|p| p.name == "groq"),
        ) else {
            return Err("groq".into());
        };
        assert!(!same_connection(was, now));
        Ok(())
    }

    #[test]
    fn a_provider_key_may_be_a_credential_in_the_store_and_a_rule_may_take_the_callers()
    -> TestResult {
        let named = MORE.replace("    key_env: GROQ_API_KEY\n", "    credential: groq-prod\n");
        // Credentials are kept in the store: without one the fix is named.
        let text = errors(check("credential-no-store", &named, None)?)?;
        assert!(
            text.contains("credential \"groq-prod\"") && text.contains("store:"),
            "{text}"
        );
        let stored = format!("store: {{ postgres_url_env: DATABASE_URL }}\n{named}");
        let loaded = check("credential", &stored, None)?.map_err(|e| e.join("\n"))?;
        let groq = loaded
            .providers
            .iter()
            .find(|p| p.name == "groq")
            .ok_or("groq")?;
        assert_eq!(groq.credential.as_deref(), Some("groq-prod"));
        let both = stored.replace(
            "    credential: groq-prod\n",
            "    credential: groq-prod\n    key_env: GROQ_API_KEY\n",
        );
        let text = errors(check("credential-both", &both, None)?)?;
        assert!(
            text.contains("takes one of key_env, key_file or credential"),
            "{text}"
        );
        let new = check(
            "credential-renamed",
            &stored.replace("groq-prod", "groq-next"),
            None,
        )?
        .map_err(|e| e.join("\n"))?;
        assert!(!needs_restart(&loaded, &new).join("\n").contains("provider"));
        let groq_now = new
            .providers
            .iter()
            .find(|p| p.name == "groq")
            .ok_or("groq")?;
        assert!(!same_connection(groq, groq_now));
        // The store's connection is made at start: changing it still needs a restart. Approval does not.
        let moved = check(
            "store-moved",
            &stored.replace("DATABASE_URL", "OTHER_URL"),
            None,
        )?
        .map_err(|e| e.join("\n"))?;
        assert!(
            needs_restart(&loaded, &moved)
                .join("\n")
                .contains("store section")
        );
        let approved = check(
            "store-approval",
            &stored.replace(
                "DATABASE_URL }",
                "DATABASE_URL, policy_from: file, approval: true }",
            ),
            None,
        )?
        .map_err(|e| e.join("\n"))?;
        assert!(
            !needs_restart(&loaded, &approved)
                .join("\n")
                .contains("store section")
        );
        let wrong = errors(check(
            "store-source",
            &stored.replace("DATABASE_URL }", "DATABASE_URL, policy_from: database }"),
            None,
        )?)?;
        assert!(
            wrong.contains("policy_from") && wrong.contains("store"),
            "{wrong}"
        );

        let rule = |value: &str| {
            format!(
                "version: 1\nproviders:\n  - name: openai\n    kind: openai\n    url: https://api.openai.com\n    key_env: K\n    models: [gpt-4o]\nrules:\n  - name: byok\n    principals: {{ team: data }}\n    models: [gpt-4o]\n    caller_provider_key: {value}\n"
            )
        };
        for (value, wanted) in [
            ("allowed", CallerKey::Allowed),
            ("allowed_budgeted", CallerKey::AllowedBudgeted),
            ("refused", CallerKey::Refused),
        ] {
            let loaded = check("caller-key", &rule(value), None)?.map_err(|e| e.join("\n"))?;
            let byok = loaded.policy.rule_list().first().ok_or("rule")?;
            assert_eq!(byok.limits.caller_provider_key, wanted);
        }
        let text = errors(check("caller-key-bad", &rule("yes"), None)?)?;
        assert!(
            text.contains(":12: caller_provider_key is \"yes\"") && text.contains("allowed"),
            "{text}"
        );
        Ok(())
    }

    #[test]
    fn a_url_may_have_a_path_and_the_route_follows_it() {
        for good in [
            "http://127.0.0.1:9000",
            "http://127.0.0.1:9000/",
            "HTTP://localhost:9000",
            "http://[::1]:9000",
            "http://127.0.0.1:9000/v1",
            "https://generativelanguage.googleapis.com/v1beta/openai/",
        ] {
            assert!(base_url(good).is_ok(), "{good}");
        }
        for bad in [
            "http://svc:S3cret@127.0.0.1:9000",
            "http://127.0.0.1:9000?x=1",
            "http://127.0.0.1:9000#frag",
            "http://127.0.0.1:0",
            "http://:9000",
            "http://127.0.0.1:65536",
            "http://127.0.0.1:9000;x",
            "ftp://127.0.0.1:9000",
            "http://127.0.0.1:9000 ",
            "127.0.0.1:9000",
            "http://[::1",
            "",
        ] {
            let err = base_url(bad).err().unwrap_or_default();
            assert!(!err.is_empty() && !err.contains("S3cret"), "{bad}: {err}");
        }
        let chat = "/v1/chat/completions";
        assert_eq!(
            join("https://api.openai.com", chat),
            "https://api.openai.com/v1/chat/completions"
        );
        assert_eq!(
            join("https://api.groq.com/openai/v1", chat),
            "https://api.groq.com/openai/v1/chat/completions"
        );
        assert_eq!(
            join("https://openrouter.ai/api/v1", chat),
            "https://openrouter.ai/api/v1/chat/completions"
        );
        assert_eq!(
            join(
                "https://generativelanguage.googleapis.com/v1beta/openai",
                chat
            ),
            "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
        );
        assert_eq!(
            join("http://127.0.0.1:9/v1", "/v1/messages?beta=true"),
            "http://127.0.0.1:9/v1/messages?beta=true"
        );
    }

    #[test]
    fn each_new_field_is_checked_with_its_line_and_fix() -> TestResult {
        let cases = [
            (
                "    api_version: 2024-10-21\n",
                "    api_version: latest\n",
                ":7: api_version is a date",
            ),
            (
                "      gpt-4o-mini: prod-mini\n",
                "",
                "model \"gpt-4o-mini\" has no entry in deployments",
            ),
            (
                "    fallback: groq\n",
                "    fallback: grok\n",
                ":13: fallback names provider \"grok\", and there is none",
            ),
            (
                "    fallback: groq\n",
                "    fallback: anthropic\n",
                "speaks another API",
            ),
            (
                "    fallback: bedrock\n",
                "    fallback: anthropic\n",
                "names itself",
            ),
            (
                "    retries: 2\n",
                "    retries: 9\n",
                ":12: retries is at most 5",
            ),
            (
                "    models: [llama-4]\n",
                "    models: [llama-4]\n    accept_chat: true\n",
                ":19: accept_chat translates",
            ),
            (
                "    region: us-east-1\n",
                "",
                "a bedrock provider needs region",
            ),
            (
                "    region: us-east-1\n",
                "    region: us-east-1\n    key_env: AWS_KEY\n",
                "a bedrock provider takes no key_env",
            ),
            (
                "    region: us-east-1\n",
                "    region: us-east-1\n    key_file: aws.key\n",
                "a bedrock provider takes no key_file",
            ),
            (
                "    key_env: GROQ_API_KEY\n",
                "    key_env: GROQ_API_KEY\n    key_file: groq.key\n",
                "takes key_env or key_file, not both",
            ),
            (
                "    key_env: GROQ_API_KEY\n",
                "    key_file: \"\"\n",
                "key_file is the path of a file that holds the provider key",
            ),
            (
                "    models: [llama-4]\n",
                "    models: [llama-4]\n    region: us-east-1\n",
                "region is for a provider of kind bedrock",
            ),
            (
                "    models: [llama-4]\n",
                "    models: [llama-4]\n    role_arn: arn:aws:iam::123456789012:role/x\n",
                "role_arn is for a provider of kind bedrock",
            ),
            (
                "    region: us-east-1\n",
                "    region: us-east-1\n    role_arn: enterplace-bedrock\n",
                "role_arn is the ARN of an IAM role",
            ),
            (
                "    url: https://api.groq.com/openai/v1/\n",
                "",
                "provider \"groq\" has no url",
            ),
            (
                "    url: https://api.groq.com/openai/v1/\n",
                "    url: https://api.groq.com:99999/openai\n",
                "a port no server can listen on",
            ),
        ];
        for (from, to, expected) in cases {
            let text = errors(check("fields", &MORE.replacen(from, to, 1), None)?)?;
            assert!(text.contains(expected), "{expected} not in: {text}");
        }
        // The fallback for claude-sonnet-5-5 must have a model ID for it.
        let unmapped = MORE.replace(
            "claude-sonnet-5-5: \"arn:aws:bedrock:us-east-1:123456789012:inference-profile/x\" ",
            "",
        );
        let text = errors(check("unmapped", &unmapped, None)?)?;
        assert!(
            text.contains("fallback \"bedrock\" cannot serve claude-sonnet-5-5"),
            "{text}"
        );
        Ok(())
    }

    #[test]
    fn a_model_map_holds_model_names_not_keys() -> TestResult {
        // gpt4o: looks like a key; under deployments it is a model name.
        let text = errors(check(
            "map-typo",
            &MORE.replace("    retries: 2", "    retires: 2"),
            None,
        )?)?;
        assert!(
            text.contains(":12: \"retires\"") && text.contains("Did you mean \"retries\""),
            "{text}"
        );
        assert!(!text.contains("gpt4o"), "{text}");
        Ok(())
    }

    const GOOGLE: &str = "\
version: 1
providers:
  - name: gemini
    kind: gemini
    url: https://generativelanguage.googleapis.com/v1beta
    key_env: GEMINI_API_KEY
    models: [gemini-2.5-flash]
    fallback: vertex
  - name: vertex
    kind: vertex
    url: https://us-central1-aiplatform.googleapis.com/v1/projects/acme/locations/us-central1/publishers/google
    key_env: VERTEX_ACCESS_TOKEN
    models: [gemini-2.5-pro]
  - name: ollama
    kind: openai
    url: http://127.0.0.1:11434/v1
    allow_private: true
    models: [llama3.2]
rules:
  - name: everyone
    principals: { any: true }
    models: [\"*\"]
";

    #[test]
    fn gemini_vertex_and_a_local_server_without_a_key_load() -> TestResult {
        let loaded = check("google", GOOGLE, None)?.map_err(|e| e.join("\n"))?;
        let [gemini, vertex, ollama] = &loaded.providers[..] else {
            return Err("three providers".into());
        };
        assert_eq!((gemini.kind, vertex.kind), (Kind::Gemini, Kind::Vertex));
        assert_eq!(gemini.kind.api(), Kind::OpenAi);
        assert_eq!(ollama.key_env, "");
        Ok(())
    }

    /// Without key_env, Vertex AI signs in with Application Default Credentials; Bedrock may name a role to assume.
    #[test]
    fn cloud_providers_load_without_static_keys() -> TestResult {
        let text = GOOGLE.replace("    key_env: VERTEX_ACCESS_TOKEN\n", "");
        let loaded = check("adc", &text, None)?.map_err(|e| e.join("\n"))?;
        assert_eq!(loaded.providers[1].key_env, "");
        let text = MORE.replacen(
            "    region: us-east-1\n",
            "    region: us-east-1\n    role_arn: arn:aws:iam::123456789012:role/enterplace-bedrock\n",
            1,
        );
        let loaded = check("role", &text, None)?.map_err(|e| e.join("\n"))?;
        let bedrock = loaded
            .providers
            .iter()
            .find(|p| p.kind == Kind::Bedrock)
            .ok_or("no bedrock provider")?;
        assert_eq!(
            bedrock.role_arn.as_deref(),
            Some("arn:aws:iam::123456789012:role/enterplace-bedrock")
        );
        Ok(())
    }

    #[test]
    fn vertex_anthropic_and_accept_messages_load_and_are_checked() -> TestResult {
        let text = GOOGLE.replace(
            "    models: [gemini-2.5-pro]\n",
            "    models: [gemini-2.5-pro]\n    accept_messages: true\n  - name: claude-vertex\n    kind: vertex_anthropic\n    url: https://us-east5-aiplatform.googleapis.com/v1/projects/acme/locations/us-east5/publishers/anthropic\n    key_env: VERTEX_ACCESS_TOKEN\n    models: [claude-sonnet-4-6]\n    accept_chat: true\n",
        );
        let loaded = check("vertex-claude", &text, None)?.map_err(|e| e.join("\n"))?;
        let claude = loaded
            .providers
            .iter()
            .find(|p| p.name == "claude-vertex")
            .ok_or("claude-vertex")?;
        assert_eq!(claude.kind, Kind::VertexAnthropic);
        assert_eq!(claude.kind.api(), Kind::Anthropic);
        assert!(claude.accept_chat && !claude.accept_messages);
        assert!(
            loaded
                .providers
                .iter()
                .any(|p| p.name == "vertex" && p.accept_messages)
        );
        for (from, to, expected) in [
            (
                "publishers/anthropic",
                "publishers/google",
                "ends in /publishers/anthropic",
            ),
            (
                "    accept_chat: true\n",
                "    accept_messages: true\n",
                "accept_messages translates",
            ),
        ] {
            let found = errors(check("vertex-claude-bad", &text.replace(from, to), None)?)?;
            assert!(found.contains(expected), "{expected}: {found}");
        }
        Ok(())
    }

    #[test]
    fn google_kinds_are_checked() -> TestResult {
        for (from, to, expected) in [
            (
                "/v1/projects/acme/locations/us-central1/publishers/google\n",
                "/v1/projects/acme\n",
                "url ends in /publishers/google",
            ),
            // A key may be left out only for a local server.
            ("    allow_private: true\n", "", "allow_private: true"),
            (
                "    url: http://127.0.0.1:11434/v1\n    allow_private: true\n",
                "    url: https://api.groq.com/openai/v1\n",
                "has no key_env",
            ),
            // A gemini request is translated before it is recorded, so it cannot fall back to openai.
            (
                "fallback: vertex",
                "fallback: ollama",
                "take chat completions translated",
            ),
            ("kind: gemini", "kind: palm", "gemini (Google's Gemini API)"),
        ] {
            let text = errors(check("google-bad", &GOOGLE.replace(from, to), None)?)?;
            assert!(text.contains(expected), "{expected}: {text}");
        }
        Ok(())
    }

    const HIERARCHY: &str = "\
version: 1
providers:
  - name: openai
    kind: openai
    url: https://api.openai.com
    key_env: OPENAI_API_KEY
    models: [gpt-4o-mini, gpt-4o, o3]
orgs: [acme, globex]
guardrails:
  - name: no-secrets
    type: secrets
    action: block
profiles:
  - name: standard
    models: [gpt-4o-mini]
    guardrails: [no-secrets]
    budget: [{ usd: 10, per: day }, { usd: 100, per: month, tz: America/New_York }]
    rate: { rpm: 60, tpm: 100000 }
    parallel: 4
rules:
  - name: acme-payments
    org: acme
    principals: { team: payments }
    profiles: [standard]
    models: [o3]
    budget: [{ usd: 20, per: day }, { usd: 5, per: week, models: [o3] }]
    rate: { tpm: 50000 }
    tags: [search, \"checkout\"]
    customers: [\"*\"]
  - name: ci
    principals: { tag: ci }
    models: [gpt-4o-mini]
  - name: everyone-else
    principals: { any: true }
    models: []
limits:
  - { global: true, budget: { usd: 50000, per: month } }
  - { org: acme, budget: { usd: 20000, per: month, tz: America/New_York }, parallel: 200 }
  - { person: \"*\", budget: [{ usd: 5, per: day }, { usd: 50, per: month }] }
  - { person: \"*\", org: acme, budget: { usd: 8, per: day } }
  - { person: maya, org: acme, budget: { usd: 30, per: day } }
  - { customer: \"*\", budget: { usd: 2, per: 6h }, rate: { rpm: 30 }, parallel: 2 }
  - { tag: search, budget: { usd: 300, per: week } }
  - { model: o3, budget: { usd: 1000, per: 3mo } }
roles:
  - name: finance
    permissions: [see_spend, see_records]
    org: acme
    sso_values: [finance]
";

    #[test]
    fn organizations_profiles_limits_and_roles_load_into_the_policy() -> TestResult {
        let keys = format!(
            "keys:\n  - name: maya\n    team: payments\n    sha256: {}\n    org: acme\n    customer: globex-shop\n    tags: [ci]\n    parallel: 3\n    role: finance\n",
            "a".repeat(64)
        );
        let loaded = check("hierarchy", HIERARCHY, Some(&keys))?.map_err(|e| e.join("\n"))?;
        let policy = &loaded.policy;
        let rule = &policy.rule_list()[0];
        assert_eq!(rule.org.as_deref(), Some("acme"));
        // The profile's model joins the rule's, its guardrail runs, and the rule's own budget and tpm win.
        assert_eq!(
            rule.models,
            Models::Only(vec!["o3".into(), "gpt-4o-mini".into()])
        );
        assert_eq!(rule.guardrails.len(), 1);
        assert_eq!(rule.limits.tpm, Some(50000));
        assert_eq!(rule.limits.rpm, Some(60));
        assert_eq!(rule.limits.parallel, Some(4));
        assert_eq!(rule.limits.budgets.len(), 3);
        assert!(
            rule.overrides
                .iter()
                .any(|o| o.contains("tpm 100000 of profile \"standard\""))
        );
        assert!(
            rule.overrides
                .iter()
                .any(|o| o.contains("budget $10 a day of profile \"standard\""))
        );
        let per_ny = rule.limits.budgets[2].budget.per;
        assert_eq!(per_ny.tz, Some("America/New_York"));
        assert_eq!(policy.scope_limits().len(), 8);
        assert_eq!(policy.roles()[0].org.as_deref(), Some("acme"));
        let who = policy
            .entries()
            .map(|(_, p)| p.clone())
            .next()
            .ok_or("no key")?;
        assert_eq!((who.org.as_str(), who.parallel), ("acme", Some(3)));
        assert_eq!(who.customer.as_deref(), Some("globex-shop"));
        let role = policy.role_of(&who).ok_or("no role")?;
        assert!(role.may(crate::policy::Permission::SeeSpend));
        assert!(!role.may(crate::policy::Permission::IssueKeys));
        assert!(
            matches!(policy.decide(&who, "o3"), Decision::Allow(r) if r.name == "acme-payments")
        );
        Ok(())
    }

    #[test]
    fn a_sliding_budget_loads_beside_a_calendar_one_and_a_wrong_one_is_named() -> TestResult {
        let sliding = HIERARCHY.replace(
            "{ tag: search, budget: { usd: 300, per: week } }",
            "{ tag: search, budget: [{ usd: 300, per: week }, { usd: 80, per: { sliding: 24h } }] }",
        );
        let loaded = check("sliding", &sliding, None)?.map_err(|e| e.join("\n"))?;
        let tag = loaded
            .policy
            .scope_limits()
            .iter()
            .find(|l| l.name == "search")
            .ok_or("no tag entry")?;
        let pers: Vec<String> = tag.budgets.iter().map(|b| b.per.word()).collect();
        assert_eq!(pers, ["week", "sliding:24h"]);
        let bad = sliding.replace("{ sliding: 24h }", "{ sliding: 3mo }");
        let errors = errors(check("sliding-bad", &bad, None)?)?;
        assert!(
            errors.contains("A sliding window is a fixed length"),
            "{errors}"
        );
        Ok(())
    }

    #[test]
    fn hierarchy_mistakes_are_named_with_their_line_and_fix() -> TestResult {
        let bad = HIERARCHY
            .replace(
                "org: acme\n    principals",
                "org: acme-corp\n    principals",
            )
            .replace("profiles: [standard]", "profiles: [standrd]")
            .replace("tz: America/New_York }]", "tz: Mars/Olympus }]")
            .replace("see_records]", "see_records, see_everything]")
            .replace("{ tag: search, budget", "{ tag: search, team: x, budget")
            .replace("per: 3mo", "per: 13mo");
        let errors = errors(check("hierarchy-bad", &bad, None)?)?;
        for expected in [
            "organization \"acme-corp\" is not listed under orgs",
            "includes profile \"standrd\", which is not defined under profiles",
            "tz is \"Mars/Olympus\", which is not a time zone Enterplace knows",
            "\"see_everything\" is not a permission",
            "a limits entry names one scope",
            "longer than a year",
        ] {
            assert!(errors.contains(expected), "{expected} in\n{errors}");
        }
        let keys = format!(
            "keys:\n  - name: dana\n    team: t\n    sha256: {}\n    org: initech\n    role: auditor\n",
            "b".repeat(64)
        );
        let errors = super::tests::errors(check("hierarchy-keys", HIERARCHY, Some(&keys))?)?;
        assert!(
            errors.contains("enterplace.keys.yaml:4: organization \"initech\" is not listed"),
            "{errors}"
        );
        assert!(
            errors.contains("role \"auditor\" is not defined under roles"),
            "{errors}"
        );
        Ok(())
    }
}

#[cfg(test)]
mod resilience_tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn model_patterns_match_runs_of_characters() {
        assert!(model_matches("gpt-*", "gpt-5"));
        assert!(model_matches("gpt-*", "gpt-"));
        assert!(!model_matches("gpt-*", "o3"));
        assert!(model_matches("claude-*-5", "claude-sonnet-5"));
        assert!(!model_matches("claude-*-5", "claude-sonnet-4"));
        assert!(model_matches("*", "anything"));
        assert!(model_matches("a*b*c", "aXbYc"));
        assert!(!model_matches("a*b*c", "aXcYb"));
        assert!(!model_matches("ab*ba", "aba"));
        assert!(model_matches("exact", "exact"));
        assert!(!model_matches("exact", "exactly"));
    }

    fn load_text(
        name: &str,
        text: &str,
    ) -> Result<Result<Loaded, Vec<String>>, Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!(
            "enterplace-resilience-{}-{name}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("enterplace.policy.yaml");
        std::fs::write(&path, text)?;
        Ok(load(&path, None))
    }

    const BASE: &str = "version: 1
providers:
  - name: east
    kind: openai
    url: https://api.openai.com
    keys: [{ key_env: EAST_A }, { key_env: EAST_B, weight: 3 }]
    key_balance: least_used
    key_quarantine_seconds: 600
    headers_env: { X-Team-Id: EAST_TEAM }
    proxy_env: EAST_PROXY
    timeouts: { connect_ms: 1000, first_byte_ms: 20000, total_ms: 60000, idle_ms: 5000 }
    models: [gpt-*]
  - name: claude
    kind: anthropic
    url: https://api.anthropic.com
    key_env: ANTHROPIC_KEY
    models: [claude-sonnet-5-5]
aliases:
  - name: smart
    balance: adaptive
    weights: { latency: 2, errors: 1, cost: 0 }
    timeouts: { first_byte_ms: 10000 }
    fallbacks: [claude-sonnet-5-5]
    fallback_on: [rate_limit, timeout]
    rate_limit_headroom_percent: 10
    deployments:
      - { provider: east, model: gpt-4o, probe: { every_seconds: 30 }, max_parallel: 8, rpm: 600, tpm: 90000 }
      - provider: east
        model: gpt-4o-mini
        timeouts: { first_byte_ms: 3000 }
        when: { max_prompt_tokens: 2000, tools: false, header: { X-Tier: free } }
rules:
  - name: all
    principals: { any: true }
    models: [smart, gpt-*]
";

    #[test]
    fn resilience_settings_load() -> TestResult {
        let loaded = load_text("good", BASE)?.map_err(|e| e.join("\n"))?;
        let east = &loaded.providers[0];
        assert_eq!(
            east.keys,
            [
                KeySource::Env("EAST_A".into()),
                KeySource::Env("EAST_B".into())
            ]
        );
        assert!(east.least_used_key);
        assert_eq!(east.key_weights, [1, 3]);
        assert_eq!(east.key_quarantine_seconds, Some(600));
        assert_eq!(east.headers_env, [("x-team-id".into(), "EAST_TEAM".into())]);
        assert_eq!(east.proxy_env.as_deref(), Some("EAST_PROXY"));
        assert_eq!(loaded.providers[1].key_quarantine_seconds, None);
        assert_eq!(east.timeouts.idle_ms, Some(5000));
        let smart = &loaded.aliases[0];
        assert_eq!(smart.balance, Balance::Adaptive);
        assert_eq!(smart.rate_limit_headroom_percent, Some(10));
        let first = &smart.deployments[0];
        assert_eq!(
            (first.max_parallel, first.rpm, first.tpm),
            (Some(8), Some(600), Some(90000))
        );
        assert_eq!(smart.weights.latency, 2.0);
        assert_eq!(smart.fallbacks, ["claude-sonnet-5-5"]);
        assert_eq!(
            smart.fallback_on,
            [FallbackOn::RateLimit, FallbackOn::Timeout]
        );
        assert_eq!(
            smart.deployments[0].probe,
            Some(Probe {
                every_seconds: 30,
                chat: false
            })
        );
        let when = smart.deployments[1].when.clone().unwrap_or_default();
        assert_eq!(when.header, Some(("x-tier".into(), "free".into())));
        assert_eq!(when.tools, Some(false));
        assert_eq!(smart.deployments[1].timeouts.first_byte_ms, Some(3000));
        Ok(())
    }

    #[test]
    fn wrong_resilience_settings_are_named() -> TestResult {
        for (from, to, says) in [
            (
                "first_byte_ms: 20000, total_ms: 60000",
                "first_byte_ms: 20000, total_ms: 10",
                "shorter than first_byte_ms",
            ),
            (
                "connect_ms: 1000",
                "connect_ms: 0",
                "timeouts.connect_ms is in milliseconds",
            ),
            (
                "key_balance: least_used",
                "key_balance: random",
                "key_balance is \"random\"",
            ),
            ("weight: 3", "weight: 0", "a key's weight"),
            (
                "key_quarantine_seconds: 600",
                "key_quarantine_seconds: 0",
                "key_quarantine_seconds",
            ),
            (
                "X-Team-Id: EAST_TEAM",
                "Authorization: EAST_TEAM",
                "keys go in key_env",
            ),
            (
                "proxy_env: EAST_PROXY",
                "proxy_env: http://proxy",
                "proxy_env names",
            ),
            ("rpm: 600", "rpm: 0", "max_parallel, rpm and tpm"),
            (
                "rate_limit_headroom_percent: 10",
                "rate_limit_headroom_percent: 101",
                "rate_limit_headroom_percent",
            ),
            (
                "keys: [{ key_env: EAST_A }, { key_env: EAST_B, weight: 3 }]",
                "keys: [{ key_env: EAST_A }, { key_env: EAST_A }]",
                "the same key twice",
            ),
            (
                "keys: [{ key_env: EAST_A }, { key_env: EAST_B, weight: 3 }]",
                "keys: [{ credential: x }]",
                "credentials are kept in the store",
            ),
            (
                "keys: [{ key_env: EAST_A }, { key_env: EAST_B, weight: 3 }]",
                "key_env: K\n    keys: [{ key_env: EAST_A }]",
                "keys list and key_env",
            ),
            (
                "fallbacks: [claude-sonnet-5-5]",
                "fallbacks: [nothing]",
                "fallbacks names \"nothing\"",
            ),
            (
                "fallback_on: [rate_limit, timeout]",
                "fallback_on: [sometimes]",
                "fallback_on lists \"sometimes\"",
            ),
            (
                "balance: adaptive",
                "balance: round_robin",
                "weights apply to balance: adaptive only",
            ),
            (
                "every_seconds: 30",
                "every_seconds: 1",
                "probe.every_seconds",
            ),
            (
                "every_seconds: 30",
                "every_seconds: 30, with: sometimes",
                "probe.with is \"sometimes\"",
            ),
            ("tools: false,", "", "keeps"),
            (
                "max_prompt_tokens: 2000",
                "max_prompt_tokens: 2000, min_prompt_tokens: 5000",
                "is above max_prompt_tokens",
            ),
        ] {
            assert!(BASE.contains(from), "{from}");
            let text = BASE.replace(from, to);
            match load_text("bad", &text)? {
                Ok(_) if says == "keeps" => {}
                Ok(_) => return Err(format!("{to} was accepted").into()),
                Err(errors) => {
                    let errors = errors.join("\n");
                    assert!(errors.contains(says), "{to}: {errors}");
                }
            }
        }
        Ok(())
    }
}
