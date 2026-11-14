//! Reads the policy file and the keys file, and says exactly what is wrong with them.
//! `gantry check` and `gantry serve` both go through `load`, so a file that passes one is accepted by the other.

use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
    path::{Path, PathBuf},
};

use serde::Deserialize;

use crate::{
    guard::{self, Guardrail, GuardrailFile},
    id::sha256_hex,
    policy::{Budget, CallerKey, Limits, Models, Period, Policy, Principal, Rule, Who},
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
    "rate",
    "rpm",
    "cache",
    "ttl_seconds",
    "buffer_stream",
    "check_stream_every",
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
    "expires_days",
    "expires",
    "headers_env",
    "model",
    "prompt",
    "guardrail_id",
    "guardrail_version",
    "threshold",
    "anonymizer_url",
    "project_id",
    "template_id",
    "case_sensitive",
    "whole_word",
    "shadow_until",
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
    "store",
    "postgres_url_env",
    "credential",
    "caller_provider_key",
];
/// Keys whose value is a map whose keys the user chooses: model names, or header names under `headers_env`.
/// Those names are not Gantry keys, so the unknown-key scan never reads them.
/// A regex guardrail's `patterns` and a keywords guardrail's `keywords` are maps of entry names the user chooses.
const FREE_MAPS: &[&str] = &[
    "deployments",
    "model_ids",
    "headers_env",
    "patterns",
    "keywords",
];
/// The most retries a provider may ask for. Each one can wait the whole first-byte timeout.
pub const MAX_RETRIES: u32 = 5;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    version: u32,
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
    store: Option<StoreFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreFile {
    postgres_url_env: String,
}

/// Where several gateways keep what they share while they run, as `store:` in the policy sets it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreSetting {
    /// The environment variable that holds the Postgres connection string. The string never goes in the file: it
    /// carries a password.
    pub postgres_url_env: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AliasFile {
    name: String,
    deployments: Vec<DeploymentFile>,
    #[serde(default)]
    balance: Option<String>,
    #[serde(default)]
    cooldown_seconds: Option<u64>,
    #[serde(default)]
    context_window_fallback: Option<String>,
    #[serde(default)]
    content_policy_fallback: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentFile {
    provider: String,
    model: String,
    #[serde(default)]
    weight: Option<u32>,
}

/// How an alias picks among its deployments.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Balance {
    /// In turn, each as often as its weight says.
    #[default]
    RoundRobin,
    /// The one with the fewest requests in flight through this Gantry.
    LeastBusy,
}

/// One place an alias can send a request: a provider and the model it is known by there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deployment {
    pub provider: String,
    pub model: String,
    pub weight: u32,
}

/// A model name callers send that Gantry serves from one or more deployments.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    // Instead of key_env, for a key that changes while Gantry runs: the file is read again once a second.
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
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    name: String,
    principals: PrincipalsFile,
    models: Vec<String>,
    #[serde(default)]
    guardrails: Vec<String>,
    #[serde(default)]
    budget: Option<BudgetFile>,
    #[serde(default)]
    rate: Option<RateFile>,
    #[serde(default)]
    cache: Option<CacheFile>,
    #[serde(default)]
    buffer_stream: bool,
    #[serde(default)]
    check_stream_every: Option<i64>,
    #[serde(default)]
    passthrough: Vec<PassthroughFile>,
    #[serde(default)]
    tools: Vec<String>,
    #[serde(default)]
    caller_provider_key: Option<String>,
}

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
    per: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RateFile {
    #[serde(default)]
    rpm: Option<i64>,
    #[serde(default)]
    tpm: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheFile {
    ttl_seconds: i64,
}

/// The longest an answer may be served from the cache: a day.
const MAX_CACHE_TTL: i64 = 86_400;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalsFile {
    team: Option<String>,
    name: Option<String>,
    any: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditFile {
    path: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsoleFile {
    #[serde(default)]
    sso: Option<SsoFile>,
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

/// Who may get a personal key of their own with `gantry login`, as checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelfIssue {
    /// Lower case, as `Sso::allowed_domains`.
    pub allowed_domains: Vec<String>,
    pub allowed_emails: Vec<String>,
    /// The team the keys are in. `developers` unless set.
    pub team: String,
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
    /// `gantry login` issues keys only when this is set.
    pub self_issue: Option<SelfIssue>,
}

/// An address Gantry may send a secret or trust a key from: https, or http to this machine for a provider run beside it.
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
            "{}: client_secret_env is the name of an environment variable, for example GANTRY_SSO_SECRET. The secret itself never goes in this file.",
            at("client_secret_env")
        ));
    }
    if !secure_url(&sso.redirect_url) || !sso.redirect_url.ends_with("/console/sso/callback") {
        errors.push(format!(
            "{}: redirect_url must be the console's callback at its public https address, for example https://gantry.example.com/console/sso/callback, and be registered as a redirect URI at the identity provider.",
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
    let self_issue = sso.self_issue.as_ref().map(|si| {
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
                "{}: expires_days is {expires_days}. A key from gantry login works 1 to 365 days; 30 is usual.",
                at("expires_days")
            ));
        }
        SelfIssue {
            allowed_domains: lower(&si.allowed_domains),
            allowed_emails: lower(&si.allowed_emails),
            team,
            expires_days,
        }
    });
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
    })
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
}

/// One entry of a keys file, as checked.
#[derive(Clone, Debug, PartialEq, Eq)]
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
}

/// The tokens-per-minute limit `tpm` names, or what is wrong with it. `at` names where it is written.
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

/// Reads a budget's `per` and `usd`, or says what is wrong with them. `at` names where the budget is written.
fn budget_of(budget: &BudgetFile, at: &str, errors: &mut Vec<String>) -> Option<Budget> {
    let per = match budget.per.as_str() {
        "day" => Some(Period::Day),
        "month" => Some(Period::Month),
        other => {
            errors.push(format!(
                "{at}: per is \"{other}\". A budget starts again each day or each month (UTC): write per: day or per: month."
            ));
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
            Kind::OpenAi | Kind::Azure | Kind::Gemini | Kind::Vertex => Kind::OpenAi,
            Kind::Anthropic | Kind::Bedrock | Kind::VertexAnthropic => Kind::Anthropic,
        }
    }
}

/// The one rule for a provider URL, used by `gantry check` and `gantry serve` alike: http or https, a host, an
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
    /// A file that holds the provider key, in place of `key_env`. Gantry reads it at start and again whenever it
    /// changes, so the key can be rotated without a restart. A relative path is read from where Gantry runs.
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
    /// An IAM role Bedrock requests are signed as, assumed with the credentials Gantry finds.
    pub role_arn: Option<String>,
    /// The provider a request goes to when this one fails before answering.
    pub fallback: Option<String>,
    /// How many times a failure before the answer starts is tried again on this provider.
    pub retries: u32,
    /// Whether chat completions requests for its models are translated to the messages API.
    pub accept_chat: bool,
    /// Whether messages requests (Claude Code) for its models are translated to the chat completions API.
    pub accept_messages: bool,
}

/// Everything `gantry serve` needs from the two files.
#[derive(Clone, Debug)]
pub struct Loaded {
    pub policy: Policy,
    pub providers: Vec<Provider>,
    pub audit_path: PathBuf,
    pub keys_path: PathBuf,
    pub policy_sha256: String,
    pub keys_sha256: String,
    /// The policy file as it was read. It holds no secrets, so each version's text goes into its audit record.
    pub policy_text: String,
    /// Whether there was a keys file. A new setup may have none yet, which reads as no keys.
    pub keys_file_found: bool,
    /// Console sign-in through an identity provider, when the policy file sets `console.sso`.
    pub sso: Option<Sso>,
    /// Model names callers send that Gantry serves from one or more deployments.
    pub aliases: Vec<Alias>,
    /// Upstream MCP servers whose tools Gantry serves at `/mcp`.
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
    policy_path.with_file_name("gantry.keys.yaml")
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

/// Every YAML file Gantry reads goes through here, so all of them refuse duplicate keys and bound alias
/// expansion (serde-saphyr's defaults), and an error is one plain line for `explain`, not a source snippet.
pub(crate) fn from_yaml<T: serde::de::DeserializeOwned>(
    text: &str,
) -> Result<T, serde_saphyr::Error> {
    serde_saphyr::from_str_with_options(
        text,
        serde_saphyr::options! { with_snippet: false, strict_booleans: true },
    )
}

/// Turns a YAML error into one line: where, what, and the nearest word Gantry knows.
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
        ("a map", "audit") => Wanted::Example("audit: { path: gantry-audit.jsonl }"),
        ("a map", "console") => {
            Wanted::Example("console: { sso: { issuer: ..., client_id: ... } }")
        }
        // A map under a key Gantry does not know by name is a model's price under prices.
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
            format!("{at}: \"{word}\" is not a key Gantry knows. Did you mean \"{known}\"?")
        }
        None => {
            format!("{at}: \"{word}\" is not a key Gantry knows. Remove it, or check the spelling.")
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

/// Finds every key Gantry does not know or does not enforce, each with its line, in one pass over the text.
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
pub(crate) fn is_private(url: &str) -> bool {
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
            // `127.1`, `2130706433` and `0x7f.1` are addresses too, to the resolver. Gantry does not work out which
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
        let who = match (&p.team, &p.name, p.any) {
            (Some(team), None, None) => Who::Team(team.clone()),
            (None, Some(name), None) => Who::Name(name.clone()),
            (None, None, Some(true)) => Who::Any,
            _ => {
                errors.push(format!(
                    "{}: principals must be exactly one of {{ team: <team> }}, {{ name: <person or workload> }} or {{ any: true }}.",
                    at("principals")
                ));
                continue;
            }
        };
        let wildcard = rule.models.iter().any(|m| m == "*");
        if wildcard && rule.models.len() > 1 {
            errors.push(format!(
                "{}: \"*\" already allows every model. List it alone, or list the models by name.",
                at("models")
            ));
        }
        let models = if wildcard {
            Models::Any
        } else {
            Models::Only(rule.models.clone())
        };
        let limits = limits(rule, &at, errors);
        crate::mcp::check_tools(&at("tools"), &rule.tools, &parsed.mcp, errors);
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
            tools: rule.tools.clone(),
        });
    }
    rules
}

/// Each rule's `passthrough:` entries must name a provider of a kind Gantry can send to as is, and paths that
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
            match providers.iter().find(|p| p.name == entry.provider) {
                None => errors.push(format!(
                    "{at}: passthrough names no provider named \"{}\". Use the name of one under providers:.",
                    entry.provider
                )),
                Some(p) if matches!(p.kind, Kind::Bedrock | Kind::Vertex | Kind::VertexAnthropic) => errors.push(format!(
                    "{at}: provider \"{}\" is {}, whose requests Gantry must sign or translate, so it cannot be reached as sent. Pass through to an openai, anthropic, azure or gemini provider.",
                    entry.provider,
                    p.kind.word()
                )),
                Some(_) => {}
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
) {
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
        return;
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
            return;
        }
    };
    let (lines, end) = rule_lines(text);
    for (i, rule) in parsed.rules.iter().enumerate() {
        if rule.guardrails.is_empty() {
            continue;
        }
        let line = lines.get(i).copied().unwrap_or(0);
        let until = lines.get(i + 1).copied().unwrap_or(end);
        match guard::for_rule(&rule.name, &rule.guardrails, &defined) {
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
}

/// The budget, rate and cache of one rule, each checked. `at` gives the place of a key in the rule.
fn limits(rule: &RuleFile, at: &dyn Fn(&str) -> String, errors: &mut Vec<String>) -> Limits {
    let mut limits = Limits::default();
    if let Some(budget) = &rule.budget {
        limits.budget = budget_of(budget, &at("budget"), errors);
    }
    if let Some(rate) = &rule.rate {
        if rate.rpm.is_none() && rate.tpm.is_none() {
            errors.push(format!(
                "{}: rate sets no limit. Give rpm, tpm or both, for example rate: {{ rpm: 600, tpm: 200000 }}, or remove the line.",
                at("rate")
            ));
        }
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
    }
    limits.buffer_stream = rule.buffer_stream;
    limits.caller_provider_key = match rule.caller_provider_key.as_deref() {
        None | Some("refused") => CallerKey::Refused,
        Some("allowed") => CallerKey::Allowed,
        Some("allowed_budgeted") => CallerKey::AllowedBudgeted,
        Some(other) => {
            errors.push(format!(
                "{}: caller_provider_key is \"{other}\". It is refused (the default: a request that carries x-gantry-provider-key is refused), allowed (the caller's own provider key is sent, and what it spends is recorded but not counted against budgets) or allowed_budgeted (as allowed, and counted against budgets).",
                at("caller_provider_key")
            ));
            CallerKey::Refused
        }
    };
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
        if rule.limits.budget.is_none() {
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
        for model in reached {
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
/// speak one API, and each fallback names a model or alias Gantry serves.
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
            deployments.push(Deployment {
                provider: d.provider.clone(),
                model: d.model.clone(),
                weight,
            });
        }
        let balance = match entry.balance.as_deref() {
            None | Some("round_robin") => Balance::RoundRobin,
            Some("least_busy") => Balance::LeastBusy,
            Some(other) => {
                errors.push(format!("{at}: balance is \"{other}\". Write round_robin (in turn, by weight) or least_busy (fewest requests in flight)."));
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
        if errors.len() == before {
            out.push(Alias {
                name: entry.name.clone(),
                deployments,
                balance,
                cooldown_seconds,
                context_window_fallback: entry.context_window_fallback.clone(),
                content_policy_fallback: entry.content_policy_fallback.clone(),
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
        Kind::Bedrock => Some("model_ids"),
        Kind::OpenAi | Kind::Anthropic | Kind::Gemini | Kind::Vertex | Kind::VertexAnthropic => {
            None
        }
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
    if entry.api_version.is_some() && kind != Some(Kind::Azure) {
        only("api_version", "azure", errors);
    }
    if entry.model_ids.is_some() && kind != Some(Kind::Bedrock) {
        only("model_ids", "bedrock", errors);
    }
    if entry.region.is_some() && kind != Some(Kind::Bedrock) {
        only("region", "bedrock", errors);
    }
    if entry.role_arn.is_some() && kind != Some(Kind::Bedrock) {
        only("role_arn", "bedrock", errors);
    }
    if let Some(role) = &entry.role_arn
        && !(role.starts_with("arn:aws") && role.contains(":role/"))
    {
        errors.push(format!(
            "{}: role_arn is the ARN of an IAM role, for example arn:aws:iam::123456789012:role/gantry-bedrock.",
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
            "{}: accept_messages translates messages requests (Claude Code) to the chat completions API, so it is for a provider of kind openai, azure, gemini or vertex. Remove the line.",
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
        Some(Kind::Azure) => {
            match entry.api_version.as_deref() {
                None => errors.push(format!(
                    "{}: an azure provider needs api_version, the Azure OpenAI REST API version, for example `api_version: 2024-10-21`.",
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
        Some(Kind::Bedrock) => {
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
    // A chat request for gemini or vertex is translated before it is recorded, so its fallback takes the same body.
    if other_kind.api() != kind.api() || other_kind.google() != kind.google() {
        errors.push(format!(
            "{}: fallback \"{name}\" is of kind {}, which speaks another API than this provider ({}). A fallback must take the same requests: anthropic and bedrock take messages, openai and azure take chat completions, gemini and vertex take Google's generateContent, anthropic, bedrock and vertex_anthropic take messages.",
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
                "{}:{}: preset \"{id}\" is not in Gantry's provider catalog;{closest} `gantry providers` lists every id. Or remove preset and write url and kind.",
                file.display(),
                line_of_key(text, "preset", line, until)
            ));
            continue;
        };
        entry.url.get_or_insert_with(|| preset.url.to_string());
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
    // Which provider, at which line, claimed each model: a model served by two providers would be ambiguous.
    let mut claimed: HashMap<String, (String, usize)> = HashMap::new();
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
        .flat_map(|rule| rule.models.iter().map(String::as_str))
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
                        "{}: kind is \"{word}\". It must be openai (the chat completions API), anthropic (the messages API), azure (Azure OpenAI), bedrock (Amazon Bedrock, Anthropic models), gemini (Google's Gemini API) vertex (Gemini on Google Cloud Vertex AI) or vertex_anthropic (Claude on Google Cloud Vertex AI).",
                        at("kind")
                    ));
                }
                kind
            }
            None => None,
        };
        let bedrock = kind == Some(Kind::Bedrock);
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
                    "{}: a bedrock provider takes no credential. Gantry signs its requests with AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and, for temporary credentials, AWS_SESSION_TOKEN from its environment. Remove the line.",
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
            } else if parsed.store.is_none() {
                errors.push(format!(
                    "{}: provider \"{}\" takes its key from credential \"{name}\", and credentials are kept in the store, which this policy does not name. Add `store: {{ postgres_url_env: DATABASE_URL }}`, or keep the key in an environment variable with `key_env:`.",
                    at("credential"),
                    entry.name
                ));
            }
        }
        if let Some(path) = &entry.key_file {
            if bedrock {
                errors.push(format!(
                    "{}: a bedrock provider takes no key_file. Gantry signs its requests with the AWS credentials it finds: the role of its pod, task or instance, or AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in its environment. Remove the line.",
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
                "{}: a bedrock provider takes no key_env. Gantry signs its requests with the AWS credentials it finds: the role of its pod, task or instance, or AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in its environment. Remove the line.",
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
            (None, false) if entry.key_file.is_some() || entry.credential.is_some() => {}
            // Vertex AI signs in with Google's Application Default Credentials.
            (None, false) if matches!(kind, Some(Kind::Vertex | Kind::VertexAnthropic)) => {}
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
            match claimed.get(model) {
                Some((other, other_line)) => errors.push(format!(
                    "{}: model \"{model}\" is listed by provider \"{}\" and by provider \"{other}\" at line {other_line}. A model is served by one provider. Remove it from one of them.",
                    at("models"),
                    entry.name
                )),
                None => {
                    let model_line = line_of_key(text, "models", line, until);
                    claimed.insert(model.clone(), (entry.name.clone(), model_line));
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
                    "{}: model \"{model}\" has no entry in {map}, so Gantry would not know what to call it at provider \"{}\". Add `{model}: <name>` under {map}.",
                    at(map),
                    entry.name
                ));
            }
        }
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
                accept_messages: entry.accept_messages.unwrap_or(false),
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

/// Every problem in the text of a keys file. Empty means `gantry serve` will accept it.
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
            errors.push(format!("{at}: sha256 must be 64 hex characters. Run `gantry key new` to add a key instead of writing one by hand."));
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
        if entry.models.as_ref().is_some_and(Vec::is_empty) {
            errors.push(format!("{at}: models is empty, so this key could use no model. List the models it may use, or remove the line to leave its rule's list."));
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
            },
        );
    }
    keys
}

/// Reads and checks both files. Returns every problem found, one per line, each with its file and line.
pub fn load(policy_path: &Path, keys_path: Option<&Path>) -> Result<Loaded, Vec<String>> {
    let policy_text = read(policy_path, "policy file").map_err(|e| vec![e])?;
    if names_store(&policy_text) {
        // The keys are in the store: a keys file left beside the policy is not read. `gantry check` has no
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
/// load: `gantry check` says why.
pub fn credentials_named(policy_path: &Path) -> Vec<(String, String)> {
    std::fs::read_to_string(policy_path)
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
    Some(StoreSetting {
        postgres_url_env: env.clone(),
    })
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
            "{}:{}: version is {}. This version of Gantry reads version 1.",
            policy_path.display(),
            line_of_key(policy_text, "version", 1, usize::MAX),
            parsed.version
        ));
    }
    presets(policy_path, policy_text, &mut parsed.providers, &mut errors);
    let providers = providers(policy_path, policy_text, &parsed, &mut errors);
    let mut rules = policy_rules(policy_path, policy_text, &parsed, &mut errors);
    rule_guardrails(policy_path, policy_text, &parsed, &mut rules, &mut errors);
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
    let store = store_setting(policy_path, policy_text, &parsed, &mut errors);
    let audit_path = match &parsed.audit {
        Some(audit) => audit.path.clone(),
        None => policy_path.with_file_name("gantry-audit.jsonl"),
    };
    match providers {
        providers if errors.is_empty() => Ok(Loaded {
            policy: Policy::from_parts(principals(keys), rules).with_prices(parsed.prices),
            providers,
            audit_path,
            keys_path: keys_file.to_path_buf(),
            policy_sha256: sha256_hex(policy_text.as_bytes()),
            keys_sha256: sha256_hex(keys_text.as_bytes()),
            policy_text: policy_text.to_string(),
            keys_file_found: true,
            sso,
            aliases,
            mcp,
            store,
        }),
        _ => Err(errors),
    }
}

/// Why a running Gantry cannot change from `old` to `new` without a restart. Empty when it can.
/// The provider keys are read from the environment once, at start, and the audit log is opened once.
pub fn needs_restart(old: &Loaded, new: &Loaded) -> Vec<String> {
    let mut reasons = Vec::new();
    if old.audit_path != new.audit_path {
        reasons.push(format!(
            "the audit log path changed from {} to {}. A running Gantry keeps writing one chain: restart Gantry to change it.",
            old.audit_path.display(),
            new.audit_path.display()
        ));
    }
    // Each server's credentials are read from the environment at start, like a provider key.
    if old.mcp != new.mcp {
        reasons.push(
            "the mcp servers changed. Their credentials are read at start: restart Gantry to apply it. A rule's tools may change without one.".to_string(),
        );
    }
    // The connection to the store is made once, at start.
    if old.store != new.store {
        reasons.push(
            "the store section changed. Gantry connects to its store at start: restart Gantry to apply it.".to_string(),
        );
    }
    for provider in &old.providers {
        let Some(now) = new.providers.iter().find(|p| p.name == provider.name) else {
            reasons.push(format!(
                "provider \"{}\" was removed. Adding or removing a provider needs a restart: restart Gantry to apply it.",
                provider.name
            ));
            continue;
        };
        let changed = [
            (
                "kind",
                provider.kind.word().to_string(),
                now.kind.word().to_string(),
            ),
            ("url", provider.url.clone(), now.url.clone()),
            ("key_env", provider.key_env.clone(), now.key_env.clone()),
            (
                "key_file",
                provider
                    .key_file
                    .as_deref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default(),
                now.key_file
                    .as_deref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default(),
            ),
            (
                "credential",
                provider.credential.clone().unwrap_or_default(),
                now.credential.clone().unwrap_or_default(),
            ),
            (
                "api_version",
                provider.api_version.clone().unwrap_or_default(),
                now.api_version.clone().unwrap_or_default(),
            ),
            (
                "region",
                provider.region.clone().unwrap_or_default(),
                now.region.clone().unwrap_or_default(),
            ),
            (
                "role_arn",
                provider.role_arn.clone().unwrap_or_default(),
                now.role_arn.clone().unwrap_or_default(),
            ),
            (
                "allow_private",
                provider.allow_private.to_string(),
                now.allow_private.to_string(),
            ),
        ];
        for (what, was, is) in changed {
            if was != is {
                reasons.push(format!(
                    "the {what} of provider \"{}\" changed from {was} to {is}. That needs a restart: restart Gantry to apply it. A provider's models may change without one.",
                    provider.name
                ));
            }
        }
    }
    for provider in &new.providers {
        if !old.providers.iter().any(|p| p.name == provider.name) {
            reasons.push(format!(
                "provider \"{}\" was added. Adding or removing a provider needs a restart: restart Gantry to apply it, with its key in {}.",
                provider.name, provider.key_env
            ));
        }
    }
    reasons
}

/// A warning for each model a rule names that no provider serves. Requests for it are refused, so it is
/// probably a typo or a provider not added yet, but it is not an error: the rule still decides correctly.
pub fn unserved_models(policy_path: &Path, loaded: &Loaded) -> Vec<String> {
    let mut warnings = Vec::new();
    for rule in loaded.policy.rule_list() {
        let Models::Only(models) = &rule.models else {
            continue;
        };
        let models_line = line_of_key(&loaded.policy_text, "models", rule.line, usize::MAX);
        for model in models {
            if !loaded.providers.iter().any(|p| p.models.contains(model))
                && !loaded.aliases.iter().any(|a| a.name == *model)
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
            if model.contains('*') {
                warnings.push(format!(
                    "{at} lists model \"{model}\". A provider lists exact names, so \"*\" here is not a pattern: only a request for exactly \"{model}\" reaches it."
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
        let dir = std::env::temp_dir().join(format!("gantry-config-{}-{name}", std::process::id()));
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
        let path = dir.join("gantry.policy.yaml");
        std::fs::write(&path, policy)?;
        if let Some(keys) = keys {
            std::fs::write(dir.join("gantry.keys.yaml"), keys)?;
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
        for (entry, expected) in [
            (
                "      - { provider: nope, paths: [/v1/x] }\n",
                "no provider named \"nope\"",
            ),
            ("      - { provider: bedrock, paths: [/x] }\n", "bedrock"),
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
                found.contains("gantry.policy.yaml:"),
                "the error names file and line: {found}"
            );
        }
        Ok(())
    }

    #[test]
    fn the_example_file_loads_with_rule_lines() -> TestResult {
        let key = "gantry_test";
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
        assert!(text.contains("gantry.policy.yaml:12"), "{text}");
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
            "gantry.policy.yaml:13: tool \"gitlab.create_issue\" is on MCP server \"gitlab\", which is not defined under mcp. The MCP servers are: git.hub.",
            "gantry.policy.yaml:13: tool \"search\" names no server.",
            "gantry.policy.yaml:18: an MCP server name uses letters",
            "gantry.policy.yaml:19: the MCP server url points at this machine or a private network",
            "gantry.policy.yaml:20: headers_env gives header Authorization the value \"Bearer abc\"",
        ] {
            assert!(text.contains(expected), "missing {expected}:\n{text}");
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
    fn budget_rate_cache_and_prices_load_into_the_rules() -> TestResult {
        let loaded = check("limits", LIMITED, None)?.map_err(|e| e.join("\n"))?;
        let rules = loaded.policy.rule_list();
        assert_eq!(
            rules[0].limits,
            Limits {
                budget: Some(Budget {
                    usd: 2000.0,
                    per: Period::Month
                }),
                rpm: Some(600),
                tpm: None,
                cache_ttl_seconds: Some(300),
                buffer_stream: false,
                check_stream_every: None,
                caller_provider_key: CallerKey::Refused,
            }
        );
        assert_eq!(
            rules[1].limits.budget,
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
    fn bad_limits_are_named_with_their_line_and_the_fix() -> TestResult {
        let cases = [
            (
                "usd: 2000, per: month",
                "usd: 2000, per: week",
                ":17",
                "per: day or per: month",
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
                text.contains(&format!("gantry.policy.yaml{line}:")),
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
        assert!(text.contains("gantry.policy.yaml:23"), "{text}");
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
    fn near_duplicate_and_starred_model_names_are_warned_about() -> TestResult {
        let odd = GOOD.replace(
            "models: [gpt-4o-mini, gpt-4o]",
            "models: [gpt-4o-mini, gpt-4o, GPT-4o, \" gpt-x\", \"gpt-*\"]",
        );
        let dir = dir("near")?;
        let path = dir.join("gantry.policy.yaml");
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
        assert!(warnings.contains("is not a pattern"), "{warnings}");
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
            text.contains("gantry.policy.yaml:13") && text.contains("at line 8"),
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
            ("    budget: { usd: 5, per: week }\n", "per is \"week\""),
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
            problems.contains("gantry.policy.yaml:3: \"version\" is written twice"),
            "{problems}"
        );
        let nested = GOOD.replacen(
            "    models: [gpt-4o-mini]\n",
            "    models: [gpt-4o-mini]\n    models: [gpt-4o]\n",
            1,
        );
        let problems = errors(check("dup-key-nested", &nested, None)?)?;
        assert!(
            problems.contains("gantry.policy.yaml:13: \"models\" is written twice"),
            "{problems}"
        );
        Ok(())
    }

    #[test]
    fn a_price_or_a_list_of_the_wrong_kind_is_explained() -> TestResult {
        let price = format!("{GOOD}prices:\n  gpt-4o: 5\n");
        let problems = errors(check("price-kind", &price, None)?)?;
        assert!(
            problems.contains("gantry.policy.yaml:17: gpt-4o is integer 5. Write it as gpt-4o: { input: 2.5, output: 10 }"),
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
            problems.contains("gantry.policy.yaml:14: any must be true or false"),
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
            // A key Gantry knows, in a place it does not belong, is not a misspelling of itself.
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
            text.contains("gantry.policy.yaml:21")
                && text.contains("\"no-secret\", which is not defined"),
            "{text}"
        );
        let no_failure = format!("{GUARDED}{GOOD}").replace("    on_failure: fail_closed\n", "");
        let text = errors(check("no-failure", &no_failure, None)?)?;
        assert!(
            text.contains("gantry.policy.yaml:5: guardrail \"vendor\"")
                && text.contains("on_failure"),
            "{text}"
        );
        let typo = format!("{GUARDED}{GOOD}").replace(
            "    on_failure: fail_closed\n",
            "    on_failure: fail_closed\n    timeoutms: 5\n",
        );
        let text = errors(check("guard-typo", &typo, None)?)?;
        assert!(
            text.contains("gantry.policy.yaml:9") && text.contains("Did you mean \"timeout_ms\""),
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
        // Moving the key to another file needs a restart, as changing key_env does.
        let moved = text.replace("secrets/groq.key", "other.key");
        let new = check("key-file-moved", &moved, None)?.map_err(|e| e.join("\n"))?;
        let reasons = needs_restart(&loaded, &new).join("\n");
        assert!(
            reasons.contains("the key_file of provider \"groq\""),
            "{reasons}"
        );
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
        assert!(
            needs_restart(&loaded, &new)
                .join("\n")
                .contains("the credential of provider \"groq\""),
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
                "    region: us-east-1\n    role_arn: gantry-bedrock\n",
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
            "    region: us-east-1\n    role_arn: arn:aws:iam::123456789012:role/gantry-bedrock\n",
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
            Some("arn:aws:iam::123456789012:role/gantry-bedrock")
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
                "take Google's generateContent",
            ),
            ("kind: gemini", "kind: palm", "gemini (Google's Gemini API)"),
        ] {
            let text = errors(check("google-bad", &GOOGLE.replace(from, to), None)?)?;
            assert!(text.contains(expected), "{expected}: {text}");
        }
        Ok(())
    }
}
