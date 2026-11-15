//! `GET /metrics` in the Prometheus text format, on its own listener (`gantry serve --metrics <host:port>`).
//!
//! Counted always, served only when asked: the counters cost one short lock per request, and the listener that
//! shows them is off unless `--metrics` names an address. That address takes no key, so it belongs on loopback or a
//! private network that only the scraper reaches. Labels come from the policy (routes, codes, providers, teams,
//! models), never from what a caller sends, so their number stays bounded.

use std::{
    collections::{BTreeMap, HashMap},
    fmt::Write,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use axum::{
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use gantry_core::metrics::Histogram;

use crate::AppState;

/// (route, verdict, code, provider).
type RequestKey = (&'static str, &'static str, &'static str, String);

#[derive(Default)]
pub(crate) struct Metrics {
    /// (route, verdict, code, provider): decisions, as the audit log records them.
    requests: Mutex<HashMap<RequestKey, u64>>,
    /// (provider, outcome): each attempt at a provider, by HTTP status or the refusal code when it did not answer.
    upstream: Mutex<HashMap<(String, String), u64>>,
    /// Time to the provider's answer headers, per provider.
    upstream_seconds: Mutex<BTreeMap<String, Arc<Histogram>>>,
    /// Gantry's own time on a forwarded request: identify, decide, guard, record, plus handing the answer back.
    overhead: Histogram,
    /// (team, model): US dollars charged, as usage records write them.
    spend: Mutex<BTreeMap<(String, String), f64>>,
    /// (team, kind): US dollars caching saved, `answer` for Gantry's answer cache, `prompt` for a provider's.
    saved: Mutex<BTreeMap<(String, &'static str), f64>>,
    /// (provider, status): a pool key set aside and the next one tried.
    key_switches: Mutex<BTreeMap<(String, String), u64>>,
    /// (team, model, kind): tokens the provider reported, kind `input`, `output`, `cached` (read from its prompt
    /// cache) or `cache_write`.
    tokens: Mutex<BTreeMap<(String, String, &'static str), u64>>,
    /// Time from a request reaching Gantry to the end of its answer, per model.
    request_seconds: Mutex<BTreeMap<String, Arc<Histogram>>>,
    /// Time from a request reaching Gantry to its answer's headers leaving for the caller, per provider.
    first_byte_seconds: Mutex<BTreeMap<String, Arc<Histogram>>>,
    /// (kind): what guardrails found on requests, by detector kind.
    findings: Mutex<BTreeMap<String, u64>>,
    /// (outcome): answer cache lookups, `hit` or `miss`.
    cache: Mutex<BTreeMap<&'static str, u64>>,
    /// (guardrail, outcome): envelopes of events guardrails, `sent`, `failed` or `dropped` (observe mode's queue
    /// was full).
    events: Mutex<BTreeMap<(String, &'static str), u64>>,
    /// Time in each stage of a request, in the order of `stages::NAMES`. Atomics only: no lock on the request path.
    stages: [Histogram; crate::stages::NAMES.len()],
    /// Time of each guardrail call, by guardrail name (from the policy), `builtin` for the built-in detectors.
    guardrail_seconds: Mutex<BTreeMap<String, Arc<Histogram>>>,
    /// (model): answers from a provider for a model with no price, whose spend is counted nowhere.
    unpriced: Mutex<BTreeMap<String, u64>>,
    /// (server, outcome): MCP calls to a tool, prompt or resource.
    mcp: Mutex<BTreeMap<(String, String), u64>>,
    /// (dimension, value, verdict): requests by the `x-gantry-dim-<dimension>` headers the operator chose.
    dimensions: Mutex<BTreeMap<(String, String, &'static str), u64>>,
}

/// The request headers counted as dimensions, from `GANTRY_METRICS_DIMENSIONS` (comma-separated names: `env,app`
/// counts `x-gantry-dim-env` and `x-gantry-dim-app`). Read once: it names series, so it does not change under a
/// scraper.
pub(crate) fn dimensions() -> &'static [String] {
    static NAMES: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    NAMES
        .get_or_init(|| dimension_names(std::env::var("GANTRY_METRICS_DIMENSIONS").ok().as_deref()))
}

fn dimension_names(setting: Option<&str>) -> Vec<String> {
    setting
        .unwrap_or_default()
        .split(',')
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| {
            !name.is_empty()
                && name.len() <= 32
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        .take(MAX_DIMENSIONS)
        .collect()
}

/// A caller chooses a dimension's values, so their number is capped: past it, a new value is counted as `other`.
const MAX_DIMENSION_VALUES: usize = 100;
const MAX_DIMENSIONS: usize = 8;

/// Which budget scopes `gantry_budget_remaining_usd` shows, from `GANTRY_METRICS_BUDGET_SCOPES` (comma-separated
/// scope kinds, `none` for no budget gauges). The default leaves out person, key, customer and tag: one series
/// each would grow with the number of people.
pub(crate) fn budget_scopes(setting: Option<&str>) -> Vec<String> {
    match setting.map(str::trim) {
        None | Some("") => vec!["global".into(), "org".into(), "team".into(), "model".into()],
        Some("none") => Vec::new(),
        Some(list) => list
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect(),
    }
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // Counters only: a poisoned lock still holds sound numbers.
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The route label: a route Gantry serves, or `other`, so an unknown path cannot add a label value.
pub(crate) fn route_label(path: &str) -> &'static str {
    match path {
        crate::CHAT => "chat_completions",
        crate::MESSAGES => "messages",
        crate::COUNT_TOKENS => "count_tokens",
        crate::RESPONSES => "responses",
        crate::EMBEDDINGS => "embeddings",
        crate::MODELS => "models",
        _ if crate::gemini_path(path) => "gemini",
        _ => "other",
    }
}

impl Metrics {
    pub(crate) fn decided(&self, path: &str, code: Option<&'static str>, provider: &str) {
        let verdict = if code.is_some() { "refused" } else { "allow" };
        let key = (
            route_label(path),
            verdict,
            code.unwrap_or(""),
            provider.to_string(),
        );
        *locked(&self.requests).entry(key).or_default() += 1;
    }

    pub(crate) fn attempted(&self, provider: &str, outcome: &str, took: Duration) {
        *locked(&self.upstream)
            .entry((provider.to_string(), outcome.to_string()))
            .or_default() += 1;
        let histogram = locked(&self.upstream_seconds)
            .entry(provider.to_string())
            .or_default()
            .clone();
        histogram.observe(took);
    }

    pub(crate) fn key_switched(&self, provider: &str, status: &str) {
        *locked(&self.key_switches)
            .entry((provider.to_string(), status.to_string()))
            .or_default() += 1;
    }

    /// Counts `n` envelopes of an events guardrail: `sent`, `failed` or `dropped`.
    pub(crate) fn events(&self, guardrail: &str, outcome: &'static str, n: u64) {
        *locked(&self.events)
            .entry((guardrail.to_string(), outcome))
            .or_default() += n;
    }

    /// The stages a request has passed, and each guardrail call it made.
    pub(crate) fn stages(&self, stages: &crate::stages::Stages) {
        for (name, took) in stages.entries(None) {
            self.stage(name, took);
        }
        if !stages.calls.is_empty() {
            let mut guardrails = locked(&self.guardrail_seconds);
            for (name, took) in &stages.calls {
                guardrails.entry(name.clone()).or_default().observe(*took);
            }
        }
    }

    pub(crate) fn stage(&self, name: &str, took: Duration) {
        if let Some(at) = crate::stages::NAMES.iter().position(|n| *n == name) {
            self.stages[at].observe(took);
        }
    }

    pub(crate) fn unpriced(&self, model: &str) {
        *locked(&self.unpriced).entry(model.to_string()).or_default() += 1;
    }

    pub(crate) fn mcp_called(&self, server: &str, outcome: &str) {
        *locked(&self.mcp)
            .entry((server.to_string(), outcome.to_string()))
            .or_default() += 1;
    }

    /// Counts a request under each dimension header it carries. A value is kept to 64 characters of letters,
    /// digits, `.`, `-` and `_`; anything else, and any value past the cap, is `other`.
    pub(crate) fn dimensioned(&self, headers: &axum::http::HeaderMap, refused: bool) {
        self.dimensioned_as(dimensions(), headers, refused);
    }

    fn dimensioned_as(&self, names: &[String], headers: &axum::http::HeaderMap, refused: bool) {
        if names.is_empty() {
            return;
        }
        let verdict = if refused { "refused" } else { "allow" };
        let mut counted = locked(&self.dimensions);
        for name in names {
            let Some(value) = headers
                .get(format!("x-gantry-dim-{name}"))
                .and_then(|v| v.to_str().ok())
            else {
                continue;
            };
            let clean = !value.is_empty()
                && value.len() <= 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b));
            let known = counted
                .range((name.clone(), String::new(), "")..)
                .take_while(|((n, _, _), _)| n == name)
                .map(|((_, v, _), _)| v.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            let value = if clean && (known.contains(value) || known.len() < MAX_DIMENSION_VALUES) {
                value
            } else {
                "other"
            };
            let key = (name.clone(), value.to_string(), verdict);
            *counted.entry(key).or_default() += 1;
        }
    }

    pub(crate) fn overhead(&self, took: Duration) {
        self.overhead.observe(took);
    }

    pub(crate) fn charged(&self, team: &str, model: &str, usd: f64) {
        if usd > 0.0 && usd.is_finite() {
            *locked(&self.spend)
                .entry((team.to_string(), model.to_string()))
                .or_default() += usd;
        }
    }

    /// Can be less than zero: a provider's cache write costs more than the input it caches.
    pub(crate) fn saved(&self, team: &str, kind: &'static str, usd: f64) {
        if usd.is_finite() && usd != 0.0 {
            *locked(&self.saved)
                .entry((team.to_string(), kind))
                .or_default() += usd;
        }
    }

    /// What an answer used, when it ended: its tokens, its time, and whether the answer cache served it.
    pub(crate) fn settled(
        &self,
        team: &str,
        model: &str,
        usage: Option<&gantry_core::usage::Usage>,
        took: Duration,
    ) {
        if let Some(u) = usage {
            let mut tokens = locked(&self.tokens);
            for (kind, n) in [
                ("input", u.input),
                ("output", u.output),
                ("cached", u.cache_read),
                ("cache_write", u.cache_write + u.cache_write_1h),
            ] {
                if n > 0 {
                    *tokens
                        .entry((team.to_string(), model.to_string(), kind))
                        .or_default() += n;
                }
            }
        }
        let histogram = locked(&self.request_seconds)
            .entry(model.to_string())
            .or_default()
            .clone();
        histogram.observe(took);
    }

    pub(crate) fn first_byte(&self, provider: &str, took: Duration) {
        let histogram = locked(&self.first_byte_seconds)
            .entry(provider.to_string())
            .or_default()
            .clone();
        histogram.observe(took);
    }

    /// A request's guardrail findings (kinds, from the detectors the policy names) and its answer cache lookup.
    pub(crate) fn inspected(&self, kinds: &[String], cache: Option<&'static str>) {
        if !kinds.is_empty() {
            let mut findings = locked(&self.findings);
            for kind in kinds {
                *findings.entry(kind.clone()).or_default() += 1;
            }
        }
        if let Some(outcome) = cache {
            *locked(&self.cache).entry(outcome).or_default() += 1;
        }
    }

    fn render(&self, state: &AppState, budgets: &[Budget]) -> String {
        let mut out = String::new();
        let label = |text: &str| text.replace('\\', "\\\\").replace('"', "\\\"");
        out.push_str("# HELP gantry_requests_total Requests decided, by route, verdict, refusal code and provider.\n# TYPE gantry_requests_total counter\n");
        let mut requests: Vec<_> = locked(&self.requests)
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        requests.sort();
        for ((route, verdict, code, provider), n) in requests {
            let _ = writeln!(
                out,
                "gantry_requests_total{{route=\"{route}\",verdict=\"{verdict}\",code=\"{code}\",provider=\"{}\"}} {n}",
                label(&provider)
            );
        }
        out.push_str("# HELP gantry_refusals_total Requests refused, by refusal code.\n# TYPE gantry_refusals_total counter\n");
        let mut refusals: BTreeMap<&str, u64> = BTreeMap::new();
        for ((_, verdict, code, _), n) in locked(&self.requests).iter() {
            if *verdict == "refused" {
                *refusals.entry(code).or_default() += n;
            }
        }
        for (code, n) in refusals {
            let _ = writeln!(out, "gantry_refusals_total{{code=\"{code}\"}} {n}");
        }
        out.push_str("# HELP gantry_upstream_responses_total Attempts at a provider, by HTTP status or the code when it gave none.\n# TYPE gantry_upstream_responses_total counter\n");
        let mut upstream: Vec<_> = locked(&self.upstream)
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        upstream.sort();
        for ((provider, outcome), n) in upstream {
            let _ = writeln!(
                out,
                "gantry_upstream_responses_total{{provider=\"{}\",outcome=\"{}\"}} {n}",
                label(&provider),
                label(&outcome)
            );
        }
        out.push_str("# HELP gantry_upstream_seconds Time from sending to a provider to its answer's headers.\n# TYPE gantry_upstream_seconds histogram\n");
        for (provider, histogram) in locked(&self.upstream_seconds).iter() {
            histogram.render(
                &mut out,
                "gantry_upstream_seconds",
                &format!("provider=\"{}\"", label(provider)),
            );
        }
        out.push_str("# HELP gantry_overhead_seconds Gantry's own time on a forwarded request, without the provider.\n# TYPE gantry_overhead_seconds histogram\n");
        self.overhead
            .render(&mut out, "gantry_overhead_seconds", "");
        if let Some(audit) = &state.audit {
            let stats = audit.log.stats();
            let _ = writeln!(
                out,
                "# HELP gantry_audit_queue_depth Records waiting for the audit writer.\n# TYPE gantry_audit_queue_depth gauge\ngantry_audit_queue_depth {}",
                stats.queued.load(std::sync::atomic::Ordering::Relaxed)
            );
            out.push_str("# HELP gantry_audit_write_seconds Time of each write to the audit log (one per batch of records).\n# TYPE gantry_audit_write_seconds histogram\n");
            stats
                .write
                .render(&mut out, "gantry_audit_write_seconds", "");
            let _ = writeln!(
                out,
                "# HELP gantry_audit_broken 1 when the audit log cannot be written and every request is refused.\n# TYPE gantry_audit_broken gauge\ngantry_audit_broken {}",
                u8::from(audit.log.is_broken())
            );
        }
        out.push_str("# HELP gantry_spend_usd_total US dollars charged since start, by team and model.\n# TYPE gantry_spend_usd_total counter\n");
        for ((team, model), usd) in locked(&self.spend).iter() {
            let _ = writeln!(
                out,
                "gantry_spend_usd_total{{team=\"{}\",model=\"{}\"}} {}",
                label(team),
                label(model),
                usd_text(*usd)
            );
        }
        out.push_str("# HELP gantry_cache_saved_usd US dollars caching saved since start, by team and kind: answer (Gantry's answer cache) or prompt (a provider's prompt cache, net of cache writes).\n# TYPE gantry_cache_saved_usd gauge\n");
        for ((team, kind), usd) in locked(&self.saved).iter() {
            let _ = writeln!(
                out,
                "gantry_cache_saved_usd{{team=\"{}\",kind=\"{kind}\"}} {}",
                label(team),
                usd_text(*usd)
            );
        }
        out.push_str("# HELP gantry_provider_key_switches_total Pool keys set aside after a 401, 403 or 429, by provider and status.\n# TYPE gantry_provider_key_switches_total counter\n");
        for ((provider, status), n) in locked(&self.key_switches).iter() {
            let _ = writeln!(
                out,
                "gantry_provider_key_switches_total{{provider=\"{}\",status=\"{}\"}} {n}",
                label(provider),
                label(status)
            );
        }
        let events = locked(&self.events);
        if !events.is_empty() {
            out.push_str("# HELP gantry_events_delivered_total Envelopes of events guardrails delivered to their plugin, by guardrail and outcome: sent or failed.\n# TYPE gantry_events_delivered_total counter\n");
            for ((guardrail, outcome), n) in events.iter().filter(|((_, o), _)| *o != "dropped") {
                let _ = writeln!(
                    out,
                    "gantry_events_delivered_total{{guardrail=\"{}\",outcome=\"{outcome}\"}} {n}",
                    label(guardrail)
                );
            }
            out.push_str("# HELP gantry_events_dropped_total Envelopes an observing events guardrail dropped because its queue was full, by guardrail.\n# TYPE gantry_events_dropped_total counter\n");
            for ((guardrail, _), n) in events.iter().filter(|((_, o), _)| *o == "dropped") {
                let _ = writeln!(
                    out,
                    "gantry_events_dropped_total{{guardrail=\"{}\"}} {n}",
                    label(guardrail)
                );
            }
        }
        drop(events);
        let secrets = gantry_core::secrets::counts();
        if !secrets.is_empty() {
            out.push_str("# HELP gantry_secret_rotations_total Secrets read from a secret manager that changed on a refresh, by manager.\n# TYPE gantry_secret_rotations_total counter\n");
            for (source, rotated, _) in &secrets {
                let _ = writeln!(
                    out,
                    "gantry_secret_rotations_total{{source=\"{source}\"}} {rotated}"
                );
            }
            out.push_str("# HELP gantry_secret_refresh_failures_total Secrets a refresh could not read from their manager (the value read before is kept), by manager.\n# TYPE gantry_secret_refresh_failures_total counter\n");
            for (source, _, failed) in &secrets {
                let _ = writeln!(
                    out,
                    "gantry_secret_refresh_failures_total{{source=\"{source}\"}} {failed}"
                );
            }
        }
        out.push_str("# HELP gantry_tokens_total Tokens providers reported, by team, model and kind: input, output, cached (read from a prompt cache) or cache_write.\n# TYPE gantry_tokens_total counter\n");
        for ((team, model, kind), n) in locked(&self.tokens).iter() {
            let _ = writeln!(
                out,
                "gantry_tokens_total{{team=\"{}\",model=\"{}\",kind=\"{kind}\"}} {n}",
                label(team),
                label(model)
            );
        }
        out.push_str("# HELP gantry_request_seconds Time from a request reaching Gantry to the end of its answer, by model.\n# TYPE gantry_request_seconds histogram\n");
        for (model, histogram) in locked(&self.request_seconds).iter() {
            histogram.render(
                &mut out,
                "gantry_request_seconds",
                &format!("model=\"{}\"", label(model)),
            );
        }
        out.push_str("# HELP gantry_first_byte_seconds Time from a request reaching Gantry to its answer's headers leaving for the caller, by provider.\n# TYPE gantry_first_byte_seconds histogram\n");
        for (provider, histogram) in locked(&self.first_byte_seconds).iter() {
            histogram.render(
                &mut out,
                "gantry_first_byte_seconds",
                &format!("provider=\"{}\"", label(provider)),
            );
        }
        out.push_str("# HELP gantry_guardrail_findings_total What guardrails found on requests, by detector kind.\n# TYPE gantry_guardrail_findings_total counter\n");
        for (kind, n) in locked(&self.findings).iter() {
            let _ = writeln!(
                out,
                "gantry_guardrail_findings_total{{kind=\"{}\"}} {n}",
                label(kind)
            );
        }
        out.push_str("# HELP gantry_cache_lookups_total Answer cache lookups of rules with cache:, by outcome: hit or miss.\n# TYPE gantry_cache_lookups_total counter\n");
        for (outcome, n) in locked(&self.cache).iter() {
            let _ = writeln!(
                out,
                "gantry_cache_lookups_total{{outcome=\"{outcome}\"}} {n}"
            );
        }
        out.push_str("# HELP gantry_stage_seconds Time a request spent in each stage inside Gantry: auth, read (the body), policy, guardrails, cache (with rate limits and budgets), audit (the decision record), connect and first_byte (the provider that answered), stream.\n# TYPE gantry_stage_seconds histogram\n");
        for (name, histogram) in crate::stages::NAMES.iter().zip(&self.stages) {
            histogram.render(
                &mut out,
                "gantry_stage_seconds",
                &format!("stage=\"{name}\""),
            );
        }
        out.push_str("# HELP gantry_guardrail_seconds Time of each guardrail call on a request, by guardrail: builtin for the built-in detectors, events for events plugins.\n# TYPE gantry_guardrail_seconds histogram\n");
        for (guardrail, histogram) in locked(&self.guardrail_seconds).iter() {
            histogram.render(
                &mut out,
                "gantry_guardrail_seconds",
                &format!("guardrail=\"{}\"", label(guardrail)),
            );
        }
        out.push_str("# HELP gantry_unpriced_requests_total Answers from a provider for a model with no price: their spend is counted nowhere. Add the model under prices: in the policy.\n# TYPE gantry_unpriced_requests_total counter\n");
        for (model, n) in locked(&self.unpriced).iter() {
            let _ = writeln!(
                out,
                "gantry_unpriced_requests_total{{model=\"{}\"}} {n}",
                label(model)
            );
        }
        out.push_str("# HELP gantry_mcp_calls_total MCP calls to a tool, prompt or resource, by server and outcome: ok, tool_error, rpc_error, a refusal code, or why the server gave no answer.\n# TYPE gantry_mcp_calls_total counter\n");
        for ((server, outcome), n) in locked(&self.mcp).iter() {
            let _ = writeln!(
                out,
                "gantry_mcp_calls_total{{server=\"{}\",outcome=\"{}\"}} {n}",
                label(server),
                label(outcome)
            );
        }
        let dimensions = locked(&self.dimensions);
        if !dimensions.is_empty() {
            out.push_str("# HELP gantry_requests_by_dimension_total Requests by the x-gantry-dim-<dimension> headers GANTRY_METRICS_DIMENSIONS names, by dimension, value and verdict. At most 100 values a dimension, then other.\n# TYPE gantry_requests_by_dimension_total counter\n");
            for ((dimension, value, verdict), n) in dimensions.iter() {
                let _ = writeln!(
                    out,
                    "gantry_requests_by_dimension_total{{dimension=\"{dimension}\",value=\"{value}\",verdict=\"{verdict}\"}} {n}"
                );
            }
        }
        drop(dimensions);
        out.push_str("# HELP gantry_deployment_rate_headroom_ratio The smallest share left of the rate limits a deployment's provider named in its last answer's headers (0 to 1), for a minute after that answer.\n# TYPE gantry_deployment_rate_headroom_ratio gauge\n");
        for (deployment, left) in state.pool.headrooms() {
            let _ = writeln!(
                out,
                "gantry_deployment_rate_headroom_ratio{{deployment=\"{}\"}} {left}",
                label(&deployment)
            );
        }
        let deployments = state.pool.health();
        let probes: BTreeMap<String, bool> = state
            .pool
            .probes()
            .into_iter()
            .map(|(deployment, probed)| (deployment, probed.up))
            .collect();
        // Down while it cools down after failures, or while its last health probe got no answer.
        out.push_str("# HELP gantry_deployment_up 1 while a deployment of an alias takes requests and its last health probe (if probed) got an answer, 0 while it cools down or its probe fails.
# TYPE gantry_deployment_up gauge
");
        let mut up: BTreeMap<&str, bool> = probes.iter().map(|(d, up)| (d.as_str(), *up)).collect();
        for (deployment, cooling, _) in &deployments {
            let probed = probes.get(deployment).copied().unwrap_or(true);
            up.insert(deployment.as_str(), probed && !cooling);
        }
        for (deployment, up) in &up {
            let _ = writeln!(
                out,
                "gantry_deployment_up{{deployment=\"{}\"}} {}",
                label(deployment),
                u8::from(*up)
            );
        }
        out.push_str("# HELP gantry_deployment_cooldowns_total Times a deployment was put to cool down after a failure.\n# TYPE gantry_deployment_cooldowns_total counter\n");
        for (deployment, _, cooldowns) in &deployments {
            let _ = writeln!(
                out,
                "gantry_deployment_cooldowns_total{{deployment=\"{}\"}} {cooldowns}",
                label(deployment)
            );
        }
        out.push_str("# HELP gantry_budget_limit_usd A budget of limits: in the policy, by scope kind, name and period.\n# TYPE gantry_budget_limit_usd gauge\n# HELP gantry_budget_remaining_usd What a budget has left this period (its limit less what was spent and is held), by scope kind, name and period. GANTRY_METRICS_BUDGET_SCOPES chooses the scope kinds.\n# TYPE gantry_budget_remaining_usd gauge\n# HELP gantry_budget_reserved_usd What requests in flight hold of a budget now, by scope kind, name and period.\n# TYPE gantry_budget_reserved_usd gauge\n");
        for b in budgets {
            let labels = format!(
                "scope=\"{}\",name=\"{}\",per=\"{}\"",
                b.scope,
                label(&b.name),
                label(&b.per)
            );
            let _ = writeln!(
                out,
                "gantry_budget_limit_usd{{{labels}}} {}",
                usd_text(b.limit)
            );
            let _ = writeln!(
                out,
                "gantry_budget_remaining_usd{{{labels}}} {}",
                usd_text((b.limit - b.used).max(0.0))
            );
            let _ = writeln!(
                out,
                "gantry_budget_reserved_usd{{{labels}}} {}",
                usd_text(b.held)
            );
        }
        if let Some(store) = &state.spend.store {
            let _ = writeln!(
                out,
                "# HELP gantry_store_up 1 when the store answers, 0 when requests under a budget or rate limit would be refused.\n# TYPE gantry_store_up gauge\ngantry_store_up {}",
                u8::from(store.reachable().is_ok())
            );
        }
        out
    }
}

/// One budget gauge.
pub(crate) struct Budget {
    scope: &'static str,
    name: String,
    per: String,
    limit: f64,
    used: f64,
    held: f64,
}

/// The budgets of `limits:` in the scope kinds chosen, with what each spent and holds this period.
async fn budgets(state: &AppState) -> Vec<Budget> {
    let scopes = budget_scopes(
        std::env::var("GANTRY_METRICS_BUDGET_SCOPES")
            .ok()
            .as_deref(),
    );
    let version = state.version();
    let Some(policy) = &version.policy else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for limit in policy.scope_limits() {
        let kind = limit.kind.word();
        // A `*` entry counts each member apart: one series each would grow with the people.
        if !scopes.iter().any(|s| s == kind) || limit.name == "*" {
            continue;
        }
        let org = limit.org.as_deref().unwrap_or_default();
        let counter = match kind {
            "global" => "global".to_string(),
            "org" => format!("org:{}", limit.name),
            _ => format!("{kind}:{}", gantry_core::policy::within(org, &limit.name)),
        };
        for budget in &limit.budgets {
            let (spent, held) = state
                .spend
                .spent_now(&counter, budget.per)
                .await
                .unwrap_or_default();
            out.push(Budget {
                scope: match kind {
                    "global" => "global",
                    "org" => "org",
                    "team" => "team",
                    "person" => "person",
                    "key" => "key",
                    "customer" => "customer",
                    "tag" => "tag",
                    _ => "model",
                },
                name: gantry_core::policy::within(org, &limit.name),
                per: budget.per.word(),
                limit: budget.usd,
                used: spent + held,
                held,
            });
        }
    }
    out
}

/// Where a Prometheus Pushgateway takes this gateway's metrics, from `GANTRY_METRICS_PUSH_URL` (the whole address,
/// job and instance included: `http://pushgateway:9091/metrics/job/gantry/instance/a`), and how often
/// (`GANTRY_METRICS_PUSH_SECONDS`, 15 unless set). For a gateway nothing can scrape: a job behind NAT, a short task.
pub(crate) fn push_target(
    get: impl Fn(&str) -> Option<String>,
) -> Result<Option<(String, Duration)>, String> {
    let Some(url) = get("GANTRY_METRICS_PUSH_URL")
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
    else {
        return Ok(None);
    };
    if !(url.starts_with("http://") || url.starts_with("https://"))
        || url.parse::<axum::http::Uri>().is_err()
    {
        return Err(format!(
            "GANTRY_METRICS_PUSH_URL is {url}, which is not an http or https URL. Set it to the Pushgateway's address with the job, such as http://pushgateway:9091/metrics/job/gantry."
        ));
    }
    let every = match get("GANTRY_METRICS_PUSH_SECONDS").filter(|s| !s.trim().is_empty()) {
        None => 15,
        Some(text) => text.trim().parse::<u64>().ok().filter(|n| *n >= 1).ok_or_else(|| {
            format!("GANTRY_METRICS_PUSH_SECONDS is {text}. Set it to a whole number of seconds, 1 or more.")
        })?,
    };
    Ok(Some((url, Duration::from_secs(every))))
}

/// Pushes the metrics to the Pushgateway at `url` every `every`, for the life of the gateway. PUT replaces the
/// group's metrics, as the Pushgateway documents, so a restarted gateway leaves nothing stale.
pub(crate) async fn push(state: std::sync::Weak<AppState>, url: String, every: Duration) {
    let mut tick = tokio::time::interval(every);
    let mut last_complaint: Option<std::time::Instant> = None;
    loop {
        tick.tick().await;
        let Some(state) = state.upgrade() else {
            return;
        };
        let budgets = budgets(&state).await;
        let text = state.metrics.render(&state, &budgets);
        let sent = async {
            let request = axum::http::Request::put(&url)
                .header(header::CONTENT_TYPE, "text/plain; version=0.0.4")
                .body(axum::body::Body::from(text))
                .map_err(|err| err.to_string())?;
            let response =
                tokio::time::timeout(Duration::from_secs(5), state.client.request(request))
                    .await
                    .map_err(|_| "no answer in 5 seconds".to_string())?
                    .map_err(|err| err.to_string())?;
            if response.status().is_success() {
                Ok(())
            } else {
                Err(format!("it answered {}", response.status()))
            }
        };
        let outcome: Result<(), String> = sent.await;
        // Once a minute at most, so a Pushgateway that is down does not fill the log.
        if let Err(err) = outcome
            && last_complaint.is_none_or(|at| at.elapsed() >= Duration::from_secs(60))
        {
            last_complaint = Some(std::time::Instant::now());
            eprintln!(
                "gantry: could not push metrics to the Pushgateway: {err}. Check GANTRY_METRICS_PUSH_URL; the next push is in {} seconds.",
                every.as_secs()
            );
        }
    }
}

pub(crate) async fn serve(State(state): State<AppState>) -> Response {
    let budgets = budgets(&state).await;
    let text = state.metrics.render(&state, &budgets);
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        text,
    )
        .into_response()
}

/// A dollar sum without the float noise of adding many small prices (0.000026549999999999998). Nine places is a
/// thousandth of a micro-dollar, below any price a provider charges.
fn usd_text(usd: f64) -> String {
    let text = format!("{usd:.9}");
    text.trim_end_matches('0').trim_end_matches('.').to_string()
}

#[cfg(test)]
mod tests {
    #[test]
    fn spend_prints_without_float_noise() {
        assert_eq!(super::usd_text(0.000_026_549_999_999_999_998), "0.00002655");
        assert_eq!(super::usd_text(0.001), "0.001");
        assert_eq!(super::usd_text(12.0), "12");
        assert_eq!(super::usd_text(0.0), "0");
    }

    #[test]
    fn dimension_values_are_capped_and_cleaned() {
        assert_eq!(
            super::dimension_names(Some("Env, app ,bad name,")),
            ["env", "app"]
        );
        assert!(super::dimension_names(None).is_empty());
        let metrics = super::Metrics::default();
        let names = ["env".to_string()];
        let with = |value: &str| {
            let mut headers = axum::http::HeaderMap::new();
            if let Ok(value) = axum::http::HeaderValue::from_str(value) {
                headers.insert("x-gantry-dim-env", value);
            }
            headers
        };
        metrics.dimensioned_as(&names, &with("prod"), false);
        metrics.dimensioned_as(&names, &with("prod"), true);
        metrics.dimensioned_as(&names, &with("a b\"c"), false);
        for n in 0..super::MAX_DIMENSION_VALUES + 5 {
            metrics.dimensioned_as(&names, &with(&format!("v{n}")), false);
        }
        metrics.dimensioned_as(&names, &axum::http::HeaderMap::new(), false);
        let counted = super::locked(&metrics.dimensions);
        let get = |value: &str, verdict| {
            counted
                .get(&("env".to_string(), value.to_string(), verdict))
                .copied()
        };
        assert_eq!(get("prod", "allow"), Some(1));
        assert_eq!(get("prod", "refused"), Some(1));
        // The unclean value and every value past the cap are counted as other.
        assert_eq!(get("other", "allow"), Some(1 + 5 + 2));
        let values: std::collections::BTreeSet<_> =
            counted.keys().map(|(_, v, _)| v.clone()).collect();
        assert!(values.len() <= super::MAX_DIMENSION_VALUES + 1);
    }

    #[test]
    fn the_pushgateway_address_is_checked() {
        let none = super::push_target(|_| None);
        assert!(matches!(none, Ok(None)));
        let set = super::push_target(|name| {
            (name == "GANTRY_METRICS_PUSH_URL")
                .then(|| "http://pg:9091/metrics/job/gantry".to_string())
        });
        assert!(matches!(set, Ok(Some((_, every))) if every.as_secs() == 15));
        assert!(super::push_target(|_| Some("ftp://x".into())).is_err());
    }

    #[test]
    fn budget_gauges_leave_out_people_unless_asked() {
        let default = super::budget_scopes(None);
        assert!(default.contains(&"team".to_string()));
        assert!(!default.contains(&"person".to_string()) && !default.contains(&"key".to_string()));
        assert_eq!(
            super::budget_scopes(Some("Team, person")),
            ["team", "person"]
        );
        assert!(super::budget_scopes(Some("none")).is_empty());
    }
}
