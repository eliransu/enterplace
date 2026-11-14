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

    fn render(&self, state: &AppState) -> String {
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
        out.push_str("# HELP gantry_deployment_up 1 when the last health probe of a deployment got an answer, 0 when it did not.\n# TYPE gantry_deployment_up gauge\n");
        for (deployment, probed) in state.pool.probes() {
            let _ = writeln!(
                out,
                "gantry_deployment_up{{deployment=\"{}\"}} {}",
                label(&deployment),
                u8::from(probed.up)
            );
        }
        out
    }
}

pub(crate) async fn serve(State(state): State<AppState>) -> Response {
    let text = state.metrics.render(&state);
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
}
