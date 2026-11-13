//! Aliases: one model name a caller sends, served by several deployments (a provider and a model there), picked in
//! turn by weight or by the fewest requests in flight, with a deployment that failed passed over for a while.
//! Also the two body edits routing needs: the model of a JSON body, and the model field of a multipart form.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use axum::body::Bytes;
use gantry_core::config::{Alias, Balance};

/// What Gantry remembers about each deployment and alias. One per server, kept across reloads.
#[derive(Default)]
pub(crate) struct Pool {
    deployments: Mutex<HashMap<String, Deployed>>,
    turns: Mutex<HashMap<String, u64>>,
    /// With a store, a deployment that fails here is passed over by every gateway, and one that failed on another
    /// gateway is passed over here.
    store: Option<Arc<dyn gantry_core::store::Store>>,
}

/// A deployment's circuit: closed (no failure since the last answer), open (cooling down), or half open (the
/// cooldown is over and one request is out probing it).
#[derive(Default)]
struct Deployed {
    cool_until: Option<Instant>,
    busy: Arc<AtomicUsize>,
    /// Failures since the last answer: each doubles the next cooldown, up to `MAX_BACKOFF` times the base.
    failures: u32,
    /// When the probe of a half-open deployment was let through. Another is let through a base cooldown later, so
    /// a probe that never reports back (its request went elsewhere, or the caller left) cannot shut it out.
    probe_since: Option<Instant>,
    base: Duration,
}

/// How many times the base cooldown a deployment that keeps failing waits at most.
const MAX_BACKOFF: u32 = 16;

/// The name a deployment is remembered and recorded by.
pub(crate) fn label(provider: &str, model: &str) -> String {
    format!("{provider}/{model}")
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // Each update leaves its map whole, so a poisoned lock still holds sound state.
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Held while a request is at a deployment, so `least_busy` sees it. Dropped with the answer's body.
pub(crate) struct Busy(Arc<AtomicUsize>);

impl Drop for Busy {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Pool {
    pub(crate) fn new(store: Option<Arc<dyn gantry_core::store::Store>>) -> Self {
        Pool {
            store,
            ..Pool::default()
        }
    }

    /// The order to try `alias`'s deployments in: `eligible` holds the positions of those that can take this request.
    /// The balance picks the first; the rest follow in the alias's order. Deployments cooling down go last, so a
    /// request still goes somewhere when all have failed lately.
    pub(crate) fn order(&self, alias: &Alias, eligible: &[usize], now: Instant) -> Vec<usize> {
        let shared = self.store.as_ref().map(|store| store.cooling());
        let mut deployments = locked(&self.deployments);
        // One half-open deployment at most is probed by this request, and it is tried first.
        let mut probe = None;
        let mut cooling = |i: &usize| {
            let Some(d) = alias.deployments.get(*i) else {
                return false;
            };
            let name = label(&d.provider, &d.model);
            // Cooling down after a failure on another gateway. Its circuit here is closed, so once that is over
            // it is used as before, not probed: the gateway it failed on probes it.
            if shared
                .as_ref()
                .and_then(|shared| shared.get(&name))
                .is_some_and(|until| *until > now)
            {
                return true;
            }
            let Some(s) = deployments.get_mut(&name) else {
                return false;
            };
            match s.cool_until {
                None => false,
                Some(until) if until > now => true,
                Some(_) => {
                    let free = s.probe_since.is_none_or(|at| now >= at + s.base);
                    if free && probe.is_none() {
                        s.probe_since = Some(now);
                        probe = Some(*i);
                        false
                    } else {
                        true
                    }
                }
            }
        };
        let (mut warm, cold): (Vec<usize>, Vec<usize>) =
            eligible.iter().copied().partition(|i| !cooling(i));
        if let Some(probe) = probe {
            warm.retain(|i| *i != probe);
            warm.extend(cold);
            warm.insert(0, probe);
            return warm;
        }
        if let Some(first) = match alias.balance {
            Balance::RoundRobin => {
                let total: u64 = warm
                    .iter()
                    .filter_map(|i| alias.deployments.get(*i))
                    .map(|d| u64::from(d.weight))
                    .sum();
                let mut turns = locked(&self.turns);
                let turn = turns.entry(alias.name.clone()).or_default();
                let mut at = *turn % total.max(1);
                *turn = turn.wrapping_add(1);
                warm.iter().position(|i| {
                    let weight = alias.deployments.get(*i).map_or(0, |d| u64::from(d.weight));
                    if at < weight {
                        return true;
                    }
                    at -= weight;
                    false
                })
            }
            Balance::LeastBusy => warm
                .iter()
                .enumerate()
                .min_by_key(|(_, i)| {
                    alias.deployments.get(**i).map_or(usize::MAX, |d| {
                        deployments
                            .get(&label(&d.provider, &d.model))
                            .map_or(0, |s| s.busy.load(Ordering::Relaxed))
                    })
                })
                .map(|(at, _)| at),
        } {
            let picked = warm.remove(first);
            warm.insert(0, picked);
        }
        warm.extend(cold);
        warm
    }

    /// Counts a request in flight at a deployment until the returned guard is dropped.
    pub(crate) fn busy(&self, deployment: &str) -> Busy {
        let mut deployments = locked(&self.deployments);
        let busy = deployments
            .entry(deployment.to_string())
            .or_default()
            .busy
            .clone();
        busy.fetch_add(1, Ordering::Relaxed);
        Busy(busy)
    }

    /// A deployment failed (no answer, a 429 or a 5xx): it is passed over for `cooldown`.
    pub(crate) fn failed(&self, deployment: &str, cooldown: Duration) {
        let mut deployments = locked(&self.deployments);
        let state = deployments.entry(deployment.to_string()).or_default();
        state.failures = state.failures.saturating_add(1);
        let factor = 1u32
            .checked_shl(state.failures - 1)
            .unwrap_or(MAX_BACKOFF)
            .min(MAX_BACKOFF);
        state.base = cooldown;
        state.cool_until = Some(Instant::now() + cooldown * factor);
        state.probe_since = None;
        if let Some(store) = &self.store {
            store.cooled(deployment, cooldown * factor);
        }
    }

    /// A deployment answered: its circuit closes and its backoff starts over.
    pub(crate) fn answered(&self, deployment: &str) {
        if let Some(state) = locked(&self.deployments).get_mut(deployment) {
            state.cool_until = None;
            state.failures = 0;
            state.probe_since = None;
        }
        // Writes only when the deployment is cooling down on the store's list, so a normal answer costs nothing.
        if let Some(store) = &self.store {
            store.warmed(deployment);
        }
    }
}

/// The boundary of a `multipart/form-data` content type. A second boundary parameter is refused: parsers differ on
/// which one they use.
fn boundary(content_type: &str) -> Option<&str> {
    let (kind, params) = content_type.split_once(';')?;
    if !kind.trim().eq_ignore_ascii_case("multipart/form-data") {
        return None;
    }
    let mut found = params.split(';').filter_map(|param| {
        let (name, value) = param.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("boundary")
            .then(|| value.trim().trim_matches('"'))
    });
    let one = found.next().filter(|b| !b.is_empty())?;
    found.next().is_none().then_some(one)
}

/// One field of a form: its name, whether it is a file, and where its value is in the body.
pub(crate) struct Part {
    pub(crate) name: String,
    pub(crate) file: bool,
    pub(crate) value: std::ops::Range<usize>,
}

/// Why a form is refused: anything a standard parser could read differently from Gantry.
const NOT_PLAIN: &str = "a form part's Content-Disposition is not plain (only name=\"...\" and filename=\"...\" without escapes, extended name*= parameters or spaces around =)";

/// The `name` and whether there is a `filename` of a part's Content-Disposition value. QA14-4: parsed with quoted
/// strings, and anything that is not plain is refused rather than read one way of several.
fn disposition(value: &str) -> Result<(String, bool), &'static str> {
    let rest = value.trim_start_matches([' ', '\t']);
    let kind_end = rest.find(';').unwrap_or(rest.len());
    if !rest[..kind_end]
        .trim_end()
        .eq_ignore_ascii_case("form-data")
    {
        return Err("a form part's Content-Disposition is not form-data");
    }
    let mut rest = &rest[kind_end..];
    let (mut name, mut file, mut seen) = (None, false, Vec::new());
    loop {
        rest = rest.trim_start_matches([' ', '\t']);
        if rest.is_empty() {
            break;
        }
        rest = rest.strip_prefix(';').ok_or(NOT_PLAIN)?;
        rest = rest.trim_start_matches([' ', '\t']);
        let eq = rest.find('=').ok_or(NOT_PLAIN)?;
        let key = rest[..eq].to_ascii_lowercase();
        if key.is_empty()
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(NOT_PLAIN);
        }
        rest = &rest[eq + 1..];
        let value = if let Some(quoted) = rest.strip_prefix('"') {
            let end = quoted.find('"').ok_or(NOT_PLAIN)?;
            rest = &quoted[end + 1..];
            &quoted[..end]
        } else {
            let end = rest.find([';', ' ', '\t']).unwrap_or(rest.len());
            let token = &rest[..end];
            rest = &rest[end..];
            if token.is_empty() || token.contains(['\'', '"']) {
                return Err(NOT_PLAIN);
            }
            token
        };
        if value.contains('\\') || seen.contains(&key) {
            return Err(NOT_PLAIN);
        }
        match key.as_str() {
            "name" => name = Some(value.to_string()),
            "filename" => file = true,
            _ => {}
        }
        seen.push(key);
    }
    Ok((name.ok_or("a form part has no name")?, file))
}

/// Every field of a `multipart/form-data` body, parsed strictly: the body starts with its delimiter, every other
/// delimiter starts a line and is followed by a line end or the closing `--`, each part has one plain
/// Content-Disposition, and nothing follows the closing delimiter but a line end.
pub(crate) fn form_parts(content_type: &str, body: &[u8]) -> Result<Vec<Part>, &'static str> {
    let boundary =
        boundary(content_type).ok_or("the body is not multipart/form-data with one boundary")?;
    let open = format!("--{boundary}");
    let inner = format!("\r\n--{boundary}");
    let find = |from: usize, needle: &[u8]| {
        body.get(from..)?
            .windows(needle.len())
            .position(|w| w == needle)
            .map(|p| p + from)
    };
    if !body.starts_with(open.as_bytes()) {
        return Err("the form does not start with its boundary");
    }
    let mut at = open.len();
    let mut parts = Vec::new();
    loop {
        let rest = &body[at..];
        if let Some(after) = rest.strip_prefix(b"--") {
            if !matches!(after, b"" | b"\r\n") {
                return Err("the form has bytes after its closing boundary");
            }
            return Ok(parts);
        }
        if !rest.starts_with(b"\r\n") {
            return Err("a form boundary is followed by something other than a line end");
        }
        let headers_end = find(at, b"\r\n\r\n").ok_or("a form part has no end to its headers")?;
        let headers = std::str::from_utf8(body.get(at + 2..headers_end).unwrap_or_default())
            .map_err(|_| "a form part's headers are not UTF-8")?;
        let mut named = None;
        for line in headers.split("\r\n") {
            let (header, value) = line
                .split_once(':')
                .ok_or("a form part has a header line without a colon")?;
            // A folded line, or a name with spaces, is read differently by different parsers.
            if header.is_empty() || header.trim() != header {
                return Err("a form part has a folded or spaced header line");
            }
            if header.eq_ignore_ascii_case("content-disposition")
                && named.replace(disposition(value)?).is_some()
            {
                return Err("a form part has two Content-Disposition headers");
            }
        }
        let (name, file) = named.ok_or("a form part has no Content-Disposition")?;
        let value_start = headers_end + 4;
        let next = find(value_start, inner.as_bytes()).ok_or("a form part does not end")?;
        parts.push(Part {
            name,
            file,
            value: value_start..next,
        });
        at = next + inner.len();
    }
}

/// The byte range of the value of the one form field named `model`, or why there is none. Two fields named `model`
/// are refused: the policy would check one and the provider could read the other.
pub(crate) fn multipart_model(
    content_type: &str,
    body: &[u8],
) -> Result<std::ops::Range<usize>, &'static str> {
    let mut models = form_parts(content_type, body)?
        .into_iter()
        .filter(|p| p.name == "model");
    let model = models.next().ok_or("the form has no model field")?;
    if models.next().is_some() {
        return Err("the form names model twice");
    }
    if model.file {
        return Err("the model field is a file");
    }
    Ok(model.value)
}

/// The body with its model replaced by `model`: a JSON body's `model` key, or a form's `model` field. A body that
/// is neither is sent as it is.
pub(crate) fn with_model(content_type: Option<&str>, body: &Bytes, model: &str) -> Bytes {
    if let Some(range) = content_type.and_then(|ct| multipart_model(ct, body).ok()) {
        let mut out = Vec::with_capacity(body.len() + model.len());
        out.extend_from_slice(&body[..range.start]);
        out.extend_from_slice(model.as_bytes());
        out.extend_from_slice(&body[range.end..]);
        return Bytes::from(out);
    }
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(serde_json::Value::Object(mut map)) if map.contains_key("model") => {
            map.insert("model".into(), model.into());
            serde_json::to_vec(&map).map_or_else(|_| body.clone(), Bytes::from)
        }
        _ => body.clone(),
    }
}

/// Why the provider refused a request, as far as a named fallback goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    ContextWindow,
    ContentPolicy,
}

/// Reads a provider's error answer for the two refusals a named fallback can take. OpenAI and Azure name them in
/// `error.code`; Anthropic says "prompt is too long" in an invalid_request_error.
pub(crate) fn refused(body: &[u8]) -> Option<Refused> {
    let answer: serde_json::Value = serde_json::from_slice(body).ok()?;
    let error = &answer["error"];
    let code = error["code"].as_str().unwrap_or_default();
    let kind = error["type"].as_str().unwrap_or_default();
    let message = error["message"]
        .as_str()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if code == "context_length_exceeded"
        || message.contains("maximum context length")
        || message.contains("prompt is too long")
        || message.contains("context window")
    {
        return Some(Refused::ContextWindow);
    }
    if matches!(code, "content_policy_violation" | "content_filter")
        || kind == "content_policy_violation"
        || message.contains("content management policy")
    {
        return Some(Refused::ContentPolicy);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use gantry_core::config::Deployment;

    fn alias(balance: Balance, weights: &[u32]) -> Alias {
        Alias {
            name: "smart".into(),
            deployments: weights
                .iter()
                .enumerate()
                .map(|(i, w)| Deployment {
                    provider: format!("p{i}"),
                    model: "m".into(),
                    weight: *w,
                })
                .collect(),
            balance,
            cooldown_seconds: 30,
            context_window_fallback: None,
            content_policy_fallback: None,
        }
    }

    #[test]
    fn round_robin_follows_the_weights_and_skips_a_cooling_deployment() {
        let pool = Pool::default();
        let smart = alias(Balance::RoundRobin, &[2, 1]);
        let now = Instant::now();
        let firsts: Vec<usize> = (0..6)
            .map(|_| pool.order(&smart, &[0, 1], now)[0])
            .collect();
        assert_eq!(firsts, [0, 0, 1, 0, 0, 1]);
        pool.failed("p0/m", Duration::from_secs(30));
        assert_eq!(pool.order(&smart, &[0, 1], Instant::now()), [1, 0]);
        pool.answered("p0/m");
        assert_eq!(pool.order(&smart, &[0, 1], Instant::now()).len(), 2);
    }

    #[test]
    fn a_deployment_that_keeps_failing_waits_longer_and_comes_back_through_one_probe() {
        let pool = Pool::default();
        let smart = alias(Balance::RoundRobin, &[1, 1, 1]);
        let base = Duration::from_secs(10);
        let start = Instant::now();
        pool.failed("p0/m", base);
        let cold = |at: Instant| pool.order(&smart, &[0, 1, 2], at).last().copied();
        assert_eq!(
            cold(start + Duration::from_secs(5)),
            Some(0),
            "open: tried last"
        );
        // Half open: once the cooldown is over, one request probes it first; the others still pass it over.
        let probe = pool.order(&smart, &[0, 1, 2], start + Duration::from_secs(11));
        assert_eq!(
            probe[0], 0,
            "the probe goes to the recovering deployment first"
        );
        for _ in 0..3 {
            assert_eq!(
                cold(start + Duration::from_secs(11)),
                Some(0),
                "while one probe is out, others pass it over"
            );
        }
        // The probe failed: open again, for twice as long.
        pool.failed("p0/m", base);
        let again = Instant::now();
        assert_eq!(
            cold(again + Duration::from_secs(15)),
            Some(0),
            "the second cooldown is 20 seconds"
        );
        assert_eq!(
            pool.order(&smart, &[0, 1, 2], again + Duration::from_secs(21))[0],
            0,
            "then one probe"
        );
        for _ in 0..10 {
            pool.failed("p0/m", base);
        }
        let capped = Instant::now();
        assert_eq!(
            pool.order(&smart, &[0, 1, 2], capped + Duration::from_secs(161))[0],
            0,
            "capped at 16 times the base"
        );
        // The probe answered: closed, in turn with the others again.
        pool.answered("p0/m");
        let firsts: Vec<usize> = (0..3)
            .map(|_| pool.order(&smart, &[0, 1, 2], Instant::now())[0])
            .collect();
        assert!(
            firsts.contains(&0) && firsts.contains(&1) && firsts.contains(&2),
            "{firsts:?}"
        );
        pool.failed("p0/m", base);
        assert_eq!(cold(Instant::now() + Duration::from_secs(5)), Some(0));
        assert!(
            pool.order(&smart, &[0, 1, 2], Instant::now() + Duration::from_secs(11))[0] == 0,
            "after a success the backoff starts over"
        );
    }

    #[test]
    fn a_probe_that_never_reports_back_does_not_shut_the_deployment_out() {
        let pool = Pool::default();
        let smart = alias(Balance::RoundRobin, &[1, 1]);
        let base = Duration::from_secs(10);
        pool.failed("p0/m", base);
        let after = Instant::now() + Duration::from_secs(11);
        assert_eq!(pool.order(&smart, &[0, 1], after)[0], 0);
        // That request went elsewhere or was dropped: after another base cooldown a new probe is let through.
        assert_eq!(
            pool.order(&smart, &[0, 1], after + Duration::from_secs(11))[0],
            0
        );
    }

    #[test]
    fn least_busy_picks_the_deployment_with_fewest_in_flight() {
        let pool = Pool::default();
        let smart = alias(Balance::LeastBusy, &[1, 1]);
        let held = pool.busy("p0/m");
        assert_eq!(pool.order(&smart, &[0, 1], Instant::now())[0], 1);
        drop(held);
        let _other = pool.busy("p1/m");
        assert_eq!(pool.order(&smart, &[0, 1], Instant::now())[0], 0);
    }

    #[test]
    fn the_model_field_of_a_form_is_found_once_and_replaced() {
        let ct = "multipart/form-data; boundary=XyZ";
        let body = b"--XyZ\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.wav\"\r\nContent-Type: audio/wav\r\n\r\nRIFF\x00\x01model\r\n--XyZ\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nwhisper\r\n--XyZ--\r\n";
        let range = multipart_model(ct, body);
        assert_eq!(range.clone().map(|r| &body[r]), Ok(&b"whisper"[..]));
        let swapped = with_model(Some(ct), &Bytes::from_static(body), "whisper-1");
        assert!(swapped.windows(14).any(|w| w == b"\r\n\r\nwhisper-1\r"));
        let twice = b"--b\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\na\r\n--b\r\nContent-Disposition: form-data; name=model\r\n\r\nb\r\n--b--\r\n";
        assert!(multipart_model("multipart/form-data; boundary=b", twice).is_err());
        assert!(multipart_model("application/json", body).is_err());
    }

    #[test]
    fn context_window_and_content_policy_refusals_are_told_apart() {
        assert_eq!(
            refused(br#"{"error":{"code":"context_length_exceeded","message":"x"}}"#),
            Some(Refused::ContextWindow)
        );
        assert_eq!(
            refused(br#"{"type":"error","error":{"type":"invalid_request_error","message":"prompt is too long: 300000 tokens > 200000 maximum"}}"#),
            Some(Refused::ContextWindow)
        );
        assert_eq!(
            refused(br#"{"error":{"code":"content_filter","message":"x"}}"#),
            Some(Refused::ContentPolicy)
        );
        assert_eq!(refused(br#"{"error":{"code":"invalid_api_key"}}"#), None);
    }
}
