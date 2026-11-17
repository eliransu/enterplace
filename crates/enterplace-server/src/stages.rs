//! Where a request's time went inside Enterplace, stage by stage.
//!
//! One `Stages` is filled as a request passes through: identifying the caller, reading the body, deciding by the
//! policy, the guardrails (each webhook, vendor or events guardrail by its name; the built-in detectors together as
//! `builtin`, since they share one scan), the cache and limits, the audit write, then connecting to the provider and
//! its first byte. The stream's time is added when the answer ends. The same numbers go three ways: the
//! `Server-Timing` header (what is known when the answer's head leaves), the `enterplace_stage_seconds` and
//! `enterplace_guardrail_seconds` histograms, and `stages_ms` on the usage record, which the request log shows.

use std::time::Duration;

use serde_json::{Map, Value};

/// The stages in the order a request passes them. The histogram and the usage record use these names.
pub(crate) const NAMES: [&str; 9] = [
    "auth",
    "read",
    "policy",
    "guardrails",
    "cache",
    "audit",
    "connect",
    "first_byte",
    "stream",
];

#[derive(Clone, Debug, Default)]
pub(crate) struct Stages {
    /// Identifying the caller: the key or JWT, kill switches, expiry.
    pub(crate) auth: Duration,
    /// Reading the request body off the socket. A slow client shows here, not under the policy.
    pub(crate) read: Duration,
    /// Deciding by the policy: the rule, the model, the route and where it goes.
    pub(crate) policy: Duration,
    /// Transforms, the tool check and every guardrail on the request.
    pub(crate) guardrails: Duration,
    /// The answer cache lookup with the rate limits and budget reservations made beside it.
    pub(crate) cache: Duration,
    /// Waiting for the decision record to be written.
    pub(crate) audit: Duration,
    /// Getting a connection to the provider that answered: near zero when one was reused.
    pub(crate) connect: Option<Duration>,
    /// From sending to the provider that answered to its answer's headers.
    pub(crate) first_byte: Option<Duration>,
    /// Each guardrail call by guardrail name, in the order made.
    pub(crate) calls: Vec<(String, Duration)>,
}

/// Milliseconds with microsecond precision, as a JSON number.
fn ms(took: Duration) -> Value {
    ((took.as_micros() as f64) / 1000.0).into()
}

impl Stages {
    /// The stages measured so far, in order, with `stream` when the answer has ended.
    pub(crate) fn entries(&self, stream: Option<Duration>) -> Vec<(&'static str, Duration)> {
        let mut out = vec![
            ("auth", self.auth),
            ("read", self.read),
            ("policy", self.policy),
            ("guardrails", self.guardrails),
            ("cache", self.cache),
            ("audit", self.audit),
        ];
        out.extend(self.connect.map(|d| ("connect", d)));
        out.extend(self.first_byte.map(|d| ("first_byte", d)));
        out.extend(stream.map(|d| ("stream", d)));
        out
    }

    /// `Server-Timing` entries, one per stage: `enterplace-auth;dur=0.021, enterplace-policy;dur=0.105`.
    pub(crate) fn server_timing(&self) -> String {
        self.entries(None)
            .iter()
            .map(|(name, took)| {
                format!(
                    "enterplace-{};dur={:.3}",
                    name.replace('_', "-"),
                    took.as_secs_f64() * 1000.0
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// `stages_ms` and, when a guardrail was called, `guardrail_ms`, for the usage record.
    pub(crate) fn record(&self, stream: Duration, record: &mut Map<String, Value>) {
        let stages: Map<String, Value> = self
            .entries(Some(stream))
            .into_iter()
            .map(|(name, took)| (name.to_string(), ms(took)))
            .collect();
        record.insert("stages_ms".into(), stages.into());
        if !self.calls.is_empty() {
            let mut calls = Map::new();
            for (name, took) in &self.calls {
                // A guardrail called twice (request and a retry) shows its total.
                let so_far = calls.get(name).and_then(Value::as_f64).unwrap_or(0.0);
                calls.insert(
                    name.clone(),
                    (so_far + (took.as_micros() as f64) / 1000.0).into(),
                );
            }
            record.insert("guardrail_ms".into(), calls.into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_and_the_record_name_each_stage_once() {
        let stages = Stages {
            auth: Duration::from_micros(21),
            policy: Duration::from_micros(105),
            first_byte: Some(Duration::from_millis(40)),
            calls: vec![
                ("lakera".into(), Duration::from_millis(3)),
                ("lakera".into(), Duration::from_millis(2)),
            ],
            ..Stages::default()
        };
        let header = stages.server_timing();
        assert!(header.starts_with(
            "enterplace-auth;dur=0.021, enterplace-read;dur=0.000, enterplace-policy;dur=0.105"
        ));
        assert!(
            header.ends_with("enterplace-first-byte;dur=40.000"),
            "{header}"
        );
        assert!(!header.contains("connect") && !header.contains("stream"));
        let mut record = Map::new();
        stages.record(Duration::from_millis(7), &mut record);
        assert_eq!(record["stages_ms"]["stream"], 7.0);
        assert_eq!(record["stages_ms"]["auth"], 0.021);
        assert_eq!(record["guardrail_ms"]["lakera"], 5.0);
        for (name, _) in stages.entries(Some(Duration::ZERO)) {
            assert!(NAMES.contains(&name));
        }
    }
}
