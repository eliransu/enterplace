//! OpenTelemetry traces: one span per request, exported over OTLP/HTTP with JSON.
//!
//! The span joins the caller's trace when the request carries a W3C `traceparent`, and the provider gets a
//! `traceparent` naming Gantry's span, so a trace runs caller, Gantry, provider. The span's attributes come from
//! the audit records the request writes (decision, then usage), so a trace says what the audit log says and
//! nothing more: no prompt, no answer, no key, no person's name.
//!
//! Configured with the standard variables: `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` (or `OTEL_EXPORTER_OTLP_ENDPOINT`
//! plus `/v1/traces`), `OTEL_EXPORTER_OTLP_HEADERS` and `OTEL_SERVICE_NAME`. Export never slows a request: spans
//! queue in memory, go out once a second, and are dropped (and counted) when the collector cannot keep up.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    body::Body,
    http::{HeaderName, HeaderValue, Method, Request, header},
};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use serde_json::{Map, Value, json};

/// A request's span is finished by its usage record. One that never gets one (an upstream that failed, a route
/// with no usage) is finished this long after its answer, ending when the answer was sent.
// ponytail: a stream that runs longer than this is cut at its first byte; raise it if traces of long agent
// streams matter more than memory.
const UNFINISHED: Duration = Duration::from_secs(300);
/// Most spans held open or waiting for export. Past it, new requests are not traced and the drop is counted.
const MAX_HELD: usize = 50_000;
const BATCH: usize = 1_000;

/// Where traces go.
#[derive(Clone, Debug)]
pub struct TraceExport {
    pub endpoint: String,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub service: String,
}

impl TraceExport {
    /// From the OpenTelemetry environment variables, read through `get`. `None` when no endpoint is set.
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, String> {
        let endpoint = match (
            get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"),
            get("OTEL_EXPORTER_OTLP_ENDPOINT"),
        ) {
            (Some(full), _) if !full.trim().is_empty() => full.trim().to_string(),
            (_, Some(base)) if !base.trim().is_empty() => {
                format!("{}/v1/traces", base.trim().trim_end_matches('/'))
            }
            _ => return Ok(None),
        };
        for name in [
            "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
            "OTEL_EXPORTER_OTLP_PROTOCOL",
        ] {
            if let Some(protocol) = get(name) {
                if protocol.trim() != "http/json" {
                    return Err(format!(
                        "{name} is {protocol}, and Gantry exports traces as http/json only. Set {name}=http/json, or unset it."
                    ));
                }
                break;
            }
        }
        if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
            return Err(format!(
                "the trace endpoint {endpoint} is not an http or https URL. Set OTEL_EXPORTER_OTLP_ENDPOINT to the collector, such as http://otel-collector:4318."
            ));
        }
        let mut headers = Vec::new();
        for pair in get("OTEL_EXPORTER_OTLP_HEADERS")
            .unwrap_or_default()
            .split(',')
            .filter(|p| !p.trim().is_empty())
        {
            let (name, value) = pair.split_once('=').ok_or_else(|| {
                "OTEL_EXPORTER_OTLP_HEADERS is name=value pairs separated by commas, such as authorization=Bearer%20abc."
                    .to_string()
            })?;
            let value = percent_decode(value.trim());
            let bad = || {
                format!(
                    "OTEL_EXPORTER_OTLP_HEADERS has a header Gantry cannot send: {}",
                    name.trim()
                )
            };
            headers.push((
                HeaderName::try_from(name.trim()).map_err(|_| bad())?,
                HeaderValue::try_from(value).map_err(|_| bad())?,
            ));
        }
        let service = get("OTEL_SERVICE_NAME")
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "gantry".to_string());
        Ok(Some(Self {
            endpoint,
            headers,
            service,
        }))
    }
}

/// The spec writes header values percent-encoded, so a value can hold a comma or a space.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// The trace and parent span of a valid W3C `traceparent`, version 00.
fn parent(value: &HeaderValue) -> Option<(String, String)> {
    let text = value.to_str().ok()?;
    let mut parts = text.trim().split('-');
    let (version, trace, span, _flags) =
        (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    let hex = |s: &str, n: usize| {
        s.len() == n
            && s.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    };
    let zero = |s: &str| s.bytes().all(|b| b == b'0');
    (version == "00" && hex(trace, 32) && hex(span, 16) && !zero(trace) && !zero(span))
        .then(|| (trace.to_string(), span.to_string()))
}

#[derive(Debug)]
struct Open {
    trace: String,
    span: String,
    parent: Option<String>,
    name: String,
    start: u64,
    answered: Option<(u64, u16)>,
    attributes: Map<String, Value>,
}

/// The spans of requests in flight and those waiting to be sent.
#[derive(Debug)]
pub struct Tracer {
    export: TraceExport,
    open: Mutex<HashMap<String, Open>>,
    done: Mutex<Vec<Value>>,
    /// Spans not traced or not sent: the queue was full or the collector refused them.
    pub dropped: AtomicU64,
    /// Spans the collector accepted.
    pub sent: AtomicU64,
}

fn locked<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Tracer {
    pub fn new(export: TraceExport) -> Self {
        Self {
            export,
            open: Mutex::default(),
            done: Mutex::default(),
            dropped: AtomicU64::new(0),
            sent: AtomicU64::new(0),
        }
    }

    /// Starts the request's span. Returns the `traceparent` to send upstream, naming this span, or `None` when the
    /// request is not traced because too many spans are held.
    pub fn begin(
        &self,
        decision: &str,
        method: &Method,
        path: &str,
        incoming: Option<&HeaderValue>,
    ) -> Option<HeaderValue> {
        let (trace, parent) = match incoming.and_then(parent) {
            Some((trace, span)) => (trace, Some(span)),
            None => (gantry_core::id::random_hex(16), None),
        };
        let span = gantry_core::id::random_hex(8);
        let header = HeaderValue::from_str(&format!("00-{trace}-{span}-01")).ok()?;
        let mut open = locked(&self.open);
        if open.len() + locked(&self.done).len() >= MAX_HELD {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        open.insert(
            decision.to_string(),
            Open {
                trace,
                span,
                parent,
                name: format!("{method} {path}"),
                start: now_ns(),
                answered: None,
                attributes: Map::new(),
            },
        );
        Some(header)
    }

    /// The answer's head went to the caller.
    pub fn answered(&self, decision: &str, status: u16) {
        if let Some(open) = locked(&self.open).get_mut(decision) {
            open.answered = Some((now_ns(), status));
        }
    }

    /// Reads one audit record's fields (as the writer chains them) into its request's span.
    pub fn observe(&self, fields: &str) {
        let Ok(Value::Object(record)) = serde_json::from_str::<Value>(&format!("{{{fields}}}"))
        else {
            return;
        };
        let Some(id) = record.get("id").and_then(Value::as_str) else {
            return;
        };
        let mut open = locked(&self.open);
        let Some(span) = open.get_mut(id) else {
            return;
        };
        let copy = |span: &mut Open, from: &str, to: &str| {
            if let Some(v) = record.get(from).filter(|v| !v.is_null()) {
                span.attributes.insert(to.to_string(), v.clone());
            }
        };
        let finish = match record.get("event").and_then(Value::as_str) {
            None => {
                for (from, to) in [
                    ("verdict", "gantry.verdict"),
                    ("code", "gantry.code"),
                    ("rule", "gantry.rule"),
                    ("team", "gantry.team"),
                    ("model", "gen_ai.request.model"),
                    ("provider", "gantry.provider"),
                    ("cache", "gantry.cache"),
                ] {
                    copy(span, from, to);
                }
                span.attributes.insert("gantry.decision".into(), id.into());
                // A refusal writes no usage record: its decision is the whole story.
                record.get("verdict").and_then(Value::as_str) != Some("allow")
            }
            Some("usage") => {
                for (from, to) in [
                    ("input_tokens", "gen_ai.usage.input_tokens"),
                    ("output_tokens", "gen_ai.usage.output_tokens"),
                    ("charged_usd", "gantry.charged_usd"),
                    ("ended", "gantry.ended"),
                    ("status", "http.response.status_code"),
                ] {
                    copy(span, from, to);
                }
                true
            }
            Some("answer_guardrails") => {
                copy(span, "verdict", "gantry.answer_verdict");
                false
            }
            Some(_) => false,
        };
        if finish {
            if let Some(span) = open.remove(id) {
                drop(open);
                self.finish(span, now_ns());
            }
        }
    }

    fn finish(&self, span: Open, end: u64) {
        let mut attributes = span.attributes;
        if let Some((_, status)) = span.answered {
            attributes
                .entry("http.response.status_code")
                .or_insert_with(|| status.into());
        }
        let status = attributes
            .get("http.response.status_code")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let mut out = json!({
            "traceId": span.trace,
            "spanId": span.span,
            "name": span.name,
            "kind": 2,
            "startTimeUnixNano": span.start.to_string(),
            "endTimeUnixNano": end.max(span.start).to_string(),
            "attributes": attributes.into_iter().map(|(k, v)| json!({"key": k, "value": any(&v)})).collect::<Vec<_>>(),
            // A refusal is the policy working, not an error; a 5xx is.
            "status": { "code": if status >= 500 { 2 } else { 0 } },
        });
        if let Some(parent) = span.parent {
            out["parentSpanId"] = parent.into();
        }
        let mut done = locked(&self.done);
        if done.len() >= MAX_HELD {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        } else {
            done.push(out);
        }
    }

    /// Finishes spans whose answer went out long ago and whose usage never came. Returns the spans to send.
    fn take(&self, now: u64) -> Vec<Value> {
        let late = UNFINISHED.as_nanos() as u64;
        let stale: Vec<Open> = {
            let mut open = locked(&self.open);
            let ids: Vec<String> = open
                .iter()
                .filter(|(_, o)| match o.answered {
                    Some((at, _)) => now.saturating_sub(at) > late,
                    None => now.saturating_sub(o.start) > 2 * late,
                })
                .map(|(id, _)| id.clone())
                .collect();
            ids.iter().filter_map(|id| open.remove(id)).collect()
        };
        for span in stale {
            let end = span.answered.map_or(span.start, |(at, _)| at);
            self.finish(span, end);
        }
        let mut done = locked(&self.done);
        let n = done.len().min(BATCH);
        done.drain(..n).collect()
    }

    fn body(&self, spans: Vec<Value>) -> Value {
        json!({ "resourceSpans": [{
            "resource": { "attributes": [ { "key": "service.name", "value": { "stringValue": self.export.service } } ] },
            "scopeSpans": [{ "scope": { "name": "gantry", "version": gantry_core::VERSION }, "spans": spans }],
        }]})
    }

    /// Sends what is waiting, once a second, for the life of the process.
    pub async fn run(self: Arc<Self>, client: Client<HttpsConnector<HttpConnector>, Body>) {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let mut last_complaint = 0u64;
        loop {
            tick.tick().await;
            loop {
                let spans = self.take(now_ns());
                if spans.is_empty() {
                    break;
                }
                let n = spans.len() as u64;
                match self.send(&client, spans).await {
                    Ok(()) => {
                        self.sent.fetch_add(n, Ordering::Relaxed);
                    }
                    Err(err) => {
                        self.dropped.fetch_add(n, Ordering::Relaxed);
                        // Once a minute at most, so a collector that is down does not fill the log.
                        let now = now_ns() / 1_000_000_000;
                        if now >= last_complaint + 60 {
                            last_complaint = now;
                            eprintln!(
                                "gantry: could not send traces to {}: {err}. Spans are dropped until it answers; check the collector and OTEL_EXPORTER_OTLP_ENDPOINT.",
                                self.export.endpoint
                            );
                        }
                        break;
                    }
                }
            }
        }
    }

    async fn send(
        &self,
        client: &Client<HttpsConnector<HttpConnector>, Body>,
        spans: Vec<Value>,
    ) -> Result<(), String> {
        let mut request = Request::post(&self.export.endpoint)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(self.body(spans).to_string()))
            .map_err(|err| err.to_string())?;
        for (name, value) in &self.export.headers {
            request.headers_mut().insert(name.clone(), value.clone());
        }
        let response = tokio::time::timeout(Duration::from_secs(5), client.request(request))
            .await
            .map_err(|_| "no answer in 5 seconds".to_string())?
            .map_err(|err| err.to_string())?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("it answered {}", response.status()))
        }
    }
}

/// An attribute value in OTLP JSON form.
fn any(v: &Value) -> Value {
    match v {
        Value::Bool(b) => json!({ "boolValue": b }),
        Value::Number(n) if n.is_u64() || n.is_i64() => json!({ "intValue": n.to_string() }),
        Value::Number(n) => json!({ "doubleValue": n.as_f64().unwrap_or(0.0) }),
        Value::String(s) => json!({ "stringValue": s }),
        other => json!({ "stringValue": other.to_string() }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn export() -> TraceExport {
        TraceExport {
            endpoint: "http://127.0.0.1:1/v1/traces".into(),
            headers: vec![],
            service: "gantry".into(),
        }
    }

    #[test]
    fn the_standard_variables_configure_export_and_a_wrong_protocol_is_refused()
    -> Result<(), String> {
        let vars = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| v.to_string())
            }
        };
        assert!(TraceExport::from_env(vars(&[]))?.is_none());
        let e = TraceExport::from_env(vars(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel:4318/"),
            (
                "OTEL_EXPORTER_OTLP_HEADERS",
                "authorization=Bearer%20abc,x-team=ml",
            ),
        ]))?
        .ok_or("no export")?;
        assert_eq!(e.endpoint, "http://otel:4318/v1/traces");
        assert_eq!(e.headers.len(), 2);
        assert_eq!(e.headers[0].1, "Bearer abc");
        assert_eq!(e.service, "gantry");
        let full = TraceExport::from_env(vars(&[
            ("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "https://c/x"),
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://other"),
        ]))?
        .ok_or("no export")?;
        assert_eq!(full.endpoint, "https://c/x");
        let err = TraceExport::from_env(vars(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel:4318"),
            ("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc"),
        ]));
        assert!(err.is_err_and(|e| e.contains("http/json")));
        Ok(())
    }

    #[test]
    fn a_span_joins_the_callers_trace_and_takes_its_attributes_from_the_records()
    -> Result<(), String> {
        let t = Tracer::new(export());
        let incoming =
            HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");
        let out = t
            .begin("D1", &Method::POST, "/v1/chat/completions", Some(&incoming))
            .ok_or("not traced")?;
        let out = out.to_str().map_err(|e| e.to_string())?.to_string();
        assert!(out.starts_with("00-4bf92f3577b34da6a3ce929d0e0e4736-"));
        assert!(
            !out.contains("00f067aa0ba902b7"),
            "the provider gets Gantry's span as its parent"
        );
        t.observe(r#""id":"D1","time":"t","person":"maya@example.com","team":"payments","model":"gpt-4o","verdict":"allow","rule":"r","provider":"openai""#);
        t.answered("D1", 200);
        assert!(
            t.take(now_ns()).is_empty(),
            "an allowed request waits for its usage record"
        );
        t.observe(r#""event":"usage","id":"D1","input_tokens":12,"output_tokens":5,"status":200,"ended":"complete""#);
        let spans = t.take(now_ns());
        assert_eq!(spans.len(), 1);
        let s = &spans[0];
        assert_eq!(s["traceId"], "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(s["parentSpanId"], "00f067aa0ba902b7");
        assert_eq!(s["name"], "POST /v1/chat/completions");
        let text = s.to_string();
        assert!(
            text.contains("gen_ai.usage.input_tokens")
                && text.contains("\"12\"")
                && text.contains("payments")
        );
        assert!(
            !text.contains("maya@example.com"),
            "no person's name leaves in a trace"
        );
        Ok(())
    }

    #[test]
    fn a_refusal_ends_the_span_and_a_bad_traceparent_starts_a_new_trace() -> Result<(), String> {
        let t = Tracer::new(export());
        let bad =
            HeaderValue::from_static("00-00000000000000000000000000000000-00f067aa0ba902b7-01");
        let out = t
            .begin("D2", &Method::POST, "/v1/messages", Some(&bad))
            .ok_or("not traced")?;
        assert!(
            !out.to_str()
                .map_err(|e| e.to_string())?
                .contains("00000000000000000000000000000000")
        );
        t.observe(r#""id":"D2","verdict":"refused","code":"model_not_allowed""#);
        let spans = t.take(now_ns());
        assert_eq!(spans.len(), 1);
        assert!(spans[0].get("parentSpanId").is_none());
        assert!(spans[0].to_string().contains("model_not_allowed"));
        Ok(())
    }

    #[test]
    fn a_span_with_no_usage_is_finished_at_its_answer_after_a_while() -> Result<(), String> {
        let t = Tracer::new(export());
        t.begin("D3", &Method::GET, "/v1/models", None)
            .ok_or("not traced")?;
        t.observe(r#""id":"D3","verdict":"allow""#);
        t.answered("D3", 502);
        assert!(t.take(now_ns()).is_empty());
        let spans = t.take(now_ns() + UNFINISHED.as_nanos() as u64 + 1);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0]["status"]["code"], 2, "a 5xx is an error");
        Ok(())
    }
}
