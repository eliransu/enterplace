//! OpenTelemetry traces: one span per request with a child span per attempt at a provider and per guardrail
//! call, exported over OTLP as HTTP with JSON, HTTP with protobuf, or gRPC.
//!
//! The request's span joins the caller's trace when the request carries a W3C `traceparent`, and the provider gets
//! a `traceparent` naming the span of the attempt that reached it, so a trace runs caller, Enterplace, attempt,
//! provider. `ENTERPLACE_TRACE_PROPAGATION` turns either side off. The request span's attributes come from the audit
//! records the request writes (decision, then usage), so a trace says what the audit log says and nothing more:
//! no prompt, no answer, no key, no person's name. Attempt spans follow the OpenTelemetry GenAI conventions for a
//! client span (`chat gpt-4o`, `gen_ai.operation.name`, `gen_ai.provider.name`, `gen_ai.request.model`).
//!
//! Configured with the standard variables: `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` (or `OTEL_EXPORTER_OTLP_ENDPOINT`
//! plus `/v1/traces` for HTTP), `OTEL_EXPORTER_OTLP_PROTOCOL` (`http/json`, the default, `http/protobuf` or
//! `grpc`), `OTEL_EXPORTER_OTLP_HEADERS` and `OTEL_SERVICE_NAME`. The protobuf is written by hand (a dozen fields
//! of the trace schema), so no protobuf or gRPC library is in the build. Export never slows a request: spans queue
//! in memory, go out once a second, and are dropped (and counted) when the collector cannot keep up.

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

/// How spans are written to the collector.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TraceProtocol {
    /// OTLP/HTTP with a JSON body.
    #[default]
    HttpJson,
    /// OTLP/HTTP with a protobuf body.
    HttpProtobuf,
    /// OTLP/gRPC: HTTP/2, in the clear for an `http://` endpoint and over TLS for `https://`.
    Grpc,
}

/// Where traces go.
#[derive(Clone, Debug)]
pub struct TraceExport {
    pub endpoint: String,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub service: String,
    pub protocol: TraceProtocol,
    /// Join the trace a caller's `traceparent` names. Off, every request starts a trace of its own.
    pub join_caller: bool,
    /// Send a `traceparent` naming Enterplace's span to the provider. Off, the provider gets none, the caller's
    /// included.
    pub to_provider: bool,
}

impl Default for TraceExport {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            headers: Vec::new(),
            service: "enterplace".into(),
            protocol: TraceProtocol::HttpJson,
            join_caller: true,
            to_provider: true,
        }
    }
}

/// The gRPC method of the OTLP trace service.
const GRPC_EXPORT: &str = "/opentelemetry.proto.collector.trace.v1.TraceService/Export";

impl TraceExport {
    /// From the OpenTelemetry environment variables, read through `get`. `None` when no endpoint is set.
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, String> {
        let mut protocol = TraceProtocol::HttpJson;
        for name in [
            "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
            "OTEL_EXPORTER_OTLP_PROTOCOL",
        ] {
            if let Some(word) = get(name).filter(|w| !w.trim().is_empty()) {
                protocol = match word.trim() {
                    "http/json" => TraceProtocol::HttpJson,
                    "http/protobuf" => TraceProtocol::HttpProtobuf,
                    "grpc" => TraceProtocol::Grpc,
                    other => {
                        return Err(format!(
                            "{name} is {other}, and Enterplace exports traces as http/json, http/protobuf or grpc. Set {name} to one of them, or unset it for http/json."
                        ));
                    }
                };
                break;
            }
        }
        let grpc = protocol == TraceProtocol::Grpc;
        let endpoint = match (
            get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"),
            get("OTEL_EXPORTER_OTLP_ENDPOINT"),
        ) {
            // gRPC names the service in its own path: the endpoint is the collector's address alone.
            (Some(full), _) if !full.trim().is_empty() && grpc => {
                format!("{}{GRPC_EXPORT}", full.trim().trim_end_matches('/'))
            }
            (Some(full), _) if !full.trim().is_empty() => full.trim().to_string(),
            (_, Some(base)) if !base.trim().is_empty() => format!(
                "{}{}",
                base.trim().trim_end_matches('/'),
                if grpc { GRPC_EXPORT } else { "/v1/traces" }
            ),
            _ => return Ok(None),
        };
        let (mut join_caller, mut to_provider) = (true, true);
        if let Some(words) = get("ENTERPLACE_TRACE_PROPAGATION").filter(|w| !w.trim().is_empty()) {
            (join_caller, to_provider) = (false, false);
            for word in words.split(',').map(str::trim) {
                match word {
                    "caller" => join_caller = true,
                    "provider" => to_provider = true,
                    "none" => {}
                    other => {
                        return Err(format!(
                            "ENTERPLACE_TRACE_PROPAGATION is \"{other}\". Set it to caller (join the caller's trace), provider (send traceparent to the provider), caller,provider (the default) or none."
                        ));
                    }
                }
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
                    "OTEL_EXPORTER_OTLP_HEADERS has a header Enterplace cannot send: {}",
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
            .unwrap_or_else(|| "enterplace".to_string());
        Ok(Some(Self {
            endpoint,
            headers,
            service,
            protocol,
            join_caller,
            to_provider,
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

pub(crate) fn now_ns() -> u64 {
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

/// A request's span stays findable this long after it ends, for a child that ends after it (a guardrail on the
/// answer).
const CLOSED_FOR_NS: u64 = 60_000_000_000;

/// The GenAI operation a route is, by the OpenTelemetry GenAI conventions' names. `None` for a route that is not
/// a model call.
pub(crate) fn operation(path: &str) -> Option<&'static str> {
    match path {
        crate::CHAT | crate::MESSAGES | crate::RESPONSES => Some("chat"),
        crate::EMBEDDINGS => Some("embeddings"),
        crate::COMPLETIONS => Some("text_completion"),
        _ if path.ends_with(":generateContent") || path.ends_with(":streamGenerateContent") => {
            Some("generate_content")
        }
        _ => None,
    }
}

/// The spans of requests in flight and those waiting to be sent.
#[derive(Debug)]
pub struct Tracer {
    export: TraceExport,
    open: Mutex<HashMap<String, Open>>,
    /// The trace and span of requests that ended a moment ago, and when, by decision.
    closed: Mutex<HashMap<String, (String, String, u64)>>,
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
            closed: Mutex::default(),
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
        let (trace, parent) = match incoming
            .filter(|_| self.export.join_caller)
            .and_then(parent)
        {
            Some((trace, span)) => (trace, Some(span)),
            None => (enterplace_core::id::random_hex(16), None),
        };
        let span = enterplace_core::id::random_hex(8);
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
                attributes: operation(path)
                    .map(|op| ("gen_ai.operation.name".to_string(), Value::from(op)))
                    .into_iter()
                    .collect(),
            },
        );
        Some(header)
    }

    /// Whether the provider is sent a `traceparent`.
    pub fn to_provider(&self) -> bool {
        self.export.to_provider
    }

    /// The trace and span of a request, in flight or just ended.
    fn ids(&self, decision: &str) -> Option<(String, String)> {
        if let Some(open) = locked(&self.open).get(decision) {
            return Some((open.trace.clone(), open.span.clone()));
        }
        locked(&self.closed)
            .get(decision)
            .map(|(trace, span, _)| (trace.clone(), span.clone()))
    }

    /// A child span of the request's that started at `start` and ends now: a guardrail or plugin call.
    pub fn child(&self, decision: &str, name: &str, start: u64, attributes: &[(&str, &str)]) {
        let attributes = attributes
            .iter()
            .map(|(k, v)| ((*k).to_string(), Value::from(*v)))
            .collect();
        self.push_child(decision, None, name, 1, start, attributes, false);
    }

    /// Starts the span of one attempt at a provider: its span ID and the `traceparent` that names it, for the
    /// provider. `None` when the request is not traced.
    pub fn attempt(&self, decision: &str) -> Option<(String, HeaderValue)> {
        let (trace, _) = self.ids(decision)?;
        let span = enterplace_core::id::random_hex(8);
        let header = HeaderValue::from_str(&format!("00-{trace}-{span}-01")).ok()?;
        Some((span, header))
    }

    /// Ends the span [`Tracer::attempt`] started: a client span named by the GenAI conventions.
    pub fn attempted(
        &self,
        decision: &str,
        span: String,
        name: &str,
        start: u64,
        attributes: Map<String, Value>,
        failed: bool,
    ) {
        self.push_child(decision, Some(span), name, 3, start, attributes, failed);
    }

    #[allow(clippy::too_many_arguments)]
    fn push_child(
        &self,
        decision: &str,
        span: Option<String>,
        name: &str,
        kind: u8,
        start: u64,
        attributes: Map<String, Value>,
        failed: bool,
    ) {
        let Some((trace, parent)) = self.ids(decision) else {
            return;
        };
        let out = json!({
            "traceId": trace,
            "spanId": span.unwrap_or_else(|| enterplace_core::id::random_hex(8)),
            "parentSpanId": parent,
            "name": name,
            "kind": kind,
            "startTimeUnixNano": start.to_string(),
            "endTimeUnixNano": now_ns().max(start).to_string(),
            "attributes": attributes.into_iter().map(|(k, v)| json!({"key": k, "value": any(&v)})).collect::<Vec<_>>(),
            "status": { "code": if failed { 2 } else { 0 } },
        });
        let mut done = locked(&self.done);
        if done.len() >= MAX_HELD {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        } else {
            done.push(out);
        }
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
                    ("verdict", "enterplace.verdict"),
                    ("code", "enterplace.code"),
                    ("rule", "enterplace.rule"),
                    ("team", "enterplace.team"),
                    ("model", "gen_ai.request.model"),
                    ("provider", "enterplace.provider"),
                    ("cache", "enterplace.cache"),
                    ("session", "gen_ai.conversation.id"),
                ] {
                    copy(span, from, to);
                }
                span.attributes
                    .insert("enterplace.decision".into(), id.into());
                // A refusal writes no usage record: its decision is the whole story.
                record.get("verdict").and_then(Value::as_str) != Some("allow")
            }
            Some("usage") => {
                for (from, to) in [
                    ("input_tokens", "gen_ai.usage.input_tokens"),
                    ("output_tokens", "gen_ai.usage.output_tokens"),
                    ("charged_usd", "enterplace.charged_usd"),
                    ("ended", "enterplace.ended"),
                    ("status", "http.response.status_code"),
                    ("model", "gen_ai.response.model"),
                ] {
                    copy(span, from, to);
                }
                true
            }
            Some("answer_guardrails") => {
                copy(span, "verdict", "enterplace.answer_verdict");
                false
            }
            Some(_) => false,
        };
        if finish {
            if let Some(span) = open.remove(id) {
                drop(open);
                self.finish(id, span, now_ns());
            }
        }
    }

    fn finish(&self, decision: &str, span: Open, end: u64) {
        locked(&self.closed).insert(
            decision.to_string(),
            (span.trace.clone(), span.span.clone(), now_ns()),
        );
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
        locked(&self.closed).retain(|_, (_, _, at)| now.saturating_sub(*at) < CLOSED_FOR_NS);
        let stale: Vec<(String, Open)> = {
            let mut open = locked(&self.open);
            let ids: Vec<String> = open
                .iter()
                .filter(|(_, o)| match o.answered {
                    Some((at, _)) => now.saturating_sub(at) > late,
                    None => now.saturating_sub(o.start) > 2 * late,
                })
                .map(|(id, _)| id.clone())
                .collect();
            ids.into_iter()
                .filter_map(|id| open.remove(&id).map(|span| (id, span)))
                .collect()
        };
        for (id, span) in stale {
            let end = span.answered.map_or(span.start, |(at, _)| at);
            self.finish(&id, span, end);
        }
        let mut done = locked(&self.done);
        let n = done.len().min(BATCH);
        done.drain(..n).collect()
    }

    fn body(&self, spans: Vec<Value>) -> Value {
        json!({ "resourceSpans": [{
            "resource": { "attributes": [ { "key": "service.name", "value": { "stringValue": self.export.service } } ] },
            "scopeSpans": [{ "scope": { "name": "enterplace", "version": enterplace_core::VERSION }, "spans": spans }],
        }]})
    }

    /// Sends what is waiting, once a second, for the life of the process.
    pub async fn run(self: Arc<Self>, client: Client<HttpsConnector<HttpConnector>, Body>) {
        // gRPC is HTTP/2 from the first byte, which the client to providers does not speak: one of its own.
        let client = if self.export.protocol == TraceProtocol::Grpc {
            let mut http = HttpConnector::new();
            http.set_connect_timeout(Some(Duration::from_secs(5)));
            http.enforce_http(false);
            crate::ring_default();
            let connector = hyper_rustls::HttpsConnectorBuilder::new()
                .with_webpki_roots()
                .https_or_http()
                .enable_http2()
                .wrap_connector(http);
            Client::builder(hyper_util::rt::TokioExecutor::new())
                .http2_only(true)
                .build(connector)
        } else {
            client
        };
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
                                "enterplace: could not send traces to {}: {err}. Spans are dropped until it answers; check the collector and OTEL_EXPORTER_OTLP_ENDPOINT.",
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
        let grpc = self.export.protocol == TraceProtocol::Grpc;
        let (content_type, body) = match self.export.protocol {
            TraceProtocol::HttpJson => (
                "application/json",
                self.body(spans).to_string().into_bytes(),
            ),
            TraceProtocol::HttpProtobuf => (
                "application/x-protobuf",
                proto::request(&self.export.service, &spans),
            ),
            TraceProtocol::Grpc => {
                let message = proto::request(&self.export.service, &spans);
                // A gRPC message: not compressed, then its length.
                let mut framed = vec![0u8];
                framed.extend(
                    u32::try_from(message.len())
                        .unwrap_or(u32::MAX)
                        .to_be_bytes(),
                );
                framed.extend(message);
                ("application/grpc", framed)
            }
        };
        let mut request = Request::post(&self.export.endpoint)
            .header(header::CONTENT_TYPE, content_type)
            .body(Body::from(body))
            .map_err(|err| err.to_string())?;
        if grpc {
            request
                .headers_mut()
                .insert(header::TE, HeaderValue::from_static("trailers"));
        }
        for (name, value) in &self.export.headers {
            request.headers_mut().insert(name.clone(), value.clone());
        }
        let response = tokio::time::timeout(Duration::from_secs(5), client.request(request))
            .await
            .map_err(|_| "no answer in 5 seconds".to_string())?
            .map_err(|err| err.to_string())?;
        if !response.status().is_success() {
            return Err(format!("it answered {}", response.status()));
        }
        if !grpc {
            return Ok(());
        }
        // gRPC says how the call went in grpc-status: in the headers when there is no body, else in the trailers.
        let code = |headers: &axum::http::HeaderMap| {
            headers
                .get("grpc-status")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let status = match code(response.headers()) {
            Some(status) => Some(status),
            None => tokio::time::timeout(
                Duration::from_secs(5),
                http_body_util::BodyExt::collect(response.into_body()),
            )
            .await
            .map_err(|_| "its answer did not end in 5 seconds".to_string())?
            .map_err(|err| err.to_string())?
            .trailers()
            .and_then(code),
        };
        match status.as_deref() {
            Some("0") => Ok(()),
            Some(other) => Err(format!("it answered grpc-status {other}")),
            None => Err("it answered without a grpc-status, so it is not an OTLP/gRPC collector. For an OTLP/HTTP collector set OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf".into()),
        }
    }
}

/// The OTLP trace export request as protobuf, written from the spans' JSON form. Field numbers are those of
/// opentelemetry-proto's `trace.proto`, `common.proto` and `resource.proto`.
mod proto {
    use serde_json::Value;

    fn varint(out: &mut Vec<u8>, mut n: u64) {
        while n >= 0x80 {
            out.push((n as u8 & 0x7f) | 0x80);
            n >>= 7;
        }
        out.push(n as u8);
    }

    /// A length-delimited field: a string, bytes or a nested message.
    fn bytes(out: &mut Vec<u8>, field: u32, value: &[u8]) {
        varint(out, u64::from(field << 3 | 2));
        varint(out, value.len() as u64);
        out.extend_from_slice(value);
    }

    fn number(out: &mut Vec<u8>, field: u32, n: u64) {
        varint(out, u64::from(field << 3));
        varint(out, n);
    }

    fn fixed64(out: &mut Vec<u8>, field: u32, n: u64) {
        varint(out, u64::from(field << 3 | 1));
        out.extend(n.to_le_bytes());
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len() / 2)
            .filter_map(|i| u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok())
            .collect()
    }

    /// A KeyValue: key = 1, value = 2 (an AnyValue: string 1, bool 2, int 3, double 4).
    fn key_value(key: &str, value: &Value) -> Vec<u8> {
        let mut any = Vec::new();
        if let Some(text) = value["stringValue"].as_str() {
            bytes(&mut any, 1, text.as_bytes());
        } else if let Some(b) = value["boolValue"].as_bool() {
            number(&mut any, 2, u64::from(b));
        } else if let Some(n) = value["intValue"]
            .as_str()
            .and_then(|n| n.parse::<i64>().ok())
        {
            number(&mut any, 3, n as u64);
        } else if let Some(n) = value["doubleValue"].as_f64() {
            fixed64(&mut any, 4, n.to_bits());
        }
        let mut out = Vec::new();
        bytes(&mut out, 1, key.as_bytes());
        bytes(&mut out, 2, &any);
        out
    }

    fn span(span: &Value) -> Vec<u8> {
        let text = |name: &str| span[name].as_str().unwrap_or_default();
        let nanos = |name: &str| text(name).parse::<u64>().unwrap_or(0);
        let mut out = Vec::new();
        bytes(&mut out, 1, &unhex(text("traceId")));
        bytes(&mut out, 2, &unhex(text("spanId")));
        if !text("parentSpanId").is_empty() {
            bytes(&mut out, 4, &unhex(text("parentSpanId")));
        }
        bytes(&mut out, 5, text("name").as_bytes());
        number(&mut out, 6, span["kind"].as_u64().unwrap_or(0));
        fixed64(&mut out, 7, nanos("startTimeUnixNano"));
        fixed64(&mut out, 8, nanos("endTimeUnixNano"));
        for attribute in span["attributes"].as_array().into_iter().flatten() {
            bytes(
                &mut out,
                9,
                &key_value(
                    attribute["key"].as_str().unwrap_or_default(),
                    &attribute["value"],
                ),
            );
        }
        let mut status = Vec::new();
        number(&mut status, 3, span["status"]["code"].as_u64().unwrap_or(0));
        bytes(&mut out, 15, &status);
        out
    }

    /// ExportTraceServiceRequest { resource_spans = 1 { resource = 1 { attributes = 1 }, scope_spans = 2 {
    /// scope = 1 { name = 1, version = 2 }, spans = 2 } } }.
    pub(super) fn request(service: &str, spans: &[Value]) -> Vec<u8> {
        let mut resource = Vec::new();
        bytes(
            &mut resource,
            1,
            &key_value(
                "service.name",
                &serde_json::json!({ "stringValue": service }),
            ),
        );
        let mut scope = Vec::new();
        bytes(&mut scope, 1, b"enterplace");
        bytes(&mut scope, 2, enterplace_core::VERSION.as_bytes());
        let mut scope_spans = Vec::new();
        bytes(&mut scope_spans, 1, &scope);
        for one in spans {
            bytes(&mut scope_spans, 2, &span(one));
        }
        let mut resource_spans = Vec::new();
        bytes(&mut resource_spans, 1, &resource);
        bytes(&mut resource_spans, 2, &scope_spans);
        let mut out = Vec::new();
        bytes(&mut out, 1, &resource_spans);
        out
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn a_span_is_written_with_the_schemas_field_numbers() {
            let span = serde_json::json!({
                "traceId": "4bf92f3577b34da6a3ce929d0e0e4736", "spanId": "00f067aa0ba902b7",
                "name": "chat m", "kind": 3, "startTimeUnixNano": "1", "endTimeUnixNano": "2",
                "attributes": [{"key": "n", "value": {"intValue": "300"}}],
                "status": {"code": 2},
            });
            let out = super::span(&span);
            // trace_id: field 1, 16 bytes.
            assert_eq!(&out[..3], &[0x0a, 16, 0x4b]);
            // span_id: field 2, 8 bytes, right after.
            assert_eq!(&out[18..20], &[0x12, 8]);
            // name: field 5.
            let name = [&[0x2a, 6][..], b"chat m"].concat();
            assert!(out.windows(name.len()).any(|w| w == name));
            // kind: field 6 varint 3; start: field 7 fixed64 1.
            assert!(out.windows(2).any(|w| w == [0x30, 3]));
            assert!(out.windows(9).any(|w| w == [0x39, 1, 0, 0, 0, 0, 0, 0, 0]));
            // The attribute's int 300 as a varint (0xac 0x02) in AnyValue field 3.
            assert!(out.windows(3).any(|w| w == [0x18, 0xac, 0x02]));
            // status: field 15 { code = 3: 2 }.
            assert!(out.ends_with(&[0x7a, 2, 0x18, 2]));
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

    #[test]
    fn children_hang_off_the_requests_span_even_just_after_it_ended() -> Result<(), String> {
        let t = Tracer::new(export());
        t.begin("D9", &Method::POST, "/v1/chat/completions", None)
            .ok_or("not traced")?;
        let (attempt, header) = t.attempt("D9").ok_or("no attempt span")?;
        assert!(
            header
                .to_str()
                .map_err(|e| e.to_string())?
                .contains(&attempt)
        );
        t.attempted("D9", attempt.clone(), "chat m", now_ns(), Map::new(), true);
        t.observe(r#""id":"D9","verdict":"refused","code":"x""#);
        // The request's span has ended: a guardrail on its answer still finds its parent.
        t.child(
            "D9",
            "guardrail pii",
            now_ns(),
            &[("enterplace.guardrail", "pii")],
        );
        t.child("unknown", "guardrail pii", now_ns(), &[]);
        let spans = t.take(now_ns());
        assert_eq!(spans.len(), 3, "{spans:?}");
        let request = spans
            .iter()
            .find(|s| s["name"] == "POST /v1/chat/completions")
            .ok_or("no request span")?;
        assert!(request.to_string().contains("gen_ai.operation.name"));
        for child in spans.iter().filter(|s| s["name"] != request["name"]) {
            assert_eq!(child["parentSpanId"], request["spanId"]);
            assert_eq!(child["traceId"], request["traceId"]);
        }
        let attempted = spans
            .iter()
            .find(|s| s["name"] == "chat m")
            .ok_or("no attempt")?;
        assert_eq!(attempted["spanId"], attempt.as_str());
        assert_eq!(attempted["kind"], 3);
        assert_eq!(attempted["status"]["code"], 2);
        Ok(())
    }

    fn export() -> TraceExport {
        TraceExport {
            endpoint: "http://127.0.0.1:1/v1/traces".into(),
            ..TraceExport::default()
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
        assert_eq!(e.service, "enterplace");
        let full = TraceExport::from_env(vars(&[
            ("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "https://c/x"),
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://other"),
        ]))?
        .ok_or("no export")?;
        assert_eq!(full.endpoint, "https://c/x");
        let grpc = TraceExport::from_env(vars(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel:4317/"),
            ("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc"),
            ("ENTERPLACE_TRACE_PROPAGATION", "caller"),
        ]))?
        .ok_or("no export")?;
        assert_eq!(grpc.protocol, TraceProtocol::Grpc);
        assert_eq!(
            grpc.endpoint,
            "http://otel:4317/opentelemetry.proto.collector.trace.v1.TraceService/Export"
        );
        assert!(grpc.join_caller && !grpc.to_provider);
        let err = TraceExport::from_env(vars(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel:4318"),
            ("OTEL_EXPORTER_OTLP_PROTOCOL", "thrift"),
        ]));
        assert!(err.is_err_and(|e| e.contains("http/json, http/protobuf or grpc")));
        let err = TraceExport::from_env(vars(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel:4318"),
            ("ENTERPLACE_TRACE_PROPAGATION", "everyone"),
        ]));
        assert!(err.is_err_and(|e| e.contains("ENTERPLACE_TRACE_PROPAGATION")));
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
            "the provider gets Enterplace's span as its parent"
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
