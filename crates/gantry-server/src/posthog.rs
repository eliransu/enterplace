//! Process-wide PostHog client for server-side analytics.

use std::sync::{Arc, OnceLock};

use axum::body::Bytes;
use gantry_core::{policy::Principal, usage::Usage};
use posthog_rs::{Client, ClientOptionsBuilder, ErrorTrackingOptionsBuilder, Event};
use serde_json::{Value, json};

static CLIENT: OnceLock<Arc<Client>> = OnceLock::new();

/// Builds the single PostHog client for this process when both configuration
/// variables are present. Server startup continues without analytics when they
/// are absent, but debug builds make the configuration problem visible.
pub(crate) async fn init() {
    if CLIENT.get().is_some() {
        return;
    }

    let token = std::env::var("POSTHOG_PROJECT_TOKEN").unwrap_or_default();
    let host = std::env::var("POSTHOG_HOST").unwrap_or_default();

    for (name, value) in [
        ("POSTHOG_PROJECT_TOKEN", token.trim()),
        ("POSTHOG_HOST", host.trim()),
    ] {
        if value.is_empty() {
            if cfg!(debug_assertions) {
                eprintln!(
                    "{name} variable required by PostHog is missing or un-configured, this causes events to be silently missed. This error stops appearing once {name} is configured"
                );
            }
            return;
        }
    }

    // Panic capture is process-wide in posthog-rs, so initialize the same
    // singleton client globally rather than adding per-route error handling.
    let error_tracking = match ErrorTrackingOptionsBuilder::default()
        .capture_panics(true)
        .build()
    {
        Ok(options) => options,
        Err(error) => {
            if cfg!(debug_assertions) {
                eprintln!("PostHog error tracking could not be configured: {error}");
            }
            return;
        }
    };
    let options = match ClientOptionsBuilder::default()
        .api_key(token)
        .host(host)
        .error_tracking(error_tracking)
        .build()
    {
        Ok(options) => options,
        Err(error) => {
            if cfg!(debug_assertions) {
                eprintln!("PostHog client could not be configured: {error}");
            }
            return;
        }
    };

    match posthog_rs::init_global(options).await {
        Ok(client) => {
            let _ = CLIENT.set(Arc::new(client));
        }
        Err(error) => {
            if cfg!(debug_assertions) {
                eprintln!("PostHog client could not be initialized: {error}");
            }
        }
    }
}

/// Returns the process-wide client after server startup has initialized it.
pub(crate) fn client() -> Option<Arc<Client>> {
    CLIENT.get().cloned()
}

/// Produces the stable, non-PII PostHog identity for an authenticated request.
///
/// `Principal::key` is Gantry's stable identifier for both API-key and JWT
/// callers. Its value is already a one-way key fingerprint, rather than the
/// mutable display name or a JWT claim that might contain PII. The Rust SDK
/// has no request context, so every event and exception captured for this
/// principal must use this value as its distinct id.
pub(crate) fn distinct_id(person: &Principal) -> String {
    format!("gantry:{}", person.key)
}

/// Whether a request has a model generation to report and PostHog is configured.
///
/// Keeping the request and answer only when this is true preserves the gateway's
/// normal memory behavior when analytics is disabled.
pub(crate) fn captures_ai_generation(route: &str) -> bool {
    let route = route.split('?').next().unwrap_or(route);
    let generation = matches!(
        route,
        crate::CHAT | crate::MESSAGES | crate::RESPONSES | crate::COMPLETIONS
    ) || crate::gemini_native(route)
        .is_some_and(|(_, _, method)| matches!(method, "generateContent" | "streamGenerateContent"));
    generation && client().is_some()
}

/// Captures one completed model request for AI Observability.
///
/// This is manual capture because Gantry forwards HTTP requests to several
/// provider APIs rather than calling a single vendor SDK. The gateway's decision
/// id is one trace per request; an events-plugin session, when present, groups
/// its turns without introducing a new identifier.
#[allow(clippy::too_many_arguments)]
pub(crate) fn capture_ai_generation(
    distinct_id: &str,
    trace_id: &str,
    session_id: Option<&str>,
    model: &str,
    provider: &str,
    route: &str,
    request: &Bytes,
    answer: Option<&Bytes>,
    streamed: bool,
    usage: Option<&Usage>,
    status: Option<u16>,
    latency_secs: f64,
    failed: bool,
    cost_usd: Option<f64>,
) {
    let Some(client) = client() else {
        return;
    };

    let mut event = Event::new("$ai_generation", distinct_id);
    let _ = event.insert_prop("$ai_trace_id", trace_id);
    let _ = event.insert_prop("$ai_span_id", format!("generation:{trace_id}"));
    let _ = event.insert_prop("$ai_span_name", route.split('?').next().unwrap_or(route));
    let _ = event.insert_prop(
        "$ai_session_id",
        session_id.filter(|id| valid_ai_id(id)).map_or(Value::Null, Value::from),
    );
    let _ = event.insert_prop("$ai_model", model);
    let _ = event.insert_prop("$ai_provider", provider);
    let _ = event.insert_prop("$ai_input", input_messages(request));
    let _ = event.insert_prop("$ai_stream", streamed);
    if let Some(status) = status {
        let _ = event.insert_prop("$ai_http_status", status);
    }
    let _ = event.insert_prop("$ai_latency", latency_secs);
    let _ = event.insert_prop("$ai_is_error", failed);
    if let Some(answer) = answer {
        let _ = event.insert_prop("$ai_output_choices", output_choices(answer, streamed));
    }
    if let Some(usage) = usage {
        let _ = event.insert_prop("$ai_input_tokens", usage.input);
        let _ = event.insert_prop("$ai_output_tokens", usage.output);
        if usage.cache_read > 0 {
            let _ = event.insert_prop("$ai_cache_read_input_tokens", usage.cache_read);
        }
        let cache_written = usage.cache_write + usage.cache_write_1h;
        if cache_written > 0 {
            let _ = event.insert_prop("$ai_cache_creation_input_tokens", cache_written);
        }
    }
    if let Some(cost) = cost_usd.filter(|cost| cost.is_finite() && *cost >= 0.0) {
        let _ = event.insert_prop("$ai_total_cost_usd", cost);
    }
    if let Ok(body) = serde_json::from_slice::<Value>(request)
        && let Some(tools) = body.get("tools").filter(|tools| !tools.is_null())
    {
        let _ = event.insert_prop("$ai_tools", tools.clone());
    }
    client.capture(event);
}

fn valid_ai_id(id: &str) -> bool {
    !id.is_empty()
        && id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'~' | b'.' | b'@' | b'(' | b')' | b'!' | b'\'' | b':' | b'|')
        })
}

fn input_messages(request: &[u8]) -> Value {
    let Ok(body) = serde_json::from_slice::<Value>(request) else {
        return Value::Array(Vec::new());
    };
    if let Some(messages) = body.get("messages").and_then(Value::as_array) {
        return Value::Array(messages.clone());
    }
    if let Some(input) = body.get("input") {
        let mut messages = match input {
            Value::String(text) => vec![json!({"role": "user", "content": text})],
            Value::Array(items) => items.clone(),
            _ => Vec::new(),
        };
        if let Some(instructions) = body.get("instructions").filter(|value| value.is_string()) {
            messages.insert(0, json!({"role": "system", "content": instructions}));
        }
        return Value::Array(messages);
    }
    if let Some(contents) = body.get("contents").and_then(Value::as_array) {
        let messages = contents
            .iter()
            .map(|content| {
                let mut content = content.clone();
                if content.get("role").and_then(Value::as_str) == Some("model") {
                    content["role"] = Value::from("assistant");
                }
                content
            })
            .collect();
        return Value::Array(messages);
    }
    body.get("prompt")
        .map(|prompt| json!([{"role": "user", "content": prompt}]))
        .unwrap_or_else(|| Value::Array(Vec::new()))
}

fn output_choices(answer: &[u8], streamed: bool) -> Value {
    if streamed {
        return Value::Array(
            crate::stream_texts(answer)
                .unwrap_or_default()
                .into_iter()
                .map(|(_, text)| json!({"role": "assistant", "content": text}))
                .collect(),
        );
    }
    let Ok(body) = serde_json::from_slice::<Value>(answer) else {
        return Value::Array(Vec::new());
    };
    if let Some(choices) = body.get("choices").and_then(Value::as_array) {
        return Value::Array(
            choices
                .iter()
                .filter_map(|choice| {
                    choice
                        .get("message")
                        .cloned()
                        .or_else(|| choice.get("text").map(|text| json!({"role": "assistant", "content": text})))
                })
                .collect(),
        );
    }
    if let Some(output) = body.get("output").and_then(Value::as_array) {
        return Value::Array(output.clone());
    }
    if let Some(content) = body.get("content").filter(|content| content.is_array()) {
        return json!([{"role": "assistant", "content": content}]);
    }
    if let Some(candidates) = body.get("candidates").and_then(Value::as_array) {
        return Value::Array(
            candidates
                .iter()
                .filter_map(|candidate| candidate.get("content").cloned())
                .map(|mut content| {
                    if content.get("role").and_then(Value::as_str) == Some("model") {
                        content["role"] = Value::from("assistant");
                    }
                    content
                })
                .collect(),
        );
    }
    body.get("text")
        .map(|text| json!([{"role": "assistant", "content": text}]))
        .unwrap_or_else(|| Value::Array(Vec::new()))
}

/// Delivers queued analytics before the server process exits.
pub(crate) async fn shutdown() {
    if let Some(client) = CLIENT.get() {
        client.flush().await;
        client.shutdown().await;
    }
}
