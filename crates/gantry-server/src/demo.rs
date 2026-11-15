//! The demo model (`preset: demo`): answered here, inside the gateway, with a short sample text. Nothing is sent
//! anywhere, so a first request works before any provider key is set. The request still goes through every check
//! and is recorded like any other, under the provider named `demo`, at a price of zero.

use axum::{
    body::Body,
    http::{StatusCode, header},
    response::Response,
};
use http_body_util::BodyExt;
use serde_json::{Value, json};

/// The URL the demo preset names. It is never reached: a provider at this URL is answered by [`answer`].
pub(crate) const URL: &str = "https://demo.gantry.invalid/v1";

const TEXT: &str = "Hello from the Gantry demo model. Your request went through the gateway, was checked against the policy and recorded in the audit log. Connect a provider in the console to get real answers.";

/// The answer to one request sent to the demo provider, in the shape its API asks for.
pub(crate) async fn answer(request: axum::http::Request<Body>) -> Response {
    let path = request.uri().path().to_string();
    let body = request
        .into_body()
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    let asked: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let model = asked["model"].as_str().unwrap_or("gantry-demo").to_string();
    let stream = asked["stream"] == true;
    // A rough count, so the records carry tokens; the price is zero either way.
    let input = u64::try_from(body.len() / 4).unwrap_or(0).max(1);
    let words: Vec<&str> = TEXT.split(' ').collect();
    let output = u64::try_from(words.len()).unwrap_or(0);
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    if path.ends_with("/chat/completions") {
        let usage = json!({ "prompt_tokens": input, "completion_tokens": output, "total_tokens": input + output });
        if !stream {
            return json_response(json!({
                "id": "chatcmpl-demo",
                "object": "chat.completion",
                "created": created,
                "model": model,
                "choices": [{ "index": 0, "message": { "role": "assistant", "content": TEXT }, "finish_reason": "stop" }],
                "usage": usage,
            }));
        }
        let chunk = |delta: Value, finish: Value| {
            json!({ "id": "chatcmpl-demo", "object": "chat.completion.chunk", "created": created, "model": model,
                    "choices": [{ "index": 0, "delta": delta, "finish_reason": finish }] })
        };
        let mut events = vec![chunk(
            json!({ "role": "assistant", "content": "" }),
            Value::Null,
        )];
        events.extend(words.iter().enumerate().map(|(i, w)| {
            let piece = if i == 0 {
                (*w).to_string()
            } else {
                format!(" {w}")
            };
            chunk(json!({ "content": piece }), Value::Null)
        }));
        events.push(chunk(json!({}), json!("stop")));
        events.push(
            json!({ "id": "chatcmpl-demo", "object": "chat.completion.chunk", "created": created,
                            "model": model, "choices": [], "usage": usage }),
        );
        let mut text: String = events.iter().map(|e| format!("data: {e}\n\n")).collect();
        text.push_str("data: [DONE]\n\n");
        return sse(text);
    }
    if path.ends_with("/responses") {
        let usage = json!({ "input_tokens": input, "output_tokens": output, "total_tokens": input + output });
        let done = json!({
            "id": "resp_demo",
            "object": "response",
            "created_at": created,
            "status": "completed",
            "model": model,
            "output": [{ "type": "message", "id": "msg_demo", "status": "completed", "role": "assistant",
                         "content": [{ "type": "output_text", "text": TEXT, "annotations": [] }] }],
            "usage": usage,
        });
        if !stream {
            return json_response(done);
        }
        let mut started = done.clone();
        started["status"] = json!("in_progress");
        started["output"] = json!([]);
        started["usage"] = Value::Null;
        let mut events = vec![(
            "response.created",
            json!({ "type": "response.created", "response": started }),
        )];
        events.extend(words.iter().enumerate().map(|(i, w)| {
            let piece = if i == 0 {
                (*w).to_string()
            } else {
                format!(" {w}")
            };
            (
                "response.output_text.delta",
                json!({ "type": "response.output_text.delta", "item_id": "msg_demo",
                "output_index": 0, "content_index": 0, "delta": piece }),
            )
        }));
        events.push((
            "response.completed",
            json!({ "type": "response.completed", "response": done }),
        ));
        return sse(events
            .iter()
            .map(|(name, e)| format!("event: {name}\ndata: {e}\n\n"))
            .collect());
    }
    let mut response = json_response(json!({ "error": {
        "type": "invalid_request_error",
        "code": "demo_chat_only",
        "message": "The demo model answers chat only: chat completions, responses and messages. Connect a provider in the console (Start here, Connect a model) for the rest.",
    }}));
    *response.status_mut() = StatusCode::BAD_REQUEST;
    response
}

fn json_response(value: Value) -> Response {
    let mut response = Response::new(Body::from(value.to_string()));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    response
}

fn sse(text: String) -> Response {
    let mut response = Response::new(Body::from(text));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/event-stream"),
    );
    response
}
