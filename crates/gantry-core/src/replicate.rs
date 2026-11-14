//! Translation between the OpenAI chat completions format and a Replicate prediction of a language model.
//!
//! A prediction takes one `input` object whose fields each model's schema names; Replicate's language models take
//! `prompt`, `system_prompt`, `max_tokens`, `temperature`, `top_p`, `seed` and `stop_sequences`. The conversation is
//! written into `prompt` as a transcript (`User: ...`, `Assistant: ...`, ending with `Assistant:`). As in
//! [`crate::translate`], a request field that cannot be carried across is an error that names it (AGENTS.md rule 7).
//!
//! The prediction is waited for (`Prefer: wait`), and its `output`, a list of text pieces or one text, becomes the
//! chat answer. Its `metrics` give the token counts when the model reports them.
//!
//! Formats as documented on 2026-11-14: <https://replicate.com/docs/reference/http>.

use serde_json::{Map, Value, json};

use crate::translate::{
    Result, describe, fail, insert, is_openai_default, object, openai_usage, untranslatable,
    write_event,
};
use crate::usage::Usage;

const TO_REPLICATE: &str = "a Replicate prediction's input";

/// A chat completions request as a prediction body: `{"input": {...}}`, with `version` when `id` pins one
/// (`owner/name:version`).
pub fn openai_to_prediction(request: &Value, id: &str) -> Result<Value> {
    let fields = object(request, "The request body")?;
    let mut input = Map::new();
    let mut transcript = String::new();
    let mut system = Vec::new();
    for (key, value) in fields {
        if value.is_null() || is_openai_default(key, value) {
            continue;
        }
        match key.as_str() {
            "model" | "stream" | "user" => {}
            "stream_options" => {}
            "messages" => {
                for message in value.as_array().map_or(&[][..], Vec::as_slice) {
                    let role = message["role"].as_str().unwrap_or_default();
                    let text = text_of(&message["content"])?;
                    for extra in object(message, "A message")?.keys() {
                        if !matches!(extra.as_str(), "role" | "content" | "name") {
                            return untranslatable(
                                &format!("The message field \"{extra}\""),
                                TO_REPLICATE,
                            );
                        }
                    }
                    match role {
                        "system" | "developer" => system.push(text),
                        "user" => transcript.push_str(&format!("User: {text}\n")),
                        "assistant" => transcript.push_str(&format!("Assistant: {text}\n")),
                        other => {
                            return untranslatable(
                                &format!("A message with role \"{other}\""),
                                TO_REPLICATE,
                            );
                        }
                    }
                }
            }
            "max_tokens" | "max_completion_tokens" => {
                insert(&mut input, "max_tokens", value.clone())
            }
            "temperature" | "top_p" | "seed" => insert(&mut input, key, value.clone()),
            "stop" => insert(
                &mut input,
                "stop_sequences",
                match value {
                    Value::Array(all) => all
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(",")
                        .into(),
                    _ => value.clone(),
                },
            ),
            _ => return untranslatable(&describe(key, value), TO_REPLICATE),
        }
    }
    if transcript.is_empty() {
        return fail("The request has no user message. Send at least one.".into());
    }
    transcript.push_str("Assistant:");
    input.insert("prompt".into(), transcript.into());
    if !system.is_empty() {
        input.insert("system_prompt".into(), system.join("\n").into());
    }
    let mut body = json!({ "input": input });
    if let Some((_, version)) = id.split_once(':') {
        body["version"] = version.into();
    }
    Ok(body)
}

/// A message's text: a string, or text parts. An image or audio part has no place in a text prompt.
fn text_of(content: &Value) -> Result<String> {
    match content {
        Value::String(text) => Ok(text.clone()),
        Value::Array(parts) => {
            let mut out = String::new();
            for part in parts {
                if part["type"] != "text" {
                    return untranslatable(
                        &format!("A content part of type {}", part["type"]),
                        TO_REPLICATE,
                    );
                }
                out.push_str(part["text"].as_str().unwrap_or_default());
            }
            Ok(out)
        }
        Value::Null => Ok(String::new()),
        _ => fail("A message's content must be text or a list of text parts.".into()),
    }
}

/// The tokens a prediction reports in its `metrics`, when the model reports them.
pub fn usage(prediction: &Value) -> Option<Usage> {
    let metrics = &prediction["metrics"];
    let input = metrics["input_token_count"].as_u64();
    let output = metrics["output_token_count"].as_u64();
    if input.is_none() && output.is_none() {
        return None;
    }
    Some(Usage {
        input: input.unwrap_or_default(),
        output: output.unwrap_or_default(),
        ..Usage::default()
    })
}

/// A finished prediction as a chat completion. A prediction that did not succeed is an error naming its status.
pub fn prediction_to_openai(prediction: &Value, model: &str, created: u64) -> Result<Value> {
    match prediction["status"].as_str() {
        Some("succeeded") => {}
        Some(status @ ("starting" | "processing")) => {
            return fail(format!(
                "Replicate had not finished the prediction after waiting 60 seconds (status {status}); it was cancelled. Ask for fewer tokens, or use a model that answers faster."
            ));
        }
        status => {
            return fail(format!(
                "Replicate's prediction ended {}: {}",
                status.unwrap_or("without a status"),
                prediction["error"]
            ));
        }
    }
    let text = match &prediction["output"] {
        Value::Array(pieces) => pieces.iter().filter_map(Value::as_str).collect::<String>(),
        Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    let mut answer = json!({
        "id": format!("chatcmpl-{}", prediction["id"].as_str().unwrap_or("replicate")),
        "object": "chat.completion",
        "created": created,
        "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
    });
    if let Some(usage) = usage(prediction) {
        answer["usage"] = openai_usage(&usage);
    }
    Ok(answer)
}

/// A chat completion as the stream a client that asked for one reads: the whole text in one chunk, the finish, the
/// usage when asked for, and `[DONE]`.
pub fn completion_to_stream(completion: &Value, include_usage: bool) -> Vec<u8> {
    let chunk = |choices: Value| {
        json!({
            "id": completion["id"],
            "object": "chat.completion.chunk",
            "created": completion["created"],
            "model": completion["model"],
            "choices": choices,
        })
    };
    let text = &completion["choices"][0]["message"]["content"];
    let mut out = Vec::new();
    write_event(
        &mut out,
        &chunk(
            json!([{"index": 0, "delta": {"role": "assistant", "content": text}, "finish_reason": null}]),
        ),
    );
    write_event(
        &mut out,
        &chunk(json!([{"index": 0, "delta": {}, "finish_reason": "stop"}])),
    );
    if include_usage && completion["usage"].is_object() {
        let mut last = chunk(json!([]));
        last["usage"] = completion["usage"].clone();
        write_event(&mut out, &last);
    }
    out.extend_from_slice(b"data: [DONE]\n\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn a_conversation_becomes_a_prompt_and_unknown_fields_are_refused() -> TestResult {
        let request = json!({"model": "meta/llama", "max_tokens": 50, "temperature": 0.2, "stop": ["\n\n"],
            "messages": [{"role": "system", "content": "Be brief."}, {"role": "user", "content": "Hi"},
                {"role": "assistant", "content": "Hello"}, {"role": "user", "content": [{"type": "text", "text": "Again"}]}]});
        let body = openai_to_prediction(&request, "meta/llama:abc")?;
        assert_eq!(
            body,
            json!({"version": "abc", "input": {"prompt": "User: Hi\nAssistant: Hello\nUser: Again\nAssistant:",
                "system_prompt": "Be brief.", "max_tokens": 50, "temperature": 0.2, "stop_sequences": "\n\n"}})
        );
        let tools = json!({"messages": [{"role": "user", "content": "Hi"}], "tools": []});
        assert!(openai_to_prediction(&tools, "m").is_err_and(|e| e.to_string().contains("tools")));
        Ok(())
    }

    #[test]
    fn a_prediction_becomes_a_completion_and_an_unfinished_one_an_error() -> TestResult {
        let done = json!({"id": "p1", "status": "succeeded", "output": ["Hel", "lo"],
            "metrics": {"input_token_count": 7, "output_token_count": 2}});
        let answer = prediction_to_openai(&done, "meta/llama", 9)?;
        assert_eq!(answer["choices"][0]["message"]["content"], "Hello");
        assert_eq!(answer["usage"]["prompt_tokens"], 7);
        let stream = String::from_utf8(completion_to_stream(&answer, true))?;
        assert!(stream.contains("\"content\":\"Hello\"") && stream.ends_with("data: [DONE]\n\n"));
        assert!(stream.contains("\"completion_tokens\":2"));
        let slow = json!({"id": "p2", "status": "processing"});
        assert!(
            prediction_to_openai(&slow, "m", 0)
                .is_err_and(|e| e.to_string().contains("60 seconds"))
        );
        Ok(())
    }
}
