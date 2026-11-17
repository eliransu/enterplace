//! Translation between the OpenAI chat completions format and Cohere's v2 chat API, and the small changes watsonx.ai
//! needs, whose chat API is OpenAI's shape with its own model and project fields.
//!
//! As in [`crate::translate`], a request field that cannot be carried across is an error that names it (AGENTS.md
//! rule 7), and a field at null or its documented default is accepted.
//!
//! Formats as documented on 2026-11-14:
//! - <https://docs.cohere.com/reference/chat> and <https://docs.cohere.com/reference/chat-stream>
//! - <https://cloud.ibm.com/apidocs/watsonx-ai#text-chat> and `#text-chat-stream`

use std::collections::HashMap;

use serde_json::{Map, Value, json};

use crate::translate::{
    Result, describe, fail, insert, is_openai_default, object, openai_usage, thinking_budget,
    untranslatable, write_event,
};
use crate::usage::{Usage, sse_data};

const TO_COHERE: &str = "Cohere's chat API";
const TO_WATSONX: &str = "watsonx.ai's chat API";
const TO_OPENAI: &str = "the OpenAI chat completions API";

/// A chat completions request as a Cohere v2 chat body. Messages, tools and tool calls are OpenAI's shape already.
pub fn openai_to_cohere_request(request: &Value) -> Result<Value> {
    let fields = object(request, "The request body")?;
    let mut out = Map::new();
    let mut max_tokens: Option<&Value> = None;
    for (key, value) in fields {
        if value.is_null() {
            continue;
        }
        match key.as_str() {
            "model" | "messages" | "tools" | "temperature" | "seed" | "frequency_penalty"
            | "presence_penalty" | "stream" => {
                out.insert(key.clone(), value.clone());
            }
            "top_p" => insert(&mut out, "p", value.clone()),
            "max_tokens" | "max_completion_tokens" => {
                if max_tokens.is_some_and(|m| m != value) {
                    return fail(
                        "\"max_tokens\" and \"max_completion_tokens\" differ. Send only one of them."
                            .into(),
                    );
                }
                max_tokens = Some(value);
            }
            "stop" => insert(
                &mut out,
                "stop_sequences",
                match value {
                    Value::String(_) => json!([value]),
                    _ => value.clone(),
                },
            ),
            "stream_options" => {
                for (option, setting) in object(value, "\"stream_options\"")? {
                    if option != "include_usage"
                        && !matches!(setting, Value::Null | Value::Bool(false))
                    {
                        return untranslatable(
                            &format!("The stream option \"{option}\""),
                            TO_COHERE,
                        );
                    }
                }
            }
            "tool_choice" => match value.as_str() {
                Some("auto") => {}
                Some("required") => insert(&mut out, "tool_choice", json!("REQUIRED")),
                Some("none") => insert(&mut out, "tool_choice", json!("NONE")),
                _ => return untranslatable(&describe(key, value), TO_COHERE),
            },
            "parallel_tool_calls" if *value == true => {}
            "response_format" => match value["type"].as_str() {
                Some("text") => {}
                Some("json_object") => {
                    insert(&mut out, "response_format", json!({"type": "json_object"}))
                }
                Some("json_schema") => insert(
                    &mut out,
                    "response_format",
                    json!({"type": "json_object", "json_schema": value["json_schema"]["schema"]}),
                ),
                _ => return untranslatable(&describe(key, &value["type"]), TO_COHERE),
            },
            "reasoning_effort" => match value.as_str() {
                Some("none") => insert(&mut out, "thinking", json!({"type": "disabled"})),
                Some(level) if thinking_budget(level).is_some() => insert(
                    &mut out,
                    "thinking",
                    json!({"type": "enabled", "token_budget": thinking_budget(level)}),
                ),
                _ => return untranslatable(&describe(key, value), TO_COHERE),
            },
            // An end-user ID for OpenAI's abuse monitoring and a cache routing hint: no answer depends on them.
            "user" | "safety_identifier" | "prompt_cache_key" | "metadata" => {}
            _ if is_openai_default(key, value) => {}
            _ => return untranslatable(&describe(key, value), TO_COHERE),
        }
    }
    if let Some(max) = max_tokens {
        insert(&mut out, "max_tokens", max.clone());
    }
    // Cohere takes the developer role as system.
    if let Some(messages) = out.get_mut("messages").and_then(Value::as_array_mut) {
        for message in messages {
            if message["role"] == "developer" {
                message["role"] = json!("system");
            }
        }
    }
    Ok(Value::Object(out))
}

fn cohere_finish(reason: &Value) -> Result<Value> {
    Ok(match reason.as_str() {
        None => Value::Null,
        Some("COMPLETE" | "STOP_SEQUENCE") => json!("stop"),
        Some("MAX_TOKENS") => json!("length"),
        Some("TOOL_CALL") => json!("tool_calls"),
        Some(other) => return untranslatable(&format!("The finish reason \"{other}\""), TO_OPENAI),
    })
}

/// The usage of a Cohere answer in the gateway's terms.
fn cohere_usage(usage: &Value) -> Usage {
    Usage::from_cohere(usage).unwrap_or_default()
}

/// A Cohere v2 chat answer as an OpenAI chat completion.
pub fn cohere_to_openai_response(answer: &Value, model: &str, created: u64) -> Result<Value> {
    object(answer, "The provider's answer")?;
    let message = &answer["message"];
    let mut text = String::new();
    let mut reasoning = String::new();
    for part in message["content"].as_array().map_or(&[][..], Vec::as_slice) {
        match part["type"].as_str() {
            Some("text") => text.push_str(part["text"].as_str().unwrap_or_default()),
            Some("thinking") => reasoning.push_str(part["thinking"].as_str().unwrap_or_default()),
            other => {
                return untranslatable(
                    &format!("A {} part in the answer", other.unwrap_or("untyped")),
                    TO_OPENAI,
                );
            }
        }
    }
    let calls = message["tool_calls"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut reply = json!({"role": "assistant", "content": (!text.is_empty() || calls.is_empty()).then_some(text)});
    if let Some(fields) = reply.as_object_mut() {
        if !calls.is_empty() {
            insert(fields, "tool_calls", Value::Array(calls));
        }
        if !reasoning.is_empty() {
            insert(fields, "reasoning_content", json!(reasoning));
        }
    }
    Ok(json!({
        "id": answer["id"],
        "object": "chat.completion",
        "created": created,
        "model": model,
        "choices": [{"index": 0, "message": reply, "logprobs": null, "finish_reason": cohere_finish(&answer["finish_reason"])?}],
        "usage": openai_usage(&cohere_usage(&answer["usage"])),
    }))
}

/// Turns a Cohere v2 chat stream into an OpenAI chat completions stream as bytes arrive.
#[derive(Debug)]
pub struct CohereToOpenAiStream {
    include_usage: bool,
    model: String,
    created: u64,
    id: Value,
    line: Vec<u8>,
    calls: HashMap<u64, usize>,
    done: bool,
}

impl CohereToOpenAiStream {
    pub fn new(include_usage: bool, model: String, created: u64) -> Self {
        Self {
            include_usage,
            model,
            created,
            id: Value::Null,
            line: Vec::new(),
            calls: HashMap::new(),
            done: false,
        }
    }

    pub fn feed(&mut self, mut bytes: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(end) = bytes.iter().position(|&b| b == b'\n') {
            self.line.extend_from_slice(&bytes[..end]);
            bytes = &bytes[end + 1..];
            let line = std::mem::take(&mut self.line);
            self.on_line(&line, &mut out)?;
        }
        self.line.extend_from_slice(bytes);
        Ok(out)
    }

    pub fn finish(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let line = std::mem::take(&mut self.line);
        self.on_line(&line, &mut out)?;
        if !self.done {
            return fail("The provider's stream ended before its message-end event, so the answer is incomplete. Retry the request.".into());
        }
        Ok(out)
    }

    fn chunk(&self, delta: Value, finish: Value) -> Value {
        json!({
            "id": self.id, "object": "chat.completion.chunk", "created": self.created, "model": self.model,
            "choices": [{"index": 0, "delta": delta, "logprobs": null, "finish_reason": finish}],
        })
    }

    fn on_line(&mut self, line: &[u8], out: &mut Vec<u8>) -> Result<()> {
        if self.done {
            return Ok(());
        }
        let Some(data) = sse_data(line) else {
            return Ok(());
        };
        let event: Value = match serde_json::from_slice(data) {
            Ok(event) => event,
            Err(e) => {
                return fail(format!(
                    "The provider sent a stream event that is not JSON: {e}."
                ));
            }
        };
        let delta = &event["delta"]["message"];
        let index = event["index"].as_u64().unwrap_or_default();
        match event["type"].as_str().unwrap_or_default() {
            "message-start" => {
                self.id = event["id"].clone();
                write_event(
                    out,
                    &self.chunk(json!({"role": "assistant", "content": ""}), Value::Null),
                );
            }
            "content-delta" => {
                let content = &delta["content"];
                if let Some(text) = content["text"].as_str() {
                    write_event(out, &self.chunk(json!({"content": text}), Value::Null));
                } else if let Some(text) = content["thinking"].as_str() {
                    write_event(
                        out,
                        &self.chunk(json!({"reasoning_content": text}), Value::Null),
                    );
                }
            }
            "tool-call-start" => {
                let call = &delta["tool_calls"];
                let n = self.calls.len();
                self.calls.insert(index, n);
                write_event(out, &self.chunk(json!({"tool_calls": [{"index": n, "id": call["id"], "type": "function", "function": {"name": call["function"]["name"], "arguments": call["function"]["arguments"].as_str().unwrap_or_default()}}]}), Value::Null));
            }
            "tool-call-delta" => {
                let Some(n) = self.calls.get(&index) else {
                    return fail("The provider streamed tool arguments for a call it never started. Retry the request.".into());
                };
                write_event(out, &self.chunk(json!({"tool_calls": [{"index": n, "function": {"arguments": delta["tool_calls"]["function"]["arguments"]}}]}), Value::Null));
            }
            "message-end" => {
                let end = &event["delta"];
                write_event(
                    out,
                    &self.chunk(json!({}), cohere_finish(&end["finish_reason"])?),
                );
                if self.include_usage {
                    let chunk = json!({
                        "id": self.id, "object": "chat.completion.chunk", "created": self.created,
                        "model": self.model, "choices": [], "usage": openai_usage(&cohere_usage(&end["usage"])),
                    });
                    write_event(out, &chunk);
                }
                out.extend_from_slice(b"data: [DONE]\n\n");
                self.done = true;
            }
            // content-start, content-end, tool-plan-delta and tool-call-end carry nothing a chat client reads.
            _ => {}
        }
        Ok(())
    }
}

/// A chat completions request as watsonx.ai's chat body: the model as `model_id`, in `project`.
pub fn openai_to_watsonx_request(request: &Value, project: &str) -> Result<(Value, bool)> {
    let fields = object(request, "The request body")?;
    let mut out = Map::new();
    let mut stream = false;
    for (key, value) in fields {
        if value.is_null() {
            continue;
        }
        match key.as_str() {
            "model" => insert(&mut out, "model_id", value.clone()),
            "stream" => stream = *value == true,
            "max_completion_tokens" => insert(&mut out, "max_tokens", value.clone()),
            "messages" | "tools" | "temperature" | "top_p" | "stop" | "seed"
            | "frequency_penalty" | "presence_penalty" | "max_tokens" | "response_format"
            | "logprobs" | "top_logprobs" | "n" => {
                out.insert(key.clone(), value.clone());
            }
            "tool_choice" => match value.as_str() {
                Some(option) => insert(&mut out, "tool_choice_option", json!(option)),
                None => insert(&mut out, "tool_choice", value.clone()),
            },
            "stream_options"
            | "parallel_tool_calls"
            | "user"
            | "safety_identifier"
            | "prompt_cache_key"
            | "metadata" => {}
            _ if is_openai_default(key, value) => {}
            _ => return untranslatable(&describe(key, value), TO_WATSONX),
        }
    }
    insert(&mut out, "project_id", json!(project));
    Ok((Value::Object(out), stream))
}

/// A watsonx.ai chat answer (whole or one stream chunk) in OpenAI's shape: `model_id` back to `model`.
pub fn watsonx_to_openai(answer: &mut Value, chunk: bool) {
    if let Some(fields) = answer.as_object_mut() {
        if let Some(model) = fields.remove("model_id") {
            fields.insert("model".into(), model);
        }
        fields.remove("model_version");
        fields.remove("created_at");
        fields.entry("object").or_insert(json!(if chunk {
            "chat.completion.chunk"
        } else {
            "chat.completion"
        }));
    }
}

/// Turns a watsonx.ai chat stream into an OpenAI one: each chunk renamed, usage kept only when asked for, and the
/// `[DONE]` line OpenAI's clients wait for.
#[derive(Debug)]
pub struct WatsonxToOpenAiStream {
    include_usage: bool,
    line: Vec<u8>,
    done: bool,
    finished: bool,
}

impl WatsonxToOpenAiStream {
    pub fn new(include_usage: bool) -> Self {
        Self {
            include_usage,
            line: Vec::new(),
            done: false,
            finished: false,
        }
    }

    pub fn feed(&mut self, mut bytes: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(end) = bytes.iter().position(|&b| b == b'\n') {
            self.line.extend_from_slice(&bytes[..end]);
            bytes = &bytes[end + 1..];
            let line = std::mem::take(&mut self.line);
            self.on_line(&line, &mut out)?;
        }
        self.line.extend_from_slice(bytes);
        Ok(out)
    }

    pub fn finish(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let line = std::mem::take(&mut self.line);
        self.on_line(&line, &mut out)?;
        if !self.finished {
            return fail("The provider's stream ended before a chunk with a finish reason, so the answer is incomplete. Retry the request.".into());
        }
        if !self.done {
            out.extend_from_slice(b"data: [DONE]\n\n");
        }
        Ok(out)
    }

    fn on_line(&mut self, line: &[u8], out: &mut Vec<u8>) -> Result<()> {
        let Some(data) = sse_data(line) else {
            return Ok(());
        };
        if data.trim_ascii() == b"[DONE]" {
            self.done = true;
            out.extend_from_slice(b"data: [DONE]\n\n");
            return Ok(());
        }
        let mut chunk: Value = match serde_json::from_slice(data) {
            Ok(chunk) => chunk,
            Err(e) => {
                return fail(format!(
                    "The provider sent a stream event that is not JSON: {e}."
                ));
            }
        };
        watsonx_to_openai(&mut chunk, true);
        self.finished |= chunk["choices"]
            .as_array()
            .is_some_and(|c| c.iter().any(|c| !c["finish_reason"].is_null()));
        let has_usage = chunk["usage"].is_object();
        if !self.include_usage && has_usage {
            if let Some(fields) = chunk.as_object_mut() {
                fields.remove("usage");
            }
            if chunk["choices"].as_array().is_none_or(Vec::is_empty) {
                return Ok(());
            }
        }
        write_event(out, &chunk);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn a_chat_request_becomes_a_cohere_body_and_back() -> TestResult {
        let chat = json!({"model": "command-a", "top_p": 0.9, "stop": "x", "tool_choice": "required", "reasoning_effort": "low",
            "messages": [{"role": "developer", "content": "Be brief."}, {"role": "user", "content": "hi"}]});
        let body = openai_to_cohere_request(&chat)?;
        assert_eq!(body["p"], 0.9);
        assert_eq!(body["stop_sequences"], json!(["x"]));
        assert_eq!(body["tool_choice"], "REQUIRED");
        assert_eq!(body["thinking"]["token_budget"], 1024);
        assert_eq!(body["messages"][0]["role"], "system");
        let answer = json!({"id": "c1", "finish_reason": "TOOL_CALL", "message": {"role": "assistant",
            "content": [{"type": "text", "text": "Calling."}],
            "tool_calls": [{"id": "t1", "type": "function", "function": {"name": "f", "arguments": "{}"}}]},
            "usage": {"billed_units": {"input_tokens": 7, "output_tokens": 3}, "tokens": {"input_tokens": 9, "output_tokens": 3}}});
        let chat = cohere_to_openai_response(&answer, "command-a", 1)?;
        assert_eq!(chat["choices"][0]["finish_reason"], "tool_calls");
        assert_eq!(chat["usage"]["prompt_tokens"], 7);
        Ok(())
    }

    #[test]
    fn a_cohere_stream_becomes_chat_chunks() -> TestResult {
        let sse = [
            json!({"type": "message-start", "id": "m1", "delta": {"message": {"role": "assistant"}}}),
            json!({"type": "content-delta", "index": 0, "delta": {"message": {"content": {"text": "Hi"}}}}),
            json!({"type": "message-end", "delta": {"finish_reason": "COMPLETE", "usage": {"billed_units": {"input_tokens": 2, "output_tokens": 1}}}}),
        ]
        .iter()
        .map(|e| format!("event: {}\ndata: {e}\n\n", e["type"].as_str().unwrap_or_default()))
        .collect::<String>();
        let mut stream = CohereToOpenAiStream::new(true, "command-a".into(), 1);
        let mut out = stream.feed(sse.as_bytes())?;
        out.extend(stream.finish()?);
        let text = String::from_utf8(out)?;
        assert!(
            text.contains("\"content\":\"Hi\"") && text.contains("\"prompt_tokens\":2"),
            "{text}"
        );
        assert!(text.ends_with("data: [DONE]\n\n"));
        Ok(())
    }

    #[test]
    fn a_watsonx_request_names_its_model_and_project() -> TestResult {
        let (body, stream) = openai_to_watsonx_request(
            &json!({"model": "ibm/granite-3-8b-instruct", "stream": true, "tool_choice": "auto", "messages": []}),
            "p1",
        )?;
        assert!(stream);
        assert_eq!(body["model_id"], "ibm/granite-3-8b-instruct");
        assert_eq!(body["project_id"], "p1");
        assert_eq!(body["tool_choice_option"], "auto");
        assert!(body.get("stream").is_none());
        Ok(())
    }
}
