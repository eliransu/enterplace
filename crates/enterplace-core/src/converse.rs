//! Translation between the OpenAI chat completions format and Amazon Bedrock's Converse API, so a chat client can use
//! every model family Bedrock serves through Converse: Anthropic, Meta Llama, Mistral, Cohere, Amazon Nova, AI21,
//! DeepSeek, Qwen and OpenAI gpt-oss. One body for all of them is the point of Converse; what differs per family
//! (reasoning) goes in `additionalModelRequestFields`.
//!
//! As in [`crate::translate`], a request field that cannot be carried across is an error that names it (AGENTS.md
//! rule 7), and a field at null or its documented default is accepted.
//!
//! Formats as documented on 2026-11-14:
//! - <https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html>
//! - <https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_ConverseStream.html>
//! - <https://docs.aws.amazon.com/bedrock/latest/userguide/conversation-inference-supported-models-features.html>

use std::collections::HashMap;

use serde_json::{Map, Value, json};

use crate::translate::{
    Result, array, data_url, describe, fail, insert, is_openai_default, object, openai_usage,
    string, thinking_budget, tool_input, untranslatable, write_event,
};
use crate::usage::{Usage, sse_data};

const TO_CONVERSE: &str = "Amazon Bedrock's Converse API";
const TO_OPENAI: &str = "the OpenAI chat completions API";

/// Fields dropped on purpose, each with why dropping it cannot change the answer the client gets.
pub const SAFE_TO_DROP: &[(&str, &str)] = &[
    (
        "prompt_cache_key and metadata (OpenAI request)",
        "A routing hint for OpenAI's cache and labels for completions OpenAI stores. Neither changes the answer.",
    ),
    (
        "image_url.detail (OpenAI request)",
        "A resolution hint. The whole image still reaches the model.",
    ),
    (
        "reasoningContent signature (Converse answer)",
        "Proof that the reasoning came from the model, which only Bedrock reads. The reasoning text still reaches the client as reasoning_content.",
    ),
];

/// The model family of a Bedrock model ID, an inference profile (`us.anthropic...`) or an ARN that ends in one.
pub fn family(model_id: &str) -> &str {
    let id = model_id.rsplit('/').next().unwrap_or(model_id);
    let id = [
        "us.", "eu.", "apac.", "global.", "us-gov.", "jp.", "au.", "ca.",
    ]
    .iter()
    .find_map(|p| id.strip_prefix(p))
    .unwrap_or(id);
    id.split('.').next().unwrap_or(id)
}

/// A chat completions request as a Converse body for `model_id` (the Bedrock model ID, which picks how reasoning is
/// asked for), and whether the client asked for a stream (which picks ConverseStream).
pub fn openai_to_converse_request(request: &Value, model_id: &str) -> Result<(Value, bool)> {
    let fields = object(request, "The request body")?;
    let mut out = Map::new();
    let mut config = Map::new();
    let mut extra = Map::new();
    let mut stream = false;
    let mut max_tokens: Option<u64> = None;
    let mut effort: Option<&str> = None;
    let mut tool_choice: Option<Value> = None;
    let mut tools: Option<Vec<Value>> = None;
    let mut temperature = None;
    for (key, value) in fields {
        if value.is_null() {
            continue;
        }
        match key.as_str() {
            // The model is in the URL.
            "model" | "messages" => {}
            "stream" => stream = value.as_bool() == Some(true),
            "stream_options" => {
                for (option, setting) in object(value, "\"stream_options\"")? {
                    if option != "include_usage"
                        && !matches!(setting, Value::Null | Value::Bool(false))
                    {
                        return untranslatable(
                            &format!("The stream option \"{option}\""),
                            TO_CONVERSE,
                        );
                    }
                }
            }
            "temperature" => {
                temperature = value.as_f64();
                insert(&mut config, "temperature", value.clone());
            }
            "top_p" => insert(&mut config, "topP", value.clone()),
            "max_tokens" | "max_completion_tokens" => {
                let Some(n) = value.as_u64() else {
                    return fail(format!("\"{key}\" must be a whole number."));
                };
                if max_tokens.is_some_and(|m| m != n) {
                    return fail(
                        "\"max_tokens\" and \"max_completion_tokens\" differ. Send only one of them."
                            .into(),
                    );
                }
                max_tokens = Some(n);
            }
            "stop" => {
                let stops = match value {
                    Value::String(_) => json!([value]),
                    Value::Array(_) => value.clone(),
                    _ => return fail("\"stop\" must be a string or a list of strings.".into()),
                };
                insert(&mut config, "stopSequences", stops);
            }
            "tools" => tools = Some(converse_tools(value)?),
            "tool_choice" => tool_choice = Some(value.clone()),
            // Converse lets the model call several tools in a turn and has no switch to stop it.
            "parallel_tool_calls" if *value == true => {}
            "reasoning_effort" => match value.as_str() {
                Some("none") => {}
                Some(level @ ("low" | "medium" | "high")) => effort = Some(level),
                _ => return untranslatable(&describe(key, value), TO_CONVERSE),
            },
            "user" | "safety_identifier" => {
                let Some(id) = value.as_str() else {
                    return fail(format!("\"{key}\" must be a string."));
                };
                // Bedrock keeps request metadata in its invocation logs, where an admin filters by it.
                insert(&mut out, "requestMetadata", json!({"user": id}));
            }
            // SAFE_TO_DROP.
            "prompt_cache_key" | "metadata" => {}
            _ if is_openai_default(key, value) => {}
            _ => return untranslatable(&describe(key, value), TO_CONVERSE),
        }
    }
    if let Some(level) = effort {
        let budget = thinking_budget(level).unwrap_or(1024);
        match family(model_id) {
            "anthropic" => {
                if temperature.is_some_and(|t| t != 1.0) {
                    return fail("\"temperature\" with \"reasoning_effort\": Claude takes no temperature while it reasons. Remove temperature, or remove reasoning_effort.".into());
                }
                match max_tokens {
                    Some(max) if max <= budget => {
                        return fail(format!(
                            "\"reasoning_effort\" \"{level}\" gives Claude a reasoning budget of {budget} tokens, which must be less than the max_tokens of {max}. Raise max_tokens above {budget}."
                        ));
                    }
                    None => max_tokens = Some(budget + crate::translate::DEFAULT_MAX_TOKENS),
                    _ => {}
                }
                insert(
                    &mut extra,
                    "thinking",
                    json!({"type": "enabled", "budget_tokens": budget}),
                );
            }
            "amazon" => insert(
                &mut extra,
                "reasoningConfig",
                json!({"type": "enabled", "maxReasoningEffort": level}),
            ),
            "openai" => insert(&mut extra, "reasoning_effort", json!(level)),
            other => {
                return fail(format!(
                    "\"reasoning_effort\" has no equivalent for {other} models on Amazon Bedrock, which take no reasoning setting. Remove it, or use an Anthropic, Amazon Nova or OpenAI gpt-oss model."
                ));
            }
        }
    }
    if let Some(max) = max_tokens {
        insert(&mut config, "maxTokens", json!(max));
    }
    let (system, messages) = converse_messages(&request["messages"])?;
    let history_has_tools = messages.iter().any(|m| {
        m["content"].as_array().is_some_and(|c| {
            c.iter()
                .any(|b| b.get("toolUse").or(b.get("toolResult")).is_some())
        })
    });
    if !system.is_empty() {
        insert(&mut out, "system", Value::Array(system));
    }
    insert(&mut out, "messages", Value::Array(messages));
    match (tools, tool_choice.as_ref().and_then(Value::as_str)) {
        // Converse has no "none": the tools are left out, which is the same thing, unless the conversation already
        // holds tool calls, which Converse reads only with the tools listed.
        (Some(_), Some("none")) if history_has_tools => {
            return untranslatable(
                "\"tool_choice\" \"none\" in a conversation that holds tool calls",
                TO_CONVERSE,
            );
        }
        (Some(_), Some("none")) | (None, _) => {
            if tool_choice
                .as_ref()
                .is_some_and(|c| c.as_str() != Some("none") && c.as_str() != Some("auto"))
            {
                return fail("\"tool_choice\" names a tool, and the request lists no tools. Send tools, or remove tool_choice.".into());
            }
        }
        (Some(tools), _) => {
            let mut tool_config = json!({"tools": tools});
            if let Some(choice) = tool_choice {
                let mapped = match choice.as_str() {
                    Some("auto") => json!({"auto": {}}),
                    Some("required") => json!({"any": {}}),
                    None if choice["type"] == "function" => json!({"tool": {"name": string(
                        &choice["function"]["name"],
                        "\"tool_choice.function.name\""
                    )?}}),
                    _ => return untranslatable(&describe("tool_choice", &choice), TO_CONVERSE),
                };
                tool_config["toolChoice"] = mapped;
            }
            insert(&mut out, "toolConfig", tool_config);
        }
    }
    if !config.is_empty() {
        insert(&mut out, "inferenceConfig", Value::Object(config));
    }
    if !extra.is_empty() {
        insert(
            &mut out,
            "additionalModelRequestFields",
            Value::Object(extra),
        );
    }
    Ok((Value::Object(out), stream))
}

fn converse_tools(tools: &Value) -> Result<Vec<Value>> {
    array(tools, "\"tools\"")?
        .iter()
        .map(|tool| {
            if tool["type"] != "function" {
                return untranslatable(&format!("A tool of type {}", tool["type"]), TO_CONVERSE);
            }
            let mut spec = Map::new();
            for (key, value) in object(&tool["function"], "A tool's \"function\"")? {
                match key.as_str() {
                    _ if value.is_null() => {}
                    "name" | "description" => {
                        spec.insert(key.clone(), value.clone());
                    }
                    "parameters" => insert(&mut spec, "inputSchema", json!({"json": value})),
                    // OpenAI's default, which asks for nothing (Codex sends it on every tool).
                    "strict" if *value == false => {}
                    // Strict schemas are not a Converse option: the model may not follow them exactly.
                    _ => {
                        return untranslatable(
                            &describe(&format!("function.{key}"), value),
                            TO_CONVERSE,
                        );
                    }
                }
            }
            spec.entry("inputSchema")
                .or_insert_with(|| json!({"json": {"type": "object", "properties": {}}}));
            Ok(json!({"toolSpec": spec}))
        })
        .collect()
}

/// Text content as Converse text blocks; empty text is left out, as Converse refuses blank text.
fn text_blocks(content: &Value, role: &str) -> Result<Vec<Value>> {
    let texts: Vec<&str> = match content {
        Value::String(text) => vec![text],
        Value::Array(parts) => parts
            .iter()
            .map(|part| match part["type"].as_str() {
                Some("text") => string(&part["text"], "A text part's \"text\""),
                other => untranslatable(
                    &format!("A {} part in a {role} message", other.unwrap_or("untyped")),
                    TO_CONVERSE,
                ),
            })
            .collect::<Result<_>>()?,
        Value::Null => Vec::new(),
        _ => {
            return fail(format!(
                "A {role} message needs \"content\" that is a string or a list of parts."
            ));
        }
    };
    Ok(texts
        .into_iter()
        .filter(|t| !t.trim().is_empty())
        .map(|t| json!({"text": t}))
        .collect())
}

/// The image formats Converse takes, by media type.
fn image_format(media_type: &str) -> Result<&'static str> {
    match media_type {
        "image/png" => Ok("png"),
        "image/jpeg" | "image/jpg" => Ok("jpeg"),
        "image/gif" => Ok("gif"),
        "image/webp" => Ok("webp"),
        other => fail(format!(
            "An image of type {other}: Amazon Bedrock takes png, jpeg, gif and webp. Convert it to one of those."
        )),
    }
}

fn user_blocks(content: &Value) -> Result<Vec<Value>> {
    let Value::Array(parts) = content else {
        return text_blocks(content, "user");
    };
    let mut out = Vec::new();
    for part in parts {
        match part["type"].as_str() {
            Some("text") => {
                let text = string(&part["text"], "A text part's \"text\"")?;
                if !text.trim().is_empty() {
                    out.push(json!({"text": text}));
                }
            }
            // image_url.detail: SAFE_TO_DROP.
            Some("image_url") => {
                let url = string(
                    &part["image_url"]["url"],
                    "An image part's \"image_url.url\"",
                )?;
                if !url.starts_with("data:") {
                    return fail("An image by URL: Amazon Bedrock takes images inline only. Send it as a base64 data URL (data:image/png;base64,...).".into());
                }
                let (media_type, data) = data_url(url)?;
                out.push(json!({"image": {"format": image_format(media_type)?, "source": {"bytes": data}}}));
            }
            Some("file") => {
                let file = &part["file"];
                if !file["file_id"].is_null() {
                    return untranslatable("An OpenAI file ID", TO_CONVERSE);
                }
                let (media_type, data) = data_url(string(
                    &file["file_data"],
                    "A file part's \"file.file_data\"",
                )?)?;
                let format = match media_type {
                    "application/pdf" => "pdf",
                    "text/csv" => "csv",
                    "text/plain" => "txt",
                    "text/html" => "html",
                    "text/markdown" => "md",
                    other => {
                        return fail(format!(
                            "A file of type {other}: Amazon Bedrock takes pdf, csv, txt, html and md documents. Convert it to one of those."
                        ));
                    }
                };
                // Bedrock's document names allow letters, digits, spaces, hyphens, parentheses and brackets.
                let name: String = file["filename"]
                    .as_str()
                    .unwrap_or("document")
                    .chars()
                    .map(|c| {
                        if c.is_ascii_alphanumeric() || " -()[]".contains(c) {
                            c
                        } else {
                            '-'
                        }
                    })
                    .collect();
                out.push(json!({"document": {"format": format, "name": name, "source": {"bytes": data}}}));
            }
            other => {
                return untranslatable(
                    &format!("A content part of type \"{}\"", other.unwrap_or("none")),
                    TO_CONVERSE,
                );
            }
        }
    }
    Ok(out)
}

/// Converse wants user and assistant turns to alternate, and every tool result of a turn in one user message.
fn push(out: &mut Vec<Value>, role: &str, mut blocks: Vec<Value>) {
    if blocks.is_empty() {
        return;
    }
    if let Some(content) = out
        .last_mut()
        .filter(|m| m["role"] == role)
        .and_then(|m| m.get_mut("content"))
        .and_then(Value::as_array_mut)
    {
        content.append(&mut blocks);
        return;
    }
    out.push(json!({"role": role, "content": blocks}));
}

/// The system texts, and the rest as Converse messages.
fn converse_messages(messages: &Value) -> Result<(Vec<Value>, Vec<Value>)> {
    let mut system = Vec::new();
    let mut out: Vec<Value> = Vec::new();
    for message in array(messages, "\"messages\"")? {
        let fields = object(message, "Each message")?;
        let role = message["role"].as_str().unwrap_or_default();
        for (key, value) in fields {
            let known = matches!(
                (role, key.as_str()),
                (_, "role" | "content") | ("assistant", "tool_calls") | ("tool", "tool_call_id")
            );
            if !known && !value.is_null() {
                return untranslatable(
                    &format!("The field \"{key}\" on a {role} message"),
                    TO_CONVERSE,
                );
            }
        }
        let content = &message["content"];
        match role {
            "system" | "developer" => {
                if !out.is_empty() {
                    return untranslatable(
                        "A system message after the conversation has started",
                        TO_CONVERSE,
                    );
                }
                system.extend(text_blocks(content, role)?);
            }
            "user" => push(&mut out, "user", user_blocks(content)?),
            "assistant" => {
                let mut blocks = text_blocks(content, "assistant")?;
                if let Some(calls) = message.get("tool_calls").filter(|c| !c.is_null()) {
                    for call in array(calls, "\"tool_calls\"")? {
                        if call["type"].as_str().is_some_and(|t| t != "function") {
                            return untranslatable(
                                &format!("A tool call of type {}", call["type"]),
                                TO_CONVERSE,
                            );
                        }
                        let id = string(&call["id"], "A tool call's \"id\"")?;
                        let name =
                            string(&call["function"]["name"], "A tool call's \"function.name\"")?;
                        let input = tool_input(
                            id,
                            call["function"]["arguments"].as_str().unwrap_or_default(),
                        )?;
                        blocks.push(
                            json!({"toolUse": {"toolUseId": id, "name": name, "input": input}}),
                        );
                    }
                }
                push(&mut out, "assistant", blocks);
            }
            "tool" => {
                let id = string(
                    &message["tool_call_id"],
                    "A tool message's \"tool_call_id\"",
                )?;
                let mut result = text_blocks(content, role)?;
                if result.is_empty() {
                    result.push(json!({"text": "(empty)"}));
                }
                push(
                    &mut out,
                    "user",
                    vec![json!({"toolResult": {"toolUseId": id, "content": result}})],
                );
            }
            _ => {
                return untranslatable(&format!("A message with role \"{role}\""), TO_CONVERSE);
            }
        }
    }
    Ok((system, out))
}

/// Converse usage: input excludes what was read from or written to the cache, which come separately.
pub fn usage(usage: &Value) -> Usage {
    let count = |key: &str| usage[key].as_u64().unwrap_or_default();
    Usage {
        input: count("inputTokens"),
        output: count("outputTokens"),
        cache_read: count("cacheReadInputTokens"),
        cache_write: count("cacheWriteInputTokens"),
        ..Usage::default()
    }
}

fn finish_reason(stop: &Value) -> Result<Value> {
    Ok(match stop.as_str() {
        None => Value::Null,
        Some("end_turn" | "stop_sequence") => json!("stop"),
        Some("max_tokens" | "model_context_window_exceeded") => json!("length"),
        Some("tool_use") => json!("tool_calls"),
        Some("guardrail_intervened" | "content_filtered") => json!("content_filter"),
        Some(other) => return untranslatable(&format!("The stop reason \"{other}\""), TO_OPENAI),
    })
}

/// A Converse answer as an OpenAI chat completion. `id` and `model` are the gateway's, as Converse carries neither.
pub fn converse_to_openai_response(
    answer: &Value,
    id: &str,
    model: &str,
    created: u64,
) -> Result<Value> {
    object(answer, "The provider's answer")?;
    let mut text = String::new();
    let mut reasoning = String::new();
    let mut calls = Vec::new();
    for block in answer["output"]["message"]["content"]
        .as_array()
        .map_or(&[][..], Vec::as_slice)
    {
        if let Some(t) = block["text"].as_str() {
            text.push_str(t);
        } else if let Some(r) = block["reasoningContent"]["reasoningText"]["text"].as_str() {
            reasoning.push_str(r);
        } else if block["reasoningContent"]["redactedContent"].is_string() {
            // Encrypted reasoning: nothing a client can read, and its tokens stay counted in usage.
        } else if block["toolUse"].is_object() {
            let call = &block["toolUse"];
            calls.push(json!({"id": call["toolUseId"], "type": "function", "function": {"name": call["name"], "arguments": call["input"].to_string()}}));
        } else {
            let kind = block
                .as_object()
                .and_then(|b| b.keys().next())
                .map_or("empty", String::as_str);
            return untranslatable(&format!("A {kind} block in the answer"), TO_OPENAI);
        }
    }
    let mut message = json!({"role": "assistant", "content": (!text.is_empty() || calls.is_empty()).then_some(text)});
    if let Some(fields) = message.as_object_mut() {
        if !calls.is_empty() {
            insert(fields, "tool_calls", Value::Array(calls));
        }
        if !reasoning.is_empty() {
            insert(fields, "reasoning_content", json!(reasoning));
        }
    }
    Ok(json!({
        "id": id,
        "object": "chat.completion",
        "created": created,
        "model": model,
        "choices": [{"index": 0, "message": message, "logprobs": null, "finish_reason": finish_reason(&answer["stopReason"])?}],
        "usage": openai_usage(&usage(&answer["usage"])),
    }))
}

/// Turns a ConverseStream answer (decoded by `eventstream::ConverseToSse` into one `{"<event>": payload}` per data
/// line) into an OpenAI chat completions stream as bytes arrive.
#[derive(Debug)]
pub struct ConverseToOpenAiStream {
    include_usage: bool,
    id: String,
    model: String,
    created: u64,
    line: Vec<u8>,
    /// Converse content block index to OpenAI tool call index.
    calls: HashMap<u64, usize>,
    stopped: bool,
    done: bool,
    failed: bool,
}

impl ConverseToOpenAiStream {
    pub fn new(include_usage: bool, id: String, model: String, created: u64) -> Self {
        Self {
            include_usage,
            id,
            model,
            created,
            line: Vec::new(),
            calls: HashMap::new(),
            stopped: false,
            done: false,
            failed: false,
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

    /// The end of the provider's stream: fails if Converse never said why the answer stopped.
    pub fn finish(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let line = std::mem::take(&mut self.line);
        self.on_line(&line, &mut out)?;
        if self.failed {
            return Ok(out);
        }
        if !self.stopped {
            return fail("The provider's stream ended before it said why the answer stopped, so the answer is incomplete. Retry the request.".into());
        }
        if !self.done {
            out.extend_from_slice(b"data: [DONE]\n\n");
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
        if self.failed || self.done {
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
        if event["error"].is_object() {
            write_event(out, &event);
            self.failed = true;
            return Ok(());
        }
        if event["messageStart"].is_object() {
            write_event(
                out,
                &self.chunk(json!({"role": "assistant", "content": ""}), Value::Null),
            );
        } else if let Some(start) = event.get("contentBlockStart") {
            if let Some(tool) = start["start"]["toolUse"].as_object() {
                let index = self.calls.len();
                self.calls.insert(
                    start["contentBlockIndex"].as_u64().unwrap_or_default(),
                    index,
                );
                write_event(out, &self.chunk(json!({"tool_calls": [{"index": index, "id": tool.get("toolUseId"), "type": "function", "function": {"name": tool.get("name"), "arguments": ""}}]}), Value::Null));
            }
        } else if let Some(block) = event.get("contentBlockDelta") {
            let delta = &block["delta"];
            if let Some(text) = delta["text"].as_str() {
                write_event(out, &self.chunk(json!({"content": text}), Value::Null));
            } else if let Some(input) = delta["toolUse"]["input"].as_str() {
                let at = block["contentBlockIndex"].as_u64().unwrap_or_default();
                let Some(index) = self.calls.get(&at) else {
                    return fail("The provider streamed tool input for a block it never started. Retry the request.".into());
                };
                write_event(
                    out,
                    &self.chunk(
                        json!({"tool_calls": [{"index": index, "function": {"arguments": input}}]}),
                        Value::Null,
                    ),
                );
            } else if let Some(text) = delta["reasoningContent"]["text"].as_str() {
                write_event(
                    out,
                    &self.chunk(json!({"reasoning_content": text}), Value::Null),
                );
            }
            // A reasoning signature or redacted reasoning carries nothing a chat client reads.
        } else if let Some(stop) = event.get("messageStop") {
            let finish = finish_reason(&stop["stopReason"])?;
            write_event(out, &self.chunk(json!({}), finish));
            self.stopped = true;
        } else if let Some(meta) = event.get("metadata") {
            if self.include_usage && meta["usage"].is_object() {
                let chunk = json!({
                    "id": self.id, "object": "chat.completion.chunk", "created": self.created,
                    "model": self.model, "choices": [], "usage": openai_usage(&usage(&meta["usage"])),
                });
                write_event(out, &chunk);
            }
            if self.stopped {
                out.extend_from_slice(b"data: [DONE]\n\n");
                self.done = true;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn a_chat_request_becomes_a_converse_body() -> TestResult {
        let chat = json!({
            "model": "llama", "max_tokens": 300, "temperature": 0.2, "stop": "END", "user": "maya",
            "messages": [
                {"role": "system", "content": "Be brief."},
                {"role": "user", "content": [{"type": "text", "text": "What is this?"}, {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}}]},
                {"role": "assistant", "content": null, "tool_calls": [{"id": "t1", "type": "function", "function": {"name": "look", "arguments": "{\"q\":1}"}}]},
                {"role": "tool", "tool_call_id": "t1", "content": "a cat"},
            ],
            "tools": [{"type": "function", "function": {"name": "look", "parameters": {"type": "object"}}}],
            "tool_choice": "required",
        });
        let (body, stream) = openai_to_converse_request(&chat, "meta.llama3-1-70b-instruct-v1:0")?;
        assert!(!stream);
        assert_eq!(body["system"], json!([{"text": "Be brief."}]));
        assert_eq!(body["messages"][0]["content"][1]["image"]["format"], "png");
        assert_eq!(
            body["messages"][1]["content"][0]["toolUse"]["input"],
            json!({"q": 1})
        );
        assert_eq!(
            body["messages"][2]["content"][0]["toolResult"]["toolUseId"],
            "t1"
        );
        assert_eq!(
            body["inferenceConfig"],
            json!({"maxTokens": 300, "temperature": 0.2, "stopSequences": ["END"]})
        );
        assert_eq!(body["toolConfig"]["toolChoice"], json!({"any": {}}));
        assert_eq!(
            body["toolConfig"]["tools"][0]["toolSpec"]["inputSchema"]["json"]["type"],
            "object"
        );
        assert_eq!(body["requestMetadata"]["user"], "maya");
        Ok(())
    }

    #[test]
    fn reasoning_effort_maps_per_family_and_is_refused_where_none_exists() -> TestResult {
        let ask = |model: &str, extra: Value| {
            let mut chat = json!({"model": "m", "messages": [{"role": "user", "content": "hi"}], "reasoning_effort": "medium"});
            if let (Some(c), Some(e)) = (chat.as_object_mut(), extra.as_object()) {
                c.extend(e.clone());
            }
            openai_to_converse_request(&chat, model)
        };
        let (claude, _) = ask("us.anthropic.claude-sonnet-5-5-v1:0", json!({}))?;
        assert_eq!(
            claude["additionalModelRequestFields"]["thinking"],
            json!({"type": "enabled", "budget_tokens": 4096})
        );
        assert_eq!(
            claude["inferenceConfig"]["maxTokens"],
            4096 + crate::translate::DEFAULT_MAX_TOKENS
        );
        let (nova, _) = ask("amazon.nova-2-lite-v1:0", json!({}))?;
        assert_eq!(
            nova["additionalModelRequestFields"]["reasoningConfig"]["maxReasoningEffort"],
            "medium"
        );
        let (oss, _) = ask("openai.gpt-oss-120b-1:0", json!({}))?;
        assert_eq!(
            oss["additionalModelRequestFields"]["reasoning_effort"],
            "medium"
        );
        let too_small = ask(
            "anthropic.claude-sonnet-5-5-v1:0",
            json!({"max_tokens": 1000}),
        );
        assert!(too_small.is_err_and(|e| e.to_string().contains("Raise max_tokens")));
        let llama = ask("meta.llama3-1-70b-instruct-v1:0", json!({}));
        assert!(llama.is_err_and(|e| e.to_string().contains("meta models")));
        Ok(())
    }

    #[test]
    fn untranslatable_fields_are_refused_by_name() {
        for (extra, named) in [
            (json!({"n": 2}), "\"n\""),
            (
                json!({"response_format": {"type": "json_object"}}),
                "\"response_format\"",
            ),
            (json!({"logprobs": true}), "\"logprobs\""),
        ] {
            let mut chat = json!({"model": "m", "messages": [{"role": "user", "content": "hi"}]});
            if let (Some(c), Some(e)) = (chat.as_object_mut(), extra.as_object()) {
                c.extend(e.clone());
            }
            let err = openai_to_converse_request(&chat, "mistral.mistral-large-2407-v1:0");
            assert!(err.is_err_and(|e| e.to_string().contains(named)), "{named}");
        }
    }

    #[test]
    fn a_converse_answer_becomes_a_chat_completion() -> TestResult {
        let answer = json!({
            "output": {"message": {"role": "assistant", "content": [
                {"reasoningContent": {"reasoningText": {"text": "Think.", "signature": "s"}}},
                {"text": "Calling."},
                {"toolUse": {"toolUseId": "t9", "name": "look", "input": {"q": 2}}},
            ]}},
            "stopReason": "tool_use",
            "usage": {"inputTokens": 10, "outputTokens": 5, "totalTokens": 15, "cacheReadInputTokens": 4},
        });
        let chat = converse_to_openai_response(&answer, "chatcmpl-1", "nova", 7)?;
        let choice = &chat["choices"][0];
        assert_eq!(choice["finish_reason"], "tool_calls");
        assert_eq!(choice["message"]["content"], "Calling.");
        assert_eq!(choice["message"]["reasoning_content"], "Think.");
        assert_eq!(
            choice["message"]["tool_calls"][0]["function"]["arguments"],
            "{\"q\":2}"
        );
        assert_eq!(chat["usage"]["prompt_tokens"], 14);
        assert_eq!(chat["usage"]["prompt_tokens_details"]["cached_tokens"], 4);
        Ok(())
    }

    #[test]
    fn a_converse_stream_becomes_chat_chunks() -> TestResult {
        let events = [
            json!({"messageStart": {"role": "assistant"}}),
            json!({"contentBlockDelta": {"contentBlockIndex": 0, "delta": {"text": "Hel"}}}),
            json!({"contentBlockDelta": {"contentBlockIndex": 0, "delta": {"text": "lo"}}}),
            json!({"contentBlockStart": {"contentBlockIndex": 1, "start": {"toolUse": {"toolUseId": "t1", "name": "f"}}}}),
            json!({"contentBlockDelta": {"contentBlockIndex": 1, "delta": {"toolUse": {"input": "{}"}}}}),
            json!({"messageStop": {"stopReason": "tool_use"}}),
            json!({"metadata": {"usage": {"inputTokens": 3, "outputTokens": 2}}}),
        ];
        let sse: String = events.iter().map(|e| format!("data: {e}\n\n")).collect();
        let mut stream = ConverseToOpenAiStream::new(true, "c1".into(), "m".into(), 1);
        let mut out = Vec::new();
        for piece in sse.as_bytes().chunks(7) {
            out.extend(stream.feed(piece)?);
        }
        out.extend(stream.finish()?);
        let text = String::from_utf8(out)?;
        assert!(text.contains("\"content\":\"Hel\""), "{text}");
        assert!(text.contains("\"finish_reason\":\"tool_calls\""), "{text}");
        assert!(text.contains("\"prompt_tokens\":3"), "{text}");
        assert!(text.ends_with("data: [DONE]\n\n"), "{text}");
        Ok(())
    }
}
