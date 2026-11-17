//! Translation between the OpenAI chat completions format and Google's Gemini generateContent format, so a chat
//! client can use a model on the Gemini API or on Vertex AI, which take the same body.
//!
//! Requests translate from chat to Gemini; whole and streamed (`alt=sse`) answers translate back. As in
//! [`crate::translate`], a request field that cannot be carried across is an error that names it (AGENTS.md
//! rule 7), a field at null or its documented default is accepted, and the fields dropped on purpose are listed in
//! [`SAFE_TO_DROP`].
//!
//! Formats as documented on 2026-11-13:
//! - <https://ai.google.dev/api/generate-content> (now served at <https://aistudio.google.com/api-reference/generate-content>)
//! - <https://docs.cloud.google.com/vertex-ai/generative-ai/docs/model-reference/function-calling>

use std::collections::HashMap;

use serde_json::{Map, Value, json};

use crate::translate::{
    Result, array, data_url, describe, fail, insert, is_openai_default, object, openai_usage,
    string, tool_input, untranslatable, write_event,
};
use crate::usage::{Usage, sse_data};

const TO_GEMINI: &str = "Google's Gemini API";
const TO_OPENAI: &str = "the OpenAI chat completions API";

/// Fields dropped on purpose, each with why dropping it cannot change the answer the client gets.
pub const SAFE_TO_DROP: &[(&str, &str)] = &[
    (
        "user and safety_identifier (OpenAI request)",
        "An end-user ID for OpenAI's abuse monitoring. Gemini takes none, and no answer depends on it.",
    ),
    (
        "prompt_cache_key and metadata (OpenAI request)",
        "A routing hint for OpenAI's cache and labels for completions OpenAI stores. Neither changes the answer.",
    ),
    (
        "image_url.detail (OpenAI request)",
        "A resolution hint. The whole image still reaches the model.",
    ),
    (
        "response_format.json_schema name, description and strict (OpenAI request)",
        "A label for the schema and a strictness switch. The schema itself goes to Gemini as responseJsonSchema.",
    ),
    (
        "thought parts and thoughtSignature (Gemini answer)",
        "The model's private reasoning. Its tokens stay counted in usage as completion tokens.",
    ),
];

/// A chat completions request as a Gemini generateContent body, and whether the client asked for a stream (which
/// picks streamGenerateContent).
pub fn openai_to_gemini_request(request: &Value) -> Result<(Value, bool)> {
    let fields = object(request, "The request body")?;
    let mut out = Map::new();
    let mut config = Map::new();
    let mut stream = false;
    let mut max_tokens: Option<&Value> = None;
    for (key, value) in fields {
        if value.is_null() {
            continue;
        }
        let mut set = |name: &str| insert(&mut config, name, value.clone());
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
                            TO_GEMINI,
                        );
                    }
                }
            }
            "temperature" => set("temperature"),
            "top_p" => set("topP"),
            "presence_penalty" => set("presencePenalty"),
            "frequency_penalty" => set("frequencyPenalty"),
            "seed" => set("seed"),
            "max_tokens" | "max_completion_tokens" => {
                if max_tokens.is_some_and(|m| m != value) {
                    return fail(
                        "\"max_tokens\" and \"max_completion_tokens\" differ. Send only one of them."
                            .into(),
                    );
                }
                max_tokens = Some(value);
            }
            "stop" => {
                let stops = match value {
                    Value::String(_) => json!([value]),
                    Value::Array(_) => value.clone(),
                    _ => return fail("\"stop\" must be a string or a list of strings.".into()),
                };
                insert(&mut config, "stopSequences", stops);
            }
            "response_format" => match value["type"].as_str() {
                Some("text") => {}
                Some("json_object") => {
                    insert(&mut config, "responseMimeType", json!("application/json"));
                }
                Some("json_schema") => {
                    let schema = &value["json_schema"]["schema"];
                    if !schema.is_object() {
                        return fail(
                            "\"response_format.json_schema.schema\" must be a JSON schema object."
                                .into(),
                        );
                    }
                    insert(&mut config, "responseMimeType", json!("application/json"));
                    insert(&mut config, "responseJsonSchema", schema.clone());
                }
                _ => {
                    return untranslatable(&describe("response_format", &value["type"]), TO_GEMINI);
                }
            },
            "tools" => insert(&mut out, "tools", gemini_tools(value)?),
            "tool_choice" => insert(&mut out, "toolConfig", gemini_tool_choice(value)?),
            // Gemini may call several functions in one turn and has no switch to stop it.
            "parallel_tool_calls" if *value == true => {}
            // Gemini 3 takes a thinking level; Gemini 2.5 a budget in tokens (translate::thinking_budget).
            "reasoning_effort" => {
                let gemini_3 = request["model"]
                    .as_str()
                    .is_some_and(|m| m.contains("gemini-3"));
                let thinking = match (value.as_str(), gemini_3) {
                    (Some("none"), false) => json!({"thinkingBudget": 0}),
                    (Some(level @ ("minimal" | "low" | "medium" | "high")), true) => {
                        json!({"thinkingLevel": level})
                    }
                    (Some(level), false) if crate::translate::thinking_budget(level).is_some() => {
                        json!({"thinkingBudget": crate::translate::thinking_budget(level)})
                    }
                    _ => return untranslatable(&describe(key, value), TO_GEMINI),
                };
                insert(&mut config, "thinkingConfig", thinking);
            }
            // SAFE_TO_DROP.
            "user" | "safety_identifier" | "prompt_cache_key" | "metadata" => {}
            _ if is_openai_default(key, value) => {}
            _ => return untranslatable(&describe(key, value), TO_GEMINI),
        }
    }
    if let Some(max) = max_tokens {
        insert(&mut config, "maxOutputTokens", max.clone());
    }
    let (system, contents) = gemini_contents(&request["messages"])?;
    if !system.is_empty() {
        insert(
            &mut out,
            "systemInstruction",
            json!({"parts": system.into_iter().map(|t| json!({"text": t})).collect::<Vec<_>>()}),
        );
    }
    insert(&mut out, "contents", Value::Array(contents));
    if !config.is_empty() {
        insert(&mut out, "generationConfig", Value::Object(config));
    }
    Ok((Value::Object(out), stream))
}

/// The texts of a system, developer or tool message.
fn texts(content: &Value, role: &str) -> Result<Vec<String>> {
    match content {
        Value::String(text) => Ok(vec![text.clone()]),
        Value::Array(parts) => parts
            .iter()
            .map(|part| match part["type"].as_str() {
                Some("text") => string(&part["text"], "A text part's \"text\"").map(String::from),
                other => untranslatable(
                    &format!("A {} part in a {role} message", other.unwrap_or("untyped")),
                    TO_GEMINI,
                ),
            })
            .collect(),
        _ => fail(format!(
            "A {role} message needs \"content\" that is a string or a list of parts."
        )),
    }
}

/// The leading system and developer messages as system instruction texts, and the rest as Gemini contents.
fn gemini_contents(messages: &Value) -> Result<(Vec<String>, Vec<Value>)> {
    let messages = array(messages, "\"messages\"")?;
    let mut system = Vec::new();
    let mut out: Vec<Value> = Vec::new();
    // Gemini's function response names the function; OpenAI's tool message names only the call.
    let mut called: HashMap<String, String> = HashMap::new();
    for message in messages {
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
                    TO_GEMINI,
                );
            }
        }
        let content = &message["content"];
        match role {
            "system" | "developer" => {
                if !out.is_empty() {
                    return untranslatable(
                        &format!("A {role} message after the conversation has started"),
                        TO_GEMINI,
                    );
                }
                system.extend(texts(content, role)?);
            }
            "user" => push(&mut out, "user", user_parts(content)?),
            "assistant" => {
                let mut parts: Vec<Value> = match content {
                    Value::Null => Vec::new(),
                    content => texts(content, role)?
                        .into_iter()
                        .filter(|t| !t.is_empty())
                        .map(|t| json!({"text": t}))
                        .collect(),
                };
                if let Some(calls) = message.get("tool_calls").filter(|c| !c.is_null()) {
                    for call in array(calls, "\"tool_calls\"")? {
                        if call["type"].as_str().is_some_and(|t| t != "function") {
                            return untranslatable(
                                &format!("A tool call of type {}", call["type"]),
                                TO_GEMINI,
                            );
                        }
                        let id = string(&call["id"], "A tool call's \"id\"")?;
                        let name =
                            string(&call["function"]["name"], "A tool call's \"function.name\"")?;
                        let args = tool_input(
                            id,
                            call["function"]["arguments"].as_str().unwrap_or_default(),
                        )?;
                        called.insert(id.to_string(), name.to_string());
                        parts.push(json!({"functionCall": {"id": id, "name": name, "args": args}}));
                    }
                }
                if parts.is_empty() {
                    parts.push(json!({"text": ""}));
                }
                push(&mut out, "model", parts);
            }
            "tool" => {
                let id = string(
                    &message["tool_call_id"],
                    "A tool message's \"tool_call_id\"",
                )?;
                let Some(name) = called.get(id) else {
                    return fail(format!(
                        "The tool message answers tool call \"{id}\", which no earlier assistant message made. Gemini needs the function's name, so send the assistant message with that tool call first."
                    ));
                };
                let text = texts(content, role)?.concat();
                push(
                    &mut out,
                    "user",
                    vec![
                        json!({"functionResponse": {"id": id, "name": name, "response": {"content": text}}}),
                    ],
                );
            }
            _ => return untranslatable(&format!("A message with role \"{role}\""), TO_GEMINI),
        }
    }
    Ok((system, out))
}

/// Consecutive turns of one role are merged: the results of parallel tool calls go back in one turn.
fn push(out: &mut Vec<Value>, role: &str, mut parts: Vec<Value>) {
    if let Some(last) = out.last_mut().filter(|c| c["role"] == role) {
        if let Some(existing) = last.get_mut("parts").and_then(Value::as_array_mut) {
            existing.append(&mut parts);
            return;
        }
    }
    out.push(json!({"role": role, "parts": parts}));
}

fn user_parts(content: &Value) -> Result<Vec<Value>> {
    let Value::Array(parts) = content else {
        return Ok(texts(content, "user")?
            .into_iter()
            .map(|t| json!({"text": t}))
            .collect());
    };
    parts
        .iter()
        .map(|part| match part["type"].as_str() {
            Some("text") => Ok(json!({"text": string(&part["text"], "A text part's \"text\"")?})),
            // image_url.detail: SAFE_TO_DROP.
            Some("image_url") => {
                let url = string(
                    &part["image_url"]["url"],
                    "An image part's \"image_url.url\"",
                )?;
                if url.starts_with("data:") {
                    let (mime, data) = data_url(url)?;
                    Ok(json!({"inlineData": {"mimeType": mime, "data": data}}))
                } else {
                    Ok(json!({"fileData": {"fileUri": url}}))
                }
            }
            Some("file") => {
                let file = &part["file"];
                if !file["file_id"].is_null() {
                    return untranslatable("An OpenAI file ID", TO_GEMINI);
                }
                let (mime, data) = data_url(string(
                    &file["file_data"],
                    "A file part's \"file.file_data\"",
                )?)?;
                Ok(json!({"inlineData": {"mimeType": mime, "data": data}}))
            }
            other => untranslatable(
                &format!("A content part of type \"{}\"", other.unwrap_or("none")),
                TO_GEMINI,
            ),
        })
        .collect()
}

fn gemini_tools(tools: &Value) -> Result<Value> {
    let declarations = array(tools, "\"tools\"")?
        .iter()
        .map(|tool| {
            if tool["type"] != "function" {
                return untranslatable(&format!("A tool of type {}", tool["type"]), TO_GEMINI);
            }
            let mut out = Map::new();
            for (key, value) in object(&tool["function"], "A tool's \"function\"")? {
                match key.as_str() {
                    _ if value.is_null() => {}
                    "name" | "description" => {
                        out.insert(key.clone(), value.clone());
                    }
                    "parameters" => insert(&mut out, "parametersJsonSchema", value.clone()),
                    "strict" if *value == false => {}
                    _ => {
                        return untranslatable(
                            &describe(&format!("function.{key}"), value),
                            TO_GEMINI,
                        );
                    }
                }
            }
            Ok(Value::Object(out))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(json!([{"functionDeclarations": declarations}]))
}

fn gemini_tool_choice(choice: &Value) -> Result<Value> {
    let config = match choice.as_str() {
        Some("none") => json!({"mode": "NONE"}),
        Some("auto") => json!({"mode": "AUTO"}),
        Some("required") => json!({"mode": "ANY"}),
        None if choice["type"] == "function" => {
            let name = string(&choice["function"]["name"], "\"tool_choice.function.name\"")?;
            json!({"mode": "ANY", "allowedFunctionNames": [name]})
        }
        _ => return untranslatable(&describe("tool_choice", choice), TO_GEMINI),
    };
    Ok(json!({"functionCallingConfig": config}))
}

// ---------------------------------------------------------------------------------------------------------
// Answers.

fn finish_reason(reason: &Value, called: bool) -> Result<Value> {
    Ok(match reason.as_str() {
        None => Value::Null,
        Some("STOP") if called => json!("tool_calls"),
        Some("STOP") => json!("stop"),
        Some("MAX_TOKENS") => json!("length"),
        Some(
            "SAFETY"
            | "RECITATION"
            | "BLOCKLIST"
            | "PROHIBITED_CONTENT"
            | "SPII"
            | "IMAGE_SAFETY"
            | "IMAGE_PROHIBITED_CONTENT"
            | "IMAGE_RECITATION",
        ) => json!("content_filter"),
        // MALFORMED_FUNCTION_CALL, MISSING_THOUGHT_SIGNATURE and the like say the answer failed; naming them is
        // more use to the caller than a plain stop.
        Some(other) => {
            return untranslatable(&format!("The finish reason \"{other}\""), TO_OPENAI);
        }
    })
}

/// The text and tool calls of a candidate's parts. `first_call` numbers tool calls that carry no ID.
fn read_parts(candidate: &Value, first_call: usize) -> Result<(String, Vec<Value>)> {
    let mut text = String::new();
    let mut calls = Vec::new();
    for part in candidate["content"]["parts"]
        .as_array()
        .map_or(&[][..], Vec::as_slice)
    {
        // Thought summaries and signatures: SAFE_TO_DROP.
        if part["thought"] == true {
            continue;
        }
        if let Some(t) = part["text"].as_str() {
            text.push_str(t);
        } else if part["functionCall"].is_object() {
            let call = &part["functionCall"];
            let id = call["id"].as_str().map_or_else(
                || format!("call_{}", first_call + calls.len()),
                String::from,
            );
            let args = match &call["args"] {
                Value::Null => "{}".to_string(),
                args => args.to_string(),
            };
            calls.push(json!({"id": id, "type": "function", "function": {"name": call["name"], "arguments": args}}));
        } else {
            let kind = part
                .as_object()
                .and_then(|p| p.keys().find(|k| *k != "thoughtSignature"))
                .map_or("empty", String::as_str);
            return untranslatable(&format!("A {kind} part in the answer"), TO_OPENAI);
        }
    }
    Ok((text, calls))
}

/// A Gemini generateContent answer as an OpenAI chat completion. `created` is the Unix time in seconds.
pub fn gemini_to_openai_response(answer: &Value, created: u64) -> Result<Value> {
    object(answer, "The provider's answer")?;
    let candidates = answer["candidates"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    let mut choices = Vec::new();
    for (index, candidate) in candidates.iter().enumerate() {
        let (text, calls) = read_parts(candidate, 0)?;
        let finish = finish_reason(&candidate["finishReason"], !calls.is_empty())?;
        let mut reply = json!({"role": "assistant", "content": (!text.is_empty() || calls.is_empty()).then_some(text)});
        if let (false, Some(fields)) = (calls.is_empty(), reply.as_object_mut()) {
            insert(fields, "tool_calls", Value::Array(calls));
        }
        choices.push(
            json!({"index": index, "message": reply, "logprobs": null, "finish_reason": finish}),
        );
    }
    if choices.is_empty() && !answer["promptFeedback"]["blockReason"].is_null() {
        // The prompt itself was blocked: no candidate at all.
        choices.push(json!({"index": 0, "message": {"role": "assistant", "content": null}, "logprobs": null, "finish_reason": "content_filter"}));
    }
    Ok(json!({
        "id": answer["responseId"],
        "object": "chat.completion",
        "created": created,
        "model": answer["modelVersion"],
        "choices": choices,
        "usage": openai_usage(&Usage::from_gemini(&answer["usageMetadata"])),
    }))
}

/// Turns a Gemini `streamGenerateContent?alt=sse` stream into an OpenAI chat completions stream as bytes arrive.
#[derive(Debug)]
pub struct GeminiToOpenAiStream {
    include_usage: bool,
    created: u64,
    line: Vec<u8>,
    id: Value,
    model: Value,
    started: bool,
    calls: usize,
    usage: Usage,
    /// A chunk carried a finish reason: the answer is whole.
    finished: bool,
    /// An error event ended the stream.
    failed: bool,
}

impl GeminiToOpenAiStream {
    /// The chunk ID to use when the provider sends no `responseId`.
    pub fn with_id(mut self, id: String) -> Self {
        self.id = Value::String(id);
        self
    }

    /// `include_usage` is the client's `stream_options.include_usage`; `created` is the Unix time in seconds.
    pub fn new(include_usage: bool, created: u64) -> Self {
        Self {
            include_usage,
            created,
            line: Vec::new(),
            id: Value::Null,
            model: Value::Null,
            started: false,
            calls: 0,
            usage: Usage::default(),
            finished: false,
            failed: false,
        }
    }

    /// Feeds the next bytes of the provider's stream, split anywhere, and returns the OpenAI bytes ready to send.
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

    /// Call when the provider's stream ends. Gemini sends no end event, so the end is here: the usage chunk if the
    /// client asked for it, then `[DONE]`. Fails if no chunk carried a finish reason.
    pub fn finish(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let line = std::mem::take(&mut self.line);
        self.on_line(&line, &mut out)?;
        if self.failed {
            return Ok(out);
        }
        if !self.finished {
            return fail(
                "The provider's stream ended before a chunk with a finish reason, so the answer is incomplete. Retry the request."
                    .into(),
            );
        }
        if self.include_usage {
            let chunk = json!({
                "id": self.id, "object": "chat.completion.chunk", "created": self.created,
                "model": self.model, "choices": [], "usage": openai_usage(&self.usage),
            });
            write_event(&mut out, &chunk);
        }
        out.extend_from_slice(b"data: [DONE]\n\n");
        Ok(out)
    }

    fn on_line(&mut self, line: &[u8], out: &mut Vec<u8>) -> Result<()> {
        if self.failed {
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
            let error = &event["error"];
            write_event(
                out,
                &json!({"error": {"message": error["message"], "type": error["status"], "code": error["code"]}}),
            );
            self.failed = true;
            return Ok(());
        }
        if self.model.is_null() {
            if !event["responseId"].is_null() {
                self.id = event["responseId"].clone();
            }
            self.model = event["modelVersion"].clone();
        }
        if event["usageMetadata"].is_object() {
            self.usage = Usage::from_gemini(&event["usageMetadata"]);
        }
        if !self.started {
            self.started = true;
            self.chunk(
                out,
                json!({"role": "assistant", "content": ""}),
                Value::Null,
            );
        }
        let candidate = &event["candidates"][0];
        if candidate.is_null() {
            if !event["promptFeedback"]["blockReason"].is_null() {
                self.chunk(out, json!({}), json!("content_filter"));
                self.finished = true;
            }
            return Ok(());
        }
        let (text, calls) = read_parts(candidate, self.calls)?;
        if !text.is_empty() {
            self.chunk(out, json!({"content": text}), Value::Null);
        }
        for call in calls {
            let mut call = call;
            if let Some(fields) = call.as_object_mut() {
                insert(fields, "index", json!(self.calls));
            }
            self.calls += 1;
            self.chunk(out, json!({"tool_calls": [call]}), Value::Null);
        }
        let finish = finish_reason(&candidate["finishReason"], self.calls > 0)?;
        if !finish.is_null() {
            self.chunk(out, json!({}), finish);
            self.finished = true;
        }
        Ok(())
    }

    fn chunk(&self, out: &mut Vec<u8>, delta: Value, finish_reason: Value) {
        let mut chunk = json!({
            "id": self.id, "object": "chat.completion.chunk", "created": self.created, "model": self.model,
            "choices": [{"index": 0, "delta": delta, "logprobs": null, "finish_reason": finish_reason}],
        });
        if let (true, Some(fields)) = (self.include_usage, chunk.as_object_mut()) {
            insert(fields, "usage", Value::Null);
        }
        write_event(out, &chunk);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn refused(request: Value) -> String {
        match openai_to_gemini_request(&request) {
            Err(e) => e.to_string(),
            Ok(v) => format!("unexpectedly translated: {v:?}"),
        }
    }

    #[test]
    fn a_chat_request_becomes_a_gemini_request() -> TestResult {
        let request = json!({
            "model": "gemini-2.5-flash",
            "stream": true,
            "stream_options": {"include_usage": true},
            "temperature": 1.5,
            "max_tokens": 100,
            "stop": "END",
            "n": 1,
            "user": "maya",
            "response_format": {"type": "json_schema", "json_schema": {"name": "x", "schema": {"type": "object"}}},
            "messages": [
                {"role": "system", "content": "Be brief."},
                {"role": "user", "content": [
                    {"type": "text", "text": "What is in this?"},
                    {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA", "detail": "low"}}
                ]},
                {"role": "assistant", "content": null, "tool_calls": [
                    {"id": "c1", "type": "function", "function": {"name": "look", "arguments": "{\"q\":1}"}},
                    {"id": "c2", "type": "function", "function": {"name": "find", "arguments": ""}}
                ]},
                {"role": "tool", "tool_call_id": "c1", "content": "a cat"},
                {"role": "tool", "tool_call_id": "c2", "content": [{"type": "text", "text": "a hat"}]}
            ],
            "tools": [{"type": "function", "function": {"name": "look", "description": "Looks.", "parameters": {"type": "object"}, "strict": false}}],
            "tool_choice": {"type": "function", "function": {"name": "look"}}
        });
        let (body, stream) = openai_to_gemini_request(&request)?;
        assert!(stream);
        assert_eq!(
            body,
            json!({
                "systemInstruction": {"parts": [{"text": "Be brief."}]},
                "contents": [
                    {"role": "user", "parts": [{"text": "What is in this?"}, {"inlineData": {"mimeType": "image/png", "data": "AAAA"}}]},
                    {"role": "model", "parts": [
                        {"functionCall": {"id": "c1", "name": "look", "args": {"q": 1}}},
                        {"functionCall": {"id": "c2", "name": "find", "args": {}}}
                    ]},
                    {"role": "user", "parts": [
                        {"functionResponse": {"id": "c1", "name": "look", "response": {"content": "a cat"}}},
                        {"functionResponse": {"id": "c2", "name": "find", "response": {"content": "a hat"}}}
                    ]}
                ],
                "tools": [{"functionDeclarations": [{"name": "look", "description": "Looks.", "parametersJsonSchema": {"type": "object"}}]}],
                "toolConfig": {"functionCallingConfig": {"mode": "ANY", "allowedFunctionNames": ["look"]}},
                "generationConfig": {
                    "temperature": 1.5, "maxOutputTokens": 100, "stopSequences": ["END"],
                    "responseMimeType": "application/json", "responseJsonSchema": {"type": "object"}
                }
            })
        );
        Ok(())
    }

    #[test]
    fn what_cannot_be_carried_is_refused_by_name() {
        let base = |extra: Value| {
            let mut request =
                json!({"model": "g", "messages": [{"role": "user", "content": "hi"}]});
            if let (Some(r), Some(e)) = (request.as_object_mut(), extra.as_object()) {
                r.extend(e.clone());
            }
            request
        };
        for (extra, named) in [
            (json!({"logprobs": true}), "\"logprobs\""),
            (json!({"n": 2}), "\"n\""),
            (
                json!({"parallel_tool_calls": false}),
                "\"parallel_tool_calls\"",
            ),
            (json!({"reasoning_effort": "xhigh"}), "\"reasoning_effort\""),
            (json!({"audio": {"voice": "x"}}), "\"audio\""),
            (
                json!({"tools": [{"type": "function", "function": {"name": "f", "strict": true}}]}),
                "\"function.strict\"",
            ),
        ] {
            let text = refused(base(extra));
            assert!(text.contains(named) && text.contains("Gemini"), "{text}");
        }
        let late_system = json!({"model": "g", "messages": [
            {"role": "user", "content": "hi"}, {"role": "system", "content": "now be rude"}
        ]});
        assert!(refused(late_system).contains("after the conversation has started"));
        let orphan = json!({"model": "g", "messages": [{"role": "tool", "tool_call_id": "x", "content": "r"}]});
        assert!(refused(orphan).contains("tool call \"x\""));
    }

    #[test]
    fn a_gemini_answer_becomes_a_chat_completion() -> TestResult {
        let answer = json!({
            "responseId": "r1",
            "modelVersion": "gemini-2.5-flash",
            "candidates": [{"content": {"role": "model", "parts": [
                {"text": "thinking", "thought": true},
                {"text": "Let me look."},
                {"functionCall": {"name": "look", "args": {"q": 1}}, "thoughtSignature": "sig"}
            ]}, "finishReason": "STOP", "index": 0}],
            "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 4, "thoughtsTokenCount": 2, "totalTokenCount": 16}
        });
        let chat = gemini_to_openai_response(&answer, 7)?;
        assert_eq!(
            chat,
            json!({
                "id": "r1", "object": "chat.completion", "created": 7, "model": "gemini-2.5-flash",
                "choices": [{"index": 0, "logprobs": null, "finish_reason": "tool_calls", "message": {
                    "role": "assistant", "content": "Let me look.",
                    "tool_calls": [{"id": "call_0", "type": "function", "function": {"name": "look", "arguments": "{\"q\":1}"}}]
                }}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 6, "total_tokens": 16,
                          "prompt_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0}}
            })
        );
        let odd = json!({"candidates": [{"content": {"parts": [{"executableCode": {}}]}, "finishReason": "STOP"}]});
        assert!(
            gemini_to_openai_response(&odd, 0)
                .is_err_and(|e| e.to_string().contains("executableCode"))
        );
        let blocked = json!({"promptFeedback": {"blockReason": "SAFETY"}});
        assert_eq!(
            gemini_to_openai_response(&blocked, 0)?["choices"][0]["finish_reason"],
            "content_filter"
        );
        Ok(())
    }

    const STREAM: &str = "data: {\"candidates\": [{\"content\": {\"parts\": [{\"text\": \"Hel\"}],\"role\": \"model\"},\"index\": 0}],\"usageMetadata\": {\"promptTokenCount\": 5,\"candidatesTokenCount\": 1},\"modelVersion\": \"gemini-2.5-flash\",\"responseId\": \"r2\"}\r\n\r\n\
data: {\"candidates\": [{\"content\": {\"parts\": [{\"text\": \"lo\"},{\"functionCall\": {\"name\": \"look\",\"args\": {}}}],\"role\": \"model\"},\"finishReason\": \"STOP\",\"index\": 0}],\"usageMetadata\": {\"promptTokenCount\": 5,\"candidatesTokenCount\": 3},\"modelVersion\": \"gemini-2.5-flash\",\"responseId\": \"r2\"}\r\n\r\n";

    fn run(stream: &mut GeminiToOpenAiStream, bytes: &[u8], size: usize) -> Result<String> {
        let mut out = Vec::new();
        for piece in bytes.chunks(size) {
            out.extend(stream.feed(piece)?);
        }
        out.extend(stream.finish()?);
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    #[test]
    fn a_gemini_stream_becomes_chat_chunks_in_any_split() -> TestResult {
        let whole = run(
            &mut GeminiToOpenAiStream::new(true, 1),
            STREAM.as_bytes(),
            STREAM.len(),
        )?;
        for size in 1..STREAM.len() {
            assert_eq!(
                run(
                    &mut GeminiToOpenAiStream::new(true, 1),
                    STREAM.as_bytes(),
                    size
                )?,
                whole,
                "split {size}"
            );
        }
        let events: Vec<Value> = whole
            .split("\n\n")
            .filter_map(|e| e.strip_prefix("data: "))
            .filter(|e| *e != "[DONE]")
            .map(serde_json::from_str)
            .collect::<std::result::Result<_, _>>()?;
        let deltas: Vec<&Value> = events.iter().map(|e| &e["choices"][0]["delta"]).collect();
        assert_eq!(deltas[0]["role"], "assistant");
        assert_eq!(deltas[1]["content"], "Hel");
        assert_eq!(deltas[2]["content"], "lo");
        assert_eq!(deltas[3]["tool_calls"][0]["function"]["name"], "look");
        assert_eq!(deltas[3]["tool_calls"][0]["index"], 0);
        assert_eq!(events[4]["choices"][0]["finish_reason"], "tool_calls");
        assert_eq!(events[5]["usage"]["completion_tokens"], 3);
        assert_eq!(events[0]["id"], "r2");
        assert!(whole.ends_with("data: [DONE]\n\n"));
        // Without include_usage there is no usage chunk.
        let plain = run(
            &mut GeminiToOpenAiStream::new(false, 1),
            STREAM.as_bytes(),
            50,
        )?;
        assert!(!plain.contains("prompt_tokens"), "{plain}");
        Ok(())
    }

    #[test]
    fn a_gemini_stream_cut_short_or_failing_says_so() -> TestResult {
        let first = STREAM.split("\r\n\r\n").next().unwrap_or_default();
        assert!(
            run(
                &mut GeminiToOpenAiStream::new(false, 1),
                first.as_bytes(),
                10
            )
            .is_err()
        );
        let error = "data: {\"error\": {\"code\": 429, \"message\": \"slow down\", \"status\": \"RESOURCE_EXHAUSTED\"}}\n\n";
        let out = run(
            &mut GeminiToOpenAiStream::new(false, 1),
            error.as_bytes(),
            7,
        )?;
        assert!(
            out.contains("slow down") && !out.contains("[DONE]"),
            "{out}"
        );
        Ok(())
    }
}
