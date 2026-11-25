//! Translation between OpenAI's Responses API (`/v1/responses`, used by Codex and newer SDKs) and the chat
//! completions format, both ways:
//!
//! - a Responses request served by a provider that does not speak Responses (Anthropic, Bedrock, Vertex AI, Gemini,
//!   Cohere, watsonx) becomes a chat request, which the gateway's other translators carry on; the chat answer,
//!   whole or streamed, comes back as a Responses answer with its events;
//! - a chat request for a model served only through Responses becomes a Responses request, and its answer comes back
//!   as chat.
//!
//! What needs state the provider does not hold (`previous_response_id`, `conversation`, stored prompts, background
//! runs) and tools that run at OpenAI (web search, file search, code interpreter) are refused by name.
//!
//! Formats as documented on 2026-11-14: <https://platform.openai.com/docs/api-reference/responses> and
//! <https://platform.openai.com/docs/api-reference/responses-streaming>.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use crate::translate::{
    Result, array, describe, fail, insert, is_openai_default, object, string, untranslatable,
    write_event,
};
use crate::usage::{Usage, sse_data};

const TO_CHAT: &str = "the chat completions API this model's provider is reached through";
const TO_RESPONSES: &str = "the Responses API this model is served through";

/// Fields dropped on purpose, each with why dropping it cannot change the answer the client gets. A request that
/// had any of them dropped lists them in its decision record as `dropped_on_translation`.
///
/// The line: a field that only labels, routes, caches or stores the request on OpenAI's side, or asks for nothing,
/// is dropped. A field that changes what the model is asked or what the client gets back is translated, or refused
/// by name with the fix. Every top-level parameter of OpenAI's Responses reference (read 2026-11-15) is one of:
///
/// - translated: `model`, `input`, `instructions`, `temperature`, `top_p`, `parallel_tool_calls`, `stream`,
///   `max_output_tokens`, `tools`, `tool_choice`, `reasoning.effort`, `text`, `user`, `safety_identifier`;
/// - dropped (below): `client_metadata` (Codex's own, not in the reference), `metadata`, `store`,
///   `prompt_cache_key`, `prompt_cache_retention`, `prompt_cache_options`, `stream_options`, the `include` items
///   listed below, `max_tool_calls`, and the defaults `truncation: disabled`, `service_tier: auto|default`,
///   `background: false`, `top_logprobs: 0`;
/// - refused by name: `previous_response_id`, `conversation`, `prompt` (state the provider does not hold),
///   `background: true`, `truncation: auto`, `service_tier: flex|priority|scale`, `top_logprobs` above 0,
///   `include: message.output_text.logprobs`, `context_management`, `moderation`, `access_programs`, `image`, and
///   any field not named here.
pub const SAFE_TO_DROP: &[(&str, &str)] = &[
    (
        "client_metadata (Responses request)",
        "Labels Codex attaches to every request (installation, session and turn IDs) for its own telemetry. The model never reads them.",
    ),
    (
        "metadata (Responses request)",
        "Labels for the response object OpenAI stores. The provider stores nothing to label, and the model never reads them.",
    ),
    (
        "store (Responses request)",
        "Asks OpenAI to keep the response for later retrieval. The provider keeps nothing either way and the answer is the same; with store: true the gateway keeps the translated response for its creator to read back.",
    ),
    (
        "prompt_cache_key, prompt_cache_retention and prompt_cache_options (Responses request)",
        "Hints for OpenAI's own prompt cache. They change what a request costs at OpenAI, never the answer.",
    ),
    (
        "stream_options (Responses request)",
        "Holds only include_obfuscation, padding OpenAI adds to stream events. The text streamed is the same.",
    ),
    (
        "include: reasoning.encrypted_content, message.input_image.image_url, computer_call_output.output.image_url, file_search_call.results, web_search_call.results, web_search_call.action.sources, code_interpreter_call.outputs (Responses request)",
        "Asks for encrypted reasoning only OpenAI reads, for inputs echoed back, or for the results of tools that run at OpenAI, which are refused when declared. A provider reached through chat has none to give, and the answer is the same.",
    ),
    (
        "max_tool_calls (Responses request)",
        "Caps calls to tools that run at OpenAI. Those tools are refused when declared, so with function tools only it caps nothing.",
    ),
    (
        "reasoning items (Responses request input)",
        "Earlier reasoning handed back, which only the model that wrote it can read. Leaving it out is what Anthropic does with reasoning a model cannot read.",
    ),
    (
        "truncation: disabled, service_tier auto or default, background: false, top_logprobs: 0 (Responses request)",
        "The defaults: they ask for nothing.",
    ),
];

/// `include` items that may be dropped (see [`SAFE_TO_DROP`]).
const DROPPABLE_INCLUDES: &[&str] = &[
    "reasoning.encrypted_content",
    "message.input_image.image_url",
    "computer_call_output.output.image_url",
    "file_search_call.results",
    "web_search_call.results",
    "web_search_call.action.sources",
    "code_interpreter_call.outputs",
];

/// Function tools declared inside a `namespace` tool (Codex's multi-agent tools), flattened for chat as
/// `<namespace>__<name>`: each flat name with its namespace and name, to name the call back as the client declared it.
pub type Namespaces = BTreeMap<String, (String, String)>;

/// A Responses request translated to chat completions.
#[derive(Debug, Default)]
pub struct ChatRequest {
    pub body: Value,
    /// The fields dropped on the way (each in [`SAFE_TO_DROP`]), for the decision record.
    pub dropped: Vec<String>,
    pub namespaces: Namespaces,
}

/// The flat chat name of function `name` in namespace `namespace`.
fn flat_name(namespace: &str, name: &str) -> String {
    format!("{namespace}__{name}")
}

/// The name and namespace a chat tool call goes back to the client under.
fn client_name(name: &Value, namespaces: &Namespaces) -> (Value, Option<String>) {
    match name.as_str().and_then(|n| namespaces.get(n)) {
        Some((namespace, name)) => (json!(name), Some(namespace.clone())),
        None => (name.clone(), None),
    }
}

/// A Responses request as a chat completions request.
pub fn responses_to_chat_request(request: &Value) -> Result<ChatRequest> {
    let fields = object(request, "The request body")?;
    let mut out = Map::new();
    let mut messages: Vec<Value> = Vec::new();
    let mut dropped: Vec<String> = Vec::new();
    let mut namespaces = Namespaces::new();
    for (key, value) in fields {
        if value.is_null() {
            continue;
        }
        match key.as_str() {
            "model"
            | "temperature"
            | "top_p"
            | "parallel_tool_calls"
            | "user"
            | "safety_identifier" => {
                out.insert(key.clone(), value.clone());
            }
            "input" | "instructions" => {}
            "stream" => {
                out.insert(key.clone(), value.clone());
                // A Responses stream always ends with the usage, so the chat stream must report it.
                if *value == true {
                    insert(&mut out, "stream_options", json!({"include_usage": true}));
                }
            }
            "max_output_tokens" => insert(&mut out, "max_completion_tokens", value.clone()),
            "tools" => insert(&mut out, "tools", chat_tools(value, &mut namespaces)?),
            "tool_choice" => insert(&mut out, "tool_choice", chat_tool_choice(value)?),
            "reasoning" => {
                for (field, setting) in object(value, "\"reasoning\"")? {
                    match field.as_str() {
                        _ if setting.is_null() => {}
                        "effort" => insert(&mut out, "reasoning_effort", setting.clone()),
                        // A summary of the reasoning is what reasoning_content carries back.
                        "summary" | "generate_summary" => {}
                        _ => {
                            return untranslatable(
                                &describe(&format!("reasoning.{field}"), setting),
                                TO_CHAT,
                            );
                        }
                    }
                }
            }
            "text" => {
                for (field, setting) in object(value, "\"text\"")? {
                    match field.as_str() {
                        _ if setting.is_null() => {}
                        "verbosity" => insert(&mut out, "verbosity", setting.clone()),
                        "format" => match setting["type"].as_str() {
                            Some("text") => {}
                            Some("json_object") => {
                                insert(&mut out, "response_format", json!({"type": "json_object"}))
                            }
                            Some("json_schema") => {
                                let mut schema = json!({"name": setting["name"].as_str().unwrap_or("response"), "schema": setting["schema"]});
                                if let Some(strict) = setting["strict"].as_bool() {
                                    schema["strict"] = json!(strict);
                                }
                                insert(
                                    &mut out,
                                    "response_format",
                                    json!({"type": "json_schema", "json_schema": schema}),
                                );
                            }
                            _ => {
                                return untranslatable(
                                    &describe("text.format.type", &setting["type"]),
                                    TO_CHAT,
                                );
                            }
                        },
                        _ => {
                            return untranslatable(
                                &describe(&format!("text.{field}"), setting),
                                TO_CHAT,
                            );
                        }
                    }
                }
            }
            "include" => {
                for item in array(value, "\"include\"")? {
                    match item.as_str() {
                        Some(name) if DROPPABLE_INCLUDES.contains(&name) => {
                            dropped.push(format!("include: {name}"));
                        }
                        _ => return untranslatable(&describe("include", item), TO_CHAT),
                    }
                }
            }
            // SAFE_TO_DROP.
            "client_metadata"
            | "metadata"
            | "store"
            | "prompt_cache_key"
            | "prompt_cache_retention"
            | "prompt_cache_options"
            | "stream_options"
            | "max_tool_calls" => dropped.push(key.clone()),
            "truncation" if value == "disabled" => {}
            "service_tier" if matches!(value.as_str(), Some("auto" | "default")) => {}
            "background" if *value == false => {}
            _ if is_openai_default(key, value) => {}
            "previous_response_id" | "conversation" | "prompt" => {
                return fail(format!(
                    "\"{key}\" asks the provider for state kept by OpenAI's Responses API, and this model's provider keeps none. Send the whole conversation in \"input\" instead."
                ));
            }
            _ => return untranslatable(&describe(key, value), TO_CHAT),
        }
    }
    if let Some(instructions) = request["instructions"].as_str().filter(|t| !t.is_empty()) {
        messages.push(json!({"role": "system", "content": instructions}));
    }
    match &request["input"] {
        Value::String(text) => messages.push(json!({"role": "user", "content": text})),
        Value::Array(items) => {
            let mut reasoning = false;
            for item in items {
                reasoning |= item["type"] == "reasoning";
                input_item(item, &mut messages)?;
            }
            if reasoning {
                dropped.push("input: reasoning items".into());
            }
        }
        Value::Null => {}
        _ => return fail("\"input\" must be a string or a list of items.".into()),
    }
    insert(&mut out, "messages", Value::Array(messages));
    Ok(ChatRequest {
        body: Value::Object(out),
        dropped,
        namespaces,
    })
}

/// One input item as chat messages, appended to `messages`. Consecutive tool calls join one assistant message.
fn input_item(item: &Value, messages: &mut Vec<Value>) -> Result<()> {
    let kind = item["type"].as_str().unwrap_or("message");
    match kind {
        "message" => {
            let role = string(&item["role"], "An input message's \"role\"")?;
            let content = match &item["content"] {
                Value::String(text) => json!(text),
                Value::Array(parts) => {
                    let mut out = Vec::new();
                    for part in parts {
                        match part["type"].as_str() {
                            Some("input_text" | "output_text" | "text") => {
                                out.push(json!({"type": "text", "text": string(&part["text"], "A text part's \"text\"")?}));
                            }
                            Some("refusal") => {
                                out.push(json!({"type": "text", "text": string(&part["refusal"], "A refusal's \"refusal\"")?}));
                            }
                            Some("input_image") => {
                                if !part["file_id"].is_null() {
                                    return untranslatable(
                                        "An image given by OpenAI file ID",
                                        TO_CHAT,
                                    );
                                }
                                let url =
                                    string(&part["image_url"], "An input image's \"image_url\"")?;
                                out.push(json!({"type": "image_url", "image_url": {"url": url}}));
                            }
                            Some("input_file") => {
                                if !part["file_id"].is_null() || !part["file_url"].is_null() {
                                    return untranslatable(
                                        "A file given by OpenAI file ID or URL",
                                        TO_CHAT,
                                    );
                                }
                                let mut file = json!({"file_data": string(&part["file_data"], "An input file's \"file_data\"")?});
                                if let Some(name) = part["filename"].as_str() {
                                    file["filename"] = json!(name);
                                }
                                out.push(json!({"type": "file", "file": file}));
                            }
                            other => {
                                return untranslatable(
                                    &format!(
                                        "An input part of type \"{}\"",
                                        other.unwrap_or("none")
                                    ),
                                    TO_CHAT,
                                );
                            }
                        }
                    }
                    // An assistant's earlier answer goes back as text.
                    if role == "assistant" {
                        json!(
                            out.iter()
                                .filter_map(|p| p["text"].as_str())
                                .collect::<String>()
                        )
                    } else {
                        Value::Array(out)
                    }
                }
                _ => {
                    return fail(
                        "An input message's \"content\" must be a string or a list of parts."
                            .into(),
                    );
                }
            };
            messages.push(json!({"role": role, "content": content}));
        }
        "function_call" => {
            let name = string(&item["name"], "A function call's \"name\"")?;
            let name = match item["namespace"].as_str() {
                Some(namespace) => flat_name(namespace, name),
                None => name.to_string(),
            };
            let call = json!({
                "id": string(&item["call_id"], "A function call's \"call_id\"")?,
                "type": "function",
                "function": {"name": name, "arguments": item["arguments"].as_str().unwrap_or("{}")},
            });
            match messages.last_mut() {
                Some(last) if last["role"] == "assistant" && last["tool_calls"].is_array() => {
                    if let Some(calls) = last["tool_calls"].as_array_mut() {
                        calls.push(call);
                    }
                }
                Some(last) if last["role"] == "assistant" && last.get("tool_calls").is_none() => {
                    last["tool_calls"] = json!([call]);
                }
                _ => messages
                    .push(json!({"role": "assistant", "content": null, "tool_calls": [call]})),
            }
        }
        "function_call_output" => {
            let output = match &item["output"] {
                Value::String(text) => text.clone(),
                Value::Array(parts) => parts.iter().filter_map(|p| p["text"].as_str()).collect(),
                _ => return fail("A function call output's \"output\" must be a string.".into()),
            };
            messages.push(json!({"role": "tool", "tool_call_id": string(&item["call_id"], "A function call output's \"call_id\"")?, "content": output}));
        }
        // SAFE_TO_DROP.
        "reasoning" => {}
        other => return untranslatable(&format!("An input item of type \"{other}\""), TO_CHAT),
    }
    Ok(())
}

fn chat_tools(tools: &Value, namespaces: &mut Namespaces) -> Result<Value> {
    let mut out = Vec::new();
    for tool in array(tools, "\"tools\"")? {
        match tool["type"].as_str() {
            Some("function") => out.push(chat_function(tool, None)?),
            // Codex groups its multi-agent tools in a namespace. Chat has none, so each becomes a function named
            // `<namespace>__<name>`, and a call to it goes back under its namespace and name.
            Some("namespace") => {
                let namespace = string(&tool["name"], "A namespace tool's \"name\"")?;
                for inner in array(&tool["tools"], "A namespace tool's \"tools\"")? {
                    if inner["type"] != "function" {
                        return untranslatable(
                            &format!(
                                "A tool of type {} inside namespace \"{namespace}\"",
                                inner["type"]
                            ),
                            TO_CHAT,
                        );
                    }
                    let name = string(&inner["name"], "A tool's \"name\"")?;
                    let flat = flat_name(namespace, name);
                    if flat.len() > 64 {
                        return fail(format!(
                            "The tool \"{name}\" in namespace \"{namespace}\" would be named \"{flat}\" for this model's provider, which is longer than the 64 characters chat tool names may have. Shorten the namespace or tool name."
                        ));
                    }
                    namespaces.insert(flat.clone(), (namespace.to_string(), name.to_string()));
                    out.push(chat_function(inner, Some(&flat))?);
                }
            }
            _ => {
                return untranslatable(&format!("A tool of type {}", tool["type"]), TO_CHAT);
            }
        }
    }
    // A flattened name must not take the name of a function declared on its own.
    let mut seen = std::collections::BTreeSet::new();
    for function in &out {
        if let Some(name) = function["function"]["name"].as_str()
            && !seen.insert(name)
        {
            return fail(format!(
                "Two tools are named \"{name}\" once namespaced tools are flattened as <namespace>__<name> for this model's provider. Rename one of them."
            ));
        }
    }
    Ok(Value::Array(out))
}

/// One function tool as a chat tool, under `name` when given.
fn chat_function(tool: &Value, name: Option<&str>) -> Result<Value> {
    let mut function = Map::new();
    for (key, value) in object(tool, "Each tool")? {
        match key.as_str() {
            "type" => {}
            _ if value.is_null() => {}
            "name" | "description" | "parameters" | "strict" => {
                function.insert(key.clone(), value.clone());
            }
            _ => return untranslatable(&format!("The tool field \"{key}\""), TO_CHAT),
        }
    }
    if let Some(name) = name {
        function.insert("name".into(), json!(name));
    }
    Ok(json!({"type": "function", "function": function}))
}

fn chat_tool_choice(choice: &Value) -> Result<Value> {
    match choice.as_str() {
        Some("auto" | "none" | "required") => Ok(choice.clone()),
        None if choice["type"] == "function" => Ok(
            json!({"type": "function", "function": {"name": string(&choice["name"], "\"tool_choice.name\"")?}}),
        ),
        _ => untranslatable(&describe("tool_choice", choice), TO_CHAT),
    }
}

/// Responses usage from chat usage.
fn responses_usage(usage: &Usage) -> Value {
    let input = usage.prompt();
    json!({
        "input_tokens": input,
        "input_tokens_details": {"cached_tokens": usage.cache_read},
        "output_tokens": usage.output,
        "output_tokens_details": {"reasoning_tokens": 0},
        "total_tokens": input + usage.output,
    })
}

/// The response object around `output`, as OpenAI's clients read it.
fn response(
    id: &str,
    created: u64,
    model: &Value,
    status: &str,
    output: Vec<Value>,
    usage: Option<&Usage>,
    incomplete: Option<&str>,
) -> Value {
    json!({
        "id": id,
        "object": "response",
        "created_at": created,
        "status": status,
        "model": model,
        "output": output,
        "incomplete_details": incomplete.map(|reason| json!({"reason": reason})),
        "error": null,
        "usage": usage.map(responses_usage),
        "parallel_tool_calls": true,
        "tool_choice": "auto",
        "tools": [],
        "store": false,
    })
}

/// A function call item, under the namespace and name the client declared the tool with.
fn call_item(
    id: &str,
    call_id: &Value,
    name: &Value,
    arguments: &Value,
    status: &str,
    namespaces: &Namespaces,
) -> Value {
    let (name, namespace) = client_name(name, namespaces);
    let mut item = json!({"type": "function_call", "id": id, "call_id": call_id, "name": name, "arguments": arguments, "status": status});
    if let Some(namespace) = namespace {
        item["namespace"] = json!(namespace);
    }
    item
}

/// A chat completion as a Responses answer. `id` names the response, and its items after it. `namespaces` is the
/// request's (see [`ChatRequest`]).
pub fn chat_to_responses_response(
    chat: &Value,
    id: &str,
    created: u64,
    namespaces: &Namespaces,
) -> Result<Value> {
    let choices = array(&chat["choices"], "The answer's \"choices\"")?;
    let [choice] = choices else {
        return fail(format!(
            "The answer has {} choices and a response holds one.",
            choices.len()
        ));
    };
    let reply = &choice["message"];
    let mut output = Vec::new();
    if let Some(reasoning) = reply["reasoning_content"]
        .as_str()
        .filter(|r| !r.is_empty())
    {
        output.push(json!({"type": "reasoning", "id": format!("rs_{id}"), "summary": [{"type": "summary_text", "text": reasoning}]}));
    }
    let mut parts = Vec::new();
    if let Some(text) = reply["content"].as_str().filter(|t| !t.is_empty()) {
        parts.push(json!({"type": "output_text", "text": text, "annotations": []}));
    }
    if let Some(refusal) = reply["refusal"].as_str() {
        parts.push(json!({"type": "refusal", "refusal": refusal}));
    }
    if !parts.is_empty() {
        output.push(json!({"type": "message", "id": format!("msg_{id}"), "status": "completed", "role": "assistant", "content": parts}));
    }
    for (n, call) in reply["tool_calls"]
        .as_array()
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .enumerate()
    {
        output.push(call_item(
            &format!("fc_{id}_{n}"),
            &call["id"],
            &call["function"]["name"],
            &call["function"]["arguments"],
            "completed",
            namespaces,
        ));
    }
    let incomplete = match choice["finish_reason"].as_str() {
        Some("length") => Some("max_output_tokens"),
        Some("content_filter") => Some("content_filter"),
        _ => None,
    };
    let usage = Usage::from_openai(&chat["usage"]);
    Ok(response(
        id,
        created,
        &chat["model"],
        if incomplete.is_some() {
            "incomplete"
        } else {
            "completed"
        },
        output,
        Some(&usage),
        incomplete,
    ))
}

/// The item a Responses stream is writing.
#[derive(Debug)]
enum Item {
    Reasoning {
        at: usize,
        text: String,
    },
    Message {
        at: usize,
        text: String,
    },
    Call {
        at: usize,
        id: String,
        call_id: Value,
        name: Value,
        arguments: String,
    },
}

/// Turns a chat completions stream (with usage) into a Responses stream as bytes arrive: response.created, then for
/// each item output_item.added, its deltas and done events, then response.completed with the usage.
#[derive(Debug)]
pub struct ChatToResponsesStream {
    id: String,
    created: u64,
    model: Value,
    line: Vec<u8>,
    sequence: u64,
    started: bool,
    open: Option<Item>,
    output: Vec<Value>,
    /// Chat tool call index to the item number it opened.
    calls: BTreeMap<u64, usize>,
    finish: Option<String>,
    usage: Option<Usage>,
    done: bool,
    namespaces: Namespaces,
}

impl ChatToResponsesStream {
    /// `namespaces` is the request's (see [`ChatRequest`]).
    pub fn new(id: String, created: u64, namespaces: Namespaces) -> Self {
        Self {
            namespaces,
            id,
            created,
            model: Value::Null,
            line: Vec::new(),
            sequence: 0,
            started: false,
            open: None,
            output: Vec::new(),
            calls: BTreeMap::new(),
            finish: None,
            usage: None,
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
            return fail("The provider's stream ended before its [DONE] line, so the answer is incomplete. Retry the request.".into());
        }
        Ok(out)
    }

    fn emit(&mut self, out: &mut Vec<u8>, kind: &str, mut event: Value) {
        if let Some(fields) = event.as_object_mut() {
            fields.insert("type".into(), json!(kind));
            fields.insert("sequence_number".into(), json!(self.sequence));
        }
        self.sequence += 1;
        out.extend_from_slice(format!("event: {kind}\n").as_bytes());
        write_event(out, &event);
    }

    fn close(&mut self, out: &mut Vec<u8>) {
        let Some(item) = self.open.take() else {
            return;
        };
        let id = self.id.clone();
        let done = match item {
            Item::Reasoning { at, text } => {
                let part = json!({"type": "summary_text", "text": text});
                self.emit(out, "response.reasoning_summary_text.done", json!({"item_id": format!("rs_{id}"), "output_index": at, "summary_index": 0, "text": text}));
                (
                    at,
                    json!({"type": "reasoning", "id": format!("rs_{id}"), "summary": [part]}),
                )
            }
            Item::Message { at, text } => {
                let item_id = format!("msg_{id}");
                let part = json!({"type": "output_text", "text": text, "annotations": []});
                self.emit(out, "response.output_text.done", json!({"item_id": item_id, "output_index": at, "content_index": 0, "text": text}));
                self.emit(out, "response.content_part.done", json!({"item_id": item_id, "output_index": at, "content_index": 0, "part": part}));
                (
                    at,
                    json!({"type": "message", "id": item_id, "status": "completed", "role": "assistant", "content": [part]}),
                )
            }
            Item::Call {
                at,
                id: item_id,
                call_id,
                name,
                arguments,
            } => {
                self.emit(
                    out,
                    "response.function_call_arguments.done",
                    json!({"item_id": item_id, "output_index": at, "arguments": arguments}),
                );
                (
                    at,
                    call_item(
                        &item_id,
                        &call_id,
                        &name,
                        &json!(arguments),
                        "completed",
                        &self.namespaces,
                    ),
                )
            }
        };
        let (at, item) = done;
        self.emit(
            out,
            "response.output_item.done",
            json!({"output_index": at, "item": item}),
        );
        self.output.push(item);
    }

    fn on_line(&mut self, line: &[u8], out: &mut Vec<u8>) -> Result<()> {
        if self.done {
            return Ok(());
        }
        let Some(data) = sse_data(line) else {
            return Ok(());
        };
        if data.trim_ascii() == b"[DONE]" {
            return self.end(out);
        }
        let chunk: Value = match serde_json::from_slice(data) {
            Ok(chunk) => chunk,
            Err(e) => {
                return fail(format!(
                    "The provider sent a stream chunk that is not JSON: {e}."
                ));
            }
        };
        if let Some(error) = chunk.get("error").filter(|e| !e.is_null()) {
            self.emit(
                out,
                "error",
                json!({"code": error["type"], "message": error["message"], "param": null}),
            );
            self.done = true;
            return Ok(());
        }
        if !self.started {
            self.started = true;
            self.model = chunk["model"].clone();
            let created = response(
                &self.id,
                self.created,
                &self.model,
                "in_progress",
                Vec::new(),
                None,
                None,
            );
            self.emit(out, "response.created", json!({"response": created}));
            self.emit(out, "response.in_progress", json!({"response": created}));
        }
        if chunk["usage"].is_object() {
            self.usage = Some(Usage::from_openai(&chunk["usage"]));
        }
        let Some(choice) = chunk["choices"].as_array().and_then(|c| c.first()) else {
            return Ok(());
        };
        let delta = &choice["delta"];
        let id = self.id.clone();
        if let Some(text) = delta["reasoning_content"]
            .as_str()
            .filter(|t| !t.is_empty())
        {
            if !matches!(self.open, Some(Item::Reasoning { .. })) {
                self.close(out);
                let at = self.output.len();
                self.emit(out, "response.output_item.added", json!({"output_index": at, "item": {"type": "reasoning", "id": format!("rs_{id}"), "summary": []}}));
                self.open = Some(Item::Reasoning {
                    at,
                    text: String::new(),
                });
            }
            if let Some(Item::Reasoning { at, text: all }) = &mut self.open {
                all.push_str(text);
                let at = *at;
                self.emit(out, "response.reasoning_summary_text.delta", json!({"item_id": format!("rs_{id}"), "output_index": at, "summary_index": 0, "delta": text}));
            }
        }
        if let Some(text) = delta["content"].as_str().filter(|t| !t.is_empty()) {
            if !matches!(self.open, Some(Item::Message { .. })) {
                self.close(out);
                let at = self.output.len();
                let item_id = format!("msg_{id}");
                self.emit(out, "response.output_item.added", json!({"output_index": at, "item": {"type": "message", "id": item_id, "status": "in_progress", "role": "assistant", "content": []}}));
                self.emit(out, "response.content_part.added", json!({"item_id": item_id, "output_index": at, "content_index": 0, "part": {"type": "output_text", "text": "", "annotations": []}}));
                self.open = Some(Item::Message {
                    at,
                    text: String::new(),
                });
            }
            if let Some(Item::Message { at, text: all }) = &mut self.open {
                all.push_str(text);
                let at = *at;
                self.emit(out, "response.output_text.delta", json!({"item_id": format!("msg_{id}"), "output_index": at, "content_index": 0, "delta": text}));
            }
        }
        for call in delta["tool_calls"]
            .as_array()
            .map_or(&[][..], Vec::as_slice)
        {
            let index = call["index"].as_u64().unwrap_or_default();
            if !self.calls.contains_key(&index) {
                self.close(out);
                let at = self.output.len();
                let item_id = format!("fc_{id}_{index}");
                self.calls.insert(index, at);
                let item = call_item(
                    &item_id,
                    &call["id"],
                    &call["function"]["name"],
                    &json!(""),
                    "in_progress",
                    &self.namespaces,
                );
                self.emit(
                    out,
                    "response.output_item.added",
                    json!({"output_index": at, "item": item}),
                );
                self.open = Some(Item::Call {
                    at,
                    id: item_id,
                    call_id: call["id"].clone(),
                    name: call["function"]["name"].clone(),
                    arguments: String::new(),
                });
            }
            if let Some(part) = call["function"]["arguments"]
                .as_str()
                .filter(|p| !p.is_empty())
                && let Some(Item::Call {
                    at,
                    id: item_id,
                    arguments,
                    ..
                }) = &mut self.open
            {
                arguments.push_str(part);
                let (at, item_id) = (*at, item_id.clone());
                self.emit(
                    out,
                    "response.function_call_arguments.delta",
                    json!({"item_id": item_id, "output_index": at, "delta": part}),
                );
            }
        }
        if let Some(reason) = choice["finish_reason"].as_str() {
            self.finish = Some(reason.to_string());
        }
        Ok(())
    }

    fn end(&mut self, out: &mut Vec<u8>) -> Result<()> {
        if !self.started {
            return fail(
                "The provider's stream ended before any answer arrived. Retry the request.".into(),
            );
        }
        self.close(out);
        let incomplete = match self.finish.as_deref() {
            Some("length") => Some("max_output_tokens"),
            Some("content_filter") => Some("content_filter"),
            _ => None,
        };
        let status = if incomplete.is_some() {
            "incomplete"
        } else {
            "completed"
        };
        let usage = self.usage.unwrap_or_default();
        let whole = response(
            &self.id,
            self.created,
            &self.model,
            status,
            std::mem::take(&mut self.output),
            Some(&usage),
            incomplete,
        );
        self.emit(
            out,
            &format!("response.{status}"),
            json!({"response": whole}),
        );
        self.done = true;
        Ok(())
    }
}

/// A chat completions request as a Responses request, for a model served only through Responses.
pub fn chat_to_responses_request(request: &Value) -> Result<Value> {
    let fields = object(request, "The request body")?;
    let mut out = Map::new();
    let mut text = Map::new();
    for (key, value) in fields {
        if value.is_null() {
            continue;
        }
        match key.as_str() {
            "model"
            | "temperature"
            | "top_p"
            | "parallel_tool_calls"
            | "user"
            | "safety_identifier"
            | "prompt_cache_key"
            | "metadata"
            | "stream"
            | "service_tier"
            | "store" => {
                out.insert(key.clone(), value.clone());
            }
            "messages" => {}
            // The Responses stream always reports usage; include_usage decides only whether the chat client sees it.
            "stream_options" => {}
            "max_tokens" | "max_completion_tokens" => {
                insert(&mut out, "max_output_tokens", value.clone())
            }
            "reasoning_effort" => insert(&mut out, "reasoning", json!({"effort": value})),
            "verbosity" => insert(&mut text, "verbosity", value.clone()),
            "response_format" => match value["type"].as_str() {
                Some("text") => {}
                Some("json_object") => insert(&mut text, "format", json!({"type": "json_object"})),
                Some("json_schema") => {
                    let schema = &value["json_schema"];
                    let mut format = json!({"type": "json_schema", "name": schema["name"].as_str().unwrap_or("response"), "schema": schema["schema"]});
                    if let Some(strict) = schema["strict"].as_bool() {
                        format["strict"] = json!(strict);
                    }
                    insert(&mut text, "format", format);
                }
                _ => {
                    return untranslatable(
                        &describe("response_format", &value["type"]),
                        TO_RESPONSES,
                    );
                }
            },
            "tools" => {
                let tools = array(value, "\"tools\"")?
                    .iter()
                    .map(|tool| {
                        if tool["type"] != "function" {
                            return untranslatable(
                                &format!("A tool of type {}", tool["type"]),
                                TO_RESPONSES,
                            );
                        }
                        let mut flat = object(&tool["function"], "A tool's \"function\"")?.clone();
                        flat.insert("type".into(), json!("function"));
                        Ok(Value::Object(flat))
                    })
                    .collect::<Result<Vec<_>>>()?;
                insert(&mut out, "tools", Value::Array(tools));
            }
            "tool_choice" => match value.as_str() {
                Some(_) => insert(&mut out, "tool_choice", value.clone()),
                None if value["type"] == "function" => insert(
                    &mut out,
                    "tool_choice",
                    json!({"type": "function", "name": value["function"]["name"]}),
                ),
                None => return untranslatable(&describe(key, value), TO_RESPONSES),
            },
            _ if is_openai_default(key, value) => {}
            _ => return untranslatable(&describe(key, value), TO_RESPONSES),
        }
    }
    let mut input = Vec::new();
    for message in array(&request["messages"], "\"messages\"")? {
        let role = message["role"].as_str().unwrap_or_default();
        match role {
            "system" | "developer" | "user" | "assistant" => {
                let kind = if role == "assistant" {
                    "output_text"
                } else {
                    "input_text"
                };
                let content: Vec<Value> = match &message["content"] {
                    Value::String(t) => vec![json!({"type": kind, "text": t})],
                    Value::Array(parts) => parts
                        .iter()
                        .map(|part| match part["type"].as_str() {
                            Some("text") => Ok(json!({"type": kind, "text": part["text"]})),
                            Some("image_url") if role == "user" => Ok(json!({"type": "input_image", "image_url": part["image_url"]["url"]})),
                            other => untranslatable(&format!("A {} part in a {role} message", other.unwrap_or("untyped")), TO_RESPONSES),
                        })
                        .collect::<Result<_>>()?,
                    Value::Null => Vec::new(),
                    _ => return fail(format!("A {role} message needs \"content\" that is a string or a list of parts.")),
                };
                if !content.is_empty() {
                    input.push(json!({"type": "message", "role": role, "content": content}));
                }
                for call in message["tool_calls"]
                    .as_array()
                    .map_or(&[][..], Vec::as_slice)
                {
                    input.push(json!({"type": "function_call", "call_id": call["id"], "name": call["function"]["name"], "arguments": call["function"]["arguments"]}));
                }
            }
            "tool" => {
                let output = match &message["content"] {
                    Value::String(t) => t.clone(),
                    Value::Array(parts) => {
                        parts.iter().filter_map(|p| p["text"].as_str()).collect()
                    }
                    _ => String::new(),
                };
                input.push(json!({"type": "function_call_output", "call_id": message["tool_call_id"], "output": output}));
            }
            _ => return untranslatable(&format!("A message with role \"{role}\""), TO_RESPONSES),
        }
    }
    insert(&mut out, "input", Value::Array(input));
    if !text.is_empty() {
        insert(&mut out, "text", Value::Object(text));
    }
    // Chat completions are not stored for later retrieval unless asked.
    out.entry("store").or_insert(json!(false));
    Ok(Value::Object(out))
}

/// The text, reasoning and tool calls of a response's output.
fn read_output(output: &Value) -> Result<(String, String, Vec<Value>)> {
    let mut text = String::new();
    let mut reasoning = String::new();
    let mut calls = Vec::new();
    for item in output.as_array().map_or(&[][..], Vec::as_slice) {
        match item["type"].as_str() {
            Some("message") => {
                for part in item["content"].as_array().map_or(&[][..], Vec::as_slice) {
                    if let Some(t) = part["text"].as_str().or(part["refusal"].as_str()) {
                        text.push_str(t);
                    }
                }
            }
            Some("reasoning") => {
                for part in item["summary"].as_array().map_or(&[][..], Vec::as_slice) {
                    reasoning.push_str(part["text"].as_str().unwrap_or_default());
                }
            }
            Some("function_call") => calls.push(json!({"id": item["call_id"], "type": "function", "function": {"name": item["name"], "arguments": item["arguments"]}})),
            other => return untranslatable(&format!("An output item of type \"{}\"", other.unwrap_or("none")), "the chat completions API"),
        }
    }
    Ok((text, reasoning, calls))
}

fn chat_finish(response: &Value, calls: bool) -> Value {
    match response["incomplete_details"]["reason"].as_str() {
        Some("max_output_tokens") => json!("length"),
        Some("content_filter") => json!("content_filter"),
        _ if calls => json!("tool_calls"),
        _ => json!("stop"),
    }
}

/// A Responses answer as a chat completion.
pub fn responses_to_chat_response(answer: &Value) -> Result<Value> {
    object(answer, "The provider's answer")?;
    let (text, reasoning, calls) = read_output(&answer["output"])?;
    let finish = chat_finish(answer, !calls.is_empty());
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
        "id": answer["id"],
        "object": "chat.completion",
        "created": answer["created_at"],
        "model": answer["model"],
        "choices": [{"index": 0, "message": message, "logprobs": null, "finish_reason": finish}],
        "usage": crate::translate::openai_usage(&Usage::from_responses(&answer["usage"])),
    }))
}

/// Turns a Responses stream into a chat completions stream as bytes arrive.
#[derive(Debug)]
pub struct ResponsesToChatStream {
    include_usage: bool,
    line: Vec<u8>,
    id: Value,
    model: Value,
    created: Value,
    /// Output index of each function call, in chat tool call order.
    calls: Vec<u64>,
    done: bool,
}

impl ResponsesToChatStream {
    pub fn new(include_usage: bool) -> Self {
        Self {
            include_usage,
            line: Vec::new(),
            id: Value::Null,
            model: Value::Null,
            created: Value::Null,
            calls: Vec::new(),
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
            return fail("The provider's stream ended before its response.completed event, so the answer is incomplete. Retry the request.".into());
        }
        Ok(out)
    }

    fn chunk(&self, out: &mut Vec<u8>, delta: Value, finish: Value) {
        write_event(
            out,
            &json!({
                "id": self.id, "object": "chat.completion.chunk", "created": self.created, "model": self.model,
                "choices": [{"index": 0, "delta": delta, "logprobs": null, "finish_reason": finish}],
            }),
        );
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
        match event["type"].as_str().unwrap_or_default() {
            "response.created" => {
                let r = &event["response"];
                self.id = r["id"].clone();
                self.model = r["model"].clone();
                self.created = r["created_at"].clone();
                self.chunk(
                    out,
                    json!({"role": "assistant", "content": ""}),
                    Value::Null,
                );
            }
            "response.output_text.delta" | "response.refusal.delta" => {
                self.chunk(out, json!({"content": event["delta"]}), Value::Null);
            }
            "response.reasoning_summary_text.delta" => {
                self.chunk(
                    out,
                    json!({"reasoning_content": event["delta"]}),
                    Value::Null,
                );
            }
            "response.output_item.added" if event["item"]["type"] == "function_call" => {
                let n = self.calls.len();
                self.calls
                    .push(event["output_index"].as_u64().unwrap_or_default());
                let item = &event["item"];
                self.chunk(out, json!({"tool_calls": [{"index": n, "id": item["call_id"], "type": "function", "function": {"name": item["name"], "arguments": ""}}]}), Value::Null);
            }
            "response.function_call_arguments.delta" => {
                let at = event["output_index"].as_u64();
                if let Some(n) = self.calls.iter().position(|&c| Some(c) == at) {
                    self.chunk(out, json!({"tool_calls": [{"index": n, "function": {"arguments": event["delta"]}}]}), Value::Null);
                }
            }
            "response.completed" | "response.incomplete" => {
                let r = &event["response"];
                self.chunk(out, json!({}), chat_finish(r, !self.calls.is_empty()));
                if self.include_usage {
                    write_event(
                        out,
                        &json!({
                            "id": self.id, "object": "chat.completion.chunk", "created": self.created, "model": self.model,
                            "choices": [], "usage": crate::translate::openai_usage(&Usage::from_responses(&r["usage"])),
                        }),
                    );
                }
                out.extend_from_slice(b"data: [DONE]\n\n");
                self.done = true;
            }
            "response.failed" | "error" => {
                let error = if event["type"] == "error" {
                    event.clone()
                } else {
                    event["response"]["error"].clone()
                };
                write_event(
                    out,
                    &json!({"error": {"message": error["message"], "type": error["code"], "code": null}}),
                );
                self.done = true;
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn a_codex_request_becomes_a_chat_request() -> TestResult {
        let request = json!({
            "model": "claude-sonnet-5-5", "instructions": "You are Codex.", "stream": true, "store": false,
            "include": ["reasoning.encrypted_content"], "reasoning": {"effort": "medium", "summary": "auto"},
            "max_output_tokens": 2000,
            "input": [
                {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "List files"}]},
                {"type": "reasoning", "id": "rs_1", "summary": [], "encrypted_content": "x"},
                {"type": "function_call", "call_id": "c1", "name": "shell", "arguments": "{\"cmd\":\"ls\"}"},
                {"type": "function_call_output", "call_id": "c1", "output": "a.txt"},
            ],
            "tools": [{"type": "function", "name": "shell", "parameters": {"type": "object"}, "strict": false}],
            "tool_choice": "auto",
        });
        let chat = responses_to_chat_request(&request)?.body;
        assert_eq!(
            chat["messages"][0],
            json!({"role": "system", "content": "You are Codex."})
        );
        assert_eq!(
            chat["messages"][2]["tool_calls"][0]["function"]["name"],
            "shell"
        );
        assert_eq!(
            chat["messages"][3],
            json!({"role": "tool", "tool_call_id": "c1", "content": "a.txt"})
        );
        assert_eq!(chat["tools"][0]["function"]["name"], "shell");
        assert_eq!(chat["reasoning_effort"], "medium");
        assert_eq!(chat["max_completion_tokens"], 2000);
        assert_eq!(chat["stream_options"]["include_usage"], true);
        let stateful = json!({"model": "m", "input": "hi", "previous_response_id": "resp_1"});
        assert!(
            responses_to_chat_request(&stateful)
                .is_err_and(|e| e.to_string().contains("previous_response_id"))
        );
        let web = json!({"model": "m", "input": "hi", "tools": [{"type": "web_search"}]});
        assert!(
            responses_to_chat_request(&web).is_err_and(|e| e.to_string().contains("web_search"))
        );
        Ok(())
    }

    #[test]
    fn a_chat_answer_becomes_a_response() -> TestResult {
        let chat = json!({"model": "m", "choices": [{"message": {"role": "assistant", "content": "Done.", "reasoning_content": "Hmm.",
            "tool_calls": [{"id": "c2", "type": "function", "function": {"name": "f", "arguments": "{}"}}]}, "finish_reason": "tool_calls"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 4}});
        let response = chat_to_responses_response(&chat, "resp_x", 1, &Namespaces::new())?;
        assert_eq!(response["object"], "response");
        assert_eq!(response["status"], "completed");
        assert_eq!(response["output"][0]["type"], "reasoning");
        assert_eq!(response["output"][1]["content"][0]["text"], "Done.");
        assert_eq!(response["output"][2]["call_id"], "c2");
        assert_eq!(response["usage"]["input_tokens"], 10);
        Ok(())
    }

    #[test]
    fn a_chat_stream_becomes_responses_events() -> TestResult {
        let chunks = [
            json!({"id": "c", "model": "m", "choices": [{"delta": {"role": "assistant", "content": "Hel"}}]}),
            json!({"id": "c", "model": "m", "choices": [{"delta": {"content": "lo"}}]}),
            json!({"id": "c", "model": "m", "choices": [{"delta": {"tool_calls": [{"index": 0, "id": "t1", "function": {"name": "f", "arguments": "{\"a\""}}]}}]}),
            json!({"id": "c", "model": "m", "choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": ":1}"}}]}, "finish_reason": "tool_calls"}]}),
            json!({"id": "c", "model": "m", "choices": [], "usage": {"prompt_tokens": 5, "completion_tokens": 2}}),
        ];
        let mut sse: String = chunks.iter().map(|c| format!("data: {c}\n\n")).collect();
        sse.push_str("data: [DONE]\n\n");
        let mut stream = ChatToResponsesStream::new("resp_1".into(), 1, Namespaces::new());
        let mut out = Vec::new();
        for piece in sse.as_bytes().chunks(11) {
            out.extend(stream.feed(piece)?);
        }
        out.extend(stream.finish()?);
        let text = String::from_utf8(out)?;
        for event in [
            "response.created",
            "response.output_text.delta",
            "response.output_text.done",
            "response.function_call_arguments.done",
            "response.completed",
        ] {
            assert!(
                text.contains(&format!("event: {event}\n")),
                "{event}: {text}"
            );
        }
        assert!(text.contains("\"arguments\":\"{\\\"a\\\":1}\""), "{text}");
        assert!(text.contains("\"input_tokens\":5"), "{text}");
        Ok(())
    }

    #[test]
    fn a_chat_request_reaches_a_responses_only_model_and_comes_back() -> TestResult {
        let chat = json!({"model": "o3-pro", "max_tokens": 100, "reasoning_effort": "high",
            "messages": [{"role": "system", "content": "Be brief."}, {"role": "user", "content": "hi"}]});
        let request = chat_to_responses_request(&chat)?;
        assert_eq!(request["max_output_tokens"], 100);
        assert_eq!(request["reasoning"]["effort"], "high");
        assert_eq!(
            request["input"][1]["content"][0],
            json!({"type": "input_text", "text": "hi"})
        );
        let answer = json!({"id": "resp_1", "object": "response", "created_at": 5, "model": "o3-pro", "status": "completed",
            "output": [{"type": "message", "content": [{"type": "output_text", "text": "Hello"}]}],
            "usage": {"input_tokens": 8, "output_tokens": 2}});
        let back = responses_to_chat_response(&answer)?;
        assert_eq!(back["choices"][0]["message"]["content"], "Hello");
        assert_eq!(back["usage"]["prompt_tokens"], 8);
        let events = [
            json!({"type": "response.created", "response": {"id": "r", "model": "o3-pro", "created_at": 1}}),
            json!({"type": "response.output_text.delta", "delta": "Hi"}),
            json!({"type": "response.completed", "response": {"usage": {"input_tokens": 3, "output_tokens": 1}}}),
        ];
        let sse: String = events
            .iter()
            .map(|e| {
                format!(
                    "event: {}\ndata: {e}\n\n",
                    e["type"].as_str().unwrap_or_default()
                )
            })
            .collect();
        let mut stream = ResponsesToChatStream::new(true);
        let mut out = stream.feed(sse.as_bytes())?;
        out.extend(stream.finish()?);
        let text = String::from_utf8(out)?;
        assert!(
            text.contains("\"content\":\"Hi\"")
                && text.contains("\"prompt_tokens\":3")
                && text.ends_with("data: [DONE]\n\n"),
            "{text}"
        );
        Ok(())
    }
    #[test]
    fn every_documented_parameter_is_translated_dropped_or_refused() -> TestResult {
        // (field, value, the chat field it becomes, or "" when dropped, or None when refused).
        let cases: &[(&str, Value, Option<&str>)] = &[
            ("temperature", json!(0.2), Some("temperature")),
            ("top_p", json!(0.9), Some("top_p")),
            (
                "parallel_tool_calls",
                json!(false),
                Some("parallel_tool_calls"),
            ),
            ("user", json!("maya"), Some("user")),
            ("safety_identifier", json!("u1"), Some("safety_identifier")),
            (
                "max_output_tokens",
                json!(100),
                Some("max_completion_tokens"),
            ),
            (
                "reasoning",
                json!({"effort": "low"}),
                Some("reasoning_effort"),
            ),
            ("text", json!({"verbosity": "low"}), Some("verbosity")),
            ("client_metadata", json!({"session_id": "s"}), Some("")),
            ("metadata", json!({"team": "a"}), Some("")),
            ("store", json!(true), Some("")),
            ("prompt_cache_key", json!("k"), Some("")),
            ("prompt_cache_retention", json!("24h"), Some("")),
            ("prompt_cache_options", json!({"ttl": "30m"}), Some("")),
            (
                "stream_options",
                json!({"include_obfuscation": false}),
                Some(""),
            ),
            ("max_tool_calls", json!(3), Some("")),
            (
                "include",
                json!(["message.input_image.image_url"]),
                Some(""),
            ),
            ("truncation", json!("disabled"), Some("")),
            ("service_tier", json!("auto"), Some("")),
            ("background", json!(false), Some("")),
            ("top_logprobs", json!(0), Some("")),
            ("previous_response_id", json!("resp_1"), None),
            ("conversation", json!("conv_1"), None),
            ("prompt", json!({"id": "p"}), None),
            ("background", json!(true), None),
            ("truncation", json!("auto"), None),
            ("service_tier", json!("priority"), None),
            ("top_logprobs", json!(3), None),
            ("include", json!(["message.output_text.logprobs"]), None),
            ("context_management", json!([{"type": "compaction"}]), None),
            ("moderation", json!({"policy": "block"}), None),
            ("access_programs", json!({"cyber": true}), None),
            ("image", json!({"context_compression": true}), None),
            ("reasoning", json!({"mode": "x"}), None),
            ("something_new", json!(1), None),
        ];
        for (field, value, becomes) in cases {
            let request = json!({"model": "m", "input": "hi", *field: value});
            match (responses_to_chat_request(&request), becomes) {
                (Ok(chat), Some("")) => {
                    let dropped = chat.dropped.iter().any(|d| d.starts_with(field));
                    let default = is_openai_default(field, value)
                        || matches!(*field, "truncation" | "service_tier" | "background");
                    assert!(dropped || default, "{field} dropped without a record");
                    assert!(chat.body.get(*field).is_none(), "{field}");
                }
                (Ok(chat), Some(to)) => assert!(!chat.body[*to].is_null(), "{field} -> {to}"),
                (Err(err), None) => {
                    let text = err.to_string();
                    assert!(
                        text.contains(field)
                            && (text.contains("Remove it") || text.contains("instead")),
                        "{text}"
                    );
                }
                (result, _) => return Err(format!("{field}: {result:?}").into()),
            }
        }
        Ok(())
    }

    #[test]
    fn namespaced_tools_are_flattened_and_named_back() -> TestResult {
        let request = json!({"model": "m", "stream": true, "input": [
            {"role": "user", "content": "go"},
            {"type": "function_call", "call_id": "c0", "namespace": "multi_agent_v1", "name": "wait_agent", "arguments": "{}"},
            {"type": "function_call_output", "call_id": "c0", "namespace": "multi_agent_v1", "output": "done"},
        ],
        "tools": [
            {"type": "function", "name": "exec_command", "parameters": {"type": "object"}},
            {"type": "namespace", "name": "multi_agent_v1", "description": "Agents.", "tools": [
                {"type": "function", "name": "spawn_agent", "strict": false, "parameters": {"type": "object"}},
                {"type": "function", "name": "wait_agent", "parameters": {"type": "object"}},
            ]},
        ]});
        let chat = responses_to_chat_request(&request)?;
        assert_eq!(
            chat.body["tools"][1]["function"]["name"],
            "multi_agent_v1__spawn_agent"
        );
        assert_eq!(
            chat.body["messages"][1]["tool_calls"][0]["function"]["name"],
            "multi_agent_v1__wait_agent"
        );
        // Whole answer.
        let answer = json!({"model": "m", "choices": [{"message": {"role": "assistant", "content": null, "tool_calls": [
            {"id": "c1", "type": "function", "function": {"name": "multi_agent_v1__spawn_agent", "arguments": "{}"}},
            {"id": "c2", "type": "function", "function": {"name": "exec_command", "arguments": "{}"}}]}, "finish_reason": "tool_calls"}]});
        let response = chat_to_responses_response(&answer, "r", 1, &chat.namespaces)?;
        assert_eq!(response["output"][0]["name"], "spawn_agent");
        assert_eq!(response["output"][0]["namespace"], "multi_agent_v1");
        assert_eq!(response["output"][1]["name"], "exec_command");
        assert!(response["output"][1].get("namespace").is_none());
        // Streamed answer.
        let chunks = [
            json!({"model": "m", "choices": [{"delta": {"tool_calls": [{"index": 0, "id": "c1", "function": {"name": "multi_agent_v1__spawn_agent", "arguments": "{}"}}]}, "finish_reason": "tool_calls"}]}),
            json!({"model": "m", "choices": [], "usage": {"prompt_tokens": 1, "completion_tokens": 1}}),
        ];
        let mut sse: String = chunks.iter().map(|c| format!("data: {c}\n\n")).collect();
        sse.push_str("data: [DONE]\n\n");
        let mut stream = ChatToResponsesStream::new("r".into(), 1, chat.namespaces.clone());
        let mut out = stream.feed(sse.as_bytes())?;
        out.extend(stream.finish()?);
        let text = String::from_utf8(out)?;
        assert!(!text.contains("multi_agent_v1__"), "{text}");
        assert_eq!(
            text.matches("\"namespace\":\"multi_agent_v1\"").count(),
            3,
            "{text}"
        );
        // Other tool types and clashing names are refused by name.
        let other = json!({"model": "m", "input": "hi", "tools": [{"type": "namespace", "name": "n", "tools": [{"type": "custom", "name": "c"}]}]});
        assert!(
            responses_to_chat_request(&other).is_err_and(|e| e.to_string().contains("\"custom\""))
        );
        let clash = json!({"model": "m", "input": "hi", "tools": [{"type": "function", "name": "n__f"},
            {"type": "namespace", "name": "n", "tools": [{"type": "function", "name": "f"}]}]});
        assert!(responses_to_chat_request(&clash).is_err_and(|e| e.to_string().contains("n__f")));
        let shell = json!({"model": "m", "input": "hi", "tools": [{"type": "local_shell"}]});
        assert!(
            responses_to_chat_request(&shell).is_err_and(|e| e.to_string().contains("local_shell"))
        );
        Ok(())
    }
}
