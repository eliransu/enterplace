//! Translation between the OpenAI chat completions format and Anthropic's messages format, so a client of
//! one format can use a model whose provider speaks the other.
//!
//! Requests, whole answers and streamed answers translate both ways.
//!
//! A request field that cannot be carried across is an error that names it (AGENTS.md rule 7). A field set to
//! null, or to the value the API documents as its default, asks for nothing and is accepted. The few fields
//! dropped on purpose are listed in [`SAFE_TO_DROP`] with the reason; no other field is dropped.
//!
//! Formats as documented on 2026-11-13:
//! - <https://platform.claude.com/docs/en/api/messages/create>
//! - <https://platform.claude.com/docs/en/build-with-claude/streaming>
//! - <https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create>
//! - <https://developers.openai.com/api/reference/resources/chat/subresources/completions/streaming-events>

use std::fmt;

use serde_json::{Map, Value, json};

use crate::usage::{Usage, sse_data};

/// Why a request or answer cannot be translated. The text names the cause and the fix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranslateError(String);

impl fmt::Display for TranslateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TranslateError {}

pub(crate) type Result<T> = std::result::Result<T, TranslateError>;

/// `max_tokens` is required by Anthropic and optional in OpenAI's format. Large enough for long answers,
/// small enough that a non-streamed answer finishes well within a client's timeout.
pub const DEFAULT_MAX_TOKENS: u64 = 8192;

/// Fields dropped on purpose, each with why dropping it cannot change the answer the client gets.
pub const SAFE_TO_DROP: &[(&str, &str)] = &[
    (
        "seed (OpenAI request)",
        "OpenAI documents it as best effort only, so no answer may depend on it.",
    ),
    (
        "prompt_cache_key (OpenAI request)",
        "A routing hint for OpenAI's own cache. It never changes the answer.",
    ),
    (
        "metadata (OpenAI request)",
        "Labels for completions that OpenAI stores. Anthropic stores nothing to label.",
    ),
    (
        "image_url.detail (OpenAI request)",
        "A resolution hint. The whole image still reaches the model, which sizes it itself.",
    ),
    (
        "response_format.json_schema name, description and strict (OpenAI request)",
        "A label for the schema and a strictness switch. Anthropic's structured output always follows the schema strictly.",
    ),
    (
        "cache_control (Anthropic request)",
        "A prompt caching hint. OpenAI caches long prompts by itself and the answer does not change.",
    ),
    (
        "eager_input_streaming (Anthropic tool)",
        "A streaming latency hint. The tool input arrives whole either way.",
    ),
    (
        "thinking of type adaptive (Anthropic request)",
        "Lets the model decide how much to reason, which is what OpenAI models do when not told.",
    ),
    (
        "thinking and redacted_thinking blocks (request), redacted_thinking and thinking signatures (answer)",
        "The model's private reasoning. A model of the other provider cannot read it (Anthropic drops blocks a model cannot read), and in an answer its tokens stay counted in usage. Readable thinking in an answer is carried as reasoning_content.",
    ),
    (
        "tool_result is_error (Anthropic request)",
        "OpenAI has no flag for a failed tool. The result text, which says what failed, still arrives.",
    ),
    (
        "defer_loading (Anthropic tool)",
        "Asks for a tool to be found by search instead of listed up front. Sent to a chat provider, the tool is listed in full from the start, and the model can call it either way.",
    ),
    (
        "context_management with clear_thinking edits only (Anthropic request)",
        "Clears earlier thinking blocks from the context, and the translation drops thinking blocks anyway. Any other edit is refused.",
    ),
    (
        "anthropic-* headers such as anthropic-version and anthropic-beta (messages request sent to a chat provider)",
        "Opt-ins to Anthropic API versions and features that a chat provider does not have. A body field that a beta would enable is still refused by name.",
    ),
    (
        "safeguards (Anthropic request)",
        "Asks Anthropic's server to run Claude Code's auto mode classifier on tool use. A chat provider has no such classifier, and with no safeguard_results in the answer Claude Code runs its own classifier requests, so the check still happens. Dropping it also keeps the working and home folders it carries away from the provider.",
    ),
    (
        "citations (Anthropic answer)",
        "Pointers to the sources of cited text. The text itself still arrives.",
    ),
];

const TO_ANTHROPIC: &str = "Anthropic's messages API";
const TO_OPENAI: &str = "the OpenAI chat completions API";

pub(crate) fn fail<T>(message: String) -> Result<T> {
    Err(TranslateError(message))
}

pub(crate) fn untranslatable<T>(what: &str, target: &str) -> Result<T> {
    fail(format!(
        "{what} has no equivalent in {target}, so Enterplace cannot translate it. Remove it, or use a model whose provider speaks the client's format."
    ))
}

/// `The parameter "n" set to 2`, with the value only when it is short.
pub(crate) fn describe(key: &str, value: &Value) -> String {
    match value {
        Value::String(_) | Value::Number(_) | Value::Bool(_) => {
            format!("The parameter \"{key}\" set to {value}")
        }
        _ => format!("The parameter \"{key}\""),
    }
}

pub(crate) fn object<'a>(value: &'a Value, what: &str) -> Result<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| TranslateError(format!("{what} must be a JSON object.")))
}

pub(crate) fn array<'a>(value: &'a Value, what: &str) -> Result<&'a [Value]> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| TranslateError(format!("{what} must be a list.")))
}

pub(crate) fn string<'a>(value: &'a Value, what: &str) -> Result<&'a str> {
    value
        .as_str()
        .ok_or_else(|| TranslateError(format!("{what} must be a string.")))
}

pub(crate) fn insert(map: &mut Map<String, Value>, key: &str, value: Value) {
    map.insert(key.to_owned(), value);
}

/// The thinking budget, in tokens, that OpenAI's `reasoning_effort` stands for on providers that take a budget
/// (Anthropic's `thinking.budget_tokens`, Gemini 2.5's `thinkingBudget`, Claude on Bedrock). Anthropic's least is
/// 1024. The mapping is documented on the providers overview page.
pub fn thinking_budget(effort: &str) -> Option<u64> {
    match effort {
        "minimal" | "low" => Some(1024),
        "medium" => Some(4096),
        "high" => Some(16384),
        _ => None,
    }
}

/// The `reasoning_effort` a thinking budget stands for: the reverse of [`thinking_budget`], each budget to the
/// nearest level at or above it.
pub fn effort_for_budget(budget: u64) -> &'static str {
    match budget {
        0..=1024 => "low",
        1025..=4096 => "medium",
        _ => "high",
    }
}

/// Whether the client asked for a final usage chunk in an OpenAI stream.
pub fn include_usage(openai_request: &Value) -> bool {
    openai_request["stream_options"]["include_usage"] == true
}

// ---------------------------------------------------------------------------------------------------------
// Requests, OpenAI to Anthropic.

/// An OpenAI chat completions request as an Anthropic messages request.
pub fn openai_to_anthropic_request(request: &Value) -> Result<Value> {
    let fields = object(request, "The request body")?;
    let mut out = Map::new();
    let mut max_tokens: Option<&Value> = None;
    let mut user: Option<&Value> = None;
    let mut tool_choice: Option<Value> = None;
    let mut parallel = true;
    let mut output_config = Map::new();
    let mut thinking: Option<u64> = None;
    for (key, value) in fields {
        if value.is_null() {
            continue;
        }
        match key.as_str() {
            "model" | "stream" | "top_p" => {
                out.insert(key.clone(), value.clone());
            }
            "messages" => {}
            "temperature" => {
                // Scaling OpenAI's 0 to 2 into Anthropic's 0 to 1 would change what the client asked for.
                if value.as_f64().is_some_and(|t| t > 1.0) {
                    return fail(format!(
                        "The parameter \"temperature\" is {value}, but Anthropic accepts 0 to 1. Send 1 or less."
                    ));
                }
                out.insert(key.clone(), value.clone());
            }
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
                insert(&mut out, "stop_sequences", stops);
            }
            // Read by the stream converter, through include_usage; Anthropic has no such option.
            "stream_options" => {
                for (option, setting) in object(value, "\"stream_options\"")? {
                    if option != "include_usage"
                        && !matches!(setting, Value::Null | Value::Bool(false))
                    {
                        return untranslatable(
                            &format!("The stream option \"{option}\""),
                            TO_ANTHROPIC,
                        );
                    }
                }
            }
            "user" | "safety_identifier" => {
                if user.is_some_and(|u| u != value) {
                    return fail(
                        "\"user\" and \"safety_identifier\" differ, and Anthropic takes one user ID. Send only one of them."
                            .into(),
                    );
                }
                user = Some(value);
            }
            "tools" => insert(&mut out, "tools", openai_tools(value)?),
            "tool_choice" => tool_choice = Some(openai_tool_choice(value)?),
            "parallel_tool_calls" => {
                let Some(on) = value.as_bool() else {
                    return fail("\"parallel_tool_calls\" must be true or false.".into());
                };
                parallel = on;
            }
            "response_format" => {
                match value["type"].as_str() {
                    Some("text") => {}
                    Some("json_schema") => {
                        let schema = &value["json_schema"]["schema"];
                        if !schema.is_object() {
                            return fail("\"response_format.json_schema.schema\" must be a JSON schema object.".into());
                        }
                        // Name, description and strict: SAFE_TO_DROP.
                        insert(
                            &mut output_config,
                            "format",
                            json!({"type": "json_schema", "schema": schema}),
                        );
                    }
                    _ => {
                        return untranslatable(
                            &describe("response_format", &value["type"]),
                            TO_ANTHROPIC,
                        );
                    }
                }
            }
            // low, medium and high become a thinking budget (thinking_budget); the levels above high exist only as
            // Anthropic's effort, with adaptive thinking.
            "reasoning_effort" => match value.as_str() {
                Some("none") => {}
                Some(level @ ("low" | "medium" | "high")) => thinking = thinking_budget(level),
                Some("xhigh" | "max") => {
                    insert(&mut output_config, "effort", value.clone());
                    insert(&mut out, "thinking", json!({"type": "adaptive"}));
                }
                _ => return untranslatable(&describe(key, value), TO_ANTHROPIC),
            },
            // SAFE_TO_DROP.
            "seed" | "prompt_cache_key" | "metadata" => {}
            _ if is_openai_default(key, value) => {}
            _ => return untranslatable(&describe(key, value), TO_ANTHROPIC),
        }
    }
    let (system, messages) = openai_messages(&request["messages"])?;
    if !system.is_empty() {
        insert(&mut out, "system", Value::Array(system));
    }
    insert(&mut out, "messages", Value::Array(messages));
    let mut max_tokens = max_tokens.cloned().unwrap_or(json!(DEFAULT_MAX_TOKENS));
    if let Some(budget) = thinking {
        // Claude reasons only at its default sampling, and its budget is part of max_tokens.
        if out
            .get("temperature")
            .is_some_and(|t| t.as_f64() != Some(1.0))
        {
            return fail("\"temperature\" with \"reasoning_effort\": Claude takes no temperature while it reasons. Remove temperature, or remove reasoning_effort.".into());
        }
        if out
            .get("top_p")
            .is_some_and(|p| p.as_f64().is_some_and(|p| p < 0.95))
        {
            return fail("\"top_p\" below 0.95 with \"reasoning_effort\": Claude takes top_p from 0.95 to 1 while it reasons. Raise top_p, or remove it.".into());
        }
        match (
            fields
                .get("max_tokens")
                .or(fields.get("max_completion_tokens"))
                .and_then(Value::as_u64),
            max_tokens.as_u64(),
        ) {
            (Some(max), _) if max <= budget => {
                return fail(format!(
                    "\"reasoning_effort\" gives Claude a reasoning budget of {budget} tokens, which must be less than the max_tokens of {max}. Raise max_tokens above {budget}."
                ));
            }
            (None, _) => max_tokens = json!(budget + DEFAULT_MAX_TOKENS),
            _ => {}
        }
        insert(
            &mut out,
            "thinking",
            json!({"type": "enabled", "budget_tokens": budget}),
        );
    }
    insert(&mut out, "max_tokens", max_tokens);
    if !parallel {
        let choice = tool_choice.get_or_insert_with(|| json!({"type": "auto"}));
        if let Some(choice) = choice.as_object_mut().filter(|c| c["type"] != "none") {
            insert(choice, "disable_parallel_tool_use", Value::Bool(true));
        }
    }
    if let Some(choice) = tool_choice {
        insert(&mut out, "tool_choice", choice);
    }
    if !output_config.is_empty() {
        insert(&mut out, "output_config", Value::Object(output_config));
    }
    if let Some(user) = user {
        insert(&mut out, "metadata", json!({"user_id": user}));
    }
    Ok(Value::Object(out))
}

/// A parameter at the value OpenAI documents as its default asks for nothing.
pub(crate) fn is_openai_default(key: &str, value: &Value) -> bool {
    match key {
        "n" => value.as_u64() == Some(1),
        "logprobs" | "store" => *value == false,
        "frequency_penalty" | "presence_penalty" | "top_logprobs" => value.as_f64() == Some(0.0),
        "logit_bias" => value.as_object().is_some_and(Map::is_empty),
        "service_tier" => matches!(value.as_str(), Some("auto" | "default")),
        "verbosity" => value == "medium",
        "modalities" => *value == json!(["text"]),
        _ => false,
    }
}

/// The leading system and developer messages, and the rest as Anthropic messages.
fn openai_messages(messages: &Value) -> Result<(Vec<Value>, Vec<Value>)> {
    let messages = array(messages, "\"messages\"")?;
    let mut system = Vec::new();
    let mut out: Vec<Value> = Vec::new();
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
                    TO_ANTHROPIC,
                );
            }
        }
        let content = &message["content"];
        match role {
            "system" | "developer" => {
                let blocks = text_blocks(content, role)?;
                if out.is_empty() {
                    system.extend(blocks);
                } else {
                    // Anthropic takes later operator instructions as system messages in the conversation.
                    out.push(json!({"role": "system", "content": blocks}));
                }
            }
            "user" => push_user(&mut out, user_blocks(content)?),
            "assistant" => out.push(assistant_message(message)?),
            "tool" => {
                let id = string(
                    &message["tool_call_id"],
                    "A tool message's \"tool_call_id\"",
                )?;
                let result = json!({"type": "tool_result", "tool_use_id": id, "content": text_blocks(content, role)?});
                push_user(&mut out, vec![result]);
            }
            _ => return untranslatable(&format!("A message with role \"{role}\""), TO_ANTHROPIC),
        }
    }
    Ok((system, out))
}

/// Anthropic wants every tool result of a turn in one user message, so consecutive user content is merged.
fn push_user(out: &mut Vec<Value>, mut blocks: Vec<Value>) {
    if let Some(last) = out.last_mut().filter(|m| m["role"] == "user") {
        if let Some(content) = last.get_mut("content").and_then(Value::as_array_mut) {
            content.append(&mut blocks);
            return;
        }
    }
    out.push(json!({"role": "user", "content": blocks}));
}

/// Text content as Anthropic text blocks. Empty text is left out: Anthropic refuses empty text blocks.
fn text_blocks(content: &Value, role: &str) -> Result<Vec<Value>> {
    let texts: Vec<&str> = match content {
        Value::String(text) => vec![text],
        Value::Array(parts) => parts
            .iter()
            .map(|part| match part["type"].as_str() {
                Some("text") => string(&part["text"], "A text part's \"text\""),
                other => untranslatable(
                    &format!("A {} part in a {role} message", other.unwrap_or("untyped")),
                    TO_ANTHROPIC,
                ),
            })
            .collect::<Result<_>>()?,
        _ => {
            return fail(format!(
                "A {role} message needs \"content\" that is a string or a list of parts."
            ));
        }
    };
    Ok(texts
        .into_iter()
        .filter(|t| !t.is_empty())
        .map(|t| json!({"type": "text", "text": t}))
        .collect())
}

fn user_blocks(content: &Value) -> Result<Vec<Value>> {
    let Value::Array(parts) = content else {
        return text_blocks(content, "user");
    };
    parts
        .iter()
        .map(|part| match part["type"].as_str() {
            Some("text") => Ok(json!({"type": "text", "text": string(&part["text"], "A text part's \"text\"")?})),
            // image_url.detail: SAFE_TO_DROP.
            Some("image_url") => {
                let url = string(&part["image_url"]["url"], "An image part's \"image_url.url\"")?;
                let source = match url.strip_prefix("data:") {
                    Some(_) => {
                        let (media_type, data) = data_url(url)?;
                        json!({"type": "base64", "media_type": media_type, "data": data})
                    }
                    None => json!({"type": "url", "url": url}),
                };
                Ok(json!({"type": "image", "source": source}))
            }
            Some("file") => {
                let file = &part["file"];
                if !file["file_id"].is_null() {
                    return untranslatable("An OpenAI file ID", TO_ANTHROPIC);
                }
                let (media_type, data) =
                    data_url(string(&file["file_data"], "A file part's \"file.file_data\"")?)?;
                let mut document =
                    json!({"type": "document", "source": {"type": "base64", "media_type": media_type, "data": data}});
                if let (Some(name), Some(doc)) = (file["filename"].as_str(), document.as_object_mut()) {
                    insert(doc, "title", json!(name));
                }
                Ok(document)
            }
            other => untranslatable(
                &format!("A content part of type \"{}\"", other.unwrap_or("none")),
                TO_ANTHROPIC,
            ),
        })
        .collect()
}

/// `data:image/png;base64,AAAA` as its media type and data.
pub(crate) fn data_url(url: &str) -> Result<(&str, &str)> {
    url.strip_prefix("data:")
        .and_then(|rest| rest.split_once(";base64,"))
        .ok_or_else(|| {
            TranslateError(
                "An inline image or file must be a base64 data URL (data:<type>;base64,<data>). Encode it in base64."
                    .into(),
            )
        })
}

fn assistant_message(message: &Value) -> Result<Value> {
    let mut blocks = match &message["content"] {
        Value::Null => Vec::new(),
        content => text_blocks(content, "assistant")?,
    };
    if let Some(calls) = message.get("tool_calls").filter(|c| !c.is_null()) {
        for call in array(calls, "\"tool_calls\"")? {
            if call["type"].as_str().is_some_and(|t| t != "function") {
                return untranslatable(
                    &format!("A tool call of type {}", call["type"]),
                    TO_ANTHROPIC,
                );
            }
            let id = string(&call["id"], "A tool call's \"id\"")?;
            let name = string(&call["function"]["name"], "A tool call's \"function.name\"")?;
            let input = tool_input(
                id,
                call["function"]["arguments"].as_str().unwrap_or_default(),
            )?;
            blocks.push(json!({"type": "tool_use", "id": id, "name": name, "input": input}));
        }
    }
    Ok(json!({"role": "assistant", "content": blocks}))
}

/// OpenAI carries tool arguments as a JSON string, Anthropic as an object.
pub(crate) fn tool_input(id: &str, arguments: &str) -> Result<Value> {
    if arguments.trim().is_empty() {
        return Ok(json!({}));
    }
    match serde_json::from_str::<Value>(arguments) {
        Ok(input) if input.is_object() => Ok(input),
        _ => fail(format!(
            "The arguments of tool call \"{id}\" are not a JSON object. Send them as a JSON object encoded in a string."
        )),
    }
}

fn openai_tools(tools: &Value) -> Result<Value> {
    array(tools, "\"tools\"")?
        .iter()
        .map(|tool| {
            if tool["type"] != "function" {
                return untranslatable(&format!("A tool of type {}", tool["type"]), TO_ANTHROPIC);
            }
            let mut out = Map::new();
            for (key, value) in object(&tool["function"], "A tool's \"function\"")? {
                match key.as_str() {
                    _ if value.is_null() => {}
                    "name" | "description" | "strict" => {
                        out.insert(key.clone(), value.clone());
                    }
                    "parameters" => insert(&mut out, "input_schema", value.clone()),
                    _ => return untranslatable(&format!("The tool field \"{key}\""), TO_ANTHROPIC),
                }
            }
            out.entry("input_schema")
                .or_insert_with(|| json!({"type": "object", "properties": {}}));
            Ok(Value::Object(out))
        })
        .collect::<Result<Vec<_>>>()
        .map(Value::Array)
}

fn openai_tool_choice(choice: &Value) -> Result<Value> {
    match choice.as_str() {
        Some("none") => Ok(json!({"type": "none"})),
        Some("auto") => Ok(json!({"type": "auto"})),
        Some("required") => Ok(json!({"type": "any"})),
        None if choice["type"] == "function" => {
            let name = string(&choice["function"]["name"], "\"tool_choice.function.name\"")?;
            Ok(json!({"type": "tool", "name": name}))
        }
        _ => untranslatable(&describe("tool_choice", choice), TO_ANTHROPIC),
    }
}

// ---------------------------------------------------------------------------------------------------------
// Requests, Anthropic to OpenAI.

/// An Anthropic messages request as an OpenAI chat completions request.
pub fn anthropic_to_openai_request(request: &Value) -> Result<Value> {
    let fields = object(request, "The request body")?;
    let mut out = Map::new();
    let mut tool_choice = None;
    let mut parallel = true;
    for (key, value) in fields {
        if value.is_null() {
            continue;
        }
        match key.as_str() {
            "model" | "temperature" | "top_p" => {
                out.insert(key.clone(), value.clone());
            }
            "system" | "messages" => {}
            "stream" => {
                out.insert(key.clone(), value.clone());
                // An Anthropic stream always reports usage; OpenAI reports it only when asked.
                if *value == true {
                    insert(&mut out, "stream_options", json!({"include_usage": true}));
                }
            }
            // OpenAI's max_tokens is deprecated and refused by its reasoning models.
            "max_tokens" => insert(&mut out, "max_completion_tokens", value.clone()),
            "stop_sequences" => insert(&mut out, "stop", value.clone()),
            "metadata" => {
                for (field, id) in object(value, "\"metadata\"")? {
                    match field.as_str() {
                        _ if id.is_null() => {}
                        // OpenAI takes at most 64 characters, and Claude Code sends a JSON object of device,
                        // account and session IDs. Its hash still tells users apart and reveals none of them.
                        "user_id" => insert(
                            &mut out,
                            "safety_identifier",
                            match id.as_str() {
                                Some(text) if text.len() > 64 => {
                                    crate::id::sha256_hex(text.as_bytes()).into()
                                }
                                _ => id.clone(),
                            },
                        ),
                        _ => {
                            return untranslatable(
                                &format!("The metadata field \"{field}\""),
                                TO_OPENAI,
                            );
                        }
                    }
                }
            }
            "tools" => insert(&mut out, "tools", anthropic_tools(value)?),
            "tool_choice" => {
                parallel = value["disable_parallel_tool_use"] != true;
                tool_choice = Some(anthropic_tool_choice(value)?);
            }
            "thinking" => match value["type"].as_str() {
                // Adaptive: SAFE_TO_DROP. Disabled asks for nothing.
                Some("adaptive" | "disabled") => {}
                // A budget becomes the reasoning_effort it stands for (effort_for_budget).
                Some("enabled") => {
                    let Some(budget) = value["budget_tokens"].as_u64() else {
                        return fail("\"thinking.budget_tokens\" must be a whole number.".into());
                    };
                    if !out.contains_key("reasoning_effort") {
                        insert(
                            &mut out,
                            "reasoning_effort",
                            json!(effort_for_budget(budget)),
                        );
                    }
                }
                _ => {
                    return untranslatable(
                        &format!("Thinking of type {}", value["type"]),
                        TO_OPENAI,
                    );
                }
            },
            "output_config" => {
                for (field, setting) in object(value, "\"output_config\"")? {
                    match field.as_str() {
                        _ if setting.is_null() => {}
                        // Effort is the more precise of the two, so it wins over a thinking budget.
                        "effort" => insert(&mut out, "reasoning_effort", setting.clone()),
                        "format" if setting["type"] == "json_schema" => insert(
                            &mut out,
                            "response_format",
                            // OpenAI requires a name; the schema is what matters.
                            json!({"type": "json_schema", "json_schema": {"name": "response", "schema": setting["schema"], "strict": true}}),
                        ),
                        _ => {
                            return untranslatable(
                                &describe(&format!("output_config.{field}"), setting),
                                TO_OPENAI,
                            );
                        }
                    }
                }
            }
            // SAFE_TO_DROP.
            "cache_control" | "safeguards" => {}
            // Clearing thinking blocks, which the translation drops anyway (SAFE_TO_DROP). Any other edit changes
            // what the model is sent and is refused.
            "context_management" => {
                for edit in array(&value["edits"], "\"context_management.edits\"")? {
                    let kind = edit["type"].as_str().unwrap_or("untyped");
                    if !kind.starts_with("clear_thinking_") {
                        return untranslatable(
                            &format!("The context_management edit of type {kind}"),
                            TO_OPENAI,
                        );
                    }
                }
            }
            _ => return untranslatable(&describe(key, value), TO_OPENAI),
        }
    }
    let mut messages = Vec::new();
    if let Some(system) = fields.get("system").filter(|s| !s.is_null()) {
        messages.push(json!({"role": "system", "content": anthropic_text_content(system)?}));
    }
    for message in array(&request["messages"], "\"messages\"")? {
        let fields = object(message, "Each message")?;
        if let Some(key) = fields.keys().find(|k| *k != "role" && *k != "content") {
            return untranslatable(&format!("The message field \"{key}\""), TO_OPENAI);
        }
        let content = &message["content"];
        match message["role"].as_str() {
            Some("system") => messages
                .push(json!({"role": "system", "content": anthropic_text_content(content)?})),
            Some("user") => messages.extend(anthropic_user(content)?),
            Some("assistant") => messages.push(anthropic_assistant(content)?),
            other => return untranslatable(&format!("A message with role {other:?}"), TO_OPENAI),
        }
    }
    insert(&mut out, "messages", Value::Array(messages));
    if let Some(choice) = tool_choice {
        insert(&mut out, "tool_choice", choice);
    }
    if !parallel {
        insert(&mut out, "parallel_tool_calls", Value::Bool(false));
    }
    Ok(Value::Object(out))
}

/// Refuses any field of a content block other than those named; cache_control is SAFE_TO_DROP everywhere.
fn check_block(block: &Value, allowed: &[&str]) -> Result<()> {
    let kind = block["type"].as_str().unwrap_or("untyped");
    for (key, value) in object(block, "Each content block")? {
        // The API marks a tool call made by the model itself as caller "direct"; clients send it back as is.
        let direct_caller = key == "caller" && value["type"] == "direct";
        if !value.is_null()
            && !direct_caller
            && key != "type"
            && key != "cache_control"
            && !allowed.contains(&key.as_str())
        {
            return untranslatable(&format!("The field \"{key}\" on a {kind} block"), TO_OPENAI);
        }
    }
    Ok(())
}

fn anthropic_text(block: &Value) -> Result<&str> {
    if block["type"] != "text" {
        return untranslatable(&format!("A {} block here", block["type"]), TO_OPENAI);
    }
    // citations: SAFE_TO_DROP.
    check_block(block, &["text", "citations"])?;
    string(&block["text"], "A text block's \"text\"")
}

/// A string, or text blocks as OpenAI text parts.
fn anthropic_text_content(content: &Value) -> Result<Value> {
    match content {
        Value::String(_) => Ok(content.clone()),
        _ => array(content, "\"content\"")?
            .iter()
            .map(|block| Ok(json!({"type": "text", "text": anthropic_text(block)?})))
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
    }
}

/// A user turn: its tool results as OpenAI tool messages, then the rest as one user message.
fn anthropic_user(content: &Value) -> Result<Vec<Value>> {
    if content.is_string() {
        return Ok(vec![json!({"role": "user", "content": content})]);
    }
    let mut out = Vec::new();
    let mut parts = Vec::new();
    for block in array(content, "A user message's \"content\"")? {
        match block["type"].as_str() {
            Some("text") => parts.push(json!({"type": "text", "text": anthropic_text(block)?})),
            Some("image") => {
                check_block(block, &["source"])?;
                let source = &block["source"];
                let url = match source["type"].as_str() {
                    Some("base64") => format!(
                        "data:{};base64,{}",
                        string(&source["media_type"], "An image's \"media_type\"")?,
                        string(&source["data"], "An image's \"data\"")?
                    ),
                    Some("url") => string(&source["url"], "An image's \"url\"")?.to_owned(),
                    _ => {
                        return untranslatable(
                            &format!("An image source of type {}", source["type"]),
                            TO_OPENAI,
                        );
                    }
                };
                parts.push(json!({"type": "image_url", "image_url": {"url": url}}));
            }
            Some("tool_result") => {
                // is_error: SAFE_TO_DROP.
                check_block(block, &["tool_use_id", "content", "is_error"])?;
                let id = string(&block["tool_use_id"], "A tool result's \"tool_use_id\"")?;
                let result = match &block["content"] {
                    Value::Null => json!(""),
                    content => anthropic_text_content(content)?,
                };
                out.push(json!({"role": "tool", "tool_call_id": id, "content": result}));
            }
            other => {
                return untranslatable(
                    &format!("A {} block", other.unwrap_or("untyped")),
                    TO_OPENAI,
                );
            }
        }
    }
    if !parts.is_empty() {
        out.push(json!({"role": "user", "content": parts}));
    }
    Ok(out)
}

fn anthropic_assistant(content: &Value) -> Result<Value> {
    if content.is_string() {
        return Ok(json!({"role": "assistant", "content": content}));
    }
    let mut texts = Vec::new();
    let mut calls = Vec::new();
    for block in array(content, "An assistant message's \"content\"")? {
        match block["type"].as_str() {
            Some("text") => texts.push(json!({"type": "text", "text": anthropic_text(block)?})),
            Some("tool_use") => {
                check_block(block, &["id", "name", "input"])?;
                calls.push(json!({
                    "id": block["id"],
                    "type": "function",
                    "function": {"name": block["name"], "arguments": block["input"].to_string()},
                }));
            }
            // SAFE_TO_DROP.
            Some("thinking" | "redacted_thinking") => {}
            other => {
                return untranslatable(
                    &format!("A {} block", other.unwrap_or("untyped")),
                    TO_OPENAI,
                );
            }
        }
    }
    let content = match texts.len() {
        0 => Value::Null,
        1 => texts[0]["text"].clone(),
        _ => Value::Array(texts),
    };
    let mut message = json!({"role": "assistant", "content": content});
    if let (false, Some(fields)) = (calls.is_empty(), message.as_object_mut()) {
        insert(fields, "tool_calls", Value::Array(calls));
    }
    Ok(message)
}

fn anthropic_tools(tools: &Value) -> Result<Value> {
    array(tools, "\"tools\"")?
        .iter()
        .map(|tool| {
            // Server tools (web search, bash, code execution) run at Anthropic and have a type; custom tools do not.
            if !tool["type"].is_null() && tool["type"] != "custom" {
                return untranslatable(&format!("The tool type {}", tool["type"]), TO_OPENAI);
            }
            let mut function = Map::new();
            for (key, value) in object(tool, "Each tool")? {
                match key.as_str() {
                    // eager_input_streaming, cache_control and defer_loading: SAFE_TO_DROP.
                    _ if value.is_null() => {}
                    "type" | "cache_control" | "eager_input_streaming" | "defer_loading" => {}
                    "name" | "description" | "strict" => {
                        function.insert(key.clone(), value.clone());
                    }
                    "input_schema" => insert(&mut function, "parameters", value.clone()),
                    _ => return untranslatable(&format!("The tool field \"{key}\""), TO_OPENAI),
                }
            }
            Ok(json!({"type": "function", "function": function}))
        })
        .collect::<Result<Vec<_>>>()
        .map(Value::Array)
}

fn anthropic_tool_choice(choice: &Value) -> Result<Value> {
    match choice["type"].as_str() {
        Some("auto") => Ok(json!("auto")),
        Some("any") => Ok(json!("required")),
        Some("none") => Ok(json!("none")),
        Some("tool") => Ok(
            json!({"type": "function", "function": {"name": string(&choice["name"], "\"tool_choice.name\"")?}}),
        ),
        _ => untranslatable(&describe("tool_choice.type", &choice["type"]), TO_OPENAI),
    }
}

// ---------------------------------------------------------------------------------------------------------
// Answers.

pub(crate) fn openai_usage(usage: &Usage) -> Value {
    let prompt = usage.prompt();
    json!({
        "prompt_tokens": prompt,
        "completion_tokens": usage.output,
        "total_tokens": prompt + usage.output,
        "prompt_tokens_details": {"cached_tokens": usage.cache_read, "cache_write_tokens": usage.cache_write + usage.cache_write_1h},
    })
}

fn anthropic_usage(usage: &Usage) -> Value {
    json!({
        "input_tokens": usage.input,
        "output_tokens": usage.output,
        "cache_read_input_tokens": usage.cache_read,
        "cache_creation_input_tokens": usage.cache_write + usage.cache_write_1h,
    })
}

fn openai_finish_reason(stop_reason: &Value) -> Result<Value> {
    Ok(match stop_reason.as_str() {
        None => Value::Null,
        Some("end_turn" | "stop_sequence") => json!("stop"),
        Some("max_tokens" | "model_context_window_exceeded") => json!("length"),
        Some("tool_use") => json!("tool_calls"),
        Some("refusal") => json!("content_filter"),
        // pause_turn asks the client to send the turn back so a server tool can go on; OpenAI has no such step.
        Some(other) => return untranslatable(&format!("The stop reason \"{other}\""), TO_OPENAI),
    })
}

/// An Anthropic message as an OpenAI chat completion. `created` is the Unix time in seconds, which
/// Anthropic's answer does not carry.
pub fn anthropic_to_openai_response(message: &Value, created: u64) -> Result<Value> {
    object(message, "The provider's answer")?;
    let mut text: Option<String> = None;
    let mut reasoning = String::new();
    let mut calls = Vec::new();
    for block in message["content"].as_array().map_or(&[][..], Vec::as_slice) {
        match block["type"].as_str() {
            // citations: SAFE_TO_DROP.
            Some("text") => text
                .get_or_insert_default()
                .push_str(block["text"].as_str().unwrap_or_default()),
            // Readable reasoning goes on as reasoning_content, as DeepSeek and vLLM send it; its signature and
            // redacted reasoning are SAFE_TO_DROP.
            Some("thinking") => reasoning.push_str(block["thinking"].as_str().unwrap_or_default()),
            Some("tool_use") => calls.push(json!({
                "id": block["id"],
                "type": "function",
                "function": {"name": block["name"], "arguments": block["input"].to_string()},
            })),
            // SAFE_TO_DROP.
            Some("redacted_thinking") => {}
            other => {
                return untranslatable(
                    &format!("A {} block in the answer", other.unwrap_or("untyped")),
                    TO_OPENAI,
                );
            }
        }
    }
    let mut reply = json!({"role": "assistant", "content": text});
    if let (false, Some(fields)) = (calls.is_empty(), reply.as_object_mut()) {
        insert(fields, "tool_calls", Value::Array(calls));
    }
    if let (false, Some(fields)) = (reasoning.is_empty(), reply.as_object_mut()) {
        insert(fields, "reasoning_content", json!(reasoning));
    }
    let mut usage = Usage::default();
    usage.merge_anthropic(&message["usage"]);
    Ok(json!({
        "id": message["id"],
        "object": "chat.completion",
        "created": created,
        "model": message["model"],
        "choices": [{"index": 0, "message": reply, "logprobs": null, "finish_reason": openai_finish_reason(&message["stop_reason"])?}],
        "usage": openai_usage(&usage),
    }))
}

/// An OpenAI chat completion as an Anthropic message.
pub fn openai_to_anthropic_response(completion: &Value) -> Result<Value> {
    let choices = array(&completion["choices"], "The answer's \"choices\"")?;
    let [choice] = choices else {
        return fail(format!(
            "The answer has {} choices and Anthropic's format holds one. Send \"n\": 1.",
            choices.len()
        ));
    };
    let reply = &choice["message"];
    for field in ["audio", "function_call"] {
        if !reply[field].is_null() {
            return untranslatable(&format!("The answer field \"{field}\""), TO_ANTHROPIC);
        }
    }
    if reply["annotations"]
        .as_array()
        .is_some_and(|a| !a.is_empty())
    {
        return untranslatable("Annotations in the answer", TO_ANTHROPIC);
    }
    let mut content = Vec::new();
    if let Some(text) = reply["content"].as_str().filter(|t| !t.is_empty()) {
        content.push(json!({"type": "text", "text": text}));
    }
    let refusal = reply["refusal"].as_str();
    if let Some(text) = refusal {
        content.push(json!({"type": "text", "text": text}));
    }
    for call in reply["tool_calls"]
        .as_array()
        .map_or(&[][..], Vec::as_slice)
    {
        let id = string(&call["id"], "A tool call's \"id\"")?;
        let input = tool_input(
            id,
            call["function"]["arguments"].as_str().unwrap_or_default(),
        )?;
        content.push(
            json!({"type": "tool_use", "id": id, "name": call["function"]["name"], "input": input}),
        );
    }
    let stop_reason = anthropic_stop_reason(refusal.is_some(), choice["finish_reason"].as_str())?;
    Ok(json!({
        "id": completion["id"],
        "type": "message",
        "role": "assistant",
        "model": completion["model"],
        "content": content,
        "stop_reason": stop_reason,
        // OpenAI does not say which stop string ended the answer, so a stop by one reads as end_turn.
        "stop_sequence": null,
        "usage": anthropic_usage(&Usage::from_openai(&completion["usage"])),
    }))
}

fn anthropic_stop_reason(refused: bool, finish_reason: Option<&str>) -> Result<Value> {
    Ok(match (refused, finish_reason) {
        (true, _) | (_, Some("content_filter")) => json!("refusal"),
        (_, None) => Value::Null,
        (_, Some("stop")) => json!("end_turn"),
        (_, Some("length")) => json!("max_tokens"),
        (_, Some("tool_calls")) => json!("tool_use"),
        (_, Some(other)) => {
            return untranslatable(&format!("The finish reason \"{other}\""), TO_ANTHROPIC);
        }
    })
}

// ---------------------------------------------------------------------------------------------------------
// Streams, OpenAI to Anthropic.

/// The content block open in an Anthropic stream being written: text, or the tool call with this OpenAI index.
#[derive(Debug, PartialEq)]
enum Open {
    None,
    Text,
    Tool(u64),
}

/// Turns an OpenAI chat completions stream into an Anthropic messages stream as the bytes arrive, with the
/// events Claude Code reads: message_start, content_block_start/delta/stop for text and tool_use (tool input as
/// input_json_delta), message_delta with stop_reason and usage, message_stop.
#[derive(Debug)]
pub struct OpenAiToAnthropicStream {
    line: Vec<u8>,
    fallback_id: String,
    started: bool,
    open: Open,
    /// Index of the next Anthropic content block.
    blocks: u64,
    refused: bool,
    finish: Option<String>,
    usage: Usage,
    done: bool,
}

impl OpenAiToAnthropicStream {
    /// `fallback_id` names the message when the provider's chunks carry no id.
    pub fn new(fallback_id: String) -> Self {
        Self {
            line: Vec::new(),
            fallback_id,
            started: false,
            open: Open::None,
            blocks: 0,
            refused: false,
            finish: None,
            usage: Usage::default(),
            done: false,
        }
    }

    /// Feeds the next bytes of the provider's stream, split anywhere, and returns the Anthropic bytes ready to send.
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

    /// Call when the provider's stream ends. Fails if it ended before `data: [DONE]`.
    pub fn finish(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let line = std::mem::take(&mut self.line);
        let last = self.on_line(&line, &mut out);
        if !self.done {
            return fail(
                "The provider's stream ended before its [DONE] line, so the answer is incomplete. Retry the request."
                    .into(),
            );
        }
        last.map(|()| out)
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
        let chunk: Value = serde_json::from_slice(data).map_err(|e| {
            TranslateError(format!(
                "The provider sent a stream chunk that is not JSON: {e}."
            ))
        })?;
        self.on_chunk(&chunk, out)
    }

    fn on_chunk(&mut self, chunk: &Value, out: &mut Vec<u8>) -> Result<()> {
        if let Some(error) = chunk.get("error").filter(|e| !e.is_null()) {
            // Anthropic's clients raise on an error event; nothing follows it.
            let kind = error["type"].as_str().unwrap_or("api_error");
            emit(
                out,
                "error",
                &json!({"type": "error", "error": {"type": kind, "message": error["message"]}}),
            );
            self.done = true;
            return Ok(());
        }
        if !self.started {
            self.started = true;
            let id = chunk["id"]
                .as_str()
                .filter(|id| !id.is_empty())
                .map_or_else(|| self.fallback_id.clone(), String::from);
            emit(
                out,
                "message_start",
                &json!({"type": "message_start", "message": {
                    "id": id, "type": "message", "role": "assistant", "model": chunk["model"], "content": [],
                    "stop_reason": null, "stop_sequence": null,
                    // OpenAI counts arrive in the last chunk; message_delta carries them.
                    "usage": {"input_tokens": 0, "output_tokens": 0},
                }}),
            );
        }
        if !chunk["usage"].is_null() {
            self.usage = Usage::from_openai(&chunk["usage"]);
        }
        let choices = chunk["choices"].as_array().map_or(&[][..], Vec::as_slice);
        if choices.len() > 1 {
            return fail(format!(
                "The stream has {} choices and Anthropic's format holds one. Send \"n\": 1.",
                choices.len()
            ));
        }
        let Some(choice) = choices.first() else {
            return Ok(());
        };
        let delta = &choice["delta"];
        for field in ["audio", "function_call"] {
            if !delta[field].is_null() {
                return untranslatable(&format!("The answer field \"{field}\""), TO_ANTHROPIC);
            }
        }
        for text in [delta["content"].as_str(), delta["refusal"].as_str()]
            .into_iter()
            .flatten()
            .filter(|t| !t.is_empty())
        {
            if self.open != Open::Text {
                self.close(out);
                self.start(out, json!({"type": "text", "text": ""}), Open::Text);
            }
            self.delta(out, json!({"type": "text_delta", "text": text}));
        }
        self.refused |= delta["refusal"].as_str().is_some_and(|t| !t.is_empty());
        for call in delta["tool_calls"]
            .as_array()
            .map_or(&[][..], Vec::as_slice)
        {
            let index = call["index"].as_u64().unwrap_or_default();
            if self.open != Open::Tool(index) {
                let id = string(&call["id"], "A new tool call's \"id\"")?;
                self.close(out);
                self.start(
                    out,
                    json!({"type": "tool_use", "id": id, "name": call["function"]["name"], "input": {}}),
                    Open::Tool(index),
                );
            }
            if let Some(part) = call["function"]["arguments"]
                .as_str()
                .filter(|p| !p.is_empty())
            {
                self.delta(
                    out,
                    json!({"type": "input_json_delta", "partial_json": part}),
                );
            }
        }
        if let Some(reason) = choice["finish_reason"].as_str() {
            self.finish = Some(reason.to_string());
        }
        Ok(())
    }

    fn start(&mut self, out: &mut Vec<u8>, block: Value, open: Open) {
        emit(
            out,
            "content_block_start",
            &json!({"type": "content_block_start", "index": self.blocks, "content_block": block}),
        );
        self.open = open;
    }

    fn delta(&self, out: &mut Vec<u8>, delta: Value) {
        emit(
            out,
            "content_block_delta",
            &json!({"type": "content_block_delta", "index": self.blocks, "delta": delta}),
        );
    }

    fn close(&mut self, out: &mut Vec<u8>) {
        if self.open != Open::None {
            emit(
                out,
                "content_block_stop",
                &json!({"type": "content_block_stop", "index": self.blocks}),
            );
            self.blocks += 1;
            self.open = Open::None;
        }
    }

    fn end(&mut self, out: &mut Vec<u8>) -> Result<()> {
        if !self.started {
            return fail(
                "The provider's stream ended before any answer arrived. Retry the request.".into(),
            );
        }
        self.close(out);
        let stop_reason = anthropic_stop_reason(self.refused, self.finish.as_deref())?;
        emit(
            out,
            "message_delta",
            &json!({"type": "message_delta", "delta": {"stop_reason": stop_reason, "stop_sequence": null}, "usage": anthropic_usage(&self.usage)}),
        );
        emit(out, "message_stop", &json!({"type": "message_stop"}));
        self.done = true;
        Ok(())
    }
}

fn emit(out: &mut Vec<u8>, name: &str, event: &Value) {
    out.extend_from_slice(b"event: ");
    out.extend_from_slice(name.as_bytes());
    out.push(b'\n');
    write_event(out, event);
}

// ---------------------------------------------------------------------------------------------------------
// Streams, Anthropic to OpenAI.

/// Turns an Anthropic messages stream into an OpenAI chat completions stream as the bytes arrive.
#[derive(Debug)]
pub struct AnthropicToOpenAiStream {
    include_usage: bool,
    created: u64,
    line: Vec<u8>,
    id: Value,
    model: Value,
    /// The Anthropic block index of each tool call, in OpenAI tool call order.
    tool_blocks: Vec<u64>,
    usage: Usage,
    done: bool,
}

impl AnthropicToOpenAiStream {
    /// `include_usage` is the client's `stream_options.include_usage` (see [`include_usage`]); `created` is
    /// the Unix time in seconds.
    pub fn new(include_usage: bool, created: u64) -> Self {
        Self {
            include_usage,
            created,
            line: Vec::new(),
            id: Value::Null,
            model: Value::Null,
            tool_blocks: Vec::new(),
            usage: Usage::default(),
            done: false,
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

    /// Call when the provider's stream ends. Fails if it ended before the answer was complete.
    pub fn finish(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let line = std::mem::take(&mut self.line);
        // A stream cut mid-line leaves half an event; the missing end is the cause worth reporting.
        let last = self.on_line(&line, &mut out);
        if !self.done {
            return fail(
                "The provider's stream ended before its message_stop event, so the answer is incomplete. Retry the request."
                    .into(),
            );
        }
        last.map(|()| out)
    }

    fn on_line(&mut self, line: &[u8], out: &mut Vec<u8>) -> Result<()> {
        if self.done {
            return Ok(());
        }
        let Some(data) = sse_data(line) else {
            return Ok(());
        };
        let event: Value = serde_json::from_slice(data).map_err(|e| {
            TranslateError(format!(
                "The provider sent a stream event that is not JSON: {e}."
            ))
        })?;
        self.on_event(&event, out)
    }

    fn on_event(&mut self, event: &Value, out: &mut Vec<u8>) -> Result<()> {
        match event["type"].as_str().unwrap_or_default() {
            "message_start" => {
                let message = &event["message"];
                self.id = message["id"].clone();
                self.model = message["model"].clone();
                self.usage.merge_anthropic(&message["usage"]);
                self.chunk(
                    out,
                    json!({"role": "assistant", "content": ""}),
                    Value::Null,
                );
            }
            "content_block_start" => {
                let block = &event["content_block"];
                match block["type"].as_str().unwrap_or_default() {
                    "text" => {
                        if let Some(text) = block["text"].as_str().filter(|t| !t.is_empty()) {
                            self.chunk(out, json!({"content": text}), Value::Null);
                        }
                    }
                    "tool_use" => {
                        let n = self.tool_blocks.len();
                        self.tool_blocks
                            .push(event["index"].as_u64().unwrap_or_default());
                        let call = json!({"index": n, "id": block["id"], "type": "function", "function": {"name": block["name"], "arguments": ""}});
                        self.chunk(out, json!({"tool_calls": [call]}), Value::Null);
                    }
                    // SAFE_TO_DROP.
                    "thinking" | "redacted_thinking" => {}
                    other => {
                        return untranslatable(
                            &format!("A {other} block in the answer"),
                            TO_OPENAI,
                        );
                    }
                }
            }
            "content_block_delta" => {
                let delta = &event["delta"];
                match delta["type"].as_str().unwrap_or_default() {
                    "text_delta" => self.chunk(out, json!({"content": delta["text"]}), Value::Null),
                    "input_json_delta" => {
                        let block = event["index"].as_u64();
                        let Some(n) = self.tool_blocks.iter().position(|&b| Some(b) == block)
                        else {
                            return fail(
                                "The provider sent tool input for a block that is not a tool call."
                                    .into(),
                            );
                        };
                        if let Some(part) = delta["partial_json"].as_str().filter(|p| !p.is_empty())
                        {
                            let call = json!({"index": n, "function": {"arguments": part}});
                            self.chunk(out, json!({"tool_calls": [call]}), Value::Null);
                        }
                    }
                    "thinking_delta" => {
                        if let Some(text) = delta["thinking"].as_str().filter(|t| !t.is_empty()) {
                            self.chunk(out, json!({"reasoning_content": text}), Value::Null);
                        }
                    }
                    // SAFE_TO_DROP.
                    "signature_delta" | "citations_delta" => {}
                    other => return untranslatable(&format!("A {other} in the answer"), TO_OPENAI),
                }
            }
            "message_delta" => {
                self.usage.merge_anthropic(&event["usage"]);
                let finish = openai_finish_reason(&event["delta"]["stop_reason"])?;
                if !finish.is_null() {
                    self.chunk(out, json!({}), finish);
                }
            }
            "message_stop" => {
                if self.include_usage {
                    let chunk = json!({
                        "id": self.id, "object": "chat.completion.chunk", "created": self.created,
                        "model": self.model, "choices": [], "usage": openai_usage(&self.usage),
                    });
                    write_event(out, &chunk);
                }
                out.extend_from_slice(b"data: [DONE]\n\n");
                self.done = true;
            }
            "error" => {
                // OpenAI clients raise on a data line holding an error object. No [DONE] follows: the answer failed.
                let error = &event["error"];
                write_event(
                    out,
                    &json!({"error": {"message": error["message"], "type": error["type"], "code": null}}),
                );
                self.done = true;
            }
            // ping, content_block_stop, and event types added later, which Anthropic's versioning policy says
            // a client should ignore.
            _ => {}
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

pub(crate) fn write_event(out: &mut Vec<u8>, event: &Value) {
    out.extend_from_slice(b"data: ");
    out.extend_from_slice(event.to_string().as_bytes());
    out.extend_from_slice(b"\n\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn err_text<T: fmt::Debug>(result: Result<T>) -> String {
        match result {
            Err(e) => e.to_string(),
            Ok(v) => format!("unexpectedly translated: {v:?}"),
        }
    }

    #[test]
    fn an_openai_request_becomes_an_anthropic_request() -> TestResult {
        let request = json!({
            "model": "claude-sonnet-5-5",
            "messages": [
                {"role": "system", "content": "Be brief."},
                {"role": "developer", "content": [{"type": "text", "text": "Use metric units."}]},
                {"role": "user", "content": [
                    {"type": "text", "text": "Weather here?"},
                    {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0", "detail": "high"}},
                    {"type": "image_url", "image_url": {"url": "https://example.com/map.jpg"}},
                    {"type": "file", "file": {"file_data": "data:application/pdf;base64,JVBERi0", "filename": "forecast.pdf"}},
                ]},
                {"role": "assistant", "content": "", "tool_calls": [
                    {"id": "call_1", "type": "function", "function": {"name": "weather", "arguments": "{\"city\":\"Oslo\"}"}},
                    {"id": "call_2", "type": "function", "function": {"name": "time", "arguments": ""}},
                ]},
                {"role": "tool", "tool_call_id": "call_1", "content": "4 C"},
                {"role": "tool", "tool_call_id": "call_2", "content": [{"type": "text", "text": "09:00"}]},
                {"role": "user", "content": "Thanks."},
                {"role": "system", "content": "Answer in one line."},
            ],
            "temperature": 0.2, "top_p": 0.9, "stop": "END", "stream": true,
            "stream_options": {"include_usage": true}, "user": "u-1", "seed": 7, "n": 1, "logprobs": false,
            "tools": [{"type": "function", "function": {"name": "weather", "description": "Weather by city", "parameters": {"type": "object", "properties": {"city": {"type": "string"}}}, "strict": true}},
                      {"type": "function", "function": {"name": "time"}}],
            "tool_choice": "required", "parallel_tool_calls": false,
            "response_format": {"type": "json_schema", "json_schema": {"name": "w", "schema": {"type": "object"}, "strict": true}},
            "reasoning_effort": "xhigh", "frequency_penalty": 0, "max_tokens": null,
        });
        let expected = json!({
            "model": "claude-sonnet-5-5",
            "system": [{"type": "text", "text": "Be brief."}, {"type": "text", "text": "Use metric units."}],
            "messages": [
                {"role": "user", "content": [
                    {"type": "text", "text": "Weather here?"},
                    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0"}},
                    {"type": "image", "source": {"type": "url", "url": "https://example.com/map.jpg"}},
                    {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": "JVBERi0"}, "title": "forecast.pdf"},
                ]},
                {"role": "assistant", "content": [
                    {"type": "tool_use", "id": "call_1", "name": "weather", "input": {"city": "Oslo"}},
                    {"type": "tool_use", "id": "call_2", "name": "time", "input": {}},
                ]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "call_1", "content": [{"type": "text", "text": "4 C"}]},
                    {"type": "tool_result", "tool_use_id": "call_2", "content": [{"type": "text", "text": "09:00"}]},
                    {"type": "text", "text": "Thanks."},
                ]},
                {"role": "system", "content": [{"type": "text", "text": "Answer in one line."}]},
            ],
            "temperature": 0.2, "top_p": 0.9, "stop_sequences": ["END"], "stream": true,
            "max_tokens": DEFAULT_MAX_TOKENS,
            "metadata": {"user_id": "u-1"},
            "tools": [
                {"name": "weather", "description": "Weather by city", "input_schema": {"type": "object", "properties": {"city": {"type": "string"}}}, "strict": true},
                {"name": "time", "input_schema": {"type": "object", "properties": {}}},
            ],
            "tool_choice": {"type": "any", "disable_parallel_tool_use": true},
            "output_config": {"format": {"type": "json_schema", "schema": {"type": "object"}}, "effort": "xhigh"},
            "thinking": {"type": "adaptive"},
        });
        assert_eq!(openai_to_anthropic_request(&request)?, expected);
        assert!(include_usage(&request));
        Ok(())
    }

    #[test]
    fn max_completion_tokens_and_tool_choice_forms_carry_over() -> TestResult {
        let request = json!({"model": "m", "messages": [], "max_completion_tokens": 300, "max_tokens": 300,
            "tool_choice": {"type": "function", "function": {"name": "weather"}}, "safety_identifier": "h-1"});
        let out = openai_to_anthropic_request(&request)?;
        assert_eq!(out["max_tokens"], 300);
        assert_eq!(
            out["tool_choice"],
            json!({"type": "tool", "name": "weather"})
        );
        assert_eq!(out["metadata"], json!({"user_id": "h-1"}));
        let none = openai_to_anthropic_request(
            &json!({"model": "m", "messages": [], "tool_choice": "none", "parallel_tool_calls": false}),
        )?;
        assert_eq!(none["tool_choice"], json!({"type": "none"}));
        let parallel_only = openai_to_anthropic_request(
            &json!({"model": "m", "messages": [], "parallel_tool_calls": false}),
        )?;
        assert_eq!(
            parallel_only["tool_choice"],
            json!({"type": "auto", "disable_parallel_tool_use": true})
        );
        assert!(!include_usage(&request));
        Ok(())
    }

    #[test]
    fn an_openai_parameter_anthropic_lacks_is_refused_by_name() {
        let base = |extra: Value| {
            let mut request =
                json!({"model": "m", "messages": [{"role": "user", "content": "hi"}]});
            if let (Some(r), Value::Object(e)) = (request.as_object_mut(), extra) {
                r.extend(e);
            }
            openai_to_anthropic_request(&request)
        };
        for (extra, named) in [
            (json!({"n": 2}), "\"n\" set to 2"),
            (json!({"logprobs": true}), "\"logprobs\""),
            (json!({"frequency_penalty": 0.5}), "\"frequency_penalty\""),
            (json!({"logit_bias": {"50256": -100}}), "\"logit_bias\""),
            (json!({"audio": {"voice": "x"}}), "\"audio\""),
            (json!({"invented_field": 1}), "\"invented_field\""),
            (
                json!({"response_format": {"type": "json_object"}}),
                "\"response_format\"",
            ),
            (
                json!({"reasoning_effort": "minimal"}),
                "\"reasoning_effort\" set to \"minimal\"",
            ),
            (
                json!({"stream_options": {"include_obfuscation": true}}),
                "\"include_obfuscation\"",
            ),
            (
                json!({"tool_choice": {"type": "allowed_tools"}}),
                "\"tool_choice\"",
            ),
            (
                json!({"tools": [{"type": "custom", "custom": {"name": "x"}}]}),
                "\"custom\"",
            ),
            (
                json!({"service_tier": "flex"}),
                "\"service_tier\" set to \"flex\"",
            ),
        ] {
            let text = err_text(base(extra.clone()));
            assert!(
                text.contains(named) && text.contains("Remove it"),
                "{extra} -> {text}"
            );
        }
        assert!(err_text(base(json!({"temperature": 1.5}))).contains("0 to 1"));
        assert!(
            err_text(base(json!({"max_tokens": 1, "max_completion_tokens": 2}))).contains("differ")
        );
        assert!(err_text(base(json!({"user": "a", "safety_identifier": "b"}))).contains("differ"));
    }

    #[test]
    fn an_openai_message_anthropic_cannot_hold_is_refused_by_name() {
        for (message, named) in [
            (
                json!({"role": "user", "name": "ann", "content": "hi"}),
                "\"name\"",
            ),
            (
                json!({"role": "user", "content": [{"type": "input_audio", "input_audio": {"data": "x", "format": "wav"}}]}),
                "\"input_audio\"",
            ),
            (
                json!({"role": "user", "content": [{"type": "file", "file": {"file_id": "file-1"}}]}),
                "file ID",
            ),
            (
                json!({"role": "user", "content": [{"type": "image_url", "image_url": {"url": "data:image/png,raw"}}]}),
                "base64 data URL",
            ),
            (
                json!({"role": "assistant", "content": [{"type": "refusal", "refusal": "no"}]}),
                "refusal part",
            ),
            (
                json!({"role": "assistant", "content": null, "refusal": "no"}),
                "\"refusal\"",
            ),
            (json!({"role": "function", "content": "x"}), "\"function\""),
            (
                json!({"role": "assistant", "tool_calls": [{"id": "c", "type": "function", "function": {"name": "f", "arguments": "[1]"}}]}),
                "\"c\" are not a JSON object",
            ),
        ] {
            let text = err_text(openai_to_anthropic_request(
                &json!({"model": "m", "messages": [message.clone()]}),
            ));
            assert!(text.contains(named), "{message} -> {text}");
        }
    }

    #[test]
    fn an_anthropic_request_becomes_an_openai_request() -> TestResult {
        let request = json!({
            "model": "gpt-4o",
            "max_tokens": 1024,
            "system": [{"type": "text", "text": "Be brief.", "cache_control": {"type": "ephemeral"}}],
            "messages": [
                {"role": "user", "content": "Weather in Oslo?"},
                {"role": "assistant", "content": [
                    {"type": "thinking", "thinking": "", "signature": "sig"},
                    {"type": "text", "text": "Checking."},
                    {"type": "tool_use", "id": "toolu_1", "name": "weather", "input": {"city": "Oslo"}, "caller": {"type": "direct"}},
                ]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_1", "content": "4 C", "is_error": false},
                    {"type": "text", "text": "And this map?"},
                    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0"}},
                    {"type": "image", "source": {"type": "url", "url": "https://example.com/map.jpg"}},
                ]},
            ],
            "temperature": 0.3, "top_p": 0.8, "stop_sequences": ["END"], "stream": true,
            "metadata": {"user_id": "u-1"},
            "tools": [{"name": "weather", "description": "Weather by city", "input_schema": {"type": "object"}, "cache_control": {"type": "ephemeral"}, "eager_input_streaming": true}],
            "tool_choice": {"type": "any", "disable_parallel_tool_use": true},
            "thinking": {"type": "adaptive"},
            "output_config": {"effort": "high"},
        });
        let expected = json!({
            "model": "gpt-4o",
            "max_completion_tokens": 1024,
            "messages": [
                {"role": "system", "content": [{"type": "text", "text": "Be brief."}]},
                {"role": "user", "content": "Weather in Oslo?"},
                {"role": "assistant", "content": "Checking.", "tool_calls": [
                    {"id": "toolu_1", "type": "function", "function": {"name": "weather", "arguments": "{\"city\":\"Oslo\"}"}},
                ]},
                {"role": "tool", "tool_call_id": "toolu_1", "content": "4 C"},
                {"role": "user", "content": [
                    {"type": "text", "text": "And this map?"},
                    {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0"}},
                    {"type": "image_url", "image_url": {"url": "https://example.com/map.jpg"}},
                ]},
            ],
            "temperature": 0.3, "top_p": 0.8, "stop": ["END"], "stream": true,
            "stream_options": {"include_usage": true},
            "safety_identifier": "u-1",
            "tools": [{"type": "function", "function": {"name": "weather", "description": "Weather by city", "parameters": {"type": "object"}}}],
            "tool_choice": "required", "parallel_tool_calls": false,
            "reasoning_effort": "high",
        });
        assert_eq!(anthropic_to_openai_request(&request)?, expected);
        Ok(())
    }

    #[test]
    fn an_anthropic_parameter_openai_lacks_is_refused_by_name() {
        let base = |extra: Value| {
            let mut request = json!({"model": "m", "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]});
            if let (Some(r), Value::Object(e)) = (request.as_object_mut(), extra) {
                r.extend(e);
            }
            anthropic_to_openai_request(&request)
        };
        for (extra, named) in [
            (json!({"top_k": 5}), "\"top_k\" set to 5"),
            (json!({"thinking": {"type": "sometimes"}}), "\"sometimes\""),
            (
                json!({"tools": [{"type": "web_search_20260209", "name": "web_search"}]}),
                "web_search_20260209",
            ),
            (
                // defer_loading was refused here until Claude Code 2.1 sent it on every request; it is now
                // SAFE_TO_DROP, and another tool field without an equivalent stands in for it.
                json!({"tools": [{"name": "f", "input_schema": {}, "input_examples": [{}]}]}),
                "\"input_examples\"",
            ),
            (json!({"metadata": {"tenant": "x"}}), "\"tenant\""),
            (json!({"container": "c-1"}), "\"container\""),
            (
                json!({"messages": [{"role": "user", "content": [{"type": "document", "source": {}}]}]}),
                "document",
            ),
            (
                json!({"messages": [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t", "content": [{"type": "image", "source": {}}]}]}]}),
                "image",
            ),
            (
                json!({"messages": [{"role": "assistant", "content": [{"type": "server_tool_use", "id": "s"}]}]}),
                "server_tool_use",
            ),
        ] {
            let text = err_text(base(extra.clone()));
            assert!(
                text.contains(named) && text.contains("Remove it"),
                "{extra} -> {text}"
            );
        }
    }

    #[test]
    fn an_anthropic_answer_becomes_an_openai_completion() -> TestResult {
        let message = json!({
            "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-haiku-5-5",
            "content": [
                {"type": "thinking", "thinking": "", "signature": "s"},
                {"type": "text", "text": "Checking ", "citations": [{"type": "char_location"}]},
                {"type": "text", "text": "now."},
                {"type": "tool_use", "id": "toolu_1", "name": "weather", "input": {"city": "Oslo"}},
            ],
            "stop_reason": "tool_use", "stop_sequence": null,
            "usage": {"input_tokens": 10, "output_tokens": 20, "cache_read_input_tokens": 100, "cache_creation_input_tokens": 5},
        });
        let expected = json!({
            "id": "msg_1", "object": "chat.completion", "created": 1_700_000_000, "model": "claude-haiku-5-5",
            "choices": [{"index": 0, "logprobs": null, "finish_reason": "tool_calls", "message": {
                "role": "assistant", "content": "Checking now.",
                "tool_calls": [{"id": "toolu_1", "type": "function", "function": {"name": "weather", "arguments": "{\"city\":\"Oslo\"}"}}],
            }}],
            "usage": {"prompt_tokens": 115, "completion_tokens": 20, "total_tokens": 135,
                      "prompt_tokens_details": {"cached_tokens": 100, "cache_write_tokens": 5}},
        });
        assert_eq!(
            anthropic_to_openai_response(&message, 1_700_000_000)?,
            expected
        );
        for (stop, finish) in [
            ("end_turn", "stop"),
            ("stop_sequence", "stop"),
            ("max_tokens", "length"),
            ("model_context_window_exceeded", "length"),
            ("refusal", "content_filter"),
        ] {
            let answer =
                anthropic_to_openai_response(&json!({"content": [], "stop_reason": stop}), 0)?;
            assert_eq!(answer["choices"][0]["finish_reason"], finish);
            assert_eq!(answer["choices"][0]["message"]["content"], Value::Null);
        }
        assert!(
            err_text(anthropic_to_openai_response(
                &json!({"content": [], "stop_reason": "pause_turn"}),
                0
            ))
            .contains("pause_turn")
        );
        assert!(
            err_text(anthropic_to_openai_response(
                &json!({"content": [{"type": "web_search_tool_result"}]}),
                0
            ))
            .contains("web_search_tool_result")
        );
        Ok(())
    }

    #[test]
    fn an_openai_completion_becomes_an_anthropic_answer() -> TestResult {
        let completion = json!({
            "id": "chatcmpl-1", "object": "chat.completion", "created": 1, "model": "gpt-4o-mini", "system_fingerprint": "fp",
            "choices": [{"index": 0, "finish_reason": "tool_calls", "logprobs": null, "message": {
                "role": "assistant", "content": "Checking.", "refusal": null, "annotations": [],
                "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "weather", "arguments": "{\"city\":\"Oslo\"}"}}],
            }}],
            "usage": {"prompt_tokens": 120, "completion_tokens": 7, "total_tokens": 127, "prompt_tokens_details": {"cached_tokens": 100}},
        });
        let expected = json!({
            "id": "chatcmpl-1", "type": "message", "role": "assistant", "model": "gpt-4o-mini",
            "content": [
                {"type": "text", "text": "Checking."},
                {"type": "tool_use", "id": "call_1", "name": "weather", "input": {"city": "Oslo"}},
            ],
            "stop_reason": "tool_use", "stop_sequence": null,
            "usage": {"input_tokens": 20, "output_tokens": 7, "cache_read_input_tokens": 100, "cache_creation_input_tokens": 0},
        });
        assert_eq!(openai_to_anthropic_response(&completion)?, expected);
        let refused = openai_to_anthropic_response(
            &json!({"choices": [{"finish_reason": "stop", "message": {"content": null, "refusal": "I can't."}}]}),
        )?;
        assert_eq!(refused["stop_reason"], "refusal");
        assert_eq!(
            refused["content"],
            json!([{"type": "text", "text": "I can't."}])
        );
        assert!(
            err_text(openai_to_anthropic_response(&json!({"choices": [{}, {}]})))
                .contains("\"n\": 1")
        );
        assert!(
            err_text(openai_to_anthropic_response(
                &json!({"choices": [{"message": {"audio": {"id": "a"}}}]})
            ))
            .contains("\"audio\"")
        );
        Ok(())
    }

    const ANTHROPIC_STREAM: &str = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-sonnet-5-5\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":472,\"cache_read_input_tokens\":28,\"output_tokens\":2}}}\n\n",
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"signature_delta\",\"signature\":\"abc\"}}\n\n",
        "event: content_block_stop\n",
        "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
        "event: content_block_start\r\n",
        "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\r\n\r\n",
        "event: ping\n",
        "data: {\"type\": \"ping\"}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"Caf\u{e9} \"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"weather:\"}}\n\n",
        "event: content_block_stop\n",
        "data: {\"type\":\"content_block_stop\",\"index\":1}\n\n",
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"index\":2,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"weather\",\"input\":{}}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"city\\\":\"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\" \\\"Oslo\\\"}\"}}\n\n",
        "event: content_block_stop\n",
        "data: {\"type\":\"content_block_stop\",\"index\":2}\n\n",
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"index\":3,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_2\",\"name\":\"time\",\"input\":{}}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":3,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{}\"}}\n\n",
        "event: content_block_stop\n",
        "data: {\"type\":\"content_block_stop\",\"index\":3}\n\n",
        "event: message_delta\n",
        "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":89}}\n\n",
        "event: message_stop\n",
        "data: {\"type\":\"message_stop\"}\n\n",
    );

    /// Converts the stream fed in pieces of every size and checks each split gives the same bytes.
    fn convert_all_splits(
        stream: &str,
        include_usage: bool,
    ) -> std::result::Result<String, Box<dyn std::error::Error>> {
        let bytes = stream.as_bytes();
        let mut whole = None;
        for size in 1..=bytes.len() {
            let mut converter = AnthropicToOpenAiStream::new(include_usage, 1_700_000_000);
            let mut out = Vec::new();
            for piece in bytes.chunks(size) {
                out.extend(converter.feed(piece)?);
            }
            out.extend(converter.finish()?);
            match &whole {
                None => whole = Some(out),
                Some(first) => assert_eq!(first, &out, "split size {size}"),
            }
        }
        Ok(String::from_utf8(whole.unwrap_or_default())?)
    }

    fn chunks(out: &str) -> std::result::Result<Vec<Value>, serde_json::Error> {
        out.split("\n\n")
            .filter_map(|e| e.strip_prefix("data: "))
            .filter(|d| *d != "[DONE]")
            .map(serde_json::from_str)
            .collect()
    }

    #[test]
    fn an_anthropic_stream_becomes_an_openai_stream_in_any_split() -> TestResult {
        let out = convert_all_splits(ANTHROPIC_STREAM, true)?;
        assert!(out.ends_with("data: [DONE]\n\n"), "{out}");
        let chunks = chunks(&out)?;
        assert!(chunks.iter().all(|c| c["id"] == "msg_1"
            && c["model"] == "claude-sonnet-5-5"
            && c["created"] == 1_700_000_000));
        let deltas: Vec<&Value> = chunks
            .iter()
            .filter_map(|c| c["choices"].get(0))
            .map(|c| &c["delta"])
            .collect();
        assert_eq!(deltas[0], &json!({"role": "assistant", "content": ""}));
        let text: String = deltas
            .iter()
            .filter_map(|d| d["content"].as_str())
            .collect();
        assert_eq!(text, "Caf\u{e9} weather:");
        let calls: Vec<&Value> = deltas
            .iter()
            .filter_map(|d| d["tool_calls"].get(0))
            .collect();
        assert_eq!(
            calls[0],
            &json!({"index": 0, "id": "toolu_1", "type": "function", "function": {"name": "weather", "arguments": ""}})
        );
        let args = |n: u64| -> String {
            calls
                .iter()
                .filter(|c| c["index"] == n)
                .filter_map(|c| c["function"]["arguments"].as_str())
                .collect()
        };
        assert_eq!(args(0), "{\"city\": \"Oslo\"}");
        assert_eq!(args(1), "{}");
        assert_eq!(
            calls
                .iter()
                .filter(|c| c["index"] == 1)
                .filter_map(|c| c["id"].as_str())
                .collect::<Vec<_>>(),
            ["toolu_2"]
        );
        let finishes: Vec<&Value> = chunks
            .iter()
            .filter_map(|c| c["choices"].get(0))
            .map(|c| &c["finish_reason"])
            .filter(|f| !f.is_null())
            .collect();
        assert_eq!(finishes, [&json!("tool_calls")]);
        let last = chunks.last().ok_or("no chunks")?;
        assert_eq!(last["choices"], json!([]));
        assert_eq!(
            last["usage"],
            json!({"prompt_tokens": 500, "completion_tokens": 89, "total_tokens": 589, "prompt_tokens_details": {"cached_tokens": 28, "cache_write_tokens": 0}})
        );
        assert!(
            chunks[..chunks.len() - 1]
                .iter()
                .all(|c| c["usage"].is_null() && c.get("usage").is_some())
        );
        Ok(())
    }

    #[test]
    fn without_include_usage_no_usage_chunk_is_sent() -> TestResult {
        let out = convert_all_splits(ANTHROPIC_STREAM, false)?;
        let chunks = chunks(&out)?;
        assert!(
            chunks
                .iter()
                .all(|c| c.get("usage").is_none() && c["choices"].get(0).is_some())
        );
        assert!(out.ends_with("data: [DONE]\n\n"));
        Ok(())
    }

    #[test]
    fn a_stream_error_becomes_an_openai_error_event() -> TestResult {
        let stream = concat!(
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"m\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n",
            "event: error\ndata: {\"type\": \"error\", \"error\": {\"type\": \"overloaded_error\", \"message\": \"Overloaded\"}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        );
        let out = convert_all_splits(stream, true)?;
        assert!(!out.contains("[DONE]"));
        let last = chunks(&out)?.pop().ok_or("no chunks")?;
        assert_eq!(
            last,
            json!({"error": {"message": "Overloaded", "type": "overloaded_error", "code": null}})
        );
        Ok(())
    }

    #[test]
    fn a_stream_cut_short_is_an_error() -> TestResult {
        let cut = ANTHROPIC_STREAM.len() / 2;
        let mut converter = AnthropicToOpenAiStream::new(false, 0);
        converter.feed(&ANTHROPIC_STREAM.as_bytes()[..cut])?;
        assert!(err_text(converter.finish()).contains("message_stop"));
        let mut bad = AnthropicToOpenAiStream::new(false, 0);
        assert!(err_text(bad.feed(b"data: {not json\n")).contains("not JSON"));
        let mut server_tool = AnthropicToOpenAiStream::new(false, 0);
        let event = b"data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"server_tool_use\"}}\n";
        assert!(err_text(server_tool.feed(event)).contains("server_tool_use"));
        Ok(())
    }

    const OPENAI_STREAM: &str = concat!(
        "data: {\"id\":\"chatcmpl-1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chatcmpl-1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Let me \"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chatcmpl-1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"look.\"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chatcmpl-1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_a\",\"type\":\"function\",\"function\":{\"name\":\"Read\",\"arguments\":\"\"}}]},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chatcmpl-1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"path\\\":\"}}]},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chatcmpl-1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"a.rs\\\"}\"}}]},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chatcmpl-1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":1,\"id\":\"call_b\",\"type\":\"function\",\"function\":{\"name\":\"Ls\",\"arguments\":\"{}\"}}]},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chatcmpl-1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: {\"id\":\"chatcmpl-1\",\"model\":\"gpt-4o\",\"choices\":[],\"usage\":{\"prompt_tokens\":30,\"completion_tokens\":12,\"total_tokens\":42,\"prompt_tokens_details\":{\"cached_tokens\":10}}}\n\n",
        "data: [DONE]\n\n",
    );

    /// Each event of an Anthropic stream as (event name, data).
    fn events(sse: &str) -> std::result::Result<Vec<(String, Value)>, Box<dyn std::error::Error>> {
        let mut out = Vec::new();
        for record in sse.split("\n\n").filter(|r| !r.trim().is_empty()) {
            let (name, data) = record.split_once('\n').ok_or("no data line")?;
            let name = name.strip_prefix("event: ").ok_or("no event line")?;
            let data: Value = serde_json::from_str(data.strip_prefix("data: ").ok_or("bad data")?)?;
            assert_eq!(data["type"], name, "event name and type agree");
            out.push((name.to_string(), data));
        }
        Ok(out)
    }

    #[test]
    fn an_openai_stream_becomes_an_anthropic_stream_in_any_split() -> TestResult {
        let whole = {
            let mut c = OpenAiToAnthropicStream::new("msg_x".into());
            let mut out = c.feed(OPENAI_STREAM.as_bytes())?;
            out.extend(c.finish()?);
            String::from_utf8(out)?
        };
        for size in [1, 7, 64] {
            let mut c = OpenAiToAnthropicStream::new("msg_x".into());
            let mut out = Vec::new();
            for piece in OPENAI_STREAM.as_bytes().chunks(size) {
                out.extend(c.feed(piece)?);
            }
            out.extend(c.finish()?);
            assert_eq!(String::from_utf8(out)?, whole, "split {size}");
        }
        let events = events(&whole)?;
        let names: Vec<&str> = events.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "message_start",
                "content_block_start",
                "content_block_delta",
                "content_block_delta",
                "content_block_stop",
                "content_block_start",
                "content_block_delta",
                "content_block_delta",
                "content_block_stop",
                "content_block_start",
                "content_block_delta",
                "content_block_stop",
                "message_delta",
                "message_stop",
            ]
        );
        assert_eq!(events[0].1["message"]["id"], "chatcmpl-1");
        assert_eq!(events[0].1["message"]["model"], "gpt-4o");
        assert_eq!(
            events[5].1["content_block"],
            json!({"type": "tool_use", "id": "call_a", "name": "Read", "input": {}})
        );
        assert_eq!(events[5].1["index"], 1);
        let input: String = events[6..8]
            .iter()
            .map(|(_, e)| e["delta"]["partial_json"].as_str().unwrap_or_default())
            .collect();
        assert_eq!(
            serde_json::from_str::<Value>(&input)?,
            json!({"path": "a.rs"})
        );
        assert_eq!(events[9].1["content_block"]["id"], "call_b");
        assert_eq!(events[9].1["index"], 2);
        let end = &events[12].1;
        assert_eq!(end["delta"]["stop_reason"], "tool_use");
        assert_eq!(
            end["usage"],
            json!({"input_tokens": 20, "output_tokens": 12, "cache_read_input_tokens": 10, "cache_creation_input_tokens": 0})
        );
        Ok(())
    }

    #[test]
    fn an_openai_stream_error_or_cut_is_reported() -> TestResult {
        let mut c = OpenAiToAnthropicStream::new("msg_x".into());
        let out = String::from_utf8(c.feed(
            b"data: {\"error\":{\"message\":\"Overloaded\",\"type\":\"server_error\"}}\n\n",
        )?)?;
        assert_eq!(
            events(&out)?,
            [(
                "error".to_string(),
                json!({"type": "error", "error": {"type": "server_error", "message": "Overloaded"}})
            )]
        );
        assert!(c.finish().is_ok());
        let cut = OPENAI_STREAM.len() / 2;
        let mut c = OpenAiToAnthropicStream::new("msg_x".into());
        c.feed(&OPENAI_STREAM.as_bytes()[..cut])?;
        assert!(err_text(c.finish()).contains("[DONE]"));
        let mut c = OpenAiToAnthropicStream::new("msg_x".into());
        let two = b"data: {\"choices\":[{\"index\":0,\"delta\":{}},{\"index\":1,\"delta\":{}}]}\n";
        assert!(err_text(c.feed(two)).contains("\"n\": 1"));
        Ok(())
    }

    #[test]
    fn claude_code_shaped_request_translates_and_unknown_fields_are_named() -> TestResult {
        let request = json!({
            "model": "gpt-4o",
            "max_tokens": 32000,
            "stream": true,
            "system": [{"type": "text", "text": "You are Claude Code.", "cache_control": {"type": "ephemeral"}}],
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "Read a.rs"}, {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBO"}}]},
                {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_1", "name": "Read", "input": {"path": "a.rs"}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_1", "content": "fn main() {}", "cache_control": {"type": "ephemeral"}}]},
            ],
            "tools": [{"name": "Read", "description": "Reads a file", "input_schema": {"type": "object"}}],
            "metadata": {"user_id": "u1"},
            "temperature": 1,
        });
        let chat = anthropic_to_openai_request(&request)?;
        assert_eq!(chat["stream_options"], json!({"include_usage": true}));
        assert_eq!(
            chat["messages"][0],
            json!({"role": "system", "content": [{"type": "text", "text": "You are Claude Code."}]})
        );
        assert_eq!(
            chat["messages"][1]["content"][1]["image_url"]["url"],
            "data:image/png;base64,iVBO"
        );
        assert_eq!(
            chat["messages"][2]["tool_calls"][0]["function"]["arguments"],
            "{\"path\":\"a.rs\"}"
        );
        assert_eq!(
            chat["messages"][3],
            json!({"role": "tool", "tool_call_id": "toolu_1", "content": "fn main() {}"})
        );
        assert_eq!(
            chat["tools"][0]["function"]["parameters"],
            json!({"type": "object"})
        );
        let mut odd = request.clone();
        odd["context_management"] = json!({"edits": [{"type": "clear_tool_uses_20250919"}]});
        assert!(err_text(anthropic_to_openai_request(&odd)).contains("clear_tool_uses"));
        // As Claude Code 2.1 sends it: thinking clears, adaptive thinking, a deferred tool, a long user ID.
        let mut claude_code = request.clone();
        claude_code["context_management"] =
            json!({"edits": [{"type": "clear_thinking_20251015", "keep": "all"}]});
        claude_code["thinking"] = json!({"type": "adaptive", "display": "omitted"});
        claude_code["tools"][0]["defer_loading"] = json!(true);
        let long = format!("{{\"device_id\":\"{}\"}}", "d".repeat(64));
        claude_code["metadata"] = json!({"user_id": long});
        let chat = anthropic_to_openai_request(&claude_code)?;
        assert_eq!(
            chat["safety_identifier"],
            crate::id::sha256_hex(long.as_bytes())
        );
        assert!(chat.get("context_management").is_none() && chat.get("thinking").is_none());
        // Claude Code in auto mode asks the server to run its tool use classifier. A chat provider has none, and
        // the context (working folder, home folder) is not sent to it.
        claude_code["safeguards"] = json!([{"type": "dangerous_tool_use", "classifier_context": {"v": 1, "permission_mode": "auto", "live_cwd": "/Users/maya/app", "home_dir": "/Users/maya"}}]);
        let chat = anthropic_to_openai_request(&claude_code)?;
        assert!(chat.get("safeguards").is_none() && !chat.to_string().contains("/Users/maya"));
        let mut thinking = request;
        thinking["thinking"] = json!({"type": "enabled", "budget_tokens": 2000});
        assert_eq!(
            anthropic_to_openai_request(&thinking)?["reasoning_effort"],
            "medium"
        );
        Ok(())
    }

    #[test]
    fn reasoning_effort_becomes_a_thinking_budget_and_thinking_comes_back_as_reasoning()
    -> TestResult {
        let ask = |extra: Value| {
            let mut request =
                json!({"model": "c", "messages": [{"role": "user", "content": "hi"}]});
            if let (Some(r), Some(e)) = (request.as_object_mut(), extra.as_object()) {
                r.extend(e.clone());
            }
            openai_to_anthropic_request(&request)
        };
        for (level, budget) in [("low", 1024), ("medium", 4096), ("high", 16384)] {
            let out = ask(json!({"reasoning_effort": level}))?;
            assert_eq!(
                out["thinking"],
                json!({"type": "enabled", "budget_tokens": budget})
            );
            assert_eq!(out["max_tokens"], budget + DEFAULT_MAX_TOKENS);
        }
        assert!(
            ask(json!({"reasoning_effort": "none"}))?
                .get("thinking")
                .is_none()
        );
        let small = err_text(ask(json!({"reasoning_effort": "high", "max_tokens": 1000})));
        assert!(small.contains("Raise max_tokens"), "{small}");
        let warm = err_text(ask(json!({"reasoning_effort": "low", "temperature": 0.3})));
        assert!(warm.contains("temperature"), "{warm}");
        let answer = json!({"id": "m", "model": "c", "stop_reason": "end_turn", "usage": {"input_tokens": 1, "output_tokens": 1},
            "content": [{"type": "thinking", "thinking": "Let me see.", "signature": "s"}, {"type": "text", "text": "Yes."}]});
        let chat = anthropic_to_openai_response(&answer, 1)?;
        assert_eq!(
            chat["choices"][0]["message"]["reasoning_content"],
            "Let me see."
        );
        assert_eq!(chat["choices"][0]["message"]["content"], "Yes.");
        Ok(())
    }

    #[test]
    fn every_safe_drop_has_a_reason() {
        for (field, reason) in SAFE_TO_DROP {
            assert!(!field.is_empty() && reason.len() > 20, "{field}");
        }
    }
}
