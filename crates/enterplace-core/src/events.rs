//! Plugin events: contract v2 of the guardrail webhook.
//!
//! Where a `webhook` guardrail (contract v1, guard.rs) sends a service the text of one request, an `events`
//! guardrail sends it the conversation as typed events: the system prompt, user messages, the model's answers and
//! reasoning, tool definitions, tool calls and tool results, MCP tool calls and realtime text. Every event carries
//! the session, the turn and its place in the turn, so the service can follow an agent from its first message to
//! its last tool call and judge intent, not one string at a time.
//!
//! This module holds what both ends agree on and nothing that makes a call: the policy shape, the ids, the
//! normalization of each provider API into events, the envelope, the verdict and how a mask is written back. The
//! server (enterplace-server/src/events.rs) delivers. The contract is written down in docs/governance/plugin-events.
//!
//! The ids are computed from the request alone, with no table of sessions, so every replica gives the same
//! conversation the same ids and a restart forgets nothing.

use std::collections::BTreeMap;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::Sha256;

use crate::guard::{
    Action as GuardAction, AuditEntry, Blocked, GuardrailFile, OnFailure, SHADOW, Webhook,
};
use crate::id;

/// The contract's number, sent in every envelope.
pub const CONTRACT: u32 = 2;
/// The refusal code of a request in a session a plugin ended.
pub const SESSION_ENDED: &str = "session_ended";
/// The detector name on audit entries.
pub const DETECTOR: &str = "events";
/// What a masked event's other text slots hold, when its text came from several: providers refuse empty text blocks.
pub const MASKED_SLOT: &str = "[masked]";

// ---------------------------------------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------------------------------------

/// Whether the gateway waits for the plugin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Waits for the verdict and obeys it.
    Enforce,
    /// Queues the events and goes on: the plugin never delays or changes a request.
    Observe,
}

impl Mode {
    pub fn word(self) -> &'static str {
        match self {
            Mode::Enforce => "enforce",
            Mode::Observe => "observe",
        }
    }
}

/// `stream:` of an events guardrail: a streamed answer's text is sent in windows as it comes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stream {
    /// The size of a window, in characters of the model's text.
    pub chunk_chars: usize,
    /// Whether the caller's tokens wait for their window's verdict.
    #[serde(default)]
    pub hold: bool,
}

/// A checked `type: events` guardrail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Events {
    pub hook: Webhook,
    pub mode: Mode,
    /// Sends the events before the new ones with every call.
    pub history: bool,
    pub stream: Option<Stream>,
    /// How long `session_action: end` refuses the session.
    pub session_end_seconds: u64,
    /// The variable holding the secret requests are signed with, read at each call.
    pub secret_env: Option<String>,
    /// Observe mode: where batches go. Without one, each envelope is its own POST to `url`.
    pub batch_url: Option<String>,
    /// Observe mode: the most envelopes waiting. One more is dropped and counted.
    pub queue: usize,
    /// Observe mode: the most envelopes in one batch.
    pub batch_size: usize,
    /// Observe mode: how many times a failed delivery is tried again.
    pub retries: u32,
}

const DEFAULT_SESSION_END_SECONDS: u64 = 3600;
const MAX_SESSION_END_SECONDS: u64 = 7 * 24 * 3600;
const DEFAULT_QUEUE: usize = 1024;
const MAX_QUEUE: usize = 100_000;
const DEFAULT_BATCH: usize = 50;
const MAX_BATCH: usize = 1000;
const DEFAULT_RETRIES: u32 = 2;
const MAX_RETRIES: u32 = 10;
const MIN_CHUNK_CHARS: usize = 20;

/// Whether a definition sets a field only an events guardrail takes, and which.
pub fn field_given(def: &GuardrailFile) -> Option<&'static str> {
    [
        ("mode", def.mode.is_some()),
        ("history", def.history.is_some()),
        ("stream", def.stream.is_some()),
        ("session_end_seconds", def.session_end_seconds.is_some()),
        ("secret_env", def.secret_env.is_some()),
        ("batch_url", def.batch_url.is_some()),
        ("queue", def.queue.is_some()),
        ("batch_size", def.batch_size.is_some()),
        ("retries", def.retries.is_some()),
    ]
    .into_iter()
    .find_map(|(name, given)| given.then_some(name))
}

/// The mode a definition names. `enforce` when it names none.
pub fn mode_of(def: &GuardrailFile) -> Result<Mode, String> {
    match def.mode.as_deref() {
        None | Some("enforce") => Ok(Mode::Enforce),
        Some("observe") => Ok(Mode::Observe),
        Some(other) => Err(format!(
            "guardrail \"{}\": mode is \"{other}\". Write mode: enforce (wait for the plugin's verdict) or mode: observe (send events in the background and never delay a request).",
            def.name
        )),
    }
}

/// The events settings of a definition whose webhook part (`url`, `timeout_ms`, `on_failure`, `headers_env`) is
/// already checked.
pub fn checked(
    def: &GuardrailFile,
    hook: Webhook,
    check_url: &dyn Fn(&str, &str) -> Result<String, String>,
) -> Result<Events, String> {
    let name = &def.name;
    let mode = mode_of(def)?;
    if def.action.is_some() || def.on.is_some() {
        return Err(format!(
            "guardrail \"{name}\": an events guardrail takes no action: or on:. It reads requests and answers, and mode: says whether it is obeyed (enforce) or only told (observe). Remove the line."
        ));
    }
    if let Some(stream) = &def.stream
        && stream.chunk_chars < MIN_CHUNK_CHARS
    {
        return Err(format!(
            "guardrail \"{name}\": stream.chunk_chars is {}. It must be at least {MIN_CHUNK_CHARS}, because every window is a call to the plugin.",
            stream.chunk_chars
        ));
    }
    let observe_only = [
        ("batch_url", def.batch_url.is_some()),
        ("queue", def.queue.is_some()),
        ("batch_size", def.batch_size.is_some()),
        ("retries", def.retries.is_some()),
    ];
    if mode == Mode::Enforce
        && let Some((field, _)) = observe_only.iter().find(|(_, given)| *given)
    {
        return Err(format!(
            "guardrail \"{name}\": {field} belongs to mode: observe, where events are queued and sent in batches. Remove it, or set mode: observe."
        ));
    }
    if mode == Mode::Observe && def.stream.is_some_and(|s| s.hold) {
        return Err(format!(
            "guardrail \"{name}\": stream.hold holds the caller's tokens for a verdict, and mode: observe waits for none. Remove hold, or set mode: enforce."
        ));
    }
    let within = |field: &str, value: Option<u64>, default: u64, max: u64| match value {
        None => Ok(default),
        Some(n) if (1..=max).contains(&n) => Ok(n),
        Some(n) => Err(format!(
            "guardrail \"{name}\": {field} is {n}. It must be between 1 and {max}."
        )),
    };
    let secret_env = match &def.secret_env {
        None => None,
        Some(variable) => {
            let ok = !variable.is_empty()
                && !variable.starts_with(|c: char| c.is_ascii_digit())
                && variable
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_');
            if !ok {
                return Err(format!(
                    "guardrail \"{name}\": secret_env is \"{variable}\", which is not the name of an environment variable. Write the variable's name, for example secret_env: PLUGIN_SIGNING_SECRET, and keep the secret itself out of this file."
                ));
            }
            Some(variable.clone())
        }
    };
    Ok(Events {
        hook,
        mode,
        history: def.history.unwrap_or(false),
        stream: def.stream,
        session_end_seconds: within(
            "session_end_seconds",
            def.session_end_seconds,
            DEFAULT_SESSION_END_SECONDS,
            MAX_SESSION_END_SECONDS,
        )?,
        secret_env,
        batch_url: def
            .batch_url
            .as_deref()
            .map(|url| check_url(name, url))
            .transpose()?,
        queue: within("queue", def.queue, DEFAULT_QUEUE as u64, MAX_QUEUE as u64)? as usize,
        batch_size: within(
            "batch_size",
            def.batch_size,
            DEFAULT_BATCH as u64,
            MAX_BATCH as u64,
        )? as usize,
        retries: match def.retries {
            None => DEFAULT_RETRIES,
            Some(n) if n <= u64::from(MAX_RETRIES) => n as u32,
            Some(n) => {
                return Err(format!(
                    "guardrail \"{name}\": retries is {n}. It must be between 0 and {MAX_RETRIES}."
                ));
            }
        },
    })
}

/// An application a rule's callers run as: its name and what it is for, in its owner's words.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Application {
    pub name: String,
    /// The stated purpose. A plugin judges what the conversation does against it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
}

/// The longest intent taken from a header or the policy, in characters.
pub const MAX_INTENT: usize = 500;

/// Whether an intent is one short line of text.
pub fn intent_ok(intent: &str) -> bool {
    !intent.trim().is_empty()
        && intent.chars().count() <= MAX_INTENT
        && !intent.chars().any(char::is_control)
}

// ---------------------------------------------------------------------------------------------------------
// Session and turn
// ---------------------------------------------------------------------------------------------------------

/// What a caller's headers say about its session, turn and application, read before they are taken out.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Markers {
    /// `x-enterplace-session`.
    pub enterplace_session: Option<String>,
    /// `x-session-id`.
    pub session: Option<String>,
    /// `x-claude-code-session-id`.
    pub claude_code: Option<String>,
    /// Codex's `session_id`, or its `conversation_id`.
    pub codex: Option<String>,
    /// `x-enterplace-turn`.
    pub turn: Option<String>,
    /// `x-enterplace-application`.
    pub application: Option<String>,
    /// `x-enterplace-application-intent`.
    pub intent: Option<String>,
}

impl Markers {
    /// Enterplace's own headers among these, taken out of a request before it is sent to a provider.
    pub const OWN: [&'static str; 4] = [
        "x-enterplace-session",
        "x-enterplace-turn",
        "x-enterplace-application",
        "x-enterplace-application-intent",
    ];

    /// Reads the markers with `get`, which answers a header's value by its lowercase name.
    pub fn read<'a>(get: &dyn Fn(&str) -> Option<&'a str>) -> Self {
        let own = |name: &str| {
            get(name)
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_string)
        };
        Self {
            enterplace_session: own("x-enterplace-session"),
            session: own("x-session-id"),
            claude_code: own("x-claude-code-session-id"),
            codex: own("session_id").or_else(|| own("conversation_id")),
            turn: own("x-enterplace-turn"),
            application: own("x-enterplace-application"),
            intent: own("x-enterplace-application-intent"),
        }
    }
}

/// The session a coding agent names inside Anthropic's `metadata.user_id`: Claude Code writes its session there,
/// as `..._session_<id>` or as JSON with a `session_id`.
fn session_in_user_id(user_id: &str) -> Option<String> {
    if user_id.starts_with('{') {
        return serde_json::from_str::<Value>(user_id)
            .ok()?
            .get("session_id")?
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_string);
    }
    user_id
        .rsplit_once("_session_")
        .map(|(_, session)| session.to_string())
        .filter(|s| !s.is_empty())
}

/// The session of a request and where it was read from. In order: `x-enterplace-session`, `x-session-id`, Claude
/// Code's session (its header, or the session inside `metadata.user_id`), Codex's `session_id` header,
/// `prompt_cache_key`, then `metadata.user_id` or `user` (which name a person, not a conversation, so the first
/// message is hashed in), and last the caller's key and the first message. Always hashed with the person, so a
/// session id a client treats as a secret is not passed on and two people never share a session.
pub fn session_id(
    person: &str,
    key: &str,
    markers: &Markers,
    body: &Value,
    first_message: &str,
) -> (String, &'static str) {
    let text = |pointer: &str| {
        body.pointer(pointer)
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
    };
    let user_id = text("/metadata/user_id");
    let first = || id::sha256_hex(first_message.as_bytes());
    let (source, value): (&'static str, String) = if let Some(v) = &markers.enterplace_session {
        ("x-enterplace-session", v.clone())
    } else if let Some(v) = &markers.session {
        ("x-session-id", v.clone())
    } else if let Some(v) = &markers.claude_code {
        ("claude_code", v.clone())
    } else if let Some(v) = user_id.and_then(session_in_user_id) {
        ("claude_code", v)
    } else if let Some(v) = &markers.codex {
        ("codex", v.clone())
    } else if let Some(v) = text("/prompt_cache_key") {
        ("prompt_cache_key", v.to_string())
    } else if let Some(v) = user_id {
        ("metadata.user_id", format!("{v}\n{}", first()))
    } else if let Some(v) = text("/user") {
        ("user", format!("{v}\n{}", first()))
    } else {
        ("first_message", format!("{key}\n{}", first()))
    };
    // The two spellings of one session (Claude Code's header and its metadata) hash alike: the source is not mixed in
    // for the tools' own markers.
    let hashed = id::sha256_hex(format!("{person}\n{value}").as_bytes());
    (format!("ses_{}", &hashed[..24]), source)
}

/// The id of a session's turn: the `number`th user message, and that message's text, or the caller's
/// `x-enterplace-turn`.
pub fn turn_id(session: &str, number: usize, user_text: &str, named: Option<&str>) -> String {
    let hashed = match named {
        Some(name) => id::sha256_hex(format!("{session}\nnamed\n{name}").as_bytes()),
        None => id::sha256_hex(
            format!(
                "{session}\n{number}\n{}",
                id::sha256_hex(user_text.as_bytes())
            )
            .as_bytes(),
        ),
    };
    format!("turn_{}", &hashed[..16])
}

// ---------------------------------------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    SystemPrompt,
    UserMessage,
    AssistantMessage,
    Reasoning,
    ToolDefinitions,
    ToolCall,
    ToolResult,
    McpToolCall,
    McpToolResult,
    RealtimeUserMessage,
    RealtimeAssistantMessage,
}

impl Kind {
    pub fn word(self) -> &'static str {
        match self {
            Kind::SystemPrompt => "system_prompt",
            Kind::UserMessage => "user_message",
            Kind::AssistantMessage => "assistant_message",
            Kind::Reasoning => "reasoning",
            Kind::ToolDefinitions => "tool_definitions",
            Kind::ToolCall => "tool_call",
            Kind::ToolResult => "tool_result",
            Kind::McpToolCall => "mcp_tool_call",
            Kind::McpToolResult => "mcp_tool_result",
            Kind::RealtimeUserMessage => "realtime_user_message",
            Kind::RealtimeAssistantMessage => "realtime_assistant_message",
        }
    }

    fn call(self) -> bool {
        matches!(self, Kind::ToolCall | Kind::McpToolCall)
    }
}

/// One event, as a plugin receives it. Which fields it has follows from its kind.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Event {
    pub event_id: String,
    pub event_index: usize,
    pub turn_id: String,
    pub kind: Kind,
    /// Set on the model's last message of a turn: it called no tool, so the turn is over.
    pub last_in_turn: bool,
    /// The text of a prompt, message, reasoning or tool result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// tool_definitions: each tool as `{name, description, parameters}`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Value>>,
    /// The MCP server of an MCP tool call or result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// The tool of a call or a result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The provider's id of the call, which its result names.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
    /// A tool call's arguments, as JSON.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Value>,
    /// A window of a streamed answer: `content` is the text since the window before. The whole text follows in a
    /// last event with the same index and no `partial`.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub partial: bool,
    /// The window's number, from 0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window: Option<usize>,
    /// Set on a window, or on a streamed answer's tool call, that waits for this verdict before it reaches the
    /// caller (`stream.hold`): it can still be masked.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub held: bool,
    /// Where it was read from, as JSON pointers into the body, for a mask to be written back.
    #[serde(skip)]
    pub at: Vec<String>,
}

impl Event {
    fn new(kind: Kind) -> Self {
        Self {
            event_id: String::new(),
            event_index: 0,
            turn_id: String::new(),
            kind,
            last_in_turn: false,
            content: None,
            tools: None,
            server: None,
            name: None,
            call_id: None,
            arguments: None,
            partial: false,
            window: None,
            held: false,
            at: Vec::new(),
        }
    }

    /// An event with text.
    pub fn text(kind: Kind, content: impl Into<String>) -> Self {
        Self {
            content: Some(content.into()),
            ..Self::new(kind)
        }
    }

    /// An MCP tool call through the gateway.
    pub fn mcp_call(server: &str, name: &str, arguments: Value) -> Self {
        Self {
            server: Some(server.to_string()),
            name: Some(name.to_string()),
            arguments: Some(arguments),
            ..Self::new(Kind::McpToolCall)
        }
    }

    /// An MCP tool's result.
    pub fn mcp_result(server: &str, name: &str, content: String) -> Self {
        Self {
            server: Some(server.to_string()),
            name: Some(name.to_string()),
            content: Some(content),
            ..Self::new(Kind::McpToolResult)
        }
    }

    /// Gives it its place in a turn, and the id that follows from the turn, the place and what it holds: the same
    /// event sent twice has the same id.
    pub fn placed(mut self, turn: &str, index: usize) -> Self {
        self.turn_id = turn.to_string();
        self.event_index = index;
        let held = json!([
            self.content,
            self.tools,
            self.server,
            self.name,
            self.call_id,
            self.arguments,
            self.window
        ]);
        let hashed =
            id::sha256_hex(format!("{turn}\n{index}\n{}\n{held}", self.kind.word()).as_bytes());
        self.event_id = format!("evt_{}", &hashed[..24]);
        self
    }
}

/// An event before it has a turn, with what slicing the conversation into turns needs to know about it.
#[derive(Clone, Debug, PartialEq)]
struct Item {
    event: Event,
    /// Written by the model: an answer, its reasoning, a tool call.
    assistant: bool,
    /// A user message with no tool result in it: a turn starts here.
    starts_turn: bool,
}

/// A request as events, whole: the system prompt, the tool definitions and every message in order.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Conversation {
    system: Option<Event>,
    tools: Option<Event>,
    items: Vec<Item>,
}

/// The text of a content field in any dialect, with the pointer of each string it came from: a string, or blocks
/// of which the text ones count (`{"type": "text", "text"}`, Responses' `input_text` and `output_text`, and the
/// typeless `{"text"}` of Gemini and Converse).
fn texts(value: &Value, at: &str, out: &mut Vec<(String, String)>) {
    match value {
        Value::String(text) => out.push((text.clone(), at.to_string())),
        Value::Array(blocks) => {
            for (j, block) in blocks.iter().enumerate() {
                if is_text(block)
                    && let Some(text) = block.get("text").and_then(Value::as_str)
                {
                    out.push((text.to_string(), format!("{at}/{j}/text")));
                } else if let Some(inner) = block.get("json") {
                    // Converse: a tool result given as JSON.
                    out.push((inner.to_string(), format!("{at}/{j}/json")));
                }
            }
        }
        _ => {}
    }
}

fn is_text(block: &Value) -> bool {
    if block.get("thought") == Some(&Value::Bool(true)) {
        return false;
    }
    match block.get("type").and_then(Value::as_str) {
        Some("text" | "input_text" | "output_text" | "summary_text") => true,
        Some(_) => false,
        None => block.get("text").is_some_and(Value::is_string),
    }
}

/// One event from texts read out of several strings.
fn joined(kind: Kind, parts: Vec<(String, String)>) -> Option<Event> {
    if parts.iter().all(|(text, _)| text.is_empty()) {
        return None;
    }
    let (texts, at): (Vec<String>, Vec<String>) = parts.into_iter().unzip();
    Some(Event {
        at,
        ..Event::text(kind, texts.join("\n"))
    })
}

fn str_of(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// Arguments as JSON: providers that send them as a string of JSON are parsed, and a string that is not JSON (cut
/// short, or not JSON at all) is kept as the string it is.
fn arguments_of(value: Option<&Value>) -> Value {
    match value {
        Some(Value::String(text)) if text.trim().is_empty() => json!({}),
        Some(Value::String(text)) => {
            serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.clone()))
        }
        Some(other) => other.clone(),
        None => json!({}),
    }
}

fn call(id: Option<String>, name: Option<String>, arguments: Option<&Value>, at: String) -> Event {
    Event {
        call_id: id,
        name,
        arguments: Some(arguments_of(arguments)),
        at: vec![at],
        ..Event::new(Kind::ToolCall)
    }
}

fn result(
    id: Option<String>,
    name: Option<String>,
    parts: Vec<(String, String)>,
    names: &BTreeMap<String, String>,
) -> Event {
    let (texts, at): (Vec<String>, Vec<String>) = parts.into_iter().unzip();
    Event {
        name: name.or_else(|| id.as_ref().and_then(|id| names.get(id).cloned())),
        call_id: id,
        at,
        ..Event::text(Kind::ToolResult, texts.join("\n"))
    }
}

/// What one message of any dialect holds, in the order: tool results, reasoning, text, tool calls. `system` takes
/// the text of a system or developer message. `names` learns each call's tool, so its result can name it.
fn message_items(
    message: &Value,
    at: &str,
    names: &mut BTreeMap<String, String>,
    system: &mut Vec<(String, String)>,
    out: &mut Vec<Item>,
) {
    let assistant = |event: Event| Item {
        event,
        assistant: true,
        starts_turn: false,
    };
    let other = |event: Event| Item {
        event,
        assistant: false,
        starts_turn: false,
    };
    // The Responses API's items that are not messages.
    match message.get("type").and_then(Value::as_str) {
        Some("function_call" | "custom_tool_call") => {
            let id = str_of(message, "call_id").or_else(|| str_of(message, "id"));
            let name = str_of(message, "name");
            if let (Some(id), Some(name)) = (&id, &name) {
                names.insert(id.clone(), name.clone());
            }
            let field = if message.get("arguments").is_some() {
                "arguments"
            } else {
                "input"
            };
            out.push(assistant(call(
                id,
                name,
                message.get(field),
                format!("{at}/{field}"),
            )));
            return;
        }
        Some("function_call_output" | "custom_tool_call_output") => {
            let mut parts = Vec::new();
            texts(
                message.get("output").unwrap_or(&Value::Null),
                &format!("{at}/output"),
                &mut parts,
            );
            out.push(other(result(
                str_of(message, "call_id"),
                None,
                parts,
                names,
            )));
            return;
        }
        Some("reasoning") => {
            let mut parts = Vec::new();
            for field in ["summary", "content"] {
                texts(
                    message.get(field).unwrap_or(&Value::Null),
                    &format!("{at}/{field}"),
                    &mut parts,
                );
            }
            out.extend(joined(Kind::Reasoning, parts).map(assistant));
            return;
        }
        Some("message") | None => {}
        // A built-in tool's own item (a web search call, a reference to a stored item): no text of the conversation.
        Some(_) if message.get("role").is_none() => return,
        Some(_) => {}
    }
    let role = message
        .get("role")
        .and_then(Value::as_str)
        .unwrap_or("user");
    let (field, content) = match message.get("parts") {
        Some(parts) => ("parts", parts),
        None => ("content", message.get("content").unwrap_or(&Value::Null)),
    };
    let at_content = format!("{at}/{field}");
    if matches!(role, "system" | "developer") {
        texts(content, &at_content, system);
        return;
    }
    if matches!(role, "tool" | "function") {
        // Chat completions: a tool's result is a message of its own.
        let mut parts = Vec::new();
        texts(content, &at_content, &mut parts);
        out.push(other(result(
            str_of(message, "tool_call_id"),
            str_of(message, "name"),
            parts,
            names,
        )));
        return;
    }
    let model = matches!(role, "assistant" | "model");
    let (mut results, mut reasoning, mut said, mut calls) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    if let Some(text) = message.get("reasoning_content").and_then(Value::as_str) {
        reasoning.push((text.to_string(), format!("{at}/reasoning_content")));
    }
    match content {
        Value::String(text) => said.push((text.clone(), at_content.clone())),
        Value::Array(blocks) => {
            for (j, block) in blocks.iter().enumerate() {
                let here = format!("{at_content}/{j}");
                if is_text(block) {
                    if let Some(text) = block.get("text").and_then(Value::as_str) {
                        said.push((text.to_string(), format!("{here}/text")));
                    }
                } else if block.get("thought") == Some(&Value::Bool(true)) {
                    if let Some(text) = block.get("text").and_then(Value::as_str) {
                        reasoning.push((text.to_string(), format!("{here}/text")));
                    }
                } else if block.get("type").and_then(Value::as_str) == Some("thinking") {
                    if let Some(text) = block.get("thinking").and_then(Value::as_str) {
                        reasoning.push((text.to_string(), format!("{here}/thinking")));
                    }
                } else if let Some(text) = block
                    .pointer("/reasoningContent/reasoningText/text")
                    .and_then(Value::as_str)
                {
                    reasoning.push((
                        text.to_string(),
                        format!("{here}/reasoningContent/reasoningText/text"),
                    ));
                } else if block.get("type").and_then(Value::as_str) == Some("tool_use") {
                    calls.push(call(
                        str_of(block, "id"),
                        str_of(block, "name"),
                        block.get("input"),
                        format!("{here}/input"),
                    ));
                } else if let Some(used) = block.get("toolUse") {
                    calls.push(call(
                        str_of(used, "toolUseId"),
                        str_of(used, "name"),
                        used.get("input"),
                        format!("{here}/toolUse/input"),
                    ));
                } else if let Some(called) = block.get("functionCall") {
                    calls.push(call(
                        str_of(called, "id"),
                        str_of(called, "name"),
                        called.get("args"),
                        format!("{here}/functionCall/args"),
                    ));
                } else if block.get("type").and_then(Value::as_str) == Some("tool_result") {
                    let mut parts = Vec::new();
                    texts(
                        block.get("content").unwrap_or(&Value::Null),
                        &format!("{here}/content"),
                        &mut parts,
                    );
                    results.push(result(str_of(block, "tool_use_id"), None, parts, names));
                } else if let Some(given) = block.get("toolResult") {
                    let mut parts = Vec::new();
                    texts(
                        given.get("content").unwrap_or(&Value::Null),
                        &format!("{here}/toolResult/content"),
                        &mut parts,
                    );
                    results.push(result(str_of(given, "toolUseId"), None, parts, names));
                } else if let Some(given) = block.get("functionResponse") {
                    // Gemini: the result is a JSON object, shown as its JSON text.
                    let response = given.get("response").cloned().unwrap_or(Value::Null);
                    results.push(result(
                        str_of(given, "id"),
                        str_of(given, "name"),
                        vec![(
                            response.to_string(),
                            format!("{here}/functionResponse/response"),
                        )],
                        names,
                    ));
                }
            }
        }
        _ => {}
    }
    for (k, called) in message
        .get("tool_calls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let function = called.get("function").unwrap_or(&Value::Null);
        calls.push(call(
            str_of(called, "id"),
            str_of(function, "name"),
            function.get("arguments"),
            format!("{at}/tool_calls/{k}/function/arguments"),
        ));
    }
    for called in &calls {
        if let (Some(id), Some(name)) = (&called.call_id, &called.name) {
            names.insert(id.clone(), name.clone());
        }
    }
    let starts_turn = !model && results.is_empty() && said.iter().any(|(text, _)| !text.is_empty());
    out.extend(results.into_iter().map(other));
    out.extend(joined(Kind::Reasoning, reasoning).map(assistant));
    let kind = if model {
        Kind::AssistantMessage
    } else {
        Kind::UserMessage
    };
    out.extend(joined(kind, said).map(|event| Item {
        event,
        assistant: model,
        starts_turn,
    }));
    out.extend(calls.into_iter().map(assistant));
}

/// The tools a request declares, each as `{name, description, parameters}`, whichever API declares them.
fn tool_definitions(body: &Value) -> Option<Event> {
    let listed = body
        .get("tools")
        .or_else(|| body.pointer("/toolConfig/tools"))?
        .as_array()?;
    let mut tools = Vec::new();
    let mut add = |tool: &Value, schema: Option<&Value>| {
        let name = str_of(tool, "name").or_else(|| str_of(tool, "type"));
        if let Some(name) = name {
            let mut one = Map::new();
            one.insert("name".into(), name.into());
            if let Some(description) = str_of(tool, "description") {
                one.insert("description".into(), description.into());
            }
            if let Some(schema) = schema {
                one.insert("parameters".into(), schema.clone());
            }
            tools.push(Value::Object(one));
        }
    };
    for tool in listed {
        if let Some(declared) = tool.get("functionDeclarations").and_then(Value::as_array) {
            for one in declared {
                add(
                    one,
                    one.get("parameters")
                        .or_else(|| one.get("parametersJsonSchema")),
                );
            }
        } else if let Some(spec) = tool.get("toolSpec") {
            add(spec, spec.pointer("/inputSchema/json"));
        } else if let Some(function) = tool.get("function").filter(|f| f.is_object()) {
            add(function, function.get("parameters"));
        } else {
            add(
                tool,
                tool.get("input_schema").or_else(|| tool.get("parameters")),
            );
        }
    }
    (!tools.is_empty()).then(|| Event {
        tools: Some(tools),
        ..Event::new(Kind::ToolDefinitions)
    })
}

/// A request body of any API Enterplace serves, as events: chat completions, the Responses API, Anthropic messages,
/// Gemini's generateContent and Bedrock Converse, and the text of an embeddings, completions, speech or image
/// request (`input` or `prompt`, a string or a list of strings) as user messages.
pub fn conversation(body: &Value) -> Conversation {
    let mut system = Vec::new();
    for field in ["system", "instructions"] {
        if let Some(value) = body.get(field) {
            texts(value, &format!("/{field}"), &mut system);
        }
    }
    for field in ["systemInstruction", "system_instruction"] {
        if let Some(parts) = body.get(field).and_then(|s| s.get("parts")) {
            texts(parts, &format!("/{field}/parts"), &mut system);
        }
    }
    let mut items = Vec::new();
    let mut names = BTreeMap::new();
    // `prompt` is a completions or an image request's text. The Responses API's `prompt` is an object naming a
    // stored prompt, which holds no text.
    for field in ["messages", "input", "contents", "prompt"] {
        match body.get(field) {
            Some(Value::String(text)) if !text.is_empty() => items.push(Item {
                event: Event {
                    at: vec![format!("/{field}")],
                    ..Event::text(Kind::UserMessage, text.clone())
                },
                assistant: false,
                starts_turn: true,
            }),
            Some(Value::Array(messages)) => {
                for (i, message) in messages.iter().enumerate() {
                    let at = format!("/{field}/{i}");
                    match message {
                        // A list of texts (embeddings inputs, completions prompts) is one turn: every text of
                        // it is new, and none is history.
                        Value::String(text) if !text.is_empty() => {
                            let starts_turn = !items.iter().any(|item: &Item| item.starts_turn);
                            items.push(Item {
                                event: Event {
                                    at: vec![at],
                                    ..Event::text(Kind::UserMessage, text.clone())
                                },
                                assistant: false,
                                starts_turn,
                            });
                        }
                        Value::Object(_) => {
                            message_items(message, &at, &mut names, &mut system, &mut items);
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    // Gemini's embedContent: one content, not a list of them.
    if let Some(content) = body.get("content").filter(|c| c.get("parts").is_some()) {
        message_items(content, "/content", &mut names, &mut system, &mut items);
    }
    Conversation {
        system: joined(Kind::SystemPrompt, system),
        tools: tool_definitions(body),
        items,
    }
}

/// A request's events, placed: the ones this call adds, the ones before them, and where the answer's go.
#[derive(Clone, Debug, PartialEq)]
pub struct Placed {
    pub turn_id: String,
    /// The turn's number in the session, from 1. 0 when the request has no user message.
    pub turn_index: usize,
    /// The events since the model last answered: what this request adds to the conversation.
    pub new: Vec<Event>,
    /// Every event before them, oldest first, each with its own turn.
    pub history: Vec<Event>,
    /// The index the answer's first event takes.
    pub next_index: usize,
}

impl Conversation {
    /// The text of the first user message: what a session with no marker of its own is known by.
    pub fn first_message(&self) -> &str {
        self.items
            .iter()
            .find(|item| item.starts_turn)
            .or_else(|| self.items.first())
            .and_then(|item| item.event.content.as_deref())
            .unwrap_or("")
    }

    /// Slices the conversation into turns and gives each event its place. A turn starts at a user message that
    /// carries no tool result, and holds everything up to the next one. The system prompt and the tool definitions
    /// lead every turn, so their indexes are the same in each call of a turn. The new events are those after the
    /// model's last answer in the last turn; in a turn the model has not answered in yet, all of them.
    pub fn placed(&self, session: &str, named_turn: Option<&str>) -> Placed {
        self.place(session, named_turn, None)
    }

    /// As [`Conversation::placed`], for a request that holds only what comes after an answer the provider keeps
    /// (a Responses `previous_response_id`): what precedes its first user message goes on in `prior`'s turn, at the
    /// index after that answer, and a user message starts the turn after `prior`'s.
    pub fn placed_after(&self, session: &str, named_turn: Option<&str>, prior: &Prior) -> Placed {
        self.place(session, named_turn, Some(prior))
    }

    fn place(&self, session: &str, named_turn: Option<&str>, prior: Option<&Prior>) -> Placed {
        let starts: Vec<usize> = self
            .items
            .iter()
            .enumerate()
            .filter_map(|(i, item)| item.starts_turn.then_some(i))
            .collect();
        // With a prior turn, what comes before the first user message goes on in it. With none it belongs to the
        // first turn.
        let continued = prior.filter(|_| !self.items.is_empty() && starts.first() != Some(&0));
        let base = prior.map_or(0, |p| p.turn_index);
        let mut bounds: Vec<usize> = starts.clone();
        if continued.is_some() {
            bounds.insert(0, 0);
        } else {
            match bounds.first_mut() {
                Some(first) => *first = 0,
                None => bounds.push(0),
            }
        }
        let lead: Vec<&Event> = self.system.iter().chain(&self.tools).collect();
        // Each turn: its id, its events, how many of them the model has answered, and its first event's index.
        let mut turns: Vec<(String, Vec<Event>, usize, usize)> = Vec::new();
        for (n, from) in bounds.iter().enumerate() {
            let to = bounds.get(n + 1).copied().unwrap_or(self.items.len());
            let slice = &self.items[*from..to];
            // A named turn names the last one: the ones before it were named in their own calls.
            let named = named_turn.filter(|_| n + 1 == bounds.len());
            if let Some(prior) = continued.filter(|_| n == 0) {
                let turn = match named {
                    Some(_) => turn_id(session, 0, "", named),
                    None => prior.turn_id.clone(),
                };
                let events: Vec<Event> = slice
                    .iter()
                    .enumerate()
                    .map(|(i, item)| item.event.clone().placed(&turn, prior.next_index + i))
                    .collect();
                let answered = slice
                    .iter()
                    .rposition(|item| item.assistant)
                    .map_or(0, |at| at + 1);
                turns.push((turn, events, answered, prior.next_index));
                continue;
            }
            // Which of the user messages starts this turn.
            let start = n - usize::from(continued.is_some());
            let number = if starts.is_empty() {
                0
            } else {
                base + start + 1
            };
            let user_text = starts
                .get(start)
                .and_then(|i| self.items[*i].event.content.as_deref())
                .unwrap_or("");
            let turn = turn_id(session, number, user_text, named);
            let events: Vec<Event> = lead
                .iter()
                .map(|e| (*e).clone())
                .chain(slice.iter().map(|item| item.event.clone()))
                .enumerate()
                .map(|(index, event)| event.placed(&turn, index))
                .collect();
            let answered = slice
                .iter()
                .rposition(|item| item.assistant)
                .map_or(0, |at| lead.len() + at + 1);
            turns.push((turn, events, answered, 0));
        }
        let (turn_id, mut last, answered, first) = turns.pop().unwrap_or_default();
        let new = last.split_off(answered);
        let next_index = first + answered + new.len();
        let mut history: Vec<Event> = turns
            .into_iter()
            .flat_map(|(_, events, _, _)| events)
            .collect();
        history.append(&mut last);
        Placed {
            turn_id,
            turn_index: if starts.is_empty() {
                base
            } else {
                base + starts.len()
            },
            new,
            history,
            next_index,
        }
    }
}

/// The turn a stored answer was given in, for the request that goes on from it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Prior {
    pub turn_id: String,
    pub turn_index: usize,
    /// The index after the answer's last event.
    pub next_index: usize,
}

/// The events as the plugins after one see them: each masked event with its new content or arguments, and the id
/// that follows from them.
pub fn masked_events(events: &[Event], masked: &[Masked]) -> Vec<Event> {
    events
        .iter()
        .map(|event| {
            let Some(mask) = masked.iter().rev().find(|m| m.event == event.event_index) else {
                return event.clone();
            };
            let mut event = event.clone();
            if let Some(content) = &mask.content {
                event.content = Some(content.clone());
            }
            if let Some(arguments) = &mask.arguments {
                event.arguments = Some(arguments.clone());
            }
            let (turn, index) = (event.turn_id.clone(), event.event_index);
            event.placed(&turn, index)
        })
        .collect()
}

/// Where a completions answer keeps its text.
const COMPLETION: &str = "/choices/0/text";

/// The model's message in an answer of any API, and its pointer: chat's `choices[0].message`, a messages answer
/// itself, each item of a Responses `output`, Gemini's `candidates[0].content`, Converse's `output.message`.
fn answer_messages(answer: &Value) -> Vec<(&Value, String)> {
    if let Some(message) = answer.pointer("/choices/0/message") {
        return vec![(message, "/choices/0/message".into())];
    }
    // A completions answer: read as a message whose content is the text.
    if answer
        .pointer("/choices/0/text")
        .is_some_and(Value::is_string)
    {
        return vec![(answer, COMPLETION.into())];
    }
    if let Some(content) = answer.pointer("/candidates/0/content") {
        return vec![(content, "/candidates/0/content".into())];
    }
    if let Some(message) = answer.pointer("/output/message") {
        return vec![(message, "/output/message".into())];
    }
    if let Some(items) = answer.get("output").and_then(Value::as_array) {
        return items
            .iter()
            .enumerate()
            .map(|(i, item)| (item, format!("/output/{i}")))
            .collect();
    }
    if answer.get("content").is_some() {
        return vec![(answer, String::new())];
    }
    Vec::new()
}

/// An answer's events, placed after the request's: reasoning, the message, the tool calls. The message is the
/// turn's last when the model called no tool.
pub fn answer_events(answer: &Value, turn: &str, first_index: usize) -> Vec<Event> {
    let mut items = Vec::new();
    let (mut names, mut system) = (BTreeMap::new(), Vec::new());
    for (message, at) in answer_messages(answer) {
        if at == COMPLETION {
            let text = message
                .pointer(COMPLETION)
                .and_then(Value::as_str)
                .unwrap_or("");
            items.extend(
                joined(
                    Kind::AssistantMessage,
                    vec![(text.to_string(), COMPLETION.into())],
                )
                .map(|event| Item {
                    event,
                    assistant: true,
                    starts_turn: false,
                }),
            );
            continue;
        }
        // An answer's message is the model's whatever role it is written with, or with none.
        let mut message = message.clone();
        if message.get("role").is_none()
            && message.get("type").is_none_or(|t| t == "message")
            && let Some(object) = message.as_object_mut()
        {
            object.insert("role".into(), "assistant".into());
        }
        message_items(&message, &at, &mut names, &mut system, &mut items);
    }
    let calls = items.iter().any(|item| item.event.kind == Kind::ToolCall);
    let last = items
        .iter()
        .rposition(|item| item.event.kind == Kind::AssistantMessage);
    items
        .into_iter()
        .enumerate()
        .map(|(i, item)| {
            let mut event = item.event;
            event.last_in_turn = !calls && Some(i) == last;
            event.placed(turn, first_index + i)
        })
        .collect()
}

/// A streamed answer's events so far, put back together as the whole answer of the same API, so one reader serves
/// both. `events` is the JSON of each `data:` line.
pub fn stream_answer(events: &[Value]) -> Value {
    // The Responses API ends with the whole response.
    if let Some(done) = events.iter().rev().find(|e| {
        matches!(
            e.get("type").and_then(Value::as_str),
            Some("response.completed" | "response.incomplete")
        )
    }) && let Some(response) = done.get("response")
    {
        return response.clone();
    }
    let mut text = String::new();
    // Anthropic: the blocks, by index.
    let mut blocks: BTreeMap<u64, (Value, String)> = BTreeMap::new();
    // Chat: the tool calls, by index.
    let mut calls: BTreeMap<u64, (String, String, String)> = BTreeMap::new();
    let mut reasoning = String::new();
    // Gemini: the parts, text joined while it stays text of the same kind.
    let mut parts: Vec<Value> = Vec::new();
    let (mut chat, mut messages, mut gemini, mut completion) = (false, false, false, false);
    for event in events {
        if let Some(choice) = event.pointer("/choices/0") {
            chat = true;
            if let Some(piece) = choice["text"].as_str() {
                completion = true;
                text.push_str(piece);
            }
            let delta = &choice["delta"];
            if let Some(piece) = delta["content"].as_str() {
                text.push_str(piece);
            }
            if let Some(piece) = delta["reasoning_content"].as_str() {
                reasoning.push_str(piece);
            }
            for (j, called) in delta["tool_calls"]
                .as_array()
                .into_iter()
                .flatten()
                .enumerate()
            {
                let slot = calls
                    .entry(called["index"].as_u64().unwrap_or(j as u64))
                    .or_default();
                if let Some(id) = called["id"].as_str() {
                    slot.0 = id.to_string();
                }
                if let Some(name) = called["function"]["name"].as_str() {
                    slot.1.push_str(name);
                }
                if let Some(piece) = called["function"]["arguments"].as_str() {
                    slot.2.push_str(piece);
                }
            }
        }
        match event.get("type").and_then(Value::as_str) {
            Some("content_block_start") => {
                messages = true;
                blocks.insert(
                    event["index"].as_u64().unwrap_or(0),
                    (event["content_block"].clone(), String::new()),
                );
            }
            Some("content_block_delta") => {
                messages = true;
                let (block, partial) = blocks
                    .entry(event["index"].as_u64().unwrap_or(0))
                    .or_insert_with(|| (json!({"type": "text", "text": ""}), String::new()));
                let delta = &event["delta"];
                let add = |block: &mut Value, field: &str, piece: &str| {
                    let so_far = block[field].as_str().unwrap_or("").to_string();
                    block[field] = Value::String(so_far + piece);
                };
                if let Some(piece) = delta["text"].as_str() {
                    add(block, "text", piece);
                } else if let Some(piece) = delta["thinking"].as_str() {
                    add(block, "thinking", piece);
                } else if let Some(piece) = delta["partial_json"].as_str() {
                    partial.push_str(piece);
                }
            }
            Some("response.output_text.delta") => {
                if let Some(piece) = event["delta"].as_str() {
                    text.push_str(piece);
                }
            }
            _ => {}
        }
        for part in event
            .pointer("/candidates/0/content/parts")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            gemini = true;
            let thought = part.get("thought") == Some(&Value::Bool(true));
            match (part.get("text").and_then(Value::as_str), parts.last_mut()) {
                (Some(piece), Some(last))
                    if last.get("text").is_some()
                        && (last.get("thought") == Some(&Value::Bool(true))) == thought =>
                {
                    let so_far = last["text"].as_str().unwrap_or("").to_string();
                    last["text"] = Value::String(so_far + piece);
                }
                _ => parts.push(part.clone()),
            }
        }
    }
    if messages {
        let content: Vec<Value> = blocks
            .into_values()
            .map(|(mut block, partial)| {
                if !partial.is_empty() {
                    block["input"] = arguments_of(Some(&Value::String(partial)));
                }
                block
            })
            .collect();
        return json!({"role": "assistant", "content": content});
    }
    if gemini {
        return json!({"candidates": [{"content": {"role": "model", "parts": parts}}]});
    }
    if completion {
        return json!({"choices": [{"text": text}]});
    }
    if chat {
        let mut message = Map::new();
        message.insert("role".into(), "assistant".into());
        message.insert("content".into(), text.into());
        if !reasoning.is_empty() {
            message.insert("reasoning_content".into(), reasoning.into());
        }
        if !calls.is_empty() {
            let calls: Vec<Value> = calls
                .into_values()
                .map(|(id, name, arguments)| {
                    json!({"id": id, "type": "function", "function": {"name": name, "arguments": arguments}})
                })
                .collect();
            message.insert("tool_calls".into(), calls.into());
        }
        return json!({"choices": [{"message": message}]});
    }
    // A Responses stream cut before its end: the text it got to.
    json!({"output": [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": text}]}]})
}

// ---------------------------------------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------------------------------------

/// Who and what a call's events belong to. The same for a request, its answer and each window of its stream.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Context {
    pub session_id: String,
    pub turn_id: String,
    pub turn_index: usize,
    pub decision_id: String,
    pub person: String,
    pub team: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub org: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub model: String,
    pub provider: String,
    pub route: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application: Option<Application>,
}

/// What a plugin is sent: one call's events and whose they are.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Envelope {
    pub contract: u32,
    /// The guardrail's name in the policy, so one service can serve several.
    pub guardrail: String,
    /// `enforce` or `observe`: whether the answer is obeyed.
    pub mode: &'static str,
    /// `request`, `answer`, `stream` (a window of a streamed answer), `mcp` or `realtime`.
    pub phase: &'static str,
    #[serde(flatten)]
    pub context: Context,
    pub events: Vec<Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history: Option<Vec<Event>>,
}

impl Envelope {
    /// The id a delivery is signed and deduplicated under: the same events of the same decision have the same one.
    pub fn id(&self) -> String {
        let events: Vec<&str> = self.events.iter().map(|e| e.event_id.as_str()).collect();
        let hashed = id::sha256_hex(
            format!(
                "{}\n{}\n{}\n{}",
                self.guardrail,
                self.context.decision_id,
                self.phase,
                events.join(",")
            )
            .as_bytes(),
        );
        format!("env_{}", &hashed[..24])
    }
}

/// Observe mode's batch: several envelopes in one POST.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Batch<'a> {
    pub contract: u32,
    pub batch: &'a [Envelope],
}

/// The `webhook-signature` of a delivery, the Standard Webhooks way: `v1,` and the base64 HMAC-SHA256 of
/// `<id>.<timestamp>.<body>` under the secret (the base64-decoded part after `whsec_`, or its bytes as they are).
pub fn signature(secret: &str, id: &str, timestamp: u64, body: &[u8]) -> String {
    let key = secret
        .strip_prefix("whsec_")
        .and_then(crate::x509::base64_decode)
        .unwrap_or_else(|| secret.as_bytes().to_vec());
    // HMAC takes a key of any length, so this cannot fail.
    let tag = match Hmac::<Sha256>::new_from_slice(&key) {
        Ok(mut mac) => {
            mac.update(format!("{id}.{timestamp}.").as_bytes());
            mac.update(body);
            mac.finalize().into_bytes().to_vec()
        }
        Err(_) => Vec::new(),
    };
    format!("v1,{}", crate::x509::base64_encode(&tag))
}

// ---------------------------------------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Block,
    Mask,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub kind: String,
    /// The `event_index` of the event it is about.
    #[serde(default)]
    pub event: Option<usize>,
    #[serde(default)]
    pub severity: Option<Severity>,
}

/// One event's replacement: `content` for an event with text, `arguments` for a tool call.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Masked {
    pub event: usize,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub arguments: Option<Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionAction {
    /// Refuse the session's next requests for the guardrail's `session_end_seconds`.
    End,
}

/// A plugin's answer.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verdict {
    pub action: Action,
    /// For the plugin's own logs. Checked, then neither shown nor recorded: it may quote the conversation.
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub masked: Vec<Masked>,
    #[serde(default)]
    pub session_action: Option<SessionAction>,
}

impl Verdict {
    pub fn allow() -> Self {
        Self {
            action: Action::Allow,
            reason: None,
            findings: Vec::new(),
            masked: Vec::new(),
            session_action: None,
        }
    }
}

const MAX_REASON: usize = 500;
const DOCS: &str = "https://docs.enterplace.dev/governance/plugin-events/";

/// Reads a plugin's answer to a call that carried `sent`.
pub fn parse_verdict(bytes: &[u8], sent: &[Event]) -> Result<Verdict, String> {
    let verdict: Verdict = serde_json::from_slice(bytes).map_err(|err| {
        format!("the answer is not a valid events verdict: {err}. See {DOCS} for the format")
    })?;
    check_verdict(verdict, sent)
}

/// Checks a verdict, from a webhook or from an embedding binary's plugin, against the events it answers.
pub fn check_verdict(verdict: Verdict, sent: &[Event]) -> Result<Verdict, String> {
    if verdict
        .reason
        .as_ref()
        .is_some_and(|r| r.chars().count() > MAX_REASON || r.chars().any(char::is_control))
    {
        return Err(format!(
            "the answer's reason is longer than {MAX_REASON} characters or holds control characters; keep it to one short line"
        ));
    }
    let indexes = || {
        sent.iter()
            .map(|e| e.event_index.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    for finding in &verdict.findings {
        let kind_ok = (1..=64).contains(&finding.kind.len())
            && finding
                .kind
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b));
        if !kind_ok {
            return Err("a finding's kind must be 1 to 64 letters, digits, dots, dashes or underscores, such as \"prompt_injection\"; it is written to the audit record, so it must never hold the matched text".into());
        }
        if let Some(index) = finding.event
            && !sent.iter().any(|e| e.event_index == index)
        {
            return Err(format!(
                "a finding points at event {index}, and the events sent had the indexes {}; event is the event_index of one of them",
                indexes()
            ));
        }
    }
    match (verdict.action, verdict.masked.is_empty()) {
        (Action::Mask, true) => {
            return Err("the answer says mask and has no masked; send one {\"event\": <event_index>, \"content\": ...} (or \"arguments\" for a tool call) for each event to change".into());
        }
        (Action::Allow | Action::Block, false) => {
            return Err(
                "masked is only read when action is mask; remove it, or set action to mask".into(),
            );
        }
        _ => {}
    }
    for masked in &verdict.masked {
        let Some(event) = sent.iter().find(|e| e.event_index == masked.event) else {
            return Err(format!(
                "masked names event {}, and the events sent had the indexes {}; event is the event_index of one of them",
                masked.event,
                indexes()
            ));
        };
        let fits = match (event.kind.call(), &masked.content, &masked.arguments) {
            (true, None, Some(_)) => Ok(()),
            (true, _, _) => Err(
                "a tool call is masked with \"arguments\" (its new arguments as JSON) and no \"content\"",
            ),
            (false, _, _) if event.kind == Kind::ToolDefinitions => {
                Err("tool definitions cannot be masked; block the request, or allow it")
            }
            (false, _, _) if event.partial && !event.held => Err(
                "a window of a streamed answer that is not held cannot be masked, because its text may already be with the caller; set stream.hold on the guardrail, block it, or allow it",
            ),
            (false, Some(_), None) => Ok(()),
            (false, _, _) => Err(
                "an event with text is masked with \"content\" (its new text) and no \"arguments\"",
            ),
        };
        if let Err(why) = fits {
            return Err(format!(
                "masked for event {} ({}): {why}",
                masked.event,
                event.kind.word()
            ));
        }
    }
    Ok(verdict)
}

/// Writes one masked value where its event was read from. A string goes where a string was. Where the provider
/// holds JSON (a tool's input), the masked text must be JSON of the same type, or the write is refused: the
/// unmasked value is never what goes on. Gemini's function response takes any text, wrapped as its output.
fn write_slot(body: &mut Value, at: &str, masked: &Value) -> Result<(), String> {
    let Some(slot) = body.pointer_mut(at) else {
        return Err(format!("the body has nothing at {at}"));
    };
    match (&*slot, masked) {
        (Value::String(_), Value::String(text)) => *slot = Value::String(text.clone()),
        // Arguments held as a string of JSON take the masked JSON as its text.
        (Value::String(_), other) => *slot = Value::String(other.to_string()),
        (held, Value::String(text)) => {
            let parsed = serde_json::from_str::<Value>(text)
                .ok()
                .filter(|parsed| std::mem::discriminant(held) == std::mem::discriminant(parsed));
            *slot = match parsed {
                Some(parsed) => parsed,
                // Gemini's functionResponse.response is a JSON object, and its documented key for a function's
                // output is "output": masked text that is not such an object goes there as text.
                None if at.ends_with("/functionResponse/response") => json!({ "output": text }),
                None => {
                    return Err(format!(
                        "the value at {at} is JSON, and the masked text is not JSON of the same type"
                    ));
                }
            };
        }
        (_, other) => *slot = other.clone(),
    }
    Ok(())
}

/// Writes a verdict's masks into the body its events were read from. `Ok(true)` when the body changed.
pub fn apply_masks(body: &mut Value, sent: &[Event], masked: &[Masked]) -> Result<bool, String> {
    let mut changed = false;
    for mask in masked {
        let Some(event) = sent.iter().find(|e| e.event_index == mask.event) else {
            continue;
        };
        let value = match (&mask.content, &mask.arguments) {
            (Some(text), _) => Value::String(text.clone()),
            (None, Some(arguments)) => arguments.clone(),
            (None, None) => continue,
        };
        if mask.content.as_deref() == event.content.as_deref() && mask.arguments == event.arguments
        {
            continue;
        }
        let Some((first, rest)) = event.at.split_first() else {
            return Err(format!(
                "event {} ({}) has no place in the body to write a mask to",
                event.event_index,
                event.kind.word()
            ));
        };
        write_slot(body, first, &value)?;
        for other in rest {
            write_slot(body, other, &Value::String(MASKED_SLOT.into()))?;
        }
        changed = true;
    }
    Ok(changed)
}

/// What one plugin's answer comes to, once its guardrail's mode, shadow period and `on_failure` are applied.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Settled {
    /// Lines for the record's `guardrails`: kinds and counts, as every guardrail writes them.
    pub audit: Vec<AuditEntry>,
    /// The record's `events` entry: the action, and each finding by kind, event kind, index and severity.
    pub entry: Value,
    pub blocked: Option<Blocked>,
    /// The masks to write, when it masks and is obeyed.
    pub masks: Vec<Masked>,
    /// The plugin ended the session, and is obeyed.
    pub end_session: bool,
    /// Why the plugin gave no usable answer, for the operator's log. Never recorded.
    pub cause: Option<String>,
}

/// Settles a plugin's answer (or the lack of one) to the events `sent`. `what` names what was judged in a refusal:
/// "this request", "the model's answer".
pub fn settle(
    name: &str,
    events: &Events,
    shadow: bool,
    sent: &[Event],
    outcome: Result<Verdict, String>,
    what: &str,
) -> Settled {
    let entry = |kind: &str, action: &'static str, count: usize| AuditEntry {
        guardrail: name.to_string(),
        detector: DETECTOR.to_string(),
        kind: kind.to_string(),
        action,
        count,
    };
    let mut out = Settled::default();
    let mut record = Map::new();
    record.insert("guardrail".into(), name.into());
    record.insert("mode".into(), events.mode.word().into());
    record.insert("events".into(), sent.len().into());
    let verdict = match outcome.and_then(|v| check_verdict(v, sent)) {
        Ok(verdict) => verdict,
        Err(cause) => {
            let closed = events.hook.on_failure == OnFailure::FailClosed
                && events.mode == Mode::Enforce
                && !shadow;
            let word = if closed { "block" } else { "skipped" };
            out.audit.push(entry("unavailable", word, 1));
            record.insert("action".into(), word.into());
            record.insert("unavailable".into(), true.into());
            if closed {
                out.blocked = Some(Blocked {
                    guardrail: name.to_string(),
                    message: format!(
                        "Guardrail \"{name}\" could not check {what}, and it is set to fail_closed, so it was not passed on. Try again later; if it keeps failing, ask an administrator to check the plugin service."
                    ),
                });
            }
            out.cause = Some(format!(
                "events guardrail \"{name}\" at {}: {cause}",
                events.hook.url
            ));
            out.entry = Value::Object(record);
            return out;
        }
    };
    let obeyed = events.mode == Mode::Enforce && !shadow;
    let word = match (verdict.action, obeyed) {
        (Action::Allow, _) => "warn",
        (_, false) if shadow => SHADOW,
        (_, false) => "warn",
        (Action::Block, true) => "block",
        (Action::Mask, true) => "mask",
    };
    let mut kinds: BTreeMap<&str, usize> = BTreeMap::new();
    for finding in &verdict.findings {
        *kinds.entry(finding.kind.as_str()).or_default() += 1;
    }
    if kinds.is_empty() && verdict.action != Action::Allow {
        kinds.insert("unspecified", 1);
    }
    out.audit
        .extend(kinds.iter().map(|(kind, n)| entry(kind, word, *n)));
    record.insert(
        "action".into(),
        match verdict.action {
            Action::Allow => "allow",
            Action::Block => "block",
            Action::Mask => "mask",
        }
        .into(),
    );
    if !obeyed && verdict.action != Action::Allow {
        record.insert("obeyed".into(), false.into());
    }
    let findings: Vec<Value> = verdict
        .findings
        .iter()
        .map(|finding| {
            let mut one = Map::new();
            one.insert("kind".into(), finding.kind.as_str().into());
            if let Some(index) = finding.event {
                one.insert("event_index".into(), index.into());
                if let Some(event) = sent.iter().find(|e| e.event_index == index) {
                    one.insert("event_kind".into(), event.kind.word().into());
                    one.insert("event_id".into(), event.event_id.as_str().into());
                }
            }
            if let Some(severity) = finding.severity {
                one.insert("severity".into(), json!(severity));
            }
            Value::Object(one)
        })
        .collect();
    if !findings.is_empty() {
        record.insert("findings".into(), findings.into());
    }
    if verdict.session_action == Some(SessionAction::End) {
        record.insert("session_action".into(), "end".into());
        out.end_session = obeyed;
    }
    match (verdict.action, obeyed) {
        (Action::Block, true) => {
            // From the finding kinds only: the plugin's reason is free text that may quote the conversation.
            let found: Vec<String> = kinds.iter().map(|(k, n)| format!("{k} ({n})")).collect();
            out.blocked = Some(Blocked {
                guardrail: name.to_string(),
                message: format!(
                    "Guardrail \"{name}\" refused {what}: the plugin found {}. Ask in another way, or ask an Enterplace admin about the guardrail.",
                    found.join(", ")
                ),
            });
        }
        (Action::Mask, true) => out.masks = verdict.masked,
        _ => {}
    }
    out.entry = Value::Object(record);
    out
}

/// The guardrail's action word as `guard::Action`: what an events guardrail is in the places that ask a guardrail
/// whether it blocks.
pub fn guard_action(mode: Mode) -> GuardAction {
    match mode {
        Mode::Enforce => GuardAction::Block,
        Mode::Observe => GuardAction::Warn,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// The shape of an event without its ids: kind, text, tool, call id, arguments.
    fn shape(events: &[Event]) -> Vec<Value> {
        events
            .iter()
            .map(|e| {
                json!([
                    e.event_index,
                    e.kind.word(),
                    e.content,
                    e.name,
                    e.call_id,
                    e.arguments,
                    e.last_in_turn
                ])
            })
            .collect()
    }

    fn second_call(api: &str) -> Value {
        match api {
            "chat" => json!({
                "model": "m",
                "messages": [
                    {"role": "system", "content": "Be brief."},
                    {"role": "user", "content": "Weather in Paris?"},
                    {"role": "assistant", "content": null, "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "get_weather", "arguments": "{\"city\":\"Paris\"}"}}]},
                    {"role": "tool", "tool_call_id": "c1", "content": "18C"}
                ],
                "tools": [{"type": "function", "function": {"name": "get_weather", "description": "Weather", "parameters": {"type": "object"}}}]
            }),
            "messages" => json!({
                "model": "m",
                "system": "Be brief.",
                "messages": [
                    {"role": "user", "content": "Weather in Paris?"},
                    {"role": "assistant", "content": [{"type": "tool_use", "id": "c1", "name": "get_weather", "input": {"city": "Paris"}}]},
                    {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "c1", "content": "18C"}]}
                ],
                "tools": [{"name": "get_weather", "description": "Weather", "input_schema": {"type": "object"}}]
            }),
            "responses" => json!({
                "model": "m",
                "instructions": "Be brief.",
                "input": [
                    {"role": "user", "content": [{"type": "input_text", "text": "Weather in Paris?"}]},
                    {"type": "function_call", "call_id": "c1", "name": "get_weather", "arguments": "{\"city\":\"Paris\"}"},
                    {"type": "function_call_output", "call_id": "c1", "output": "18C"}
                ],
                "tools": [{"type": "function", "name": "get_weather", "description": "Weather", "parameters": {"type": "object"}}]
            }),
            "converse" => json!({
                "system": [{"text": "Be brief."}],
                "messages": [
                    {"role": "user", "content": [{"text": "Weather in Paris?"}]},
                    {"role": "assistant", "content": [{"toolUse": {"toolUseId": "c1", "name": "get_weather", "input": {"city": "Paris"}}}]},
                    {"role": "user", "content": [{"toolResult": {"toolUseId": "c1", "content": [{"text": "18C"}]}}]}
                ],
                "toolConfig": {"tools": [{"toolSpec": {"name": "get_weather", "description": "Weather", "inputSchema": {"json": {"type": "object"}}}}]}
            }),
            _ => json!({
                "systemInstruction": {"parts": [{"text": "Be brief."}]},
                "contents": [
                    {"role": "user", "parts": [{"text": "Weather in Paris?"}]},
                    {"role": "model", "parts": [{"functionCall": {"id": "c1", "name": "get_weather", "args": {"city": "Paris"}}}]},
                    {"role": "user", "parts": [{"functionResponse": {"id": "c1", "name": "get_weather", "response": "18C"}}]}
                ],
                "tools": [{"functionDeclarations": [{"name": "get_weather", "description": "Weather", "parameters": {"type": "object"}}]}]
            }),
        }
    }

    #[test]
    fn five_apis_give_one_event_sequence() {
        let mut seen: Vec<(Vec<Value>, Vec<Value>, String)> = Vec::new();
        for api in ["chat", "messages", "responses", "converse", "gemini"] {
            let placed = conversation(&second_call(api)).placed("ses_x", None);
            assert_eq!(placed.turn_index, 1, "{api}");
            assert_eq!(placed.next_index, 5, "{api}");
            seen.push((shape(&placed.new), shape(&placed.history), placed.turn_id));
        }
        // Gemini's function response is JSON, so its text is the JSON text of the string.
        let gemini = seen.pop().map(|(new, _, _)| new).unwrap_or_default();
        assert_eq!(gemini[0][2], "\"18C\"");
        let (new, history, turn) = seen[0].clone();
        assert_eq!(
            new,
            vec![json!([
                4,
                "tool_result",
                "18C",
                "get_weather",
                "c1",
                null,
                false
            ])]
        );
        assert_eq!(
            history,
            vec![
                json!([0, "system_prompt", "Be brief.", null, null, null, false]),
                json!([1, "tool_definitions", null, null, null, null, false]),
                json!([
                    2,
                    "user_message",
                    "Weather in Paris?",
                    null,
                    null,
                    null,
                    false
                ]),
                json!([3, "tool_call", null, "get_weather", "c1", {"city": "Paris"}, false]),
            ]
        );
        for (other_new, other_history, other_turn) in &seen[1..] {
            assert_eq!(
                (other_new, other_history, other_turn),
                (&new, &history, &turn)
            );
        }
    }

    #[test]
    fn a_turn_starts_at_each_user_message_and_keeps_its_id_across_calls() {
        let first = json!({"messages": [{"role": "user", "content": "one"}]});
        let second = json!({"messages": [
            {"role": "user", "content": "one"},
            {"role": "assistant", "content": "1"},
            {"role": "user", "content": "two"}
        ]});
        let a = conversation(&first).placed("s", None);
        let b = conversation(&second).placed("s", None);
        assert_eq!((a.turn_index, b.turn_index), (1, 2));
        assert_ne!(a.turn_id, b.turn_id);
        assert_eq!(b.history[0].turn_id, a.turn_id);
        assert_eq!(b.history[0].event_id, a.new[0].event_id);
        assert_eq!(
            shape(&b.new),
            vec![json!([0, "user_message", "two", null, null, null, false])]
        );
        // The answer's events follow the request's, and the message ends the turn when no tool is called.
        let answer = json!({"choices": [{"message": {"role": "assistant", "content": "2"}}]});
        let events = answer_events(&answer, &b.turn_id, b.next_index);
        assert_eq!(
            shape(&events),
            vec![json!([1, "assistant_message", "2", null, null, null, true])]
        );
        // The same message read back from the next request's history has the same id.
        let third = json!({"messages": [
            {"role": "user", "content": "one"},
            {"role": "assistant", "content": "1"},
            {"role": "user", "content": "two"},
            {"role": "assistant", "content": "2"},
            {"role": "user", "content": "three"}
        ]});
        let c = conversation(&third).placed("s", None);
        assert!(c.history.iter().any(|e| e.event_id == events[0].event_id));
    }

    #[test]
    fn a_session_is_read_in_the_documented_order() {
        let body = json!({"prompt_cache_key": "k", "user": "u", "metadata": {"user_id": "user_1_account_2_session_abc"}});
        let mut markers = Markers {
            enterplace_session: Some("a".into()),
            session: Some("b".into()),
            claude_code: Some("abc".into()),
            codex: Some("d".into()),
            ..Markers::default()
        };
        let mut sources = Vec::new();
        let mut ids = Vec::new();
        for step in 0..4 {
            let (id, source) = session_id("ana", "key", &markers, &body, "hi");
            sources.push(source);
            ids.push(id);
            match step {
                0 => markers.enterplace_session = None,
                1 => markers.session = None,
                _ => markers.claude_code = None,
            }
        }
        assert_eq!(
            sources,
            [
                "x-enterplace-session",
                "x-session-id",
                "claude_code",
                "claude_code"
            ]
        );
        // Claude Code's header and the session inside its metadata are one session.
        assert_eq!(ids[2], ids[3]);
        let none = Markers::default();
        let source = |body: Value| session_id("ana", "key", &none, &body, "hi").1;
        assert_eq!(
            source(json!({"prompt_cache_key": "k", "user": "u"})),
            "prompt_cache_key"
        );
        assert_eq!(
            source(json!({"metadata": {"user_id": "u"}, "user": "u"})),
            "metadata.user_id"
        );
        assert_eq!(source(json!({"user": "u"})), "user");
        assert_eq!(source(json!({})), "first_message");
        // Two people who send the same session id do not share a session.
        let of = |person: &str| session_id(person, "key", &markers, &body, "hi").0;
        assert_ne!(of("ana"), of("ben"));
        assert!(of("ana").starts_with("ses_"));
    }

    #[test]
    fn a_stream_reads_as_the_whole_answer_does() -> TestResult {
        let chat: Vec<Value> = [
            r#"{"choices":[{"index":0,"delta":{"role":"assistant","content":"Let me "}}]}"#,
            r#"{"choices":[{"index":0,"delta":{"content":"check."}}]}"#,
            r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"get_weather","arguments":"{\"city\":"}}]}}]}"#,
            r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"Paris\"}"}}]}}]}"#,
        ]
        .iter()
        .map(|line| serde_json::from_str(line))
        .collect::<Result<_, _>>()?;
        let messages: Vec<Value> = [
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Let me check."}}"#,
            r#"{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"c1","name":"get_weather","input":{}}}"#,
            r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"city\":\"Paris\"}"}}"#,
        ]
        .iter()
        .map(|line| serde_json::from_str(line))
        .collect::<Result<_, _>>()?;
        let gemini: Vec<Value> = [
            r#"{"candidates":[{"content":{"role":"model","parts":[{"text":"Let me "}]}}]}"#,
            r#"{"candidates":[{"content":{"role":"model","parts":[{"text":"check."}]}}]}"#,
            r#"{"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"id":"c1","name":"get_weather","args":{"city":"Paris"}}}]}}]}"#,
        ]
        .iter()
        .map(|line| serde_json::from_str(line))
        .collect::<Result<_, _>>()?;
        let responses = vec![
            json!({"type": "response.completed", "response": {"output": [
                {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Let me check."}]},
                {"type": "function_call", "call_id": "c1", "name": "get_weather", "arguments": "{\"city\":\"Paris\"}"}
            ]}}),
        ];
        let want = vec![
            json!([
                3,
                "assistant_message",
                "Let me check.",
                null,
                null,
                null,
                false
            ]),
            json!([4, "tool_call", null, "get_weather", "c1", {"city": "Paris"}, false]),
        ];
        for stream in [chat, messages, gemini, responses] {
            assert_eq!(shape(&answer_events(&stream_answer(&stream), "t", 3)), want);
        }
        Ok(())
    }

    fn events_guard(mode: Mode, on_failure: OnFailure) -> Events {
        Events {
            hook: Webhook {
                url: "http://127.0.0.1:9".into(),
                timeout: std::time::Duration::from_millis(100),
                on_failure,
                headers_env: Vec::new(),
                vendor: crate::vendors::Vendor::Contract,
                key_env: None,
                credential: None,
            },
            mode,
            history: false,
            stream: None,
            session_end_seconds: 60,
            secret_env: None,
            batch_url: None,
            queue: 8,
            batch_size: 2,
            retries: 0,
        }
    }

    #[test]
    fn a_mask_is_written_where_its_event_was_read() -> TestResult {
        let mut body = second_call("messages");
        let placed = conversation(&body).placed("s", None);
        let verdict = parse_verdict(
            br#"{"action":"mask","masked":[{"event":4,"content":"[weather]"}],"findings":[{"kind":"pii","event":4,"severity":"high"}]}"#,
            &placed.new,
        )?;
        let settled = settle(
            "watch",
            &events_guard(Mode::Enforce, OnFailure::FailClosed),
            false,
            &placed.new,
            Ok(verdict),
            "this request",
        );
        assert_eq!(settled.audit[0].action, "mask");
        assert_eq!(settled.entry["findings"][0]["event_kind"], "tool_result");
        assert!(apply_masks(&mut body, &placed.new, &settled.masks)?);
        assert_eq!(body["messages"][2]["content"][0]["content"], "[weather]");
        // A tool call's arguments, held as an object or as a string of JSON, take JSON.
        let mut answer = json!({"choices": [{"message": {"role": "assistant", "tool_calls": [{"id": "c", "function": {"name": "f", "arguments": "{\"a\":1}"}}]}}]});
        let events = answer_events(&answer, "t", 0);
        let masks = vec![Masked {
            event: 0,
            content: None,
            arguments: Some(json!({"a": 0})),
        }];
        assert!(apply_masks(&mut answer, &events, &masks)?);
        assert_eq!(
            answer["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"],
            "{\"a\":0}"
        );
        Ok(())
    }

    #[test]
    fn gemini_takes_a_masked_tool_result_that_is_not_json_as_the_function_s_output() -> TestResult {
        let mut body = json!({"contents": [
            {"role": "user", "parts": [{"text": "Weather in Paris?"}]},
            {"role": "model", "parts": [{"functionCall": {"name": "get_weather", "args": {"city": "Paris"}}}]},
            {"role": "user", "parts": [{"functionResponse": {"name": "get_weather", "response": {"temp": "18C"}}}]}]});
        let placed = conversation(&body).placed("s", None);
        let result = placed
            .new
            .iter()
            .find(|e| e.kind == Kind::ToolResult)
            .ok_or("no tool result")?
            .event_index;
        let mask = |content: &str| {
            vec![Masked {
                event: result,
                content: Some(content.into()),
                arguments: None,
            }]
        };
        let at = "/contents/2/parts/0/functionResponse/response";
        assert!(apply_masks(&mut body, &placed.new, &mask("[masked]"))?);
        assert_eq!(body.pointer(at), Some(&json!({"output": "[masked]"})));
        // JSON of another type is text to it too; an object goes in as it is.
        assert!(apply_masks(&mut body, &placed.new, &mask("[1, 2]"))?);
        assert_eq!(body.pointer(at), Some(&json!({"output": "[1, 2]"})));
        assert!(apply_masks(
            &mut body,
            &placed.new,
            &mask("{\"temp\":\"?\"}")
        )?);
        assert_eq!(body.pointer(at), Some(&json!({"temp": "?"})));
        // A tool call's input is still refused text that is not JSON: there is no shape to wrap it in.
        let mut answer = json!({"role": "assistant", "content": [{"type": "tool_use", "id": "c", "name": "f", "input": {"a": 1}}]});
        let events = answer_events(&answer, "t", 0);
        let bad = vec![Masked {
            event: 0,
            content: Some("no".into()),
            arguments: None,
        }];
        assert!(apply_masks(&mut answer, &events, &bad).is_err());
        Ok(())
    }

    #[test]
    fn a_request_after_a_stored_answer_goes_on_in_its_turn_or_starts_the_next() {
        let prior = Prior {
            turn_id: "turn_before".into(),
            turn_index: 3,
            next_index: 7,
        };
        // A tool's result alone: the same turn, counted on from the answer.
        let result = conversation(
            &json!({"input": [{"type": "function_call_output", "call_id": "c", "output": "18C"}]}),
        );
        let placed = result.placed_after("s", None, &prior);
        assert_eq!(
            (placed.turn_id.as_str(), placed.turn_index),
            ("turn_before", 3)
        );
        assert_eq!(shape(&placed.new)[0][0], 7);
        assert_eq!(placed.next_index, 8);
        // A new question: the turn after, led by the system prompt as every turn is.
        let question = conversation(&json!({"instructions": "Be brief.", "input": "And Rome?"}));
        let placed = question.placed_after("s", None, &prior);
        assert_eq!(placed.turn_index, 4);
        assert_eq!(placed.turn_id, turn_id("s", 4, "And Rome?", None));
        assert_eq!(placed.new.len(), 2);
        assert_eq!(placed.next_index, 2);
        // Both: the result ends the turn before, and only the question is new.
        let both = conversation(&json!({"input": [
            {"type": "function_call_output", "call_id": "c", "output": "18C"},
            {"role": "user", "content": "And Rome?"}]}));
        let placed = both.placed_after("s", None, &prior);
        assert_eq!(placed.turn_index, 4);
        assert_eq!(shape(&placed.history)[0][0], 7);
        assert_eq!(placed.history[0].turn_id, "turn_before");
        assert_eq!(placed.new.len(), 1);
    }

    #[test]
    fn a_list_of_texts_is_one_turn_and_a_completion_is_an_answer() {
        for field in ["input", "prompt"] {
            let placed = conversation(&json!({ field: ["one", "two", "three"] })).placed("s", None);
            assert_eq!(placed.new.len(), 3, "{field}");
            assert!(placed.history.is_empty(), "{field}");
            assert_eq!(placed.turn_index, 1, "{field}");
        }
        let embed = json!({"content": {"parts": [{"text": "to embed"}]}});
        assert_eq!(conversation(&embed).placed("s", None).new.len(), 1);
        // A stored prompt is a reference, and token ids are not text.
        for body in [
            json!({"prompt": {"id": "pmpt_1"}}),
            json!({"input": [[1, 2, 3]]}),
        ] {
            assert!(conversation(&body).placed("s", None).new.is_empty());
        }
        let mut answer = json!({"choices": [{"text": "Once"}]});
        let events = answer_events(&answer, "t", 1);
        assert_eq!(
            shape(&events),
            [json!([
                1,
                "assistant_message",
                "Once",
                null,
                null,
                null,
                true
            ])]
        );
        let masks = vec![Masked {
            event: 1,
            content: Some("[x]".into()),
            arguments: None,
        }];
        assert_eq!(apply_masks(&mut answer, &events, &masks), Ok(true));
        assert_eq!(answer["choices"][0]["text"], "[x]");
        let chunks = [
            json!({"choices": [{"text": "On"}]}),
            json!({"choices": [{"text": "ce"}]}),
        ];
        assert_eq!(
            stream_answer(&chunks),
            json!({"choices": [{"text": "Once"}]})
        );
    }

    #[test]
    fn a_window_is_masked_only_while_it_is_held_and_the_next_plugin_sees_the_mask() {
        let window = |held: bool| {
            vec![
                Event {
                    partial: true,
                    window: Some(0),
                    held,
                    ..Event::text(Kind::AssistantMessage, "the code word")
                }
                .placed("t", 2),
            ]
        };
        let mask = br#"{"action":"mask","masked":[{"event":2,"content":"the [x]"}]}"#;
        let refused = parse_verdict(mask, &window(false));
        assert!(refused.is_err_and(|e| e.contains("stream.hold")));
        let held = window(true);
        let verdict = parse_verdict(mask, &held);
        assert!(verdict.is_ok());
        assert_eq!(json!(held[0])["held"], true);
        let masked = verdict.map(|v| v.masked).unwrap_or_default();
        let next = masked_events(&held, &masked);
        assert_eq!(next[0].content.as_deref(), Some("the [x]"));
        assert_eq!(next[0].event_index, 2);
        assert_ne!(next[0].event_id, held[0].event_id);
    }

    #[test]
    fn a_verdict_that_does_not_fit_is_refused_by_name() {
        let sent = conversation(&second_call("chat")).placed("s", None).new;
        let cause = |text: &str| {
            parse_verdict(text.as_bytes(), &sent)
                .err()
                .unwrap_or_default()
        };
        assert!(cause(r#"{"action":"deny"}"#).contains("unknown variant"));
        assert!(cause(r#"{"action":"mask"}"#).contains("has no masked"));
        assert!(
            cause(r#"{"action":"allow","masked":[{"event":4,"content":"x"}]}"#)
                .contains("only read when action is mask")
        );
        assert!(
            cause(r#"{"action":"block","findings":[{"kind":"x","event":9}]}"#)
                .contains("points at event 9")
        );
        assert!(
            cause(r#"{"action":"mask","masked":[{"event":4,"arguments":{}}]}"#)
                .contains("masked with \"content\"")
        );
        assert!(
            cause(r#"{"action":"block","findings":[{"kind":"a b"}]}"#).contains("kind must be")
        );
    }

    #[test]
    fn a_plugin_that_fails_follows_on_failure_and_observe_never_blocks() {
        let sent = conversation(&second_call("chat")).placed("s", None).new;
        let failed = || Err::<Verdict, String>("timed out".into());
        let closed = settle(
            "w",
            &events_guard(Mode::Enforce, OnFailure::FailClosed),
            false,
            &sent,
            failed(),
            "this request",
        );
        assert!(closed.blocked.is_some());
        assert_eq!(closed.audit[0].action, "block");
        let open = settle(
            "w",
            &events_guard(Mode::Enforce, OnFailure::FailOpen),
            false,
            &sent,
            failed(),
            "this request",
        );
        assert!(open.blocked.is_none());
        assert_eq!(
            (open.audit[0].kind.as_str(), open.audit[0].action),
            ("unavailable", "skipped")
        );
        let block = || {
            Ok(Verdict {
                action: Action::Block,
                session_action: Some(SessionAction::End),
                ..Verdict::allow()
            })
        };
        let observed = settle(
            "w",
            &events_guard(Mode::Observe, OnFailure::FailOpen),
            false,
            &sent,
            block(),
            "this request",
        );
        assert!(observed.blocked.is_none() && !observed.end_session);
        let shadowed = settle(
            "w",
            &events_guard(Mode::Enforce, OnFailure::FailClosed),
            true,
            &sent,
            block(),
            "this request",
        );
        assert!(shadowed.blocked.is_none());
        assert_eq!(shadowed.audit[0].action, SHADOW);
        let enforced = settle(
            "w",
            &events_guard(Mode::Enforce, OnFailure::FailClosed),
            false,
            &sent,
            block(),
            "this request",
        );
        assert!(enforced.blocked.is_some() && enforced.end_session);
    }

    #[test]
    fn a_delivery_is_signed_the_standard_webhooks_way() {
        // The example in the Standard Webhooks specification.
        let signed = signature(
            "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw",
            "msg_p5jXN8AQM9LWM0D4loKWxJek",
            1_614_265_330,
            br#"{"test": 2432232314}"#,
        );
        assert_eq!(signed, "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=");
    }
}
