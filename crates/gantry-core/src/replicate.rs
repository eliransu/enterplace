//! Translation between the OpenAI chat completions format and a Replicate prediction of a language model.
//!
//! A prediction takes one `input` object whose fields each model's schema names. The conversation is written into
//! `prompt` as a transcript (`User: ...`, `Assistant: ...`, ending with `Assistant:`), which every language model's
//! schema takes; the other fields differ by model family ([`Fields`]). As in [`crate::translate`], a request field
//! the model's schema has no place for is an error that names it (AGENTS.md rule 7).
//!
//! Without `stream`, the prediction is waited for (`Prefer: wait`), and its `output`, a list of text pieces or one
//! text, becomes the chat answer. With `stream: true`, the prediction is created with `"stream": true` and its
//! `urls.stream` read as server-sent events (`output`, `error`, `done`), each `output` becoming a chat chunk
//! ([`PredictionStream`]). Its `metrics` give the token counts when the model reports them.
//!
//! Formats as documented on 2026-11-14: <https://replicate.com/docs/reference/http> and
//! <https://replicate.com/docs/topics/predictions/streaming>; input schemas read from each model's API page on
//! replicate.com the same day.

use serde_json::{Map, Value, json};

use crate::translate::{
    Result, describe, fail, insert, is_openai_default, object, openai_usage, untranslatable,
    write_event,
};
use crate::usage::Usage;

const TO_REPLICATE: &str = "a Replicate prediction's input";

/// How a stop list is written in a model's input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stop {
    /// `stop_sequences`, one string, comma separated (Meta's Llama models).
    Comma,
    /// `stop`, a list of strings (IBM Granite).
    List,
    /// The schema has no stop field.
    None,
}

/// The input fields a family of language models on Replicate takes besides `prompt`, by its owner, as their schemas
/// on replicate.com name them (checked 2026-11-14 on meta/meta-llama-3-70b-instruct, meta/meta-llama-3-8b-instruct,
/// ibm-granite/granite-3.3-8b-instruct, anthropic/claude-4.5-sonnet, google/gemini-2.5-flash and openai/gpt-4o-mini).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fields {
    system: &'static str,
    max_tokens: &'static str,
    /// `temperature` and `top_p`.
    sampling: bool,
    seed: bool,
    stop: Stop,
}

impl Fields {
    /// The fields of model `id` (`owner/name`, or `owner/name:version`). An owner not listed is taken to follow
    /// Meta's Llama schema, which most community language models copy.
    pub fn of(id: &str) -> Self {
        let owner = id.split('/').next().unwrap_or_default();
        let fields = |system, max_tokens, sampling, seed, stop| Self {
            system,
            max_tokens,
            sampling,
            seed,
            stop,
        };
        match owner {
            "anthropic" => fields("system_prompt", "max_tokens", false, false, Stop::None),
            "google" => fields(
                "system_instruction",
                "max_output_tokens",
                true,
                false,
                Stop::None,
            ),
            "openai" => fields(
                "system_prompt",
                "max_completion_tokens",
                true,
                false,
                Stop::None,
            ),
            "ibm-granite" => fields("system_prompt", "max_tokens", true, true, Stop::List),
            _ => fields("system_prompt", "max_tokens", true, true, Stop::Comma),
        }
    }
}

/// A chat completions request as a prediction body: `{"input": {...}}`, with `version` when `id` pins one
/// (`owner/name:version`), and `"stream": true` when the request streams.
pub fn openai_to_prediction(request: &Value, id: &str) -> Result<Value> {
    let fields = object(request, "The request body")?;
    let model = Fields::of(id);
    let target = format!(
        "the input of {} on Replicate",
        id.split(':').next().unwrap_or(id)
    );
    let refuse = |key: &str, value: &Value| untranslatable(&describe(key, value), &target);
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
                insert(&mut input, model.max_tokens, value.clone())
            }
            "temperature" | "top_p" if model.sampling => insert(&mut input, key, value.clone()),
            "seed" if model.seed => insert(&mut input, key, value.clone()),
            "stop" if model.stop != Stop::None => {
                let all: Vec<&str> = match value {
                    Value::Array(all) => all.iter().filter_map(Value::as_str).collect(),
                    Value::String(one) => vec![one.as_str()],
                    _ => return refuse(key, value),
                };
                match model.stop {
                    Stop::Comma => insert(&mut input, "stop_sequences", all.join(",").into()),
                    _ => insert(&mut input, "stop", json!(all)),
                }
            }
            _ => return refuse(key, value),
        }
    }
    if transcript.is_empty() {
        return fail("The request has no user message. Send at least one.".into());
    }
    transcript.push_str("Assistant:");
    input.insert("prompt".into(), transcript.into());
    if !system.is_empty() {
        input.insert(model.system.into(), system.join("\n").into());
    }
    let mut body = json!({ "input": input });
    if let Some((_, version)) = id.split_once(':') {
        body["version"] = version.into();
    }
    if request["stream"] == true {
        body["stream"] = true.into();
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

/// A prediction's server-sent events (`event: output|error|done`, `data: ...`) as chat completions chunks. The text
/// of an `output` event is the next piece of the answer; its data lines are joined with newlines, as the SSE format
/// says. The finish, the usage (from the prediction's `metrics`, read once the stream is done) and `[DONE]` come from
/// [`PredictionStream::finish`].
#[derive(Debug, Default)]
pub struct PredictionStream {
    id: String,
    model: String,
    created: u64,
    line: Vec<u8>,
    event: String,
    data: Vec<String>,
    started: bool,
    /// The prediction ended with an error or was cancelled: why.
    failed: Option<String>,
    done: bool,
}

impl PredictionStream {
    pub fn new(prediction_id: &str, model: &str, created: u64) -> Self {
        Self {
            id: format!("chatcmpl-{prediction_id}"),
            model: model.to_string(),
            created,
            ..Self::default()
        }
    }

    /// Whether the `done` event has come.
    pub fn done(&self) -> bool {
        self.done
    }

    fn chunk(&self, choices: Value) -> Value {
        json!({"id": self.id, "object": "chat.completion.chunk", "created": self.created, "model": self.model, "choices": choices})
    }

    /// The chunks for the next bytes of the stream, split anywhere.
    pub fn feed(&mut self, mut bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(end) = bytes.iter().position(|&b| b == b'\n') {
            self.line.extend_from_slice(&bytes[..end]);
            bytes = &bytes[end + 1..];
            let line = std::mem::take(&mut self.line);
            self.on_line(&line, &mut out);
        }
        self.line.extend_from_slice(bytes);
        out
    }

    fn on_line(&mut self, line: &[u8], out: &mut Vec<u8>) {
        let line = String::from_utf8_lossy(line.strip_suffix(b"\r").unwrap_or(line)).into_owned();
        if line.is_empty() {
            self.dispatch(out);
        } else if let Some(name) = line.strip_prefix("event:") {
            self.event = name.trim().to_string();
        } else if let Some(data) = line.strip_prefix("data:") {
            self.data
                .push(data.strip_prefix(' ').unwrap_or(data).to_string());
        }
    }

    fn dispatch(&mut self, out: &mut Vec<u8>) {
        let event = std::mem::take(&mut self.event);
        let data = std::mem::take(&mut self.data).join("\n");
        match event.as_str() {
            "output" if !self.done => {
                let mut delta = json!({"content": data});
                if !self.started {
                    delta["role"] = "assistant".into();
                    self.started = true;
                }
                let chunk =
                    self.chunk(json!([{"index": 0, "delta": delta, "finish_reason": null}]));
                write_event(out, &chunk);
            }
            "error" => {
                let detail: Value = serde_json::from_str(&data).unwrap_or(Value::String(data));
                self.failed = Some(
                    detail["detail"]
                        .as_str()
                        .map_or_else(|| detail.to_string(), String::from),
                );
            }
            "done" => {
                let reason: Value = serde_json::from_str(&data).unwrap_or_default();
                if let (None, Some(why)) = (&self.failed, reason["reason"].as_str()) {
                    self.failed = Some(format!("the prediction ended: {why}"));
                }
                self.done = true;
            }
            _ => {}
        }
    }

    /// The end of the stream: an error event if the prediction failed, else the finish; the usage when `usage` is
    /// known (always written, so the gateway meters it; the gateway drops it for a client that did not ask); and
    /// `[DONE]`.
    pub fn finish(&mut self, usage: Option<Usage>) -> Vec<u8> {
        let mut out = Vec::new();
        let line = std::mem::take(&mut self.line);
        self.on_line(&line, &mut out);
        self.dispatch(&mut out);
        match (&self.failed, self.done) {
            (Some(why), _) => write_event(
                &mut out,
                &json!({"error": {"message": format!("Replicate: {why}"), "type": "upstream_failed"}}),
            ),
            (None, false) => write_event(
                &mut out,
                &json!({"error": {"message": "Replicate's stream ended before the prediction was done. Try again.", "type": "upstream_failed"}}),
            ),
            (None, true) => {
                write_event(
                    &mut out,
                    &self.chunk(json!([{"index": 0, "delta": {}, "finish_reason": "stop"}])),
                );
                if let Some(usage) = usage {
                    let mut last = self.chunk(json!([]));
                    last["usage"] = openai_usage(&usage);
                    write_event(&mut out, &last);
                }
            }
        }
        out.extend_from_slice(b"data: [DONE]\n\n");
        out
    }
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
    fn each_model_family_gets_the_fields_its_schema_names() -> TestResult {
        let request = json!({"model": "m", "max_tokens": 50, "temperature": 0.2, "stream": true,
            "messages": [{"role": "system", "content": "Be brief."}, {"role": "user", "content": "Hi"}]});
        let gemini = openai_to_prediction(&request, "google/gemini-2.5-flash")?;
        assert_eq!(
            gemini,
            json!({"stream": true, "input": {"prompt": "User: Hi\nAssistant:", "system_instruction": "Be brief.",
                "max_output_tokens": 50, "temperature": 0.2}})
        );
        let gpt = openai_to_prediction(&request, "openai/gpt-4o-mini")?;
        assert_eq!(gpt["input"]["max_completion_tokens"], 50);
        let granite = json!({"messages": [{"role": "user", "content": "Hi"}], "stop": ["END", "STOP"], "seed": 3});
        assert_eq!(
            openai_to_prediction(&granite, "ibm-granite/granite-3.3-8b-instruct")?["input"]["stop"],
            json!(["END", "STOP"])
        );
        // Claude on Replicate takes no temperature: refused by name, never dropped.
        assert!(
            openai_to_prediction(&request, "anthropic/claude-4.5-sonnet")
                .is_err_and(|e| e.to_string().contains("temperature"))
        );
        assert!(
            openai_to_prediction(&granite, "openai/gpt-4o-mini")
                .is_err_and(|e| e.to_string().contains("stop"))
        );
        Ok(())
    }

    #[test]
    fn a_prediction_stream_becomes_chat_chunks_with_usage_last() -> TestResult {
        let mut stream = PredictionStream::new("p1", "meta/llama", 9);
        let sse = "event: output\ndata: Hel\n\nevent: output\ndata: lo\ndata: there\n\nevent: done\ndata: {}\n\n";
        let (first, second) = sse.split_at(17);
        let mut out = stream.feed(first.as_bytes());
        out.extend(stream.feed(second.as_bytes()));
        assert!(stream.done());
        out.extend(stream.finish(Some(Usage {
            input: 7,
            output: 3,
            ..Usage::default()
        })));
        let text = String::from_utf8(out)?;
        assert!(text.contains("\"role\":\"assistant\""), "{text}");
        assert!(text.contains("\"content\":\"Hel\""), "{text}");
        assert!(text.contains("\"content\":\"lo\\nthere\""), "{text}");
        assert!(text.contains("\"finish_reason\":\"stop\""), "{text}");
        assert!(
            text.contains("\"completion_tokens\":3") && text.ends_with("data: [DONE]\n\n"),
            "{text}"
        );
        let mut failed = PredictionStream::new("p2", "m", 0);
        failed.feed(b"event: error\ndata: {\"detail\": \"out of memory\"}\n\nevent: done\ndata: {\"reason\": \"error\"}\n\n");
        let text = String::from_utf8(failed.finish(None))?;
        assert!(
            text.contains("out of memory") && !text.contains("finish_reason"),
            "{text}"
        );
        Ok(())
    }

    #[test]
    fn a_prediction_becomes_a_completion_and_an_unfinished_one_an_error() -> TestResult {
        let done = json!({"id": "p1", "status": "succeeded", "output": ["Hel", "lo"],
            "metrics": {"input_token_count": 7, "output_token_count": 2}});
        let answer = prediction_to_openai(&done, "meta/llama", 9)?;
        assert_eq!(answer["choices"][0]["message"]["content"], "Hello");
        assert_eq!(answer["usage"]["prompt_tokens"], 7);
        let slow = json!({"id": "p2", "status": "processing"});
        assert!(
            prediction_to_openai(&slow, "m", 0)
                .is_err_and(|e| e.to_string().contains("60 seconds"))
        );
        Ok(())
    }
}
