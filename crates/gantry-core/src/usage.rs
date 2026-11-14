//! Token usage read from a provider's answer, and what it cost, for spend tracking.
//!
//! Usage is read from a whole JSON answer of either format, or from a streamed answer of either format fed
//! in any chunk sizes. A stream is never held whole: only the line being read is kept.
//!
//! Field names as documented on 2026-11-13:
//! - Anthropic `usage`: input_tokens, output_tokens, cache_read_input_tokens, cache_creation_input_tokens and
//!   cache_creation.ephemeral_1h_input_tokens. In a stream, message_start carries the usage so far and each
//!   message_delta carries cumulative counts. <https://platform.claude.com/docs/en/api/messages/create>,
//!   <https://platform.claude.com/docs/en/build-with-claude/streaming>
//! - OpenAI `usage`: prompt_tokens (which includes cached and cache-written tokens), completion_tokens,
//!   prompt_tokens_details.cached_tokens and cache_write_tokens. A stream carries usage only in its last chunk,
//!   and only when the request set `stream_options.include_usage`.
//!   <https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create>,
//!   <https://developers.openai.com/api/docs/guides/prompt-caching>
//! - OpenAI Responses `usage`: input_tokens (which includes input_tokens_details.cached_tokens and
//!   cache_write_tokens), output_tokens. A stream carries it in the `response` of its response.completed event
//!   (response.incomplete and response.failed too).
//!   <https://developers.openai.com/api/reference/resources/responses/streaming-events>
//! - Gemini `usageMetadata`: promptTokenCount (which includes cachedContentTokenCount), candidatesTokenCount,
//!   thoughtsTokenCount (billed as output), toolUsePromptTokenCount. Every streamed chunk carries the counts so far.
//!   <https://ai.google.dev/api/generate-content>

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

/// Tokens of one answer, split by how each kind is priced.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    /// Prompt tokens at the base input price: neither read from nor written to a cache.
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    /// Prompt tokens written to a cache with the provider's short lifetime (Anthropic: 5 minutes).
    pub cache_write: u64,
    /// Prompt tokens written to Anthropic's 1 hour cache, which costs more than the 5 minute one.
    pub cache_write_1h: u64,
    /// Audio tokens, counted apart from the text ones above because audio is priced apart (realtime sessions):
    /// prompt audio, generated audio, and prompt audio read from the cache.
    pub input_audio: u64,
    pub output_audio: u64,
    pub cache_read_audio: u64,
}

impl Usage {
    /// The whole prompt, however each part was priced.
    pub fn prompt(&self) -> u64 {
        self.input
            + self.cache_read
            + self.cache_write
            + self.cache_write_1h
            + self.input_audio
            + self.cache_read_audio
    }

    /// Usage from a whole (not streamed) answer of either format. None if the body carries no usage.
    pub fn from_body(body: &[u8]) -> Option<Self> {
        let answer: Value = serde_json::from_slice(body).ok()?;
        if answer["usageMetadata"].is_object() {
            return Some(Self::from_gemini(&answer["usageMetadata"]));
        }
        let usage = &answer["usage"];
        if !usage.is_object() {
            return None;
        }
        if answer["object"] == "response" {
            return Some(Self::from_responses(usage));
        }
        if usage.get("prompt_tokens").is_some() || usage.get("completion_tokens").is_some() {
            return Some(Self::from_openai(usage));
        }
        let mut found = Self::default();
        found.merge_anthropic(usage);
        Some(found)
    }

    /// Reads an OpenAI `usage` object.
    pub fn from_openai(usage: &Value) -> Self {
        let count = |v: &Value| v.as_u64().unwrap_or_default();
        let details = &usage["prompt_tokens_details"];
        let cache_read = count(&details["cached_tokens"]);
        let cache_write = count(&details["cache_write_tokens"]);
        Self {
            // prompt_tokens includes the cached and cache-written tokens; each is priced once.
            input: count(&usage["prompt_tokens"]).saturating_sub(cache_read + cache_write),
            output: count(&usage["completion_tokens"]),
            cache_read,
            cache_write,
            cache_write_1h: 0,
            ..Self::default()
        }
    }

    /// Reads an OpenAI Responses `usage` object.
    pub fn from_responses(usage: &Value) -> Self {
        let count = |v: &Value| v.as_u64().unwrap_or_default();
        let details = &usage["input_tokens_details"];
        let cache_read = count(&details["cached_tokens"]);
        let cache_write = count(&details["cache_write_tokens"]);
        Self {
            input: count(&usage["input_tokens"]).saturating_sub(cache_read + cache_write),
            output: count(&usage["output_tokens"]),
            cache_read,
            cache_write,
            cache_write_1h: 0,
            ..Self::default()
        }
    }

    /// Reads a Gemini `usageMetadata` object.
    pub fn from_gemini(usage: &Value) -> Self {
        let count = |key: &str| usage[key].as_u64().unwrap_or_default();
        let cache_read = count("cachedContentTokenCount");
        Self {
            input: (count("promptTokenCount") + count("toolUsePromptTokenCount"))
                .saturating_sub(cache_read),
            output: count("candidatesTokenCount") + count("thoughtsTokenCount"),
            cache_read,
            cache_write: 0,
            cache_write_1h: 0,
            ..Self::default()
        }
    }

    /// Applies an Anthropic `usage` object. Fields it lacks keep their value, because a stream's message_delta
    /// may carry only some counts, and the counts it does carry are cumulative.
    pub fn merge_anthropic(&mut self, usage: &Value) {
        let count = |key: &str| usage[key].as_u64();
        if let Some(n) = count("input_tokens") {
            self.input = n;
        }
        if let Some(n) = count("output_tokens") {
            self.output = n;
        }
        if let Some(n) = count("cache_read_input_tokens") {
            self.cache_read = n;
        }
        // cache_creation_input_tokens is the total of both lifetimes; the breakdown says how much was 1 hour.
        if let Some(n) = usage["cache_creation"]["ephemeral_1h_input_tokens"].as_u64() {
            let total = self.cache_write + self.cache_write_1h;
            self.cache_write_1h = n;
            self.cache_write = total.saturating_sub(n);
        }
        if let Some(total) = count("cache_creation_input_tokens") {
            self.cache_write = total.saturating_sub(self.cache_write_1h);
        }
    }
}

/// The payload of a server-sent events `data:` line, or None for any other line.
// ponytail: one data line per event, which is what both providers send; multi-line data fields would need joining.
pub(crate) fn sse_data(line: &[u8]) -> Option<&[u8]> {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let data = line.strip_prefix(b"data:")?;
    Some(data.strip_prefix(b" ").unwrap_or(data))
}

/// Reads usage from a streamed answer of either format while the stream passes through.
#[derive(Debug, Default)]
pub struct UsageScanner {
    line: Vec<u8>,
    usage: Option<Usage>,
    /// The event that carries the answer's final counts has passed. Until then the counts are only what was
    /// generated so far, and a stream cut off before it may have cost much more than they say.
    done: bool,
    /// Bytes of streamed text (content, tool arguments, refusals, reasoning) and data events, for an estimate of
    /// the output of a stream that reports no usage.
    text_bytes: u64,
    events: u64,
    /// OpenAI's `data: [DONE]` passed: the provider finished the stream.
    finished: bool,
}

/// String fields of streamed events that hold generated text.
const TEXT_KEYS: [&[u8]; 6] = [
    b"\"content\":",
    b"\"text\":",
    b"\"arguments\":",
    b"\"refusal\":",
    b"\"reasoning_content\":",
    b"\"delta\":",
];

/// Bytes inside the string values of `TEXT_KEYS` in one event. An escape counts as its two bytes, which only adds.
fn text_bytes(data: &[u8]) -> u64 {
    let mut total = 0;
    for key in TEXT_KEYS {
        let mut rest = data;
        while let Some(at) = rest.windows(key.len()).position(|w| w == key) {
            rest = &rest[at + key.len()..];
            let skip = rest.iter().take_while(|b| b.is_ascii_whitespace()).count();
            rest = &rest[skip..];
            let Some(value) = rest.strip_prefix(b"\"") else {
                continue;
            };
            let mut i = 0;
            while i < value.len() && value[i] != b'"' {
                i += if value[i] == b'\\' { 2 } else { 1 };
            }
            let end = i.min(value.len());
            total += end as u64;
            rest = &value[end..];
        }
    }
    total
}

impl UsageScanner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds the next bytes of the stream, split anywhere.
    pub fn feed(&mut self, mut bytes: &[u8]) {
        while let Some(end) = bytes.iter().position(|&b| b == b'\n') {
            self.line.extend_from_slice(&bytes[..end]);
            bytes = &bytes[end + 1..];
            let line = std::mem::take(&mut self.line);
            self.on_line(&line);
        }
        // ponytail: one unfinished line is buffered, so a single huge event is held until its newline.
        self.line.extend_from_slice(bytes);
    }

    /// The usage the stream reported, or None if it reported none (an OpenAI stream without include_usage).
    pub fn finish(self) -> Option<Usage> {
        self.finish_final().0
    }

    /// For a stream that finished (`data: [DONE]`) without reporting usage: at most how many output tokens it
    /// streamed, one per byte of text plus one per event. A token is at least one byte of text, so this is never
    /// under what the streamed text cost.
    // ponytail: hidden reasoning tokens are not in the stream, so this under-counts a reasoning model. It is used
    // only for requests without a budget (a budgeted stream without usage is charged its reservation); asking for
    // usage (stream_options.include_usage) gives exact charges, docs/policy.md says so.
    pub fn streamed_output(&self) -> Option<u64> {
        (self.finished && self.usage.is_none()).then_some(self.text_bytes + self.events)
    }

    /// The usage, and whether the stream got as far as the event that carries its final counts.
    pub fn finish_final(mut self) -> (Option<Usage>, bool) {
        let line = std::mem::take(&mut self.line);
        self.on_line(&line);
        (self.usage, self.done)
    }

    fn on_line(&mut self, line: &[u8]) {
        let Some(data) = sse_data(line) else {
            return;
        };
        if data.trim_ascii() == b"[DONE]" {
            self.finished = true;
            return;
        }
        self.events += 1;
        self.text_bytes += text_bytes(data);
        // Anthropic's last counts may come in more than one message_delta; message_stop says there are no more.
        if data.windows(14).any(|w| w == b"\"message_stop\"") {
            self.done = true;
            return;
        }
        // Most events carry text, not usage, and need no parsing. A quoted key cannot occur inside a JSON
        // string, where quotes are escaped, so this never skips a line that holds usage.
        if !data.windows(7).any(|w| w == b"\"usage\"")
            && !data.windows(15).any(|w| w == b"\"usageMetadata\"")
        {
            return;
        }
        let Ok(event) = serde_json::from_slice::<Value>(data) else {
            return;
        };
        if event["usageMetadata"].is_object() {
            // Gemini: each chunk carries the counts so far, so the last one holds the total. The last one is the
            // one that says why the answer stopped.
            self.usage = Some(Usage::from_gemini(&event["usageMetadata"]));
            let stopped = event["candidates"]
                .as_array()
                .is_some_and(|all| all.iter().any(|c| !c["finishReason"].is_null()));
            self.done |= stopped || !event["promptFeedback"]["blockReason"].is_null();
            return;
        }
        match event["type"].as_str() {
            Some(kind) if kind.starts_with("response.") => {
                // Only the events that end a response (completed, incomplete, failed) carry its usage.
                if event["response"]["usage"].is_object() {
                    self.usage = Some(Usage::from_responses(&event["response"]["usage"]));
                    self.done = true;
                }
            }
            // message_start carries the prompt and the first output token only.
            Some("message_start") => self
                .usage
                .get_or_insert_default()
                .merge_anthropic(&event["message"]["usage"]),
            Some("message_delta") => self
                .usage
                .get_or_insert_default()
                .merge_anthropic(&event["usage"]),
            // OpenAI sends usage once, in the last chunk.
            _ if event["usage"].is_object() => {
                self.usage = Some(Usage::from_openai(&event["usage"]));
                self.done = true;
            }
            _ => {}
        }
    }
}

/// Prices in US dollars per million tokens, for one model. The policy file sets these by model name in a
/// [`PriceOverrides`] map; a price it does not set comes from [`builtin_prices`].
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Price {
    pub input: f64,
    pub output: f64,
    /// Defaults to the input price.
    #[serde(default)]
    pub cache_read: Option<f64>,
    /// Defaults to the input price.
    #[serde(default)]
    pub cache_write: Option<f64>,
    /// Defaults to the cache write price.
    #[serde(default)]
    pub cache_write_1h: Option<f64>,
    /// Other prices for a request whose prompt is longer than a threshold.
    #[serde(default)]
    pub long_context: Option<Box<LongContext>>,
    /// The most output tokens the model writes in one answer: what a budget reserves for a request that does not
    /// say how many it wants. Not a price, kept here because it is set per model beside the prices.
    #[serde(default)]
    pub max_output: Option<u64>,
    /// The most tokens of context the model reads in one request: what a budget reserves for a Responses request
    /// that names stored context (previous_response_id, conversation, prompt), which the body does not hold.
    #[serde(default)]
    pub max_context: Option<u64>,
    /// US dollars per image, for an image model billed by the image rather than by the token. An images request is
    /// charged this for each image the answer holds, and reserves it for each image it asks for.
    #[serde(default)]
    pub per_image: Option<f64>,
    /// Audio tokens, per million: prompt audio, generated audio, and cached prompt audio. Each defaults to the text
    /// price of the same kind, which under-counts audio on most models: set them for a realtime model.
    #[serde(default)]
    pub input_audio: Option<f64>,
    #[serde(default)]
    pub output_audio: Option<f64>,
    #[serde(default)]
    pub cache_read_audio: Option<f64>,
    /// The batch API's own prices, per million: a batch line is charged these where they are set, and half the
    /// price above where they are not.
    #[serde(default)]
    pub batch_input: Option<f64>,
    #[serde(default)]
    pub batch_output: Option<f64>,
    #[serde(default)]
    pub batch_cache_read: Option<f64>,
    /// Where the price came from, written in each usage record. Never read from a file: a price in one is the policy's.
    #[serde(skip)]
    pub source: PriceSource,
}

/// Where a price came from: the policy file, Gantry's own table, or the table generated from LiteLLM's price map.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PriceSource {
    #[default]
    Policy,
    Builtin,
    Litellm,
}

impl PriceSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Builtin => "builtin",
            Self::Litellm => "litellm",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LongContext {
    /// A prompt of more than this many tokens, cache reads and writes included, pays `price`.
    pub above_prompt_tokens: u64,
    pub price: Price,
}

/// Prices the policy file sets, by exact model name.
pub type PriceOverrides = BTreeMap<String, Price>;

impl Price {
    fn per_mtok(
        input: f64,
        output: f64,
        cache_read: f64,
        cache_write: f64,
        cache_write_1h: f64,
        max_output: u64,
    ) -> Self {
        Self {
            input,
            output,
            cache_read: Some(cache_read),
            cache_write: Some(cache_write),
            cache_write_1h: Some(cache_write_1h),
            long_context: None,
            max_output: Some(max_output),
            max_context: None,
            per_image: None,
            input_audio: None,
            output_audio: None,
            cache_read_audio: None,
            batch_input: None,
            batch_output: None,
            batch_cache_read: None,
            source: PriceSource::Builtin,
        }
    }

    /// The price a batch line pays, and the share of it charged: the batch prices where both are set (share 1),
    /// else this price at `half` (OpenAI, Anthropic, Bedrock and Vertex AI bill batches at half price).
    pub fn for_batch(&self, half: f64) -> (Self, f64) {
        match (self.batch_input, self.batch_output) {
            (Some(input), Some(output)) => {
                // What the map does not price for batches keeps the ratio of the batch input price to the input price.
                let ratio = if self.input > 0.0 {
                    input / self.input
                } else {
                    half
                };
                let out_ratio = if self.output > 0.0 {
                    output / self.output
                } else {
                    half
                };
                let scaled = |p: Option<f64>| p.map(|p| p * ratio);
                let price = Self {
                    input,
                    output,
                    cache_read: self.batch_cache_read.or(scaled(self.cache_read)),
                    cache_write: scaled(self.cache_write),
                    cache_write_1h: scaled(self.cache_write_1h),
                    // ponytail: no long context tier for batches; the map prices few, add it when one matters.
                    long_context: None,
                    input_audio: scaled(self.input_audio),
                    output_audio: self.output_audio.map(|p| p * out_ratio),
                    cache_read_audio: scaled(self.cache_read_audio),
                    ..self.clone()
                };
                (price, 1.0)
            }
            _ => (self.clone(), half),
        }
    }

    /// What the usage cost, in US dollars.
    pub fn cost_usd(&self, usage: &Usage) -> f64 {
        let p = match &self.long_context {
            Some(long) if usage.prompt() > long.above_prompt_tokens => &long.price,
            _ => self,
        };
        let cache_write = p.cache_write.unwrap_or(p.input);
        let dollars_per_mtok = usage.input as f64 * p.input
            + usage.output as f64 * p.output
            + usage.cache_read as f64 * p.cache_read.unwrap_or(p.input)
            + usage.cache_write as f64 * cache_write
            + usage.cache_write_1h as f64 * p.cache_write_1h.unwrap_or(cache_write)
            + usage.input_audio as f64 * p.input_audio.unwrap_or(p.input)
            + usage.output_audio as f64 * p.output_audio.unwrap_or(p.output)
            + usage.cache_read_audio as f64
                * p.cache_read_audio.or(p.cache_read).unwrap_or(p.input);
        dollars_per_mtok / 1_000_000.0
    }

    /// Refuses a price that would let spend be under-counted or not counted at all.
    pub fn check(&self, model: &str) -> Result<(), String> {
        let all = [
            Some(self.input),
            Some(self.output),
            self.cache_read,
            self.cache_write,
            self.cache_write_1h,
            self.per_image,
            self.input_audio,
            self.output_audio,
            self.cache_read_audio,
            self.batch_input,
            self.batch_output,
            self.batch_cache_read,
        ];
        if all.into_iter().flatten().any(|p| !p.is_finite() || p < 0.0) {
            return Err(format!(
                "The price of model \"{model}\" has a negative or non-numeric value. Give every price as US dollars per million tokens, 0 or more."
            ));
        }
        if self.max_output == Some(0) {
            return Err(format!(
                "The price of model \"{model}\" sets max_output to 0. Give the most output tokens the model writes in one answer, for example max_output: 16384, or remove the line."
            ));
        }
        match &self.long_context {
            Some(long) => long.price.check(model),
            None => Ok(()),
        }
    }
}

/// One entry of the built-in price table, with where the price was read and when.
#[derive(Clone, Debug, PartialEq)]
pub struct BuiltinPrice {
    pub model: &'static str,
    pub price: Price,
    pub source: &'static str,
    pub checked: &'static str,
}

const ANTHROPIC_PRICES: &str = "https://platform.claude.com/docs/en/about-claude/pricing";
const OPENAI_PRICES: &str = "https://developers.openai.com/api/docs/pricing";

/// Prices of the models named in the README and specs. Standard tier, global routing.
pub fn builtin_prices() -> Vec<BuiltinPrice> {
    let checked = "2026-11-13";
    // OpenAI charges nothing extra to write its cache on these models, so writes cost the input price.
    vec![
        BuiltinPrice {
            model: "gpt-4o-mini",
            price: Price::per_mtok(0.15, 0.60, 0.075, 0.15, 0.15, 16_384),
            source: OPENAI_PRICES,
            checked,
        },
        BuiltinPrice {
            model: "gpt-4o",
            price: Price::per_mtok(2.50, 10.00, 1.25, 2.50, 2.50, 16_384),
            source: OPENAI_PRICES,
            checked,
        },
        BuiltinPrice {
            model: "claude-sonnet-5-5",
            price: Price::per_mtok(2.00, 10.00, 0.10, 2.50, 4.00, 64_000),
            source: ANTHROPIC_PRICES,
            checked,
        },
        BuiltinPrice {
            model: "claude-haiku-5-5",
            price: Price {
                long_context: Some(Box::new(LongContext {
                    above_prompt_tokens: 100_000,
                    price: Price::per_mtok(0.50, 2.50, 0.05, 0.625, 1.00, 64_000),
                })),
                ..Price::per_mtok(0.10, 0.50, 0.01, 0.125, 0.20, 64_000)
            },
            source: ANTHROPIC_PRICES,
            checked,
        },
    ]
}

/// The price table generated by scripts/prices.py from LiteLLM's price map (MIT, see data/LICENSE-litellm-prices).
const LITELLM_TSV: &str = include_str!("../data/litellm-prices.tsv");

/// The URL and the day the LiteLLM price table was read, from its header.
pub fn litellm_prices_origin() -> (&'static str, &'static str) {
    let header = |name: &str| {
        LITELLM_TSV
            .lines()
            .find_map(|line| {
                line.strip_prefix("# ")?
                    .strip_prefix(name)?
                    .strip_prefix('\t')
            })
            .unwrap_or("unknown")
    };
    (header("source"), header("date"))
}

/// Reads one row of the LiteLLM table; `None` for a row that does not hold a whole price.
fn litellm_row(line: &'static str) -> Option<(&'static str, Price)> {
    let cells: Vec<&str> = line.split('\t').collect();
    let [
        model,
        input,
        output,
        read,
        write,
        write_1h,
        image,
        max_out,
        max_ctx,
        above,
        l_in,
        l_out,
        l_read,
        l_write,
        a_in,
        a_out,
        a_read,
        b_in,
        b_out,
        b_read,
    ] = cells[..]
    else {
        return None;
    };
    let float = |cell: &str| cell.parse::<f64>().ok();
    let whole = |cell: &str| cell.parse::<u64>().ok();
    let base = |input: &str, output: &str, read: &str, write: &str| -> Option<Price> {
        Some(Price {
            input: input.parse().ok()?,
            output: output.parse().ok()?,
            cache_read: float(read),
            cache_write: float(write),
            cache_write_1h: None,
            long_context: None,
            max_output: whole(max_out),
            max_context: None,
            per_image: None,
            input_audio: None,
            output_audio: None,
            cache_read_audio: None,
            batch_input: None,
            batch_output: None,
            batch_cache_read: None,
            source: PriceSource::Litellm,
        })
    };
    let mut price = base(input, output, read, write)?;
    price.cache_write_1h = float(write_1h);
    price.per_image = float(image);
    price.max_context = whole(max_ctx);
    price.input_audio = float(a_in);
    price.output_audio = float(a_out);
    price.cache_read_audio = float(a_read);
    price.batch_input = float(b_in);
    price.batch_output = float(b_out);
    price.batch_cache_read = float(b_read);
    if let Some(above) = whole(above) {
        price.long_context = Some(Box::new(LongContext {
            above_prompt_tokens: above,
            price: base(l_in, l_out, l_read, l_write)?,
        }));
    }
    Some((model, price))
}

/// Every model of the LiteLLM table, by exact name. Built once, on first use.
pub fn litellm_prices() -> &'static std::collections::HashMap<&'static str, Price> {
    static TABLE: std::sync::LazyLock<std::collections::HashMap<&'static str, Price>> =
        std::sync::LazyLock::new(|| {
            LITELLM_TSV
                .lines()
                .filter(|line| !line.starts_with('#') && !line.starts_with("model\t"))
                .filter_map(litellm_row)
                .collect()
        });
    &TABLE
}

/// The price of a model: the policy file's if it sets one, else Gantry's own built-in one, else the one from the
/// LiteLLM table, else None. Each says where it came from in `source`.
pub fn price_for(model: &str, overrides: &PriceOverrides) -> Option<Price> {
    overrides.get(model).cloned().or_else(|| {
        // Looked up on every admitted request, so the table is built once.
        static BUILTIN: std::sync::LazyLock<Vec<BuiltinPrice>> =
            std::sync::LazyLock::new(builtin_prices);
        BUILTIN
            .iter()
            .find(|entry| entry.model == model)
            .map(|entry| entry.price.clone())
            .or_else(|| litellm_prices().get(model).cloned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-12
    }

    /// Feeds a stream in pieces of every size from 1 to its length and checks each gives the same usage.
    fn scan_all_splits(stream: &str) -> Option<Usage> {
        let bytes = stream.as_bytes();
        let whole = {
            let mut s = UsageScanner::new();
            s.feed(bytes);
            s.finish()
        };
        for size in 1..=bytes.len() {
            let mut s = UsageScanner::new();
            for piece in bytes.chunks(size) {
                s.feed(piece);
            }
            assert_eq!(s.finish(), whole, "split size {size}");
        }
        whole
    }

    #[test]
    fn anthropic_body_usage_splits_cache_writes_by_lifetime() {
        let body = br#"{"id":"msg_1","type":"message","usage":{"input_tokens":2095,"output_tokens":503,"cache_read_input_tokens":2051,"cache_creation_input_tokens":2051,"cache_creation":{"ephemeral_5m_input_tokens":2000,"ephemeral_1h_input_tokens":51}}}"#;
        assert_eq!(
            Usage::from_body(body),
            Some(Usage {
                input: 2095,
                output: 503,
                cache_read: 2051,
                cache_write: 2000,
                cache_write_1h: 51,
                ..Usage::default()
            })
        );
    }

    #[test]
    fn openai_body_usage_takes_cached_tokens_out_of_the_prompt() {
        let body = br#"{"id":"c","object":"chat.completion","usage":{"prompt_tokens":1200,"completion_tokens":30,"total_tokens":1230,"prompt_tokens_details":{"cached_tokens":1000,"cache_write_tokens":150}}}"#;
        let usage = Usage::from_body(body);
        assert_eq!(
            usage,
            Some(Usage {
                input: 50,
                output: 30,
                cache_read: 1000,
                cache_write: 150,
                cache_write_1h: 0,
                ..Usage::default()
            })
        );
        assert_eq!(usage.map(|u| u.prompt()), Some(1200));
    }

    #[test]
    fn a_body_without_usage_has_none() {
        assert_eq!(
            Usage::from_body(br#"{"error":{"type":"overloaded_error"}}"#),
            None
        );
        assert_eq!(Usage::from_body(b"not json"), None);
    }

    #[test]
    fn anthropic_stream_usage_in_any_split() {
        // Text that mentions "usage" in quotes must not confuse the scanner. message_delta counts are cumulative.
        let stream = concat!(
            "event: message_start\r\n",
            "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"usage\":{\"input_tokens\":472,\"cache_read_input_tokens\":100,\"cache_creation_input_tokens\":20,\"output_tokens\":2}}}\r\n\r\n",
            "event: ping\n",
            "data: {\"type\": \"ping\"}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"the \\\"usage\\\": 9 caf\u{e9}\"}}\n\n",
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":40}}\n\n",
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"delta\":{},\"usage\":{\"output_tokens\":89,\"input_tokens\":480}}\n\n",
            "event: message_stop\n",
            "data: {\"type\":\"message_stop\"}\n\n",
        );
        assert_eq!(
            scan_all_splits(stream),
            Some(Usage {
                input: 480,
                output: 89,
                cache_read: 100,
                cache_write: 20,
                cache_write_1h: 0,
                ..Usage::default()
            })
        );
    }

    #[test]
    fn openai_stream_usage_comes_from_the_last_chunk() {
        let stream = concat!(
            "data: {\"id\":\"c\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}],\"usage\":null}\n\n",
            "data: {\"id\":\"c\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"total_tokens\":15,\"prompt_tokens_details\":{\"cached_tokens\":4}}}\n\n",
            "data: [DONE]\n\n",
        );
        assert_eq!(
            scan_all_splits(stream),
            Some(Usage {
                input: 6,
                output: 5,
                cache_read: 4,
                cache_write: 0,
                cache_write_1h: 0,
                ..Usage::default()
            })
        );
    }

    /// Usage and whether the final counts were seen, for a stream fed whole.
    fn scan_final(stream: &str) -> (Option<Usage>, bool) {
        let mut s = UsageScanner::new();
        s.feed(stream.as_bytes());
        s.finish_final()
    }

    #[test]
    fn a_stream_is_final_only_after_the_event_that_ends_it() {
        let anthropic_start = "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":9,\"output_tokens\":1}}}\n\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n";
        let anthropic_delta =
            "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":40}}\n\n";
        assert!(!scan_final(anthropic_start).1);
        assert!(!scan_final(&format!("{anthropic_start}{anthropic_delta}")).1);
        let whole =
            format!("{anthropic_start}{anthropic_delta}data: {{\"type\":\"message_stop\"}}\n\n");
        assert!(scan_final(&whole).1);
        // Text that quotes the word cannot end a stream: inside a JSON string its quotes are escaped.
        let quoted = "data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"\\\"message_stop\\\"\"}}\n\n";
        assert!(!scan_final(quoted).1);

        let openai = "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}],\"usage\":null}\n\n";
        assert!(!scan_final(openai).1);
        let usage =
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":2}}\n\n";
        assert!(scan_final(&format!("{openai}{usage}")).1);

        let created = "data: {\"type\":\"response.created\",\"response\":{\"usage\":null}}\n\n";
        assert!(!scan_final(created).1);
        let completed = "data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":1,\"output_tokens\":2}}}\n\n";
        assert!(scan_final(&format!("{created}{completed}")).1);

        let gemini = "data: {\"candidates\":[{\"content\":{}}],\"usageMetadata\":{\"promptTokenCount\":3,\"candidatesTokenCount\":1}}\n\n";
        assert!(!scan_final(gemini).1);
        let last = "data: {\"candidates\":[{\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":3,\"candidatesTokenCount\":9}}\n\n";
        assert!(scan_final(&format!("{gemini}{last}")).1);
    }

    #[test]
    fn an_openai_stream_without_include_usage_reports_none() {
        let stream = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n";
        assert_eq!(scan_all_splits(stream), None);
    }

    #[test]
    fn responses_and_gemini_usage_whole_and_streamed() {
        let responses = br#"{"object":"response","usage":{"input_tokens":100,"input_tokens_details":{"cached_tokens":40},"output_tokens":7,"total_tokens":107}}"#;
        let expected = Usage {
            input: 60,
            output: 7,
            cache_read: 40,
            ..Usage::default()
        };
        assert_eq!(Usage::from_body(responses), Some(expected));
        let stream = "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"usage\":null}}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":100,\"input_tokens_details\":{\"cached_tokens\":40},\"output_tokens\":7}}}\n\n";
        assert_eq!(scan_all_splits(stream), Some(expected));

        let gemini = br#"{"candidates":[],"usageMetadata":{"promptTokenCount":12,"cachedContentTokenCount":2,"candidatesTokenCount":5,"thoughtsTokenCount":3,"totalTokenCount":20}}"#;
        let expected = Usage {
            input: 10,
            output: 8,
            cache_read: 2,
            ..Usage::default()
        };
        assert_eq!(Usage::from_body(gemini), Some(expected));
        let stream = "data: {\"candidates\":[],\"usageMetadata\":{\"promptTokenCount\":12,\"candidatesTokenCount\":1}}\r\n\r\ndata: {\"candidates\":[],\"usageMetadata\":{\"promptTokenCount\":12,\"cachedContentTokenCount\":2,\"candidatesTokenCount\":5,\"thoughtsTokenCount\":3}}\r\n\r\n";
        assert_eq!(scan_all_splits(stream), Some(expected));
        // An embeddings answer reads as OpenAI usage.
        assert_eq!(
            Usage::from_body(br#"{"object":"list","usage":{"prompt_tokens":8,"total_tokens":8}}"#)
                .map(|u| (u.input, u.output)),
            Some((8, 0))
        );
    }

    #[test]
    fn cost_uses_every_price() -> TestResult {
        let price = price_for("claude-sonnet-5-5", &PriceOverrides::new()).ok_or("no price")?;
        let usage = Usage {
            input: 1_000_000,
            output: 100_000,
            cache_read: 2_000_000,
            cache_write: 400_000,
            cache_write_1h: 250_000,
            ..Usage::default()
        };
        // 2.00 + 1.00 + 0.20 + 1.00 + 1.00
        assert!(
            close(price.cost_usd(&usage), 5.20),
            "{}",
            price.cost_usd(&usage)
        );
        Ok(())
    }

    #[test]
    fn a_long_prompt_pays_the_long_context_price() -> TestResult {
        let price = price_for("claude-haiku-5-5", &PriceOverrides::new()).ok_or("no price")?;
        let short = Usage {
            input: 50_000,
            cache_read: 50_000,
            output: 1_000_000,
            ..Usage::default()
        };
        assert!(close(price.cost_usd(&short), 0.005 + 0.0005 + 0.50));
        // One token more and every token of the request pays the higher price, cache reads included.
        let long = Usage {
            input: 50_001,
            ..short
        };
        assert!(close(price.cost_usd(&long), 0.0250005 + 0.0025 + 2.50));
        Ok(())
    }

    #[test]
    fn the_policy_file_overrides_a_price_and_unset_cache_prices_fall_back() -> TestResult {
        let overrides: PriceOverrides = crate::config::from_yaml(
            "gpt-4o-mini:\n  input: 1\n  output: 2\nmy-local-model:\n  input: 0\n  output: 0\n  long_context:\n    above_prompt_tokens: 10\n    price: { input: 3, output: 4 }\n",
        )?;
        let mini = price_for("gpt-4o-mini", &overrides).ok_or("no price")?;
        let usage = Usage {
            input: 1_000_000,
            output: 1_000_000,
            cache_read: 1_000_000,
            cache_write: 1_000_000,
            cache_write_1h: 1_000_000,
            ..Usage::default()
        };
        assert!(close(mini.cost_usd(&usage), 1.0 + 2.0 + 1.0 + 1.0 + 1.0));
        let local = price_for("my-local-model", &overrides).ok_or("no price")?;
        assert!(close(
            local.cost_usd(&Usage {
                input: 11,
                ..Usage::default()
            }),
            33.0 / 1e6
        ));
        assert!(price_for("claude-haiku-5-5", &overrides).is_some());
        assert_eq!(price_for("unknown-model", &overrides), None);
        Ok(())
    }

    #[test]
    fn a_price_with_an_unknown_field_or_a_negative_value_is_refused() -> TestResult {
        assert!(
            crate::config::from_yaml::<PriceOverrides>(
                "m:\n  input: 1\n  output: 1\n  cached: 1\n"
            )
            .is_err()
        );
        let negative: PriceOverrides = crate::config::from_yaml(
            "m:\n  input: 1\n  output: 1\n  long_context: { above_prompt_tokens: 1, price: { input: -1, output: 1 } }\n",
        )?;
        let err = negative.get("m").ok_or("no m")?.check("m");
        assert!(err.is_err_and(|e| e.contains("\"m\"") && e.contains("0 or more")));
        Ok(())
    }

    #[test]
    fn every_builtin_price_has_a_source_and_a_date_and_passes_its_check() {
        for entry in builtin_prices() {
            assert!(entry.source.starts_with("https://"), "{}", entry.model);
            assert_eq!(entry.checked.len(), 10, "{}", entry.model);
            assert_eq!(entry.price.check(entry.model), Ok(()));
        }
    }

    #[test]
    fn every_row_of_the_litellm_table_loads_and_passes_its_check() {
        let rows = LITELLM_TSV
            .lines()
            .filter(|line| !line.starts_with('#') && !line.starts_with("model\t"))
            .count();
        let table = litellm_prices();
        // A row that does not parse would leave its model unpriced without a word.
        assert_eq!(table.len(), rows);
        assert!(rows > 1000, "{rows}");
        for (model, price) in table {
            assert_eq!(price.check(model), Ok(()));
            assert_eq!(price.source, PriceSource::Litellm);
        }
        let (url, date) = litellm_prices_origin();
        assert!(url.starts_with("https://raw.githubusercontent.com/BerriAI/litellm/"));
        assert_eq!(date.len(), 10);
    }

    #[test]
    fn a_price_comes_from_the_policy_then_gantry_then_litellm() -> TestResult {
        let overrides: PriceOverrides =
            crate::config::from_yaml("gpt-4o:\n  input: 1\n  output: 2\n")?;
        let policy = price_for("gpt-4o", &overrides).ok_or("no price")?;
        assert_eq!((policy.input, policy.source), (1.0, PriceSource::Policy));
        let own = price_for("claude-haiku-5-5", &overrides).ok_or("no price")?;
        assert_eq!(own.source, PriceSource::Builtin);
        // Claude Code's Opus, a Gemini model and an embeddings model, none in Gantry's own table.
        for model in [
            "claude-opus-4-5",
            "gemini-2.5-pro",
            "text-embedding-3-small",
        ] {
            let price = price_for(model, &overrides).ok_or(model)?;
            assert_eq!(price.source, PriceSource::Litellm, "{model}");
            assert!(
                price.input > 0.0 && price.max_output.is_some_and(|m| m > 0)
                    || model.starts_with("text-"),
                "{model}"
            );
        }
        let opus = price_for("claude-opus-4-5", &overrides).ok_or("no price")?;
        let usage = Usage {
            input: 1_000_000,
            output: 1_000_000,
            ..Usage::default()
        };
        assert!(close(opus.cost_usd(&usage), opus.input + opus.output));
        // A long prompt pays the table's long context tier.
        let gemini = price_for("gemini-2.5-pro", &overrides).ok_or("no price")?;
        let long = gemini.long_context.as_ref().ok_or("no long context tier")?;
        assert!(long.price.input > gemini.input);
        // A bare name is found for a model the map lists under a provider prefix only.
        assert!(litellm_prices().keys().any(|m| m.contains('/')));
        assert_eq!(price_for("no-such-model-anywhere", &overrides), None);
        Ok(())
    }
}
