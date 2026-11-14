//! Guardrails: checks on the text Gantry is about to send to a provider.
//!
//! Built-in detectors (`secrets`, `pii`) run here, in process. A `webhook` guardrail asks an outside service;
//! this module defines what Gantry sends it and what it accepts back, and the server makes the call.
//! The contract for outside services is written down in docs/guardrail-webhook.md.
//!
//! A finding names its detector, its kind and the JSON path of the text it is in. It never carries the
//! matched text, so nothing that is logged or audited can leak what the guardrail was there to stop.

use std::{borrow::Cow, collections::BTreeMap, ops::Range, sync::OnceLock, time::Duration};

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use crate::vendors::Vendor;

/// The refusal code the server returns when a guardrail blocks a request.
pub const BLOCKED_CODE: &str = "guardrail_blocked";

/// The longest private key block masked as one span. A header with no end line within it is masked alone.
const KEY_BLOCK_LIMIT: usize = 16 * 1024;

// ---------------------------------------------------------------------------------------------------------
// Policy file shape
// ---------------------------------------------------------------------------------------------------------

/// What a guardrail does with what it finds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Refuse the request.
    Block,
    /// Replace each finding with a placeholder and forward the changed request.
    Mask,
    /// Forward the request unchanged and record the findings.
    Warn,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardType {
    Secrets,
    Pii,
    /// The policy's own regular expressions.
    Regex,
    /// The policy's own word and phrase lists.
    Keywords,
    Webhook,
    OpenaiModeration,
    Presidio,
    Lakera,
    BedrockGuardrail,
    AzureContentSafety,
    AzurePromptShield,
    LlamaGuard,
    ModelArmor,
}

/// Which text a guardrail reads, as written in `on:`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    /// The caller's request, before it is recorded and sent. The default.
    Request,
    /// The provider's whole (not streamed) answer, before it reaches the caller.
    Answer,
}

/// Where a guardrail runs. Without `on:` it runs on requests only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct On {
    pub request: bool,
    pub answer: bool,
}

impl On {
    pub const REQUEST: On = On {
        request: true,
        answer: false,
    };

    fn has(self, side: Side) -> bool {
        match side {
            Side::Request => self.request,
            Side::Answer => self.answer,
        }
    }
}

impl Default for On {
    fn default() -> Self {
        On::REQUEST
    }
}

/// What a webhook guardrail does when the service cannot give a usable answer in time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnFailure {
    /// Refuse the request: nothing goes out unchecked.
    FailClosed,
    /// Forward the request and record that the check did not run.
    FailOpen,
}

/// One entry of the top-level `guardrails:` list, as written in the policy file.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardrailFile {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: GuardType,
    #[serde(default)]
    pub action: Option<Action>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub on_failure: Option<OnFailure>,
    /// Header name to the environment variable that holds its value, for a service that wants a credential.
    #[serde(default)]
    pub headers_env: Option<std::collections::BTreeMap<String, String>>,
    /// The environment variable that holds a vendor's API key.
    #[serde(default)]
    pub key_env: Option<String>,
    /// openai_moderation and llama_guard: the model that checks.
    #[serde(default)]
    pub model: Option<String>,
    /// llama_guard: a classifier prompt with {conversation} in it.
    #[serde(default)]
    pub prompt: Option<String>,
    /// bedrock_guardrail.
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub guardrail_id: Option<String>,
    #[serde(default)]
    pub guardrail_version: Option<String>,
    /// azure_content_safety: the lowest severity that counts, 0 to 7.
    #[serde(default)]
    pub threshold: Option<u8>,
    /// presidio: the anonymizer's base URL, for action: mask.
    #[serde(default)]
    pub anonymizer_url: Option<String>,
    /// lakera.
    #[serde(default)]
    pub project_id: Option<String>,
    /// request, answer, or both.
    #[serde(default)]
    pub on: Option<Vec<Side>>,
    /// regex: entry name to pattern. The name is the finding's kind.
    #[serde(default)]
    pub patterns: Option<BTreeMap<String, String>>,
    /// keywords: entry name to the words and phrases it lists. The name is the finding's kind.
    #[serde(default)]
    pub keywords: Option<BTreeMap<String, Vec<String>>>,
    /// keywords: match case exactly. Off by default.
    #[serde(default)]
    pub case_sensitive: Option<bool>,
    /// keywords: match whole words only. On by default.
    #[serde(default)]
    pub whole_word: Option<bool>,
    /// Until this UTC date or time the guardrail only records what it would have done (`action: shadow`).
    #[serde(default)]
    pub shadow_until: Option<String>,
    /// model_armor: the Model Armor template that holds the filter settings.
    #[serde(default)]
    pub template_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Webhook {
    pub url: String,
    pub timeout: Duration,
    pub on_failure: OnFailure,
    /// (header name, environment variable). Only the variable's name is kept: its value is read when the call is
    /// made, so it is never in the policy, in a record, or in memory longer than one call.
    pub headers_env: Vec<(String, String)>,
    /// Which API the service speaks: Gantry's contract or a vendor's own.
    pub vendor: Vendor,
    /// The variable holding the vendor's API key, read like `headers_env`.
    pub key_env: Option<String>,
}

/// Headers a credential may not use: Gantry sets these itself, or they belong to the connection.
const RESERVED_HEADERS: &[&str] = &[
    "host",
    "content-type",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "upgrade",
    "te",
    "trailer",
    "proxy-authorization",
];

/// Every `headers_env` variable of every webhook guardrail in these rules that `set` says is not set, as one
/// message each. A guardrail without its credential would fail every call, so Gantry does not start or reload with one.
pub fn unset_webhook_env(rules: &[crate::policy::Rule], set: &dyn Fn(&str) -> bool) -> Vec<String> {
    let mut missing = std::collections::BTreeSet::new();
    for guardrail in rules.iter().flat_map(|rule| &rule.guardrails) {
        if let Check::Webhook(hook) = &guardrail.check {
            for (header, variable) in &hook.headers_env {
                if !set(variable) {
                    missing.insert(format!(
                        "guardrail \"{}\" sends header {header} from the environment variable {variable}, which is not set. Set it (`export {variable}=...`) or remove the header from headers_env.",
                        guardrail.name
                    ));
                }
            }
            let vendor_vars = hook.key_env.iter().map(String::as_str);
            for variable in vendor_vars.chain(hook.vendor.env().iter().copied()) {
                if !set(variable) {
                    missing.insert(format!(
                        "guardrail \"{}\" ({}) reads its credential from the environment variable {variable}, which is not set. Set it (`export {variable}=...`) and start again.",
                        guardrail.name,
                        hook.vendor.name()
                    ));
                }
            }
        }
    }
    missing.into_iter().collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Check {
    Secrets,
    Pii,
    /// A `regex` or `keywords` guardrail, compiled.
    Custom(Custom),
    Webhook(Webhook),
}

/// A checked guardrail definition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Guardrail {
    pub name: String,
    /// For a webhook: `block` obeys the service's answer, `warn` only records it.
    pub action: Action,
    pub check: Check,
    /// Whether it reads requests, answers, or both.
    pub on: On,
    /// `shadow_until`: before this UTC date or time, findings are recorded as `shadow` and nothing is blocked or masked.
    pub shadow_until: Option<String>,
}

impl Guardrail {
    /// Whether it runs inside Gantry, with no call out.
    fn local(&self) -> bool {
        !matches!(self.check, Check::Webhook(_))
    }

    /// Whether it is still in its shadow period, read from the clock at each check.
    pub fn shadowing(&self) -> bool {
        self.shadow_until.as_deref().is_some_and(|until| {
            !crate::policy::expiry_passed(
                until,
                &crate::audit::rfc3339(std::time::SystemTime::now()),
            )
        })
    }

    /// What it finds in these text parts, for a guardrail that runs inside Gantry. `builtin` is `scan` of the same
    /// parts, done once for every built-in guardrail of a request.
    fn findings(&self, parts: &[TextPart], builtin: &[Finding]) -> Vec<Finding> {
        let of = |detector: &str| {
            builtin
                .iter()
                .filter(|f| f.detector == detector)
                .cloned()
                .collect()
        };
        match &self.check {
            Check::Secrets => of(SECRETS),
            Check::Pii => of(PII),
            Check::Custom(custom) => custom.scan(parts),
            Check::Webhook(_) => Vec::new(),
        }
    }
}

/// A `regex` or `keywords` guardrail: every entry in one expression, read once per text.
#[derive(Clone, Debug)]
pub struct Custom {
    /// `regex` or `keywords`: records carry it as the detector.
    pub detector: &'static str,
    /// The entry names, which are the finding kinds. Group i + 1 of `re` is entry i.
    pub names: Vec<String>,
    re: Regex,
}

impl PartialEq for Custom {
    fn eq(&self, other: &Self) -> bool {
        self.detector == other.detector
            && self.names == other.names
            && self.re.as_str() == other.re.as_str()
    }
}

impl Eq for Custom {}

impl Custom {
    fn scan(&self, parts: &[TextPart]) -> Vec<Finding> {
        let mut found = Vec::new();
        for part in parts {
            for caps in self.re.captures_iter(&part.text) {
                let hit = caps
                    .iter()
                    .skip(1)
                    .enumerate()
                    .find_map(|(i, group)| Some((self.names.get(i)?, group?)));
                if let Some((name, m)) = hit {
                    found.push(Finding {
                        detector: self.detector,
                        kind: Cow::Owned(name.clone()),
                        path: part.path.clone(),
                        span: m.range(),
                    });
                }
            }
        }
        found
    }
}

/// The compiled size each custom pattern may reach, and the whole expression of one guardrail. The regex crate
/// never backtracks, so time is linear in the text; this bounds the memory a pattern such as `a{1000}{1000}` takes.
const PATTERN_LIMIT: usize = 1 << 20;
const CUSTOM_LIMIT: usize = 16 << 20;

/// An entry name: it is the finding's kind in records and in `[MASKED name]`, so the same safe characters as a
/// webhook finding's kind.
fn entry_name_ok(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

/// Words and phrases as one pattern: each escaped, its inner spaces matching any run of white space, with word
/// boundaries where the phrase starts or ends with a word character.
fn keyword_pattern(words: &[String], whole_word: bool) -> String {
    let word_char = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
    let alternatives: Vec<String> = words
        .iter()
        .map(|w| {
            let body: Vec<String> = w.split_whitespace().map(regex::escape).collect();
            let edge = |c| {
                if whole_word && word_char(c) {
                    r"\b"
                } else {
                    ""
                }
            };
            format!(
                "{}{}{}",
                edge(w.trim().chars().next()),
                body.join(r"\s+"),
                edge(w.trim().chars().last())
            )
        })
        .collect();
    format!("(?:{})", alternatives.join("|"))
}

/// Compiles a `regex` or `keywords` guardrail. Each problem names the entry and the fix.
fn custom(def: &GuardrailFile) -> Result<Custom, String> {
    let name = &def.name;
    let mut names = Vec::new();
    let mut groups = Vec::new();
    let build = |pattern: &str, limit: usize, fold: bool| {
        // ASCII semantics, as the built-in detectors use: \b, \w and case folding are ASCII, and literal text in any
        // script still matches.
        RegexBuilder::new(pattern)
            .unicode(false)
            .case_insensitive(fold)
            .size_limit(limit)
            .dfa_size_limit(limit)
            .build()
    };
    let (detector, fold) = if def.kind == GuardType::Regex {
        let patterns = def.patterns.as_ref().filter(|p| !p.is_empty()).ok_or_else(|| {
            format!("guardrail \"{name}\": a regex guardrail needs patterns, a map of names to patterns, for example patterns: {{ ticket_id: 'TKT-[0-9]{{6}}' }}.")
        })?;
        for (entry, pattern) in patterns {
            let re = build(pattern, PATTERN_LIMIT, false).map_err(|err| {
                format!("guardrail \"{name}\": pattern {entry} does not compile: {err}. Patterns use RE2 syntax (no lookaround, no backreferences), at most {} KiB compiled.", PATTERN_LIMIT >> 10)
            })?;
            if re.captures_len() > 1 {
                return Err(format!(
                    "guardrail \"{name}\": pattern {entry} has a capturing group. Write (?:...) for a group: findings are told apart by group, so a pattern may not add its own."
                ));
            }
            if re.is_match("") {
                return Err(format!(
                    "guardrail \"{name}\": pattern {entry} matches empty text, so it would find something everywhere. Make it match at least one character."
                ));
            }
            names.push(entry.clone());
            groups.push(format!("({pattern})"));
        }
        ("regex", false)
    } else {
        let lists = def.keywords.as_ref().filter(|k| !k.is_empty()).ok_or_else(|| {
            format!("guardrail \"{name}\": a keywords guardrail needs keywords, a map of names to lists, for example keywords: {{ codenames: [Project Falcon, bluebird] }}.")
        })?;
        let whole_word = def.whole_word.unwrap_or(true);
        for (entry, words) in lists {
            if words.is_empty() || words.iter().any(|w| w.trim().is_empty()) {
                return Err(format!(
                    "guardrail \"{name}\": keyword list {entry} is empty or holds an empty word. List at least one word, and no blank ones."
                ));
            }
            names.push(entry.clone());
            groups.push(format!("({})", keyword_pattern(words, whole_word)));
        }
        ("keywords", !def.case_sensitive.unwrap_or(false))
    };
    if let Some(bad) = names.iter().find(|n| !entry_name_ok(n)) {
        return Err(format!(
            "guardrail \"{name}\": entry name \"{bad}\" uses letters, digits, dots, dashes and underscores only, at most 64 characters. It is the kind written to records, so it never holds the text it finds."
        ));
    }
    let re = build(&groups.join("|"), CUSTOM_LIMIT, fold).map_err(|err| {
        format!("guardrail \"{name}\": its {} together do not compile: {err}. Split them across two guardrails.", if detector == "regex" { "patterns" } else { "keywords" })
    })?;
    Ok(Custom {
        detector,
        names,
        re,
    })
}

const DEFAULT_TIMEOUT_MS: u64 = 1000;
const MAX_TIMEOUT_MS: u64 = 30_000;

/// Checks the `guardrails:` definitions. Returns every problem, each naming the guardrail and the fix.
pub fn guardrails(defs: &[GuardrailFile]) -> Result<Vec<Guardrail>, Vec<String>> {
    let mut errors = Vec::new();
    let mut out: Vec<Guardrail> = Vec::new();
    for def in defs {
        let name = &def.name;
        if !crate::config::valid_name(name) {
            errors.push(format!(
                "guardrail \"{name}\": a guardrail name uses letters, digits, dots, dashes, underscores and @ only, at most 100 characters."
            ));
        }
        if out.iter().any(|g| &g.name == name) {
            errors.push(format!(
                "guardrail \"{name}\" is defined twice. Give each guardrail its own name, because records name the guardrail that acted."
            ));
        }
        let check = match def.kind {
            GuardType::Secrets | GuardType::Pii | GuardType::Regex | GuardType::Keywords => {
                if def.url.is_some()
                    || def.timeout_ms.is_some()
                    || def.on_failure.is_some()
                    || def.headers_env.is_some()
                {
                    errors.push(format!(
                        "guardrail \"{name}\": url, timeout_ms, on_failure and headers_env belong to a webhook guardrail. Remove them, or set type: webhook."
                    ));
                }
                if let Err(err) = vendor(def) {
                    errors.push(err);
                }
                match def.kind {
                    GuardType::Secrets => Check::Secrets,
                    GuardType::Pii => Check::Pii,
                    _ => match custom(def) {
                        Ok(custom) => Check::Custom(custom),
                        Err(err) => {
                            errors.push(err);
                            continue;
                        }
                    },
                }
            }
            _ => match webhook(def) {
                Ok(hook) => Check::Webhook(hook),
                Err(err) => {
                    errors.push(err);
                    continue;
                }
            },
        };
        let remote = !matches!(
            def.kind,
            GuardType::Secrets | GuardType::Pii | GuardType::Regex | GuardType::Keywords
        );
        let action = match (def.kind, def.action) {
            (GuardType::Presidio, Some(Action::Mask)) if def.anonymizer_url.is_none() => {
                errors.push(format!(
                    "guardrail \"{name}\": a presidio guardrail masks through the Presidio anonymizer. Add anonymizer_url (for example http://127.0.0.1:5001), or use action: block or warn."
                ));
                continue;
            }
            (GuardType::Presidio, Some(action)) => action,
            (
                GuardType::Webhook | GuardType::BedrockGuardrail | GuardType::ModelArmor,
                Some(Action::Mask),
            ) => {
                errors.push(format!(
                    "guardrail \"{name}\": a {} guardrail does not take action: mask, because the service decides what to mask. Use block to obey its answer or warn to only record it.",
                    type_name(def.kind)
                ));
                continue;
            }
            (_, Some(Action::Mask)) if remote => {
                errors.push(format!(
                    "guardrail \"{name}\": a {} guardrail only says whether text is allowed and cannot mask it. Use block or warn.",
                    type_name(def.kind)
                ));
                continue;
            }
            (_, None) if remote => Action::Block,
            (_, Some(action)) => action,
            (_, None) => {
                errors.push(format!(
                    "guardrail \"{name}\" has no action. Add action: block, mask or warn."
                ));
                continue;
            }
        };
        let on = match def.on.as_deref() {
            None => On::REQUEST,
            Some([]) => {
                errors.push(format!(
                    "guardrail \"{name}\" has an empty on: list. Write on: [request], on: [answer] or on: [request, answer], or remove the line to check requests only."
                ));
                continue;
            }
            Some(sides) => On {
                request: sides.contains(&Side::Request),
                answer: sides.contains(&Side::Answer),
            },
        };
        if let Some(until) = &def.shadow_until {
            if !crate::config::valid_expiry(until) {
                errors.push(format!(
                    "guardrail \"{name}\": shadow_until is \"{until}\". Write a UTC date or time, for example 2026-12-31 or 2026-12-31T18:00:00Z: until then it records what it would do and enforces nothing."
                ));
                continue;
            }
        }
        out.push(Guardrail {
            name: name.clone(),
            action,
            check,
            on,
            shadow_until: def.shadow_until.clone(),
        });
    }
    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

fn type_name(kind: GuardType) -> &'static str {
    match kind {
        GuardType::Secrets => "secrets",
        GuardType::Pii => "pii",
        GuardType::Regex => "regex",
        GuardType::Keywords => "keywords",
        GuardType::Webhook => "webhook",
        GuardType::OpenaiModeration => "openai_moderation",
        GuardType::Presidio => "presidio",
        GuardType::Lakera => "lakera",
        GuardType::BedrockGuardrail => "bedrock_guardrail",
        GuardType::AzureContentSafety => "azure_content_safety",
        GuardType::AzurePromptShield => "azure_prompt_shield",
        GuardType::LlamaGuard => "llama_guard",
        GuardType::ModelArmor => "model_armor",
    }
}

/// The vendor of a remote guardrail, with the fields only its type takes checked.
fn vendor(def: &GuardrailFile) -> Result<Vendor, String> {
    let name = &def.name;
    let kind = type_name(def.kind);
    let given = [
        ("key_env", def.key_env.is_some()),
        ("model", def.model.is_some()),
        ("prompt", def.prompt.is_some()),
        ("region", def.region.is_some()),
        ("guardrail_id", def.guardrail_id.is_some()),
        ("guardrail_version", def.guardrail_version.is_some()),
        ("threshold", def.threshold.is_some()),
        ("anonymizer_url", def.anonymizer_url.is_some()),
        ("project_id", def.project_id.is_some()),
        ("template_id", def.template_id.is_some()),
        ("patterns", def.patterns.is_some()),
        ("keywords", def.keywords.is_some()),
        ("case_sensitive", def.case_sensitive.is_some()),
        ("whole_word", def.whole_word.is_some()),
    ];
    let takes: &[&str] = match def.kind {
        GuardType::OpenaiModeration => &["key_env", "model"],
        GuardType::Presidio => &["anonymizer_url"],
        GuardType::Lakera => &["key_env", "project_id"],
        GuardType::BedrockGuardrail => &["region", "guardrail_id", "guardrail_version"],
        GuardType::AzureContentSafety => &["key_env", "threshold"],
        GuardType::AzurePromptShield => &["key_env"],
        GuardType::LlamaGuard => &["key_env", "model", "prompt"],
        GuardType::ModelArmor => &["key_env", "project_id", "region", "template_id"],
        GuardType::Regex => &["patterns"],
        GuardType::Keywords => &["keywords", "case_sensitive", "whole_word"],
        _ => &[],
    };
    if let Some((field, _)) = given.iter().find(|(f, on)| *on && !takes.contains(f)) {
        let hint = if *field == "key_env" && def.kind == GuardType::BedrockGuardrail {
            " It signs with AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN from Gantry's environment."
        } else {
            ""
        };
        return Err(format!(
            "guardrail \"{name}\": {field} does not apply to a {kind} guardrail. Remove it.{hint}"
        ));
    }
    let required = |field: &str, value: &Option<String>| {
        value
            .clone()
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| {
                format!("guardrail \"{name}\": a {kind} guardrail needs {field}. Add it.")
            })
    };
    let key_needed = matches!(
        def.kind,
        GuardType::OpenaiModeration
            | GuardType::Lakera
            | GuardType::AzureContentSafety
            | GuardType::AzurePromptShield
            | GuardType::ModelArmor
    );
    if key_needed && def.key_env.is_none() {
        return Err(format!(
            "guardrail \"{name}\": a {kind} guardrail needs key_env, the name of the environment variable that holds its API key. Add it, for example key_env: GUARD_API_KEY."
        ));
    }
    Ok(match def.kind {
        GuardType::OpenaiModeration => Vendor::OpenaiModeration {
            model: def.model.clone(),
        },
        GuardType::Presidio => Vendor::Presidio {
            anonymizer: def
                .anonymizer_url
                .as_ref()
                .map(|u| checked_url(name, u))
                .transpose()?,
        },
        GuardType::Lakera => Vendor::Lakera {
            project_id: def.project_id.clone(),
        },
        GuardType::BedrockGuardrail => {
            let region = required("region", &def.region)?;
            if !region
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err(format!(
                    "guardrail \"{name}\": region \"{region}\" is not an AWS region name such as us-east-1."
                ));
            }
            Vendor::Bedrock {
                region,
                guardrail_id: required("guardrail_id", &def.guardrail_id)?,
                version: required(
                    "guardrail_version (a number, or DRAFT)",
                    &def.guardrail_version,
                )?,
            }
        }
        GuardType::AzureContentSafety => {
            let threshold = def.threshold.unwrap_or(4);
            if threshold > 7 {
                return Err(format!(
                    "guardrail \"{name}\": threshold is {threshold}. Azure severities run from 0 to 7; 2 is low, 4 medium, 6 high."
                ));
            }
            Vendor::AzureContentSafety { threshold }
        }
        GuardType::AzurePromptShield => Vendor::AzurePromptShield,
        GuardType::ModelArmor => {
            let region = required(
                "region (the Model Armor location, such as us-central1)",
                &def.region,
            )?;
            let project = required("project_id (the Google Cloud project)", &def.project_id)?;
            let template = required("template_id", &def.template_id)?;
            let plain = |v: &str| {
                v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            };
            if let Some(bad) = [&region, &project, &template]
                .into_iter()
                .find(|v| !plain(v))
            {
                return Err(format!(
                    "guardrail \"{name}\": \"{bad}\" is not a Google Cloud location, project or template ID. Use letters, digits, dashes and underscores only."
                ));
            }
            Vendor::ModelArmor {
                region,
                project,
                template,
            }
        }
        GuardType::LlamaGuard => {
            if def
                .prompt
                .as_ref()
                .is_some_and(|p| !p.contains("{conversation}"))
            {
                return Err(format!(
                    "guardrail \"{name}\": the prompt has no {{conversation}}. Put {{conversation}} where the messages to check go."
                ));
            }
            Vendor::LlamaGuard {
                model: required("model", &def.model)?,
                prompt: def.prompt.clone(),
            }
        }
        _ => Vendor::Contract,
    })
}

/// A guardrail service URL: https, or plain http on this machine only.
fn checked_url(name: &str, url: &str) -> Result<String, String> {
    let local = ["http://localhost", "http://127.0.0.1", "http://[::1]"]
        .iter()
        .any(|p| {
            url.strip_prefix(p)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with([':', '/']))
        });
    // QA14-8: a login in the URL (`http://localhost:@example.com`) makes the host the part after `@`, so a remote
    // host would pass for this machine. No guardrail service needs one: credentials go in key_env.
    let authority = url.split_once("://").map_or(url, |(_, rest)| {
        rest.split(['/', '?', '#']).next().unwrap_or_default()
    });
    if authority.contains(['@', '\\']) {
        return Err(format!(
            "guardrail \"{name}\": the url has a login part (before an @), which would send prompts to the host after it. Remove it, and give credentials with key_env."
        ));
    }
    // Prompts sent in clear text across a network are a leak of their own; a sidecar on this machine is the exception.
    if !(url.starts_with("https://") || local) || url.contains(char::is_whitespace) {
        return Err(format!(
            "guardrail \"{name}\": the url must start with https://, or be http://localhost or http://127.0.0.1 for a service on this machine."
        ));
    }
    Ok(url.trim_end_matches('/').to_string())
}

fn webhook(def: &GuardrailFile) -> Result<Webhook, String> {
    let name = &def.name;
    let vendor = vendor(def)?;
    let Some(url) = def.url.clone().or_else(|| vendor.default_url()) else {
        return Err(if def.kind == GuardType::Webhook {
            format!(
                "guardrail \"{name}\" is a webhook with no url. Add the URL of the guardrail service."
            )
        } else {
            format!(
                "guardrail \"{name}\": a {} guardrail needs the url of the service. Add it.",
                type_name(def.kind)
            )
        });
    };
    let url = &url;
    let url = checked_url(name, url)?;
    let timeout_ms = def.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
    if !(1..=MAX_TIMEOUT_MS).contains(&timeout_ms) {
        return Err(format!(
            "guardrail \"{name}\": timeout_ms is {timeout_ms}. It must be between 1 and {MAX_TIMEOUT_MS}, because every request waits for it."
        ));
    }
    let Some(on_failure) = def.on_failure else {
        return Err(format!(
            "guardrail \"{name}\" does not say what to do when the service fails. Add on_failure: fail_closed (refuse the request) or fail_open (forward it and record that the check did not run)."
        ));
    };
    let mut headers_env = Vec::new();
    for (header, variable) in def.headers_env.iter().flatten() {
        let token = !header.is_empty()
            && header
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !token || RESERVED_HEADERS.contains(&header.to_ascii_lowercase().as_str()) {
            return Err(format!(
                "guardrail \"{name}\": headers_env names header \"{header}\", which a credential cannot use. Name a header such as Authorization or X-Api-Key."
            ));
        }
        let env_name = !variable.is_empty()
            && !variable.starts_with(|c: char| c.is_ascii_digit())
            && variable
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_');
        if !env_name {
            return Err(format!(
                "guardrail \"{name}\": headers_env gives header {header} the value \"{variable}\", which is not the name of an environment variable. Write the variable's name, for example {header}: GUARD_TOKEN, and keep the value itself out of this file."
            ));
        }
        headers_env.push((header.clone(), variable.clone()));
    }
    Ok(Webhook {
        url,
        timeout: Duration::from_millis(timeout_ms),
        on_failure,
        headers_env,
        vendor,
        key_env: def.key_env.clone(),
    })
}

/// The guardrails a rule names with `guardrails: [name, ...]`, in the order written.
pub fn for_rule(
    rule: &str,
    names: &[String],
    defined: &[Guardrail],
) -> Result<Vec<Guardrail>, String> {
    names
        .iter()
        .map(|name| {
            defined.iter().find(|g| &g.name == name).cloned().ok_or_else(|| {
                format!(
                    "rule \"{rule}\" names guardrail \"{name}\", which is not defined under guardrails. Define it there, or check the spelling."
                )
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------------------
// Text parts
// ---------------------------------------------------------------------------------------------------------

/// One piece of text Gantry sends to a provider, with where it sits in the request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TextPart {
    /// JSON pointer into the request body, for example `/messages/0/content/1/text`.
    #[serde(skip)]
    pub path: String,
    pub role: String,
    pub text: String,
}

/// The text parts of a chat completions, messages, responses or embeddings request: the system prompt or
/// instructions, every message's text, every input text, and the text inside tool results, text documents and
/// search results. Images, files, tool definitions, tool arguments and all other fields are not text Gantry checks.
// ponytail: tool_use arguments are not walked. Add them when a policy needs them checked.
pub fn text_parts(body: &Value) -> Vec<TextPart> {
    let mut parts = Vec::new();
    content(body.get("system"), "/system", "system", &mut parts);
    for (i, message) in body
        .get("messages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let role = message.get("role").and_then(Value::as_str).unwrap_or("");
        content(
            message.get("content"),
            &format!("/messages/{i}/content"),
            role,
            &mut parts,
        );
    }
    // The Responses API: instructions, and input as a string or a list of items; embeddings: input as a string
    // or a list of strings.
    // ponytail: embeddings sent as token ID arrays are not text and are not checked.
    content(
        body.get("instructions"),
        "/instructions",
        "system",
        &mut parts,
    );
    match body.get("input") {
        Some(Value::Array(items)) => {
            for (i, item) in items.iter().enumerate() {
                if item.is_string() {
                    content(Some(item), &format!("/input/{i}"), "user", &mut parts);
                } else if item.get("type").and_then(Value::as_str) == Some("function_call_output") {
                    // A tool's result, as a chat tool message or an Anthropic tool_result is read.
                    content(
                        item.get("output"),
                        &format!("/input/{i}/output"),
                        "tool",
                        &mut parts,
                    );
                } else {
                    let role = item.get("role").and_then(Value::as_str).unwrap_or("");
                    content(
                        item.get("content"),
                        &format!("/input/{i}/content"),
                        role,
                        &mut parts,
                    );
                }
            }
        }
        input => content(input, "/input", "user", &mut parts),
    }
    // A stored prompt's variables are text the provider puts into the prompt.
    if let Some(variables) = body.pointer("/prompt/variables").and_then(Value::as_object) {
        for (name, value) in variables {
            let path = format!(
                "/prompt/variables/{}",
                name.replace('~', "~0").replace('/', "~1")
            );
            match value {
                Value::String(_) => content(Some(value), &path, "user", &mut parts),
                Value::Object(_) => content(
                    Some(&Value::Array(vec![value.clone()])),
                    &path,
                    "user",
                    &mut parts,
                ),
                _ => {}
            }
        }
    }
    parts
}

/// A content field in either format: a string, or a list of blocks of which the `text` ones count.
fn content(value: Option<&Value>, path: &str, role: &str, parts: &mut Vec<TextPart>) {
    let push = |parts: &mut Vec<TextPart>, path: String, text: &str| {
        parts.push(TextPart {
            path,
            role: role.to_string(),
            text: text.to_string(),
        });
    };
    match value {
        Some(Value::String(text)) => push(parts, path.to_string(), text),
        Some(Value::Array(blocks)) => {
            for (j, block) in blocks.iter().enumerate() {
                match block.get("type").and_then(Value::as_str) {
                    Some("text" | "input_text" | "output_text") => {
                        if let Some(text) = block.get("text").and_then(Value::as_str) {
                            push(parts, format!("{path}/{j}/text"), text);
                        }
                    }
                    // A chat tool message becomes a tool_result when translated: the same text must get the
                    // same verdict on both routes. Search results and documents hold text blocks of their own.
                    Some("tool_result" | "search_result") => content(
                        block.get("content"),
                        &format!("{path}/{j}/content"),
                        role,
                        parts,
                    ),
                    Some("document") => {
                        let source = &block["source"];
                        match source.get("type").and_then(Value::as_str) {
                            Some("text") => content(
                                source.get("data"),
                                &format!("{path}/{j}/source/data"),
                                role,
                                parts,
                            ),
                            Some("content") => content(
                                source.get("content"),
                                &format!("{path}/{j}/source/content"),
                                role,
                                parts,
                            ),
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------------------------------------
// Built-in detectors
// ---------------------------------------------------------------------------------------------------------

const SECRETS: &str = "secrets";
const PII: &str = "pii";

struct Kind {
    detector: &'static str,
    kind: &'static str,
    pattern: &'static str,
    valid: fn(&str) -> bool,
}

fn any(_: &str) -> bool {
    true
}

/// Read on its own: in one expression with the card pattern, a run like "1-1-1-..." took seconds per MiB
/// (measured with regex 1.13), while each alone takes about a millisecond.
const EMAIL: Kind = Kind {
    detector: PII,
    kind: "email_address",
    pattern: r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}\b",
    valid: any,
};

/// Every other pattern, in one expression tried in this order at each position, so the text is read once.
/// No pattern may contain a capturing group: group i + 1 of the combined expression is KINDS[i].
const KINDS: &[Kind] = &[
    // The header only: the body is found by a bounded search, so a header with no end line costs nothing extra.
    Kind {
        detector: SECRETS,
        kind: "private_key",
        pattern: r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY(?: BLOCK)?-----",
        valid: any,
    },
    Kind {
        detector: SECRETS,
        kind: "aws_access_key",
        pattern: r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b",
        valid: any,
    },
    Kind {
        detector: SECRETS,
        kind: "github_token",
        pattern: r"\b(?:gh[pousr]_[A-Za-z0-9]{36,251}|github_pat_[A-Za-z0-9_]{22,255})\b",
        valid: any,
    },
    Kind {
        detector: SECRETS,
        kind: "slack_token",
        pattern: r"\bxox[abposre]-[A-Za-z0-9-]{10,250}",
        valid: any,
    },
    Kind {
        detector: SECRETS,
        kind: "gantry_key",
        pattern: r"\bgantry_[0-9a-f]{64}\b",
        valid: any,
    },
    Kind {
        detector: SECRETS,
        kind: "jwt",
        pattern: r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*",
        valid: any,
    },
    // A service account key file names its key by a 40 hex digit ID; the PEM block in it is a private_key as well.
    Kind {
        detector: SECRETS,
        kind: "gcp_service_account_key",
        pattern: r#""private_key_id"\s*:\s*"[0-9a-f]{40}""#,
        valid: any,
    },
    Kind {
        detector: SECRETS,
        kind: "gcp_api_key",
        pattern: r"\bAIza[0-9A-Za-z_-]{35}",
        valid: any,
    },
    // The key part of a storage account or Service Bus / Event Hubs connection string; the rest names the resource.
    Kind {
        detector: SECRETS,
        kind: "azure_connection_string",
        pattern: r"\b(?:AccountKey|SharedAccessKey)=[A-Za-z0-9+/]{30,}={0,2}",
        valid: any,
    },
    // Secret and restricted keys only: a publishable pk_ key is meant to be public.
    Kind {
        detector: SECRETS,
        kind: "stripe_key",
        pattern: r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,99}\b",
        valid: any,
    },
    // An API key SID: an account SID (AC...) is an identifier, and an auth token is 32 bare hex digits.
    Kind {
        detector: SECRETS,
        kind: "twilio_api_key",
        pattern: r"\bSK[0-9a-f]{32}\b",
        valid: any,
    },
    Kind {
        detector: SECRETS,
        kind: "sendgrid_key",
        pattern: r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        valid: any,
    },
    // Before api_key: at one position the first pattern listed wins, so these get their own name.
    Kind {
        detector: SECRETS,
        kind: "openai_project_key",
        pattern: r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}",
        valid: any,
    },
    Kind {
        detector: SECRETS,
        kind: "anthropic_key",
        pattern: r"\bsk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_-]{20,}",
        valid: any,
    },
    Kind {
        detector: SECRETS,
        kind: "api_key",
        pattern: r"\bsk-[A-Za-z0-9_-]{20,}",
        valid: any,
    },
    // A URL with a password in it. The classes are ASCII on purpose: the combined expression is byte based.
    Kind {
        detector: SECRETS,
        kind: "database_url",
        pattern: r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver)://[A-Za-z0-9._~%-]*:[A-Za-z0-9._~%!$&'()*+,;=-]{1,128}@[A-Za-z0-9.-]+",
        valid: database_url_ok,
    },
    Kind {
        detector: PII,
        kind: "iban",
        pattern: r"\b[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]){11,30}\b",
        valid: iban_found,
    },
    Kind {
        detector: PII,
        kind: "credit_card",
        pattern: r"\b[0-9](?:[ -]?[0-9]){12,18}\b",
        valid: luhn_ok,
    },
    Kind {
        detector: PII,
        kind: "us_ssn",
        pattern: r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b",
        valid: ssn_ok,
    },
    Kind {
        detector: PII,
        kind: "israeli_id",
        pattern: r"\b[0-9]{9}\b",
        valid: israeli_id_ok,
    },
    // Health data is found by its label: a bare number or date is too common to call a record number or a birthday.
    Kind {
        detector: PII,
        kind: "medical_record_number",
        pattern: r"(?i:\b(?:MRN|medical record(?: number| no\.?)?))[:#=\s]+[A-Z0-9-]{5,12}\b",
        valid: any,
    },
    Kind {
        detector: PII,
        kind: "date_of_birth",
        pattern: r"(?i:\b(?:DOB|date of birth|born on))[:=\s]+(?:[0-9]{1,2}[/.-][0-9]{1,2}[/.-][0-9]{2,4}|[0-9]{4}-[0-9]{2}-[0-9]{2})\b",
        valid: any,
    },
    Kind {
        detector: PII,
        kind: "phone_number",
        pattern: r"(?:\+[1-9][0-9]{0,2}[ .-]?(?:\([0-9]{1,4}\)[ .-]?)?[0-9]{1,4}(?:[ .-]?[0-9]{2,4}){1,4}|\(?\b[0-9]{3}\)?[ .-][0-9]{3}[ .-][0-9]{4}|\b05[0-9]-?[0-9]{7})\b",
        valid: phone_ok,
    },
];

fn digits(text: &str) -> Vec<u32> {
    text.chars().filter_map(|c| c.to_digit(10)).collect()
}

fn luhn_ok(text: &str) -> bool {
    let d = digits(text);
    let sum: u32 = d
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &n)| match (i % 2, n * 2) {
            (0, _) => n,
            (_, doubled) if doubled > 9 => doubled - 9,
            (_, doubled) => doubled,
        })
        .sum();
    (13..=19).contains(&d.len()) && sum % 10 == 0
}

fn iban_ok(text: &str) -> bool {
    let compact: Vec<char> = text.chars().filter(|c| *c != ' ').collect();
    if !(15..=34).contains(&compact.len()) {
        return false;
    }
    // ISO 13616: move the first four characters to the end, read letters as 10 to 35, and the number mod 97 is 1.
    let mut rest = 0u32;
    for c in compact[4..].iter().chain(&compact[..4]) {
        let Some(value) = c.to_digit(36) else {
            return false;
        };
        rest = if value < 10 {
            (rest * 10 + value) % 97
        } else {
            (rest * 100 + value) % 97
        };
    }
    rest == 1
}

/// The length of the IBAN a match starts with: all of it, or the longest part that ends before a space. The pattern
/// reads on through spaced groups, so "GB82... BIC NWBKGB2L" is matched with the words after it, which fail the check.
fn iban_len(text: &str) -> Option<usize> {
    std::iter::once(text.len())
        .chain(text.rmatch_indices(' ').map(|(at, _)| at))
        .find(|&len| iban_ok(&text[..len]))
}

fn iban_found(text: &str) -> bool {
    iban_len(text).is_some()
}

fn israeli_id_ok(text: &str) -> bool {
    let d = digits(text);
    // Weights 1, 2, 1, 2, ...; a two-digit product counts as the sum of its digits.
    let sum: u32 = d
        .iter()
        .enumerate()
        .map(|(i, &n)| {
            let p = n * (1 + (i as u32 % 2));
            p / 10 + p % 10
        })
        .sum();
    d.len() == 9 && sum % 10 == 0 && sum > 0
}

fn ssn_ok(text: &str) -> bool {
    let mut groups = text.split('-');
    let (Some(area), Some(group), Some(serial)) = (groups.next(), groups.next(), groups.next())
    else {
        return false;
    };
    area != "000" && area != "666" && !area.starts_with('9') && group != "00" && serial != "0000"
}

/// A password that is a placeholder (`${DB_PASSWORD}`, `$PASS`, `password`, `***`, `...`) is not a secret.
fn database_url_ok(text: &str) -> bool {
    let Some(password) = text
        .split_once("://")
        .and_then(|(_, rest)| rest.rsplit_once('@'))
        .and_then(|(login, _)| login.split_once(':'))
        .map(|(_, password)| password)
    else {
        return false;
    };
    let placeholder = [
        "password", "passwd", "pass", "secret", "changeme", "xxx", "xxxx",
    ];
    !(password.starts_with(['$', '%', '<', '{', '*'])
        || password.chars().all(|c| c == '*' || c == '.' || c == 'x')
        || placeholder.contains(&password.to_ascii_lowercase().as_str()))
}

fn phone_ok(text: &str) -> bool {
    (7..=15).contains(&digits(text).len())
}

/// The combined expression of KINDS, and the one for EMAIL.
fn detectors() -> Result<&'static (Regex, Regex), String> {
    static RE: OnceLock<Result<(Regex, Regex), String>> = OnceLock::new();
    // ASCII classes and word boundaries keep the fast automata in use on text that is not ASCII.
    let build = |pattern: &str| {
        RegexBuilder::new(pattern)
            .unicode(false)
            .dfa_size_limit(16 << 20)
            .build()
            .map_err(|err| {
                format!("the guardrail detectors did not compile: {err}. This is a bug in Gantry; report it.")
            })
    };
    RE.get_or_init(|| {
        let joined: Vec<String> = KINDS.iter().map(|k| format!("({})", k.pattern)).collect();
        Ok((build(&joined.join("|"))?, build(EMAIL.pattern)?))
    })
    .as_ref()
    .map_err(Clone::clone)
}

/// Something a detector found. It holds where, never what.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub detector: &'static str,
    /// A built-in kind, or the name of a `regex` or `keywords` entry.
    pub kind: Cow<'static, str>,
    /// JSON pointer to the text the finding is in.
    pub path: String,
    span: Range<usize>,
}

/// Every finding of the built-in detectors in the given text parts.
pub fn scan(parts: &[TextPart]) -> Result<Vec<Finding>, String> {
    let (re, email) = detectors()?;
    let mut found = Vec::new();
    for part in parts {
        let text = part.text.as_str();
        // "postgres://app:pw@db.example.com" holds an address shape that is a URL's login, not a mail address.
        // Looked for in the 256 bytes before the match only, so a long run of addresses costs no more than one each.
        let in_url = |at: usize| {
            let mut from = at.saturating_sub(256);
            while !text.is_char_boundary(from) {
                from -= 1;
            }
            let word = text[from..at]
                .rsplit(|c: char| c.is_whitespace() || "\"'<>(),;=`".contains(c))
                .next()
                .unwrap_or("");
            word.contains("://")
        };
        found.extend(
            email
                .find_iter(text)
                .filter(|m| !in_url(m.start()))
                .map(|m| Finding {
                    detector: EMAIL.detector,
                    kind: Cow::Borrowed(EMAIL.kind),
                    path: part.path.clone(),
                    span: m.range(),
                }),
        );
        // Where the next "-----END " is, found once and reused, so many headers cost one search, not one each.
        let mut next_end: Option<Option<usize>> = None;
        // The end of the last private key block: headers and anything else inside it are part of that finding.
        let mut covered = 0;
        for caps in re.captures_iter(text) {
            let hit = caps
                .iter()
                .skip(1)
                .enumerate()
                .find_map(|(i, group)| Some((KINDS.get(i)?, group?)));
            let Some((kind, m)) = hit else { continue };
            // ponytail: a match that fails its check (Luhn, mod 97) is dropped, not retried as another kind.
            if m.start() < covered || !(kind.valid)(m.as_str()) {
                continue;
            }
            let mut end = m.end();
            if kind.kind == "private_key" {
                let end_line = match next_end {
                    Some(Some(at)) if at >= end => Some(at),
                    Some(None) => None,
                    _ => {
                        let at = text[end..].find("-----END ").map(|i| i + end);
                        next_end = Some(at);
                        at
                    }
                };
                end = end_line
                    .filter(|at| at - end <= KEY_BLOCK_LIMIT)
                    .and_then(|at| key_line_end(text.as_bytes(), at))
                    .unwrap_or(end);
                covered = end;
            }
            if kind.kind == "iban" {
                end = m.start() + iban_len(m.as_str()).unwrap_or(m.len());
            }
            found.push(Finding {
                detector: kind.detector,
                kind: Cow::Borrowed(kind.kind),
                path: part.path.clone(),
                span: m.start()..end,
            });
        }
    }
    Ok(found)
}

/// The end of a private key's end line that starts at `at`, if the line is one.
fn key_line_end(text: &[u8], at: usize) -> Option<usize> {
    let line = &text[at..text.len().min(at + 80)];
    [&b"PRIVATE KEY-----"[..], b"PRIVATE KEY BLOCK-----"]
        .iter()
        .find_map(|tail| {
            let found = line.windows(tail.len()).position(|w| w == *tail)?;
            Some(at + found + tail.len())
        })
}

// ---------------------------------------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------------------------------------

/// Why a request was refused. The server answers with `BLOCKED_CODE` and this message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blocked {
    pub guardrail: String,
    pub message: String,
}

/// One line of what the guardrails did, for the audit record: no matched text, only counts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuditEntry {
    pub guardrail: String,
    pub detector: String,
    pub kind: String,
    /// `block`, `mask`, `warn`, `shadow` for a guardrail before its shadow_until, or `skipped` when a fail_open
    /// webhook did not answer.
    pub action: &'static str,
    pub count: usize,
}

/// What the guardrails decided about one request.
#[derive(Clone, Debug, PartialEq)]
pub struct Verdict {
    /// The body to forward. Equal to the one checked unless `changed`.
    pub body: Value,
    pub changed: bool,
    pub blocked: Option<Blocked>,
    pub audit: Vec<AuditEntry>,
}

/// Where a finding is, in words a person can find in their own conversation, then exactly as a JSON pointer:
/// "in message 3 (/messages/2/content/1/text)".
fn place(path: &str) -> String {
    let mut parts = path.trim_start_matches('/').split('/');
    let first = parts.next().unwrap_or("");
    let index = parts.next().and_then(|n| n.parse::<usize>().ok());
    let words = match (first, index) {
        ("messages", Some(n)) => format!("message {}", n + 1),
        ("input", Some(n)) => format!("input item {}", n + 1),
        ("system", _) => "the system prompt".to_string(),
        ("instructions", _) => "the instructions".to_string(),
        ("input", None) => "the input".to_string(),
        _ => return format!("at {path}"),
    };
    format!("in {words} ({path})")
}

fn action_word(action: Action) -> &'static str {
    match action {
        Action::Block => "block",
        Action::Mask => "mask",
        Action::Warn => "warn",
    }
}

/// Runs the built-in guardrails of `guards` on a request body. Webhook guardrails are left to the server,
/// which calls each one with `WebhookRequest::new(..., &verdict.body)` and folds the answer in with `merge_webhook`.
pub fn check(body: Value, guards: &[Guardrail]) -> Verdict {
    check_side(body, guards, Side::Request)
}

/// The built-in guardrails with `on: [answer]` on the text of an answer, shown to them as a request body (each
/// piece of text an assistant message). The caller writes masked text back into the answer.
pub fn check_reply(body: Value, guards: &[Guardrail]) -> Verdict {
    check_side(body, guards, Side::Answer)
}

fn check_side(body: Value, guards: &[Guardrail], side: Side) -> Verdict {
    let mut verdict = Verdict {
        body,
        changed: false,
        blocked: None,
        audit: Vec::new(),
    };
    let active: Vec<&Guardrail> = guards
        .iter()
        .filter(|g| g.on.has(side) && g.local())
        .collect();
    if active.is_empty() {
        return verdict;
    }
    let parts = text_parts(&verdict.body);
    let builtin = if active
        .iter()
        .any(|g| matches!(g.check, Check::Secrets | Check::Pii))
    {
        match scan(&parts) {
            Ok(findings) => findings,
            Err(err) => {
                // A check that cannot run must not wave the request through.
                verdict.blocked = Some(Blocked {
                    guardrail: String::new(),
                    message: err,
                });
                return verdict;
            }
        }
    } else {
        Vec::new()
    };
    let mut masks: Vec<Finding> = Vec::new();
    for guard in active {
        let mine = guard.findings(&parts, &builtin);
        if mine.is_empty() {
            continue;
        }
        let detector = match &guard.check {
            Check::Custom(custom) => custom.detector,
            Check::Pii => PII,
            _ => SECRETS,
        };
        let mut kinds: BTreeMap<&str, usize> = BTreeMap::new();
        for f in &mine {
            *kinds.entry(&f.kind).or_default() += 1;
        }
        let shadow = guard.shadowing();
        verdict
            .audit
            .extend(kinds.iter().map(|(kind, count)| AuditEntry {
                guardrail: guard.name.clone(),
                detector: detector.to_string(),
                kind: kind.to_string(),
                action: if shadow {
                    SHADOW
                } else {
                    action_word(guard.action)
                },
                count: *count,
            }));
        match guard.action {
            _ if shadow => {}
            Action::Block if verdict.blocked.is_none() => {
                let what: Vec<String> = kinds.iter().map(|(k, n)| format!("{k} ({n})")).collect();
                let mut paths: Vec<&str> = mine.iter().map(|f| f.path.as_str()).collect();
                paths.dedup();
                verdict.blocked = Some(Blocked {
                    guardrail: guard.name.clone(),
                    message: format!(
                        "Guardrail \"{}\" refused this request: it contains {} {}. Remove them and send the request again.",
                        guard.name,
                        what.join(", "),
                        paths
                            .iter()
                            .map(|p| place(p))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                });
            }
            Action::Mask => masks.extend(mine),
            Action::Block | Action::Warn => {}
        }
    }
    if verdict.blocked.is_none() && !masks.is_empty() {
        apply_masks(&mut verdict.body, &masks);
        verdict.changed = true;
    }
    verdict
}

/// The action a guardrail in its shadow period records: it would have acted, and did not.
pub const SHADOW: &str = "shadow";

/// Replaces each finding's span with `[MASKED kind]`. Only those spans change; the JSON stays valid
/// because each string is rebuilt whole and written back as a string.
fn apply_masks(body: &mut Value, masks: &[Finding]) {
    let mut by_path: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for f in masks {
        by_path.entry(f.path.as_str()).or_default().push(f);
    }
    for (path, mut found) in by_path {
        let Some(Value::String(text)) = body.pointer_mut(path) else {
            continue;
        };
        found.sort_by_key(|f| (f.span.start, std::cmp::Reverse(f.span.end)));
        let mut out = String::with_capacity(text.len());
        let mut at = 0;
        for f in found {
            // Two guardrails may mask the same span; the first one written covers it.
            if f.span.start < at {
                continue;
            }
            out.push_str(&text[at..f.span.start]);
            out.push_str(&format!("[MASKED {}]", f.kind));
            at = f.span.end;
        }
        out.push_str(&text[at..]);
        *text = out;
    }
}

// ---------------------------------------------------------------------------------------------------------
// Webhook contract
// ---------------------------------------------------------------------------------------------------------

/// What Gantry sends a webhook guardrail. Exactly these fields: see docs/guardrail-webhook.md.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WebhookRequest {
    pub decision_id: String,
    pub person: String,
    pub team: String,
    pub model: String,
    pub route: String,
    pub messages: Vec<TextPart>,
}

impl WebhookRequest {
    pub fn new(decision_id: &str, person: &str, team: &str, route: &str, body: &Value) -> Self {
        Self {
            decision_id: decision_id.to_string(),
            person: person.to_string(),
            team: team.to_string(),
            model: body
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            route: route.to_string(),
            messages: text_parts(body),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookAction {
    Allow,
    Block,
    Mask,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookFinding {
    pub kind: String,
    /// Index into the `messages` Gantry sent.
    #[serde(default)]
    pub message: Option<usize>,
}

/// A checked answer from a webhook guardrail.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookAnswer {
    pub action: WebhookAction,
    /// Accepted for the vendor's own logs and checked, never shown or recorded: it may quote the prompt.
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub findings: Vec<WebhookFinding>,
    #[serde(default)]
    pub masked_messages: Option<Vec<String>>,
}

const MAX_REASON: usize = 500;

/// Reads and checks a webhook answer to a request that carried `sent` messages.
/// Each error says what is wrong with the answer, for the operator and for the vendor.
pub fn parse_answer(bytes: &[u8], sent: usize) -> Result<WebhookAnswer, String> {
    let answer: WebhookAnswer = serde_json::from_slice(bytes).map_err(|err| {
        format!("the answer is not a valid guardrail answer: {err}. See https://gantry-docs.eliran.me/governance/guardrail-webhooks/ for the format")
    })?;
    check_answer(answer, sent)
}

/// Checks an answer, from a webhook or built from a vendor's, to a request that carried `sent` messages.
pub fn check_answer(answer: WebhookAnswer, sent: usize) -> Result<WebhookAnswer, String> {
    if answer
        .reason
        .as_ref()
        .is_some_and(|r| r.chars().count() > MAX_REASON || r.chars().any(char::is_control))
    {
        return Err(format!(
            "the answer's reason is longer than {MAX_REASON} characters or holds control characters; keep it to one short line"
        ));
    }
    for f in &answer.findings {
        let kind_ok = (1..=64).contains(&f.kind.len())
            && f.kind
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b));
        if !kind_ok {
            return Err("a finding's kind must be 1 to 64 letters, digits, dots, dashes or underscores, such as \"email_address\"; it is written to the audit record, so it must never hold the matched text".into());
        }
        if f.message.is_some_and(|i| i >= sent) {
            return Err(format!(
                "a finding points at message {}, and the request had {}; message is a 0-based index into the messages sent",
                f.message.unwrap_or_default(),
                crate::count(sent, "message")
            ));
        }
    }
    match (&answer.action, &answer.masked_messages) {
        (WebhookAction::Mask, None) => {
            Err("the answer says mask and has no masked_messages; send one string per message sent, in the same order".into())
        }
        (WebhookAction::Mask, Some(masked)) if masked.len() != sent => Err(format!(
            "masked_messages has {} and the request had {}; send one string per message sent, in the same order",
            crate::count(masked.len(), "string"),
            crate::count(sent, "message")
        )),
        (WebhookAction::Allow | WebhookAction::Block, Some(_)) => Err(
            "masked_messages is only read when action is mask; remove it, or set action to mask".into(),
        ),
        _ => Ok(answer),
    }
}

impl Verdict {
    /// Folds a webhook guardrail's outcome into the verdict. `outcome` is the answer's bytes, or why
    /// there is none (unreachable, timed out, an error status). Returns the failure cause, if any, for the
    /// server's log: it is not written to the audit record.
    pub fn merge_webhook(
        &mut self,
        guard: &Guardrail,
        sent: &WebhookRequest,
        outcome: Result<&[u8], String>,
    ) -> Option<String> {
        self.merge_answer(
            guard,
            sent,
            outcome.and_then(|bytes| parse_answer(bytes, sent.messages.len())),
        )
    }

    /// `merge_webhook` for an answer already read: a vendor's, turned into the contract's terms.
    pub fn merge_answer(
        &mut self,
        guard: &Guardrail,
        sent: &WebhookRequest,
        outcome: Result<WebhookAnswer, String>,
    ) -> Option<String> {
        let Check::Webhook(hook) = &guard.check else {
            return None;
        };
        let entry = |kind: &str, action: &'static str, count: usize| AuditEntry {
            guardrail: guard.name.clone(),
            detector: hook.vendor.name().to_string(),
            kind: kind.to_string(),
            action,
            count,
        };
        let answer = match outcome.and_then(|a| check_answer(a, sent.messages.len())) {
            Ok(answer) => answer,
            Err(cause) => {
                let closed = hook.on_failure == OnFailure::FailClosed;
                let word = if closed { "block" } else { "skipped" };
                self.audit.push(entry("unavailable", word, 1));
                if closed && self.blocked.is_none() {
                    self.blocked = Some(Blocked {
                        guardrail: guard.name.clone(),
                        message: format!(
                            "Guardrail \"{}\" could not check this request, and it is set to fail_closed, so the request was not sent. Try again later; if it keeps failing, ask an administrator to check the guardrail service.",
                            guard.name
                        ),
                    });
                }
                return Some(format!(
                    "guardrail \"{}\" at {}: {cause}",
                    guard.name, hook.url
                ));
            }
        };
        let shadow = guard.shadowing();
        let enforce = guard.action != Action::Warn && !shadow;
        let word = match (answer.action, enforce) {
            (WebhookAction::Allow, _) => "warn",
            (_, false) if shadow => SHADOW,
            (_, false) => "warn",
            (WebhookAction::Block, true) => "block",
            (WebhookAction::Mask, true) => "mask",
        };
        let mut kinds: BTreeMap<&str, usize> = BTreeMap::new();
        for f in &answer.findings {
            *kinds.entry(f.kind.as_str()).or_default() += 1;
        }
        if kinds.is_empty() && answer.action != WebhookAction::Allow {
            kinds.insert("unspecified", 1);
        }
        self.audit
            .extend(kinds.iter().map(|(kind, n)| entry(kind, word, *n)));
        match (answer.action, enforce) {
            (WebhookAction::Block, true) if self.blocked.is_none() => {
                // Built from the finding kinds only. The vendor's reason is free text that may quote the
                // prompt, and this message ends up in client logs, so it is not passed on.
                let what: Vec<String> = kinds.iter().map(|(k, n)| format!("{k} ({n})")).collect();
                self.blocked = Some(Blocked {
                    guardrail: guard.name.clone(),
                    message: format!(
                        "Guardrail \"{}\" refused this request: the guardrail service found {}. Remove it and send the request again.",
                        guard.name,
                        what.join(", ")
                    ),
                });
            }
            (WebhookAction::Mask, true) => {
                for (part, masked) in sent
                    .messages
                    .iter()
                    .zip(answer.masked_messages.into_iter().flatten())
                {
                    if masked != part.text {
                        if let Some(slot) = self.body.pointer_mut(&part.path) {
                            *slot = Value::String(masked);
                            self.changed = true;
                        }
                    }
                }
            }
            _ => {}
        }
        None
    }
}

// ---------------------------------------------------------------------------------------------------------
// Backtest
// ---------------------------------------------------------------------------------------------------------

/// The guardrails a policy file defines under `guardrails:`, whether or not a rule uses them yet, so a new one can
/// be backtested before any request meets it.
pub fn defined_in(policy_text: &str) -> Result<Vec<Guardrail>, Vec<String>> {
    #[derive(Deserialize)]
    struct Only {
        #[serde(default)]
        guardrails: Vec<GuardrailFile>,
    }
    let only: Only = crate::config::from_yaml(policy_text)
        .map_err(|err| vec![format!("the policy's guardrails: could not be read: {err}")])?;
    guardrails(&only.guardrails)
}

/// One example to backtest on: a request body, and whether the guardrail should find something in it.
#[derive(Clone, Debug, PartialEq)]
pub struct Sample {
    pub id: String,
    pub body: Value,
    pub expect: Option<bool>,
}

/// Reads a corpus file: one JSON object per line, `{"text": "..."}` or `{"body": {...}}` with an optional `id` and
/// an optional `expect` (true, false, or a list of kinds, where an empty list is false). Blank lines and lines
/// starting with `#` are skipped, so the detector corpus reads as one.
pub fn corpus(text: &str) -> Result<Vec<Sample>, String> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let n = i + 1;
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let row: Value = serde_json::from_str(line)
            .map_err(|err| format!("line {n} is not a JSON object: {err}"))?;
        out.push(sample(&row, n).map_err(|why| format!("line {n}: {why}"))?);
    }
    Ok(out)
}

/// One corpus row, from a file or from the admin API. `n` names it when it has no `id`.
pub fn sample(row: &Value, n: usize) -> Result<Sample, String> {
    let body = match (row.get("text"), row.get("body")) {
        (Some(Value::String(text)), None) => json_user(text),
        (None, Some(body @ Value::Object(_))) => body.clone(),
        _ => {
            return Err(
                "give either \"text\" (a string) or \"body\" (a request body object), not both"
                    .into(),
            );
        }
    };
    let expect = match row.get("expect") {
        None | Some(Value::Null) => None,
        Some(Value::Bool(b)) => Some(*b),
        Some(Value::Array(kinds)) => Some(!kinds.is_empty()),
        Some(_) => return Err("expect is true, false, or a list of kinds".into()),
    };
    let id = match row.get("id") {
        Some(Value::String(id)) => id.clone(),
        Some(Value::Number(id)) => id.to_string(),
        _ => n.to_string(),
    };
    Ok(Sample { id, body, expect })
}

fn json_user(text: &str) -> Value {
    serde_json::json!({"messages": [{"role": "user", "content": text}]})
}

/// What a guardrail would have done on a set of examples. Holds no matched text: each sample span is masked.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Backtest {
    pub guardrail: String,
    pub detector: String,
    pub requests: usize,
    /// Requests it would have found something in, so blocked, masked or warned about by its action.
    pub hits: usize,
    pub kinds: BTreeMap<String, usize>,
    pub samples: Vec<SampleSpan>,
    /// Set when at least one example says what it expects.
    pub labelled: Option<Labelled>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SampleSpan {
    pub id: String,
    pub kind: String,
    pub path: String,
    /// The matched text with all but its first and last two characters replaced by `*`.
    pub masked: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Labelled {
    pub examples: usize,
    pub true_positives: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
    pub true_negatives: usize,
    /// Percent of the labelled requests it hit that should be hit.
    pub precision: f64,
    /// Percent of the labelled requests that should be hit that it hit.
    pub recall: f64,
}

/// How many sample spans a backtest shows.
const SAMPLE_SPANS: usize = 20;

fn masked_span(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= 6 {
        return "*".repeat(chars.len());
    }
    let n = chars.len();
    format!(
        "{}{}{}",
        chars[..2].iter().collect::<String>(),
        "*".repeat((n - 4).min(32)),
        chars[n - 2..].iter().collect::<String>()
    )
}

/// Runs a guardrail that works inside Gantry (secrets, pii, regex, keywords) over examples, as its rule would on
/// requests. A vendor or webhook guardrail is refused: a backtest would send every example to the service.
pub fn backtest(guard: &Guardrail, samples: &[Sample]) -> Result<Backtest, String> {
    let detector = match &guard.check {
        Check::Secrets => SECRETS,
        Check::Pii => PII,
        Check::Custom(custom) => custom.detector,
        Check::Webhook(hook) => {
            return Err(format!(
                "guardrail \"{}\" is a {} guardrail. A backtest runs Gantry's own detectors (secrets, pii, regex, keywords) and would send every example to the service; try it with action: warn or shadow_until instead.",
                guard.name,
                hook.vendor.name()
            ));
        }
    };
    let mut report = Backtest {
        guardrail: guard.name.clone(),
        detector: detector.to_string(),
        requests: samples.len(),
        hits: 0,
        kinds: BTreeMap::new(),
        samples: Vec::new(),
        labelled: None,
    };
    let (mut tp, mut fp, mut fneg, mut tn) = (0, 0, 0, 0);
    for sample in samples {
        let parts = text_parts(&sample.body);
        let builtin = if matches!(guard.check, Check::Secrets | Check::Pii) {
            scan(&parts)?
        } else {
            Vec::new()
        };
        let found = guard.findings(&parts, &builtin);
        let hit = !found.is_empty();
        report.hits += usize::from(hit);
        for f in &found {
            *report.kinds.entry(f.kind.to_string()).or_default() += 1;
            if report.samples.len() < SAMPLE_SPANS {
                let text = parts
                    .iter()
                    .find(|p| p.path == f.path)
                    .and_then(|p| p.text.get(f.span.clone()))
                    .unwrap_or_default();
                report.samples.push(SampleSpan {
                    id: sample.id.clone(),
                    kind: f.kind.to_string(),
                    path: f.path.clone(),
                    masked: masked_span(text),
                });
            }
        }
        match (sample.expect, hit) {
            (Some(true), true) => tp += 1,
            (Some(false), true) => fp += 1,
            (Some(true), false) => fneg += 1,
            (Some(false), false) => tn += 1,
            (None, _) => {}
        }
    }
    let examples = tp + fp + fneg + tn;
    if examples > 0 {
        let percent = |n: usize, of: usize| {
            if of == 0 {
                100.0
            } else {
                100.0 * n as f64 / of as f64
            }
        };
        report.labelled = Some(Labelled {
            examples,
            true_positives: tp,
            false_positives: fp,
            false_negatives: fneg,
            true_negatives: tn,
            precision: percent(tp, tp + fp),
            recall: percent(tp, tp + fneg),
        });
    }
    Ok(report)
}

/// `7d`, `24h` or `30m` as seconds, for `--since`.
pub fn since_seconds(text: &str) -> Result<u64, String> {
    let (n, unit) = text.split_at(text.len().saturating_sub(1));
    let scale = match unit {
        "d" => 86_400,
        "h" => 3_600,
        "m" => 60,
        _ => 0,
    };
    match n.parse::<u64>() {
        Ok(n) if n > 0 && scale > 0 => Ok(n * scale),
        _ => Err(format!(
            "--since is \"{text}\". Write a number and a unit, such as 7d, 24h or 30m."
        )),
    }
}

/// Why `--since` has nothing to read: the audit log holds no text by design, and this build keeps no request bodies.
pub const NO_CAPTURE: &str = "a backtest over recent traffic reads captured request bodies, and this Gantry keeps none: the audit log holds no prompt text by design. Pass a corpus of examples instead (--corpus <file.jsonl>, or \"corpus\" in the admin API).";

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn guard(name: &str, check: Check, action: Action) -> Guardrail {
        Guardrail {
            name: name.into(),
            action,
            check,
            on: On::REQUEST,
            shadow_until: None,
        }
    }

    #[test]
    fn on_answer_guardrails_read_answers_only_and_on_is_checked()
    -> Result<(), Box<dyn std::error::Error>> {
        let secret = "here is AKIAIOSFODNN7EXAMPLE for you";
        let body = || json!({"messages": [{"role": "assistant", "content": secret}]});
        let mut answer_only = guard("answers", Check::Secrets, Action::Mask);
        answer_only.on = On {
            request: false,
            answer: true,
        };
        let request_only = guard("requests", Check::Secrets, Action::Block);
        let guards = [answer_only, request_only];
        let on_request = check(body(), &guards);
        assert!(on_request.blocked.is_some() && !on_request.changed);
        let on_answer = check_reply(body(), &guards);
        assert!(on_answer.blocked.is_none() && on_answer.changed);
        assert!(!on_answer.body.to_string().contains("AKIAIOSFODNN7EXAMPLE"));
        assert_eq!(on_answer.audit[0].guardrail, "answers");
        let file = |on: &str| -> Result<GuardrailFile, serde_saphyr::Error> {
            crate::config::from_yaml(&format!("name: g\ntype: secrets\naction: block\n{on}"))
        };
        let both = guardrails(&[file("on: [request, answer]")?]).map_err(|e| e.join(" "))?;
        assert_eq!(
            both[0].on,
            On {
                request: true,
                answer: true
            }
        );
        assert_eq!(
            guardrails(&[file("")?]).map_err(|e| e.join(" "))?[0].on,
            On::REQUEST
        );
        let empty = guardrails(&[file("on: []")?])
            .err()
            .unwrap_or_default()
            .join(" ");
        assert!(empty.contains("empty on: list"), "{empty}");
        assert!(file("on: [replies]").is_err());
        Ok(())
    }

    fn user(text: &str) -> Value {
        json!({"model": "gpt-4o-mini", "messages": [{"role": "user", "content": text}]})
    }

    fn kinds(text: &str) -> Result<Vec<String>, String> {
        let parts = [TextPart {
            path: "/x".into(),
            role: "user".into(),
            text: text.into(),
        }];
        Ok(scan(&parts)?.iter().map(|f| f.kind.to_string()).collect())
    }

    const GH: &str = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    const PEM: &str =
        "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD9\n-----END RSA PRIVATE KEY-----";

    #[test]
    fn each_secret_kind_is_found() -> TestResult {
        let gantry = format!("gantry_{}", "ab".repeat(32));
        let cases = [
            ("key AKIAIOSFODNN7EXAMPLE here", "aws_access_key"),
            (PEM, "private_key"),
            (GH, "github_token"),
            ("github_pat_11ABCDEFG0123456789_abcdefghij", "github_token"),
            ("xoxb-1234567890-abcdefghij", "slack_token"),
            ("sk-proj-abcdefghijklmnopqrstuvwx", "openai_project_key"),
            ("sk-ant-api03-abcdefghijklmnopqrstu", "anthropic_key"),
            ("sk-abcdefghijklmnopqrstuvwx", "api_key"),
            ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123def", "jwt"),
            (&gantry, "gantry_key"),
        ];
        for (text, kind) in cases {
            assert_eq!(kinds(text)?, [kind], "{text}");
        }
        assert!(kinds("ask- the AKIA team, sk-short, gantry_xyz")?.is_empty());
        Ok(())
    }

    /// The kinds v2 added. Values are built at run time so no file holds one whole.
    #[test]
    fn each_cloud_and_service_key_kind_is_found() -> TestResult {
        let hex40 = "0123456789abcdef0123456789abcdef01234567";
        let b64 = "q".repeat(86);
        let cases = [
            (
                format!(r#"{{"type": "service_account", "private_key_id": "{hex40}"}}"#),
                "gcp_service_account_key",
            ),
            (
                format!("key=AIza{}", "Sy0_x-".repeat(5) + "abcde"),
                "gcp_api_key",
            ),
            (
                format!(
                    "DefaultEndpointsProtocol=https;AccountName=acme;AccountKey={b64}==;EndpointSuffix=core.windows.net"
                ),
                "azure_connection_string",
            ),
            (
                format!(
                    "Endpoint=sb://acme.servicebus.windows.net/;SharedAccessKeyName=root;SharedAccessKey={}=",
                    "Ab1".repeat(14)
                ),
                "azure_connection_string",
            ),
            (
                format!("STRIPE={}_live_{}", "sk", "a1B2".repeat(6)),
                "stripe_key",
            ),
            (format!("{}_test_{}", "rk", "Zz9".repeat(10)), "stripe_key"),
            (
                format!("TWILIO_API_KEY=SK{}", "0a".repeat(16)),
                "twilio_api_key",
            ),
            (
                format!("SG.{}.{}", "a".repeat(22), "b-".repeat(21) + "c"),
                "sendgrid_key",
            ),
            (
                format!("sk-svcacct-{}", "x".repeat(30)),
                "openai_project_key",
            ),
            (
                format!("sk-ant-admin01-{}", "y".repeat(30)),
                "anthropic_key",
            ),
            (
                "DATABASE_URL=postgres://app:s3cr3t-Pa55@db.internal:5432/app".to_string(),
                "database_url",
            ),
            (
                "mongodb+srv://svc:hunter2x@cluster0.example.net/prod".to_string(),
                "database_url",
            ),
        ];
        for (text, kind) in &cases {
            assert_eq!(kinds(text)?, [*kind], "{text}");
        }
        let not_secrets = [
            "postgres://db.internal:5432/app".to_string(),
            "postgres://app@db.internal:5432/app".to_string(),
            "postgres://app:${DB_PASSWORD}@db.internal/app".to_string(),
            "mysql://root:password@localhost/test".to_string(),
            format!("pk_live_{}", "a1B2".repeat(6)),
            format!("AC{}", "0a".repeat(16)),
            format!("{}_live_short", "sk"),
            "AccountKey=<your key>".to_string(),
            format!(r#""private_key_id": "{}""#, "0123"),
        ];
        for text in &not_secrets {
            assert!(kinds(text)?.is_empty(), "{text}: {:?}", kinds(text));
        }
        Ok(())
    }

    fn custom_guard(yaml: &str) -> Result<Guardrail, String> {
        let def: GuardrailFile = crate::config::from_yaml(yaml).map_err(|e| e.to_string())?;
        guardrails(&[def])
            .map_err(|e| e.join(" "))?
            .pop()
            .ok_or_else(|| "no guardrail".to_string())
    }

    #[test]
    fn a_regex_guardrail_blocks_masks_and_warns_with_entry_names() -> TestResult {
        let base = "name: tickets\ntype: regex\npatterns:\n  ticket_id: 'TKT-[0-9]{6}'\n  employee_id: '\\bE[0-9]{7}\\b'\n";
        let body = || user("see TKT-123456 and E1234567, not TKT-12");
        let block = custom_guard(&format!("{base}action: block\n"))?;
        let v = check(body(), std::slice::from_ref(&block));
        let blocked = v.blocked.ok_or("not blocked")?;
        assert!(
            blocked.message.contains("ticket_id (1)")
                && blocked.message.contains("employee_id (1)")
        );
        assert!(!blocked.message.contains("TKT-123456"));
        assert_eq!(v.audit.len(), 2);
        assert_eq!(v.audit[0].detector, "regex");
        let mask = custom_guard(&format!("{base}action: mask\n"))?;
        let v = check(body(), &[mask]);
        assert_eq!(
            v.body["messages"][0]["content"],
            "see [MASKED ticket_id] and [MASKED employee_id], not TKT-12"
        );
        let warn = custom_guard(&format!("{base}action: warn\non: [request, answer]\n"))?;
        let reply = json!({"messages": [{"role": "assistant", "content": "TKT-000001"}]});
        let v = check_reply(reply, &[warn]);
        assert!(v.blocked.is_none() && !v.changed);
        assert_eq!(
            (v.audit[0].kind.as_str(), v.audit[0].action),
            ("ticket_id", "warn")
        );
        Ok(())
    }

    #[test]
    fn keywords_follow_case_and_word_boundary_options() -> TestResult {
        let g = |opts: &str| {
            custom_guard(&format!(
                "name: words\ntype: keywords\naction: block\nkeywords:\n  codename: [Project Falcon, bluebird, C++]\n{opts}"
            ))
        };
        let hits = |guard: &Guardrail, text: &str| {
            check(user(text), std::slice::from_ref(guard))
                .blocked
                .is_some()
        };
        let default = g("")?;
        assert!(hits(&default, "status of project   falcon?"));
        assert!(hits(&default, "the BlueBird launch"));
        assert!(hits(&default, "written in C++ mostly"));
        assert!(!hits(&default, "bluebirds are birds"));
        assert!(!hits(&default, "projectfalcon"));
        let exact = g("case_sensitive: true\n")?;
        assert!(!hits(&exact, "the BlueBird launch"));
        assert!(hits(&exact, "the bluebird launch"));
        let inside = g("whole_word: false\n")?;
        assert!(hits(&inside, "bluebirds are birds"));
        let v = check(user("Project Falcon"), &[default]);
        assert_eq!(v.audit[0].kind, "codename");
        assert_eq!(v.audit[0].detector, "keywords");
        Ok(())
    }

    #[test]
    fn bad_custom_detectors_are_each_explained() {
        let cases = [
            ("type: regex\naction: block", "needs patterns"),
            (
                "type: regex\naction: block\npatterns: {a: '(x)'}",
                "capturing group",
            ),
            (
                "type: regex\naction: block\npatterns: {a: 'x*'}",
                "matches empty text",
            ),
            (
                "type: regex\naction: block\npatterns: {a: '(?=x)'}",
                "does not compile",
            ),
            (
                "type: regex\naction: block\npatterns: {a: 'x{1000}{1000}'}",
                "does not compile",
            ),
            (
                "type: regex\naction: block\npatterns: {'bad name': x}",
                "entry name",
            ),
            ("type: keywords\naction: block\nkeywords: {a: []}", "empty"),
            (
                "type: keywords\naction: block\nkeywords: {a: ['  ']}",
                "empty",
            ),
            ("type: keywords\naction: block", "needs keywords"),
            (
                "type: secrets\naction: block\npatterns: {a: x}",
                "patterns does not apply",
            ),
            (
                "type: regex\naction: block\npatterns: {a: x}\nwhole_word: true",
                "whole_word does not apply",
            ),
            (
                "type: secrets\naction: block\nshadow_until: next week",
                "shadow_until",
            ),
        ];
        for (yaml, want) in cases {
            let got = custom_guard(&format!("name: g\n{yaml}"))
                .err()
                .unwrap_or_default();
            assert!(got.contains(want), "{yaml}: {got}");
        }
    }

    #[test]
    fn a_guardrail_in_its_shadow_period_records_and_never_enforces() -> TestResult {
        let secret = "here is AKIAIOSFODNN7EXAMPLE";
        let future =
            custom_guard("name: g\ntype: secrets\naction: block\nshadow_until: 2999-01-01\n")?;
        let v = check(user(secret), std::slice::from_ref(&future));
        assert!(v.blocked.is_none() && !v.changed);
        assert_eq!(v.audit[0].action, SHADOW);
        assert_eq!(v.audit[0].count, 1);
        let masker = custom_guard(
            "name: g\ntype: secrets\naction: mask\nshadow_until: 2999-01-01T00:00:00Z\n",
        )?;
        assert!(!check(user(secret), &[masker]).changed);
        let past =
            custom_guard("name: g\ntype: secrets\naction: block\nshadow_until: 2020-01-01\n")?;
        let v = check(user(secret), &[past]);
        assert!(v.blocked.is_some());
        assert_eq!(v.audit[0].action, "block");
        // A remote guardrail in shadow: the service's block is recorded, not obeyed.
        let mut remote = hook(OnFailure::FailClosed, Action::Block);
        remote.shadow_until = Some("2999-01-01".into());
        let mut v = check(two_messages(), &[]);
        let sent = WebhookRequest::new("d", "p", "t", "/v1/chat/completions", &v.body);
        v.merge_webhook(
            &remote,
            &sent,
            Ok(br#"{"action":"block","findings":[{"kind":"pii"}]}"#),
        );
        assert!(v.blocked.is_none());
        assert_eq!(v.audit[0].action, SHADOW);
        Ok(())
    }

    #[test]
    fn a_backtest_counts_hits_masks_samples_and_scores_labels() -> TestResult {
        let guard = custom_guard(
            "name: tickets\ntype: regex\naction: block\npatterns:\n  ticket_id: 'TKT-[0-9]{6}'\n",
        )?;
        let rows = concat!(
            "# a comment\n",
            "{\"text\": \"fix TKT-123456 today\", \"expect\": true}\n",
            "{\"text\": \"nothing here\", \"expect\": false}\n",
            "{\"text\": \"TKT-999999 and TKT-000001\", \"expect\": [\"ticket_id\"]}\n",
            "{\"text\": \"ticket TKT 123456\", \"expect\": true}\n",
            "{\"text\": \"old TKT-111111\", \"expect\": false}\n",
            "{\"id\": \"raw\", \"body\": {\"messages\": [{\"role\": \"user\", \"content\": \"TKT-222222\"}]}}\n",
        );
        let samples = corpus(rows)?;
        let report = backtest(&guard, &samples)?;
        assert_eq!((report.requests, report.hits), (6, 4));
        assert_eq!(report.kinds.get("ticket_id"), Some(&5));
        assert_eq!(report.samples[0].masked, "TK******56");
        assert_eq!(report.samples[0].path, "/messages/0/content");
        assert_eq!(report.samples.last().map(|s| s.id.as_str()), Some("raw"));
        let json = serde_json::to_string(&report)?;
        assert!(!json.contains("TKT-123456"), "{json}");
        let labelled = report.labelled.ok_or("no labels")?;
        assert_eq!(
            (
                labelled.true_positives,
                labelled.false_positives,
                labelled.false_negatives,
                labelled.true_negatives
            ),
            (2, 1, 1, 1)
        );
        assert!((labelled.precision - 200.0 / 3.0).abs() < 1e-9);
        assert!((labelled.recall - 200.0 / 3.0).abs() < 1e-9);
        assert!(corpus("{\"text\": 1}").is_err());
        assert!(corpus("not json").is_err());
        assert!(backtest(&hook(OnFailure::FailOpen, Action::Block), &samples).is_err());
        assert_eq!(since_seconds("7d")?, 604_800);
        assert!(since_seconds("7w").is_err() && since_seconds("d").is_err());
        let defined = defined_in(
            "version: 1\nproviders: []\nrules: []\nguardrails:\n  - name: s\n    type: secrets\n    action: warn\n",
        )
        .map_err(|e| e.join(" "))?;
        assert_eq!(defined[0].name, "s");
        Ok(())
    }

    /// Shapes the gantry-detectors-v1 corpus found missed: a PGP secret key, a rotating Slack app's refresh token,
    /// an IBAN followed by an uppercase word, and a labelled value written as key=value in a log line.
    #[test]
    fn shapes_the_corpus_found_missed_are_found() -> TestResult {
        let pgp = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQOYBGabcdef\n=abcd\n-----END PGP PRIVATE KEY BLOCK-----";
        let cases = [
            (pgp, "private_key"),
            ("token=xoxe-1-abcdefghijklmnopqrstuvwxyz", "slack_token"),
            ("IBAN GB82WEST12345698765432 BIC NWBKGB2L", "iban"),
            ("IBAN GB82 WEST 1234 5698 7654 32 BIC COBADEFFXXX", "iban"),
            ("chart opened MRN=MR-5344440", "medical_record_number"),
            ("intake DOB=12/21/1971", "date_of_birth"),
        ];
        for (text, kind) in cases {
            assert_eq!(kinds(text)?, [kind], "{text}");
        }
        let part = |text: &str| TextPart {
            path: "/x".into(),
            role: "user".into(),
            text: text.into(),
        };
        // The whole block is one finding, so masking leaves none of the key behind.
        assert_eq!(scan(&[part(pgp)])?[0].span, 0..pgp.len());
        // The word after the IBAN is not part of it, so masking does not eat it.
        let wire = "IBAN GB82WEST12345698765432 BIC NWBKGB2L";
        assert_eq!(scan(&[part(wire)])?[0].span, 5..27);
        assert!(kinds("IBAN GB82WEST12345698765433 BIC NWBKGB2L")?.is_empty());
        Ok(())
    }

    #[test]
    fn each_pii_kind_is_found_and_checksums_are_checked() -> TestResult {
        let found = [
            ("mail maya.cohen+x@corp.example.co.il now", "email_address"),
            ("call +1 415 555 2671", "phone_number"),
            ("call +972-54-123-4567", "phone_number"),
            ("call (415) 555-2671", "phone_number"),
            ("call 054-1234567", "phone_number"),
            ("card 4111 1111 1111 1111 ok", "credit_card"),
            ("card 4111-1111-1111-1111", "credit_card"),
            ("iban GB82 WEST 1234 5698 7654 32 ok", "iban"),
            ("iban IL620108000000099999999", "iban"),
            ("id 123456782", "israeli_id"),
            ("ssn 123-45-6789", "us_ssn"),
            ("patient MRN: A1234567 admitted", "medical_record_number"),
            ("Medical record number 00482913", "medical_record_number"),
            ("DOB: 04/12/1987", "date_of_birth"),
            ("date of birth 1987-04-12", "date_of_birth"),
        ];
        for (text, kind) in found {
            assert_eq!(kinds(text)?, [kind], "{text}");
        }
        for text in [
            "card 4111 1111 1111 1112",
            "iban GB82 WEST 1234 5698 7654 33",
            "id 123456789",
            "id 000000000",
            "ssn 000-45-6789 666-12-3456 912-12-3456",
            "version 1.2.3 on 2026-11-13, 42 items",
        ] {
            assert!(kinds(text)?.is_empty(), "{text}");
        }
        Ok(())
    }

    #[test]
    fn text_parts_cover_both_formats_and_nothing_else() {
        let openai = json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "sys"},
                {"role": "user", "content": [
                    {"type": "image_url", "image_url": {"url": "a@b.com"}},
                    {"type": "text", "text": "hi"}
                ]},
                {"role": "assistant", "content": null, "tool_calls": [{"function": {"arguments": "x"}}]}
            ],
            "user": "a@b.com"
        });
        let paths: Vec<(String, String)> = text_parts(&openai)
            .into_iter()
            .map(|p| (p.path, p.text))
            .collect();
        assert_eq!(
            paths,
            [
                ("/messages/0/content".into(), "sys".into()),
                ("/messages/1/content/1/text".into(), "hi".into())
            ]
        );
        let anthropic = json!({
            "model": "claude",
            "system": [{"type": "text", "text": "be brief"}],
            "messages": [{"role": "user", "content": [{"type": "text", "text": "q"}]}]
        });
        let parts = text_parts(&anthropic);
        assert_eq!(parts[0].path, "/system/0/text");
        assert_eq!(parts[0].role, "system");
        assert_eq!(parts[1].path, "/messages/0/content/0/text");
        assert_eq!(text_parts(&json!({"system": "s"}))[0].path, "/system");
    }

    #[test]
    fn text_parts_cover_tool_results_text_documents_and_search_results() {
        let body = json!({
            "messages": [{"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t1", "content": "r1"},
                {"type": "tool_result", "tool_use_id": "t2", "content": [{"type": "text", "text": "r2"}]},
                {"type": "document", "source": {"type": "text", "media_type": "text/plain", "data": "d1"}},
                {"type": "document", "source": {"type": "content", "content": [{"type": "text", "text": "d2"}]}},
                {"type": "document", "source": {"type": "base64", "data": "JVBERi0="}},
                {"type": "search_result", "source": "s", "title": "t", "content": [{"type": "text", "text": "s1"}]}
            ]}]
        });
        let parts: Vec<(String, String)> = text_parts(&body)
            .into_iter()
            .map(|p| (p.path, p.text))
            .collect();
        let want = [
            ("/messages/0/content/0/content", "r1"),
            ("/messages/0/content/1/content/0/text", "r2"),
            ("/messages/0/content/2/source/data", "d1"),
            ("/messages/0/content/3/source/content/0/text", "d2"),
            ("/messages/0/content/5/content/0/text", "s1"),
        ];
        assert_eq!(
            parts,
            want.map(|(p, t)| (p.to_string(), t.to_string())).to_vec()
        );
    }

    #[test]
    fn text_parts_cover_responses_and_embeddings_input() {
        let paths = |body: Value| -> Vec<String> {
            text_parts(&body).into_iter().map(|p| p.path).collect()
        };
        let responses = json!({
            "instructions": "be brief",
            "input": [
                {"role": "user", "content": [{"type": "input_text", "text": "q"}, {"type": "input_image", "image_url": "x"}]},
                {"type": "function_call_output", "call_id": "c", "output": "{}"}
            ]
        });
        // QA11-5: a tool's output, as a string or text parts, and a stored prompt's variables are read too.
        assert_eq!(
            paths(responses),
            [
                "/instructions",
                "/input/0/content/0/text",
                "/input/1/output"
            ]
        );
        assert_eq!(
            paths(
                json!({"input": [{"type": "function_call_output", "call_id": "c", "output": [{"type": "input_text", "text": "t"}]}]})
            ),
            ["/input/0/output/0/text"]
        );
        assert_eq!(
            paths(json!({"input": "x", "prompt": {"id": "p", "variables": {"a/b": "v", "n": 3}}})),
            ["/input", "/prompt/variables/a~1b"]
        );
        assert_eq!(paths(json!({"input": "hello"})), ["/input"]);
        assert_eq!(
            paths(json!({"input": ["a", "b"]})),
            ["/input/0", "/input/1"]
        );
        assert!(paths(json!({"input": [[1, 2, 3]]})).is_empty());
    }

    #[test]
    fn block_refuses_and_records_without_the_matched_text() {
        let body = user("deploy with AKIAIOSFODNN7EXAMPLE and AKIAIOSFODNN7EXAMPLF");
        let verdict = check(
            body.clone(),
            &[guard("no-secrets", Check::Secrets, Action::Block)],
        );
        let blocked = verdict.blocked.clone().unwrap_or_else(|| Blocked {
            guardrail: "none".into(),
            message: String::new(),
        });
        assert_eq!(blocked.guardrail, "no-secrets");
        assert!(
            blocked.message.contains("aws_access_key (2)"),
            "{}",
            blocked.message
        );
        assert!(blocked.message.contains("/messages/0/content"));
        // UX11 m20: the place is said in words first, then as the JSON pointer.
        assert!(
            blocked
                .message
                .contains("in message 1 (/messages/0/content"),
            "{}",
            blocked.message
        );
        assert_eq!(
            place("/system/1/text"),
            "in the system prompt (/system/1/text)"
        );
        assert_eq!(
            place("/input/2/content/0/text"),
            "in input item 3 (/input/2/content/0/text)"
        );
        assert_eq!(place("/input"), "in the input (/input)");
        assert!(!format!("{:?}", verdict.audit).contains("AKIA"));
        assert!(!blocked.message.contains("AKIA"));
        assert_eq!(
            verdict.audit,
            [AuditEntry {
                guardrail: "no-secrets".into(),
                detector: "secrets".into(),
                kind: "aws_access_key".into(),
                action: "block",
                count: 2
            }]
        );
        assert!(!verdict.changed);
        assert_eq!(BLOCKED_CODE, "guardrail_blocked");
    }

    #[test]
    fn mask_changes_only_the_matched_spans_and_keeps_valid_json() -> TestResult {
        let body = json!({
            "model": "claude",
            "system": "Reply to \"maya@corp.com\".",
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": "Mail a@b.io or c@d.io, key sk-abcdefghijklmnopqrstuvwxyz \u{05e9}\u{05dc}\u{05d5}\u{05dd}"}
            ]}],
            "max_tokens": 10
        });
        let verdict = check(
            body,
            &[
                guard("pii", Check::Pii, Action::Mask),
                guard("pii-again", Check::Pii, Action::Mask),
                guard("keys", Check::Secrets, Action::Mask),
            ],
        );
        assert!(verdict.changed && verdict.blocked.is_none());
        let reparsed: Value = serde_json::from_str(&serde_json::to_string(&verdict.body)?)?;
        assert_eq!(
            reparsed,
            json!({
                "model": "claude",
                "system": "Reply to \"[MASKED email_address]\".",
                "messages": [{"role": "user", "content": [
                    {"type": "text", "text": "Mail [MASKED email_address] or [MASKED email_address], key [MASKED api_key] \u{05e9}\u{05dc}\u{05d5}\u{05dd}"}
                ]}],
                "max_tokens": 10
            })
        );
        assert_eq!(verdict.audit.len(), 3);
        Ok(())
    }

    #[test]
    fn a_private_key_block_is_masked_whole() {
        let verdict = check(
            user(&format!("before {PEM} after")),
            &[guard("k", Check::Secrets, Action::Mask)],
        );
        assert_eq!(
            verdict.body.pointer("/messages/0/content"),
            Some(&json!("before [MASKED private_key] after"))
        );
    }

    #[test]
    fn warn_forwards_unchanged_and_records() {
        let body = user("my card is 4111111111111111");
        let verdict = check(body.clone(), &[guard("pii", Check::Pii, Action::Warn)]);
        assert_eq!(verdict.body, body);
        assert!(!verdict.changed && verdict.blocked.is_none());
        assert_eq!(verdict.audit[0].kind, "credit_card");
        assert_eq!(verdict.audit[0].action, "warn");
    }

    #[test]
    fn a_block_wins_over_a_mask_and_nothing_is_changed() {
        let body = user("a@b.io AKIAIOSFODNN7EXAMPLE");
        let verdict = check(
            body.clone(),
            &[
                guard("pii", Check::Pii, Action::Mask),
                guard("keys", Check::Secrets, Action::Block),
            ],
        );
        assert!(verdict.blocked.is_some());
        assert_eq!(verdict.body, body);
    }

    #[test]
    fn a_one_mib_prompt_is_checked_quickly_even_when_hostile() -> TestResult {
        let mut prose = String::new();
        while prose.len() < 1 << 20 {
            prose.push_str("The quarterly numbers for team 42 look fine, see ticket 2026-11-13 and r\u{00e9}sum\u{00e9}. ");
        }
        prose.push_str(" AKIAIOSFODNN7EXAMPLE a@b.io");
        let hostile = [
            prose,
            "a@".repeat(1 << 19),
            "-----BEGIN PRIVATE KEY-----".repeat(40_000),
            "4".repeat(1 << 20),
            "1-".repeat(1 << 19),
            "1-a.".repeat(1 << 18),
            "1.".repeat(1 << 19),
            "1 ".repeat(1 << 19),
            "+1 ".repeat(350_000),
            "A1".repeat(1 << 19),
            "x.".repeat(1 << 19) + "@",
            "eyJaaaaa.".repeat(120_000),
            "ghp_".repeat(1 << 18),
            "xoxb-".repeat(200_000),
            "sk-".repeat(350_000),
        ];
        let guards = [
            guard("s", Check::Secrets, Action::Mask),
            guard("p", Check::Pii, Action::Mask),
        ];
        for text in hostile {
            let body = user(&text);
            let started = std::time::Instant::now();
            let verdict = check(body, &guards);
            let took = started.elapsed();
            eprintln!("{} bytes checked in {took:?}", text.len());
            // Loose on purpose: debug builds on a busy machine. A backtracking blowup takes seconds or more.
            assert!(took.as_millis() < 500, "took {took:?}");
            assert!(verdict.blocked.is_none());
        }
        Ok(())
    }

    #[test]
    fn the_policy_shape_parses_and_rules_resolve_names() -> TestResult {
        #[derive(Deserialize)]
        struct File {
            guardrails: Vec<GuardrailFile>,
            rules: Vec<RuleFile>,
        }
        #[derive(Deserialize)]
        struct RuleFile {
            name: String,
            guardrails: Vec<String>,
        }
        let text = "\
guardrails:
  - name: no-secrets
    type: secrets
    action: block
  - name: mask-pii
    type: pii
    action: mask
  - name: lasso
    type: webhook
    url: https://guard.example.com/check
    timeout_ms: 300
    on_failure: fail_closed
  - name: sidecar
    type: webhook
    url: http://127.0.0.1:9100/
    action: warn
    on_failure: fail_open
rules:
  - name: everyone
    guardrails: [no-secrets, mask-pii, lasso]
";
        let file: File = crate::config::from_yaml(text)?;
        let defined = guardrails(&file.guardrails).map_err(|e| e.join("\n"))?;
        assert_eq!(defined.len(), 4);
        assert_eq!(
            defined[2].check,
            Check::Webhook(Webhook {
                url: "https://guard.example.com/check".into(),
                timeout: Duration::from_millis(300),
                on_failure: OnFailure::FailClosed,
                headers_env: Vec::new(),
                vendor: Vendor::Contract,
                key_env: None,
            })
        );
        assert_eq!(defined[2].action, Action::Block);
        assert!(
            matches!(&defined[3].check, Check::Webhook(w) if w.timeout == Duration::from_millis(1000) && w.url == "http://127.0.0.1:9100")
        );
        let rule = &file.rules[0];
        let names: Vec<String> = for_rule(&rule.name, &rule.guardrails, &defined)?
            .into_iter()
            .map(|g| g.name)
            .collect();
        assert_eq!(names, ["no-secrets", "mask-pii", "lasso"]);
        let missing = for_rule("everyone", &["lakera".into()], &defined)
            .err()
            .unwrap_or_default();
        assert!(
            missing.contains("\"lakera\", which is not defined"),
            "{missing}"
        );
        Ok(())
    }

    #[test]
    fn bad_guardrail_definitions_are_each_explained() -> TestResult {
        let cases = [
            ("name: a\ntype: pii", "has no action"),
            (
                "name: a\ntype: pii\naction: mask\nurl: https://x",
                "belong to a webhook",
            ),
            ("name: a\ntype: webhook\non_failure: fail_open", "no url"),
            (
                "name: a\ntype: webhook\nurl: http://guard.example.com\non_failure: fail_open",
                "must start with https://",
            ),
            (
                "name: a\ntype: webhook\nurl: https://x\non_failure: fail_open\ntimeout_ms: 0",
                "between 1 and 30000",
            ),
            ("name: a\ntype: webhook\nurl: https://x", "add on_failure"),
            (
                "name: a\ntype: webhook\nurl: https://x\non_failure: fail_open\naction: mask",
                "service decides what to mask",
            ),
            ("name: a b\ntype: secrets\naction: block", "letters, digits"),
            (
                "name: a\ntype: secrets\naction: block\nheaders_env: { Authorization: T }",
                "headers_env belong to a webhook",
            ),
            (
                "name: a\ntype: webhook\nurl: https://x\non_failure: fail_open\nheaders_env: { Host: T }",
                "header \"Host\", which a credential cannot use",
            ),
            (
                "name: a\ntype: webhook\nurl: https://x\non_failure: fail_open\nheaders_env: { Authorization: Bearer abc }",
                "not the name of an environment variable",
            ),
        ];
        for (yaml, expected) in cases {
            let def: GuardrailFile = crate::config::from_yaml(yaml)?;
            let text = guardrails(&[def]).err().unwrap_or_default().join("\n");
            assert!(
                text.to_lowercase().contains(&expected.to_lowercase()),
                "{yaml}: {text}"
            );
        }
        let one: GuardrailFile = crate::config::from_yaml("name: a\ntype: secrets\naction: block")?;
        let twice = guardrails(&[one.clone(), one])
            .err()
            .unwrap_or_default()
            .join("\n");
        assert!(twice.contains("defined twice"), "{twice}");
        assert!(
            crate::config::from_yaml::<GuardrailFile>("name: a\ntype: dlp\naction: block").is_err()
        );
        let def: GuardrailFile = crate::config::from_yaml(
            "name: v\ntype: webhook\nurl: https://x\non_failure: fail_closed\nheaders_env: { Authorization: GUARD_TOKEN }",
        )?;
        let hooks = guardrails(&[def]).map_err(|e| e.join("\n"))?;
        let Check::Webhook(hook) = &hooks[0].check else {
            return Err("not a webhook".into());
        };
        assert_eq!(
            hook.headers_env,
            [("Authorization".to_string(), "GUARD_TOKEN".to_string())]
        );
        let rule = crate::policy::Rule {
            name: "r".into(),
            line: 0,
            who: crate::policy::Who::Any,
            models: crate::policy::Models::Any,
            guardrails: hooks,
            limits: crate::policy::Limits::default(),
            passthrough: Vec::new(),
            tools: Vec::new(),
            mcp: crate::mcp::McpRule::default(),
        };
        let missing = unset_webhook_env(std::slice::from_ref(&rule), &|_| false).join("\n");
        assert!(
            missing.contains("GUARD_TOKEN, which is not set"),
            "{missing}"
        );
        assert!(unset_webhook_env(&[rule], &|_| true).is_empty());
        Ok(())
    }

    #[test]
    fn vendor_guardrails_parse_with_their_defaults_and_bad_ones_are_explained() -> TestResult {
        let parse = |yaml: &str| -> Result<Result<Vec<Guardrail>, String>, serde_saphyr::Error> {
            let def: GuardrailFile = crate::config::from_yaml(yaml)?;
            Ok(guardrails(&[def]).map_err(|e| e.join("\n")))
        };
        let hook_of = |g: &[Guardrail]| match g.first().map(|g| &g.check) {
            Some(Check::Webhook(h)) => Some(h.clone()),
            _ => None,
        };
        let ok = [
            (
                "name: m\ntype: openai_moderation\nkey_env: OPENAI_API_KEY\non_failure: fail_open",
                "https://api.openai.com/v1",
            ),
            (
                "name: l\ntype: lakera\nkey_env: LAKERA_KEY\nproject_id: p1\non_failure: fail_closed",
                "https://api.lakera.ai",
            ),
            (
                "name: b\ntype: bedrock_guardrail\nregion: eu-west-1\nguardrail_id: abc\nguardrail_version: \"1\"\non_failure: fail_closed",
                "https://bedrock-runtime.eu-west-1.amazonaws.com",
            ),
            (
                "name: p\ntype: presidio\nurl: http://127.0.0.1:5002/\nanonymizer_url: http://127.0.0.1:5001\naction: mask\non_failure: fail_closed",
                "http://127.0.0.1:5002",
            ),
            (
                "name: a\ntype: azure_content_safety\nurl: https://x.cognitiveservices.azure.com\nkey_env: AZ\non_failure: fail_closed",
                "https://x.cognitiveservices.azure.com",
            ),
            (
                "name: s\ntype: azure_prompt_shield\nurl: https://x.cognitiveservices.azure.com\nkey_env: AZ\naction: warn\non_failure: fail_open",
                "https://x.cognitiveservices.azure.com",
            ),
            (
                "name: g\ntype: llama_guard\nurl: http://localhost:8000/v1\nmodel: meta-llama/Llama-Guard-3-8B\non_failure: fail_closed",
                "http://localhost:8000/v1",
            ),
        ];
        for (yaml, url) in ok {
            let defined = parse(yaml)?.map_err(|e| format!("{yaml}: {e}"))?;
            let hook = hook_of(&defined).ok_or("not remote")?;
            assert_eq!(hook.url, url, "{yaml}");
        }
        let azure = hook_of(&parse(ok[4].0)?.map_err(|e| e.to_string())?).ok_or("not remote")?;
        assert_eq!(azure.vendor, Vendor::AzureContentSafety { threshold: 4 });
        assert_eq!(azure.key_env.as_deref(), Some("AZ"));
        let bad = [
            (
                "name: m\ntype: openai_moderation\non_failure: fail_open",
                "needs key_env",
            ),
            (
                "name: m\ntype: openai_moderation\nkey_env: K\non_failure: fail_open\naction: mask",
                "cannot mask",
            ),
            (
                "name: m\ntype: openai_moderation\nkey_env: K",
                "add on_failure",
            ),
            (
                "name: m\ntype: openai_moderation\nkey_env: K\non_failure: fail_open\nurl: http://api.example.com",
                "must start with https://",
            ),
            (
                "name: p\ntype: presidio\nurl: http://127.0.0.1:5002\naction: mask\non_failure: fail_open",
                "add anonymizer_url",
            ),
            // QA14-8: a login part makes the host the one after @.
            (
                "name: m\ntype: webhook\nurl: http://127.0.0.1:80@example.com/v1\non_failure: fail_open",
                "login part",
            ),
            (
                "name: p\ntype: presidio\nurl: http://127.0.0.1:5002\nanonymizer_url: http://localhost:@example.com\naction: mask\non_failure: fail_open",
                "login part",
            ),
            (
                "name: p\ntype: presidio\non_failure: fail_open",
                "needs the url",
            ),
            (
                "name: b\ntype: bedrock_guardrail\nregion: us-east-1\nguardrail_id: x\non_failure: fail_open",
                "needs guardrail_version",
            ),
            (
                "name: b\ntype: bedrock_guardrail\nregion: us-east-1\nguardrail_id: x\nguardrail_version: DRAFT\nkey_env: K\non_failure: fail_open",
                "aws_access_key_id",
            ),
            (
                "name: b\ntype: bedrock_guardrail\nregion: us-east-1\nguardrail_id: x\nguardrail_version: DRAFT\naction: mask\non_failure: fail_open",
                "service decides what to mask",
            ),
            (
                "name: a\ntype: azure_content_safety\nurl: https://x\nkey_env: K\nthreshold: 9\non_failure: fail_open",
                "from 0 to 7",
            ),
            (
                "name: g\ntype: llama_guard\nurl: https://x\nmodel: m\nprompt: judge this\non_failure: fail_open",
                "no {conversation}",
            ),
            (
                "name: g\ntype: llama_guard\nurl: https://x\non_failure: fail_open",
                "needs model",
            ),
            (
                "name: s\ntype: secrets\naction: block\nmodel: m",
                "model does not apply to a secrets guardrail",
            ),
            (
                "name: w\ntype: webhook\nurl: https://x\non_failure: fail_open\nkey_env: K",
                "key_env does not apply to a webhook",
            ),
        ];
        for (yaml, expected) in bad {
            let text = parse(yaml)?.err().unwrap_or_default();
            assert!(
                text.to_lowercase().contains(&expected.to_lowercase()),
                "{yaml}: {text}"
            );
        }
        // The credential's variable must be set before Gantry starts, and Bedrock's AWS variables too.
        let rule = |yaml: &str| -> Result<crate::policy::Rule, Box<dyn std::error::Error>> {
            Ok(crate::policy::Rule {
                name: "r".into(),
                line: 0,
                who: crate::policy::Who::Any,
                models: crate::policy::Models::Any,
                guardrails: parse(yaml)?.map_err(|e| e.to_string())?,
                limits: crate::policy::Limits::default(),
                passthrough: Vec::new(),
                tools: Vec::new(),
                mcp: crate::mcp::McpRule::default(),
            })
        };
        let missing = unset_webhook_env(&[rule(ok[0].0)?, rule(ok[2].0)?], &|_| false).join("\n");
        for variable in [
            "OPENAI_API_KEY",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
        ] {
            assert!(
                missing.contains(&format!("{variable}, which is not set")),
                "{missing}"
            );
        }
        Ok(())
    }

    fn hook(on_failure: OnFailure, action: Action) -> Guardrail {
        guard(
            "vendor",
            Check::Webhook(Webhook {
                url: "https://guard.example.com".into(),
                timeout: Duration::from_millis(300),
                on_failure,
                headers_env: Vec::new(),
                vendor: Vendor::Contract,
                key_env: None,
            }),
            action,
        )
    }

    fn two_messages() -> Value {
        json!({
            "model": "claude",
            "system": "be brief",
            "messages": [{"role": "user", "content": [{"type": "text", "text": "I am Maya Cohen"}]}],
            "max_tokens": 5
        })
    }

    #[test]
    fn the_webhook_request_has_exactly_the_contract_fields() -> TestResult {
        let request = WebhookRequest::new(
            "01J0",
            "maya.cohen",
            "payments",
            "/v1/messages",
            &two_messages(),
        );
        assert_eq!(
            serde_json::to_value(&request)?,
            json!({
                "decision_id": "01J0",
                "person": "maya.cohen",
                "team": "payments",
                "model": "claude",
                "route": "/v1/messages",
                "messages": [
                    {"role": "system", "text": "be brief"},
                    {"role": "user", "text": "I am Maya Cohen"}
                ]
            })
        );
        Ok(())
    }

    #[test]
    fn malformed_answers_are_each_explained() {
        let cases: [(&str, &str); 9] = [
            ("not json", "not a valid guardrail answer"),
            ("{}", "missing field `action`"),
            (r#"{"action":"deny"}"#, "unknown variant `deny`"),
            (r#"{"action":"allow","score":1}"#, "unknown field `score`"),
            (r#"{"action":"mask"}"#, "has no masked_messages"),
            (
                r#"{"action":"mask","masked_messages":["a"]}"#,
                "has 1 string and the request had 2 messages",
            ),
            (
                r#"{"action":"block","masked_messages":["a","b"]}"#,
                "only read when action is mask",
            ),
            (
                r#"{"action":"block","findings":[{"kind":"my secret is hunter2"}]}"#,
                "never hold the matched text",
            ),
            (
                r#"{"action":"block","findings":[{"kind":"pii","message":2}]}"#,
                "points at message 2",
            ),
        ];
        for (answer, expected) in cases {
            let err = parse_answer(answer.as_bytes(), 2).err().unwrap_or_default();
            assert!(err.contains(expected), "{answer}: {err}");
        }
        let long = format!(r#"{{"action":"block","reason":"{}"}}"#, "x".repeat(501));
        assert!(parse_answer(long.as_bytes(), 2).is_err());
    }

    #[test]
    fn a_webhook_mask_rewrites_only_the_messages_it_changed() -> TestResult {
        let mut verdict = check(two_messages(), &[]);
        let sent = WebhookRequest::new("d", "p", "t", "/v1/messages", &verdict.body);
        let answer = br#"{"action":"mask","findings":[{"kind":"person_name","message":1}],"masked_messages":["be brief","I am [NAME]"]}"#;
        let failure = verdict.merge_webhook(
            &hook(OnFailure::FailClosed, Action::Block),
            &sent,
            Ok(answer),
        );
        assert_eq!(failure, None);
        let mut expected = two_messages();
        if let Some(slot) = expected.pointer_mut("/messages/0/content/0/text") {
            *slot = json!("I am [NAME]");
        }
        assert_eq!(verdict.body, expected);
        assert!(verdict.changed && verdict.blocked.is_none());
        assert_eq!(verdict.audit[0].kind, "person_name");
        assert_eq!(verdict.audit[0].action, "mask");
        Ok(())
    }

    #[test]
    fn a_webhook_block_and_allow_and_warn_mode() {
        let body = two_messages();
        let sent = WebhookRequest::new("d", "p", "t", "/v1/messages", &body);
        let block = br#"{"action":"block","reason":"prompt injection detected","findings":[{"kind":"prompt_injection"}]}"#;

        let mut verdict = check(body.clone(), &[]);
        verdict.merge_webhook(&hook(OnFailure::FailOpen, Action::Block), &sent, Ok(block));
        let message = verdict.blocked.map(|b| b.message).unwrap_or_default();
        assert_eq!(
            message,
            "Guardrail \"vendor\" refused this request: the guardrail service found prompt_injection (1). Remove it and send the request again."
        );

        let mut watched = check(body.clone(), &[]);
        watched.merge_webhook(&hook(OnFailure::FailOpen, Action::Warn), &sent, Ok(block));
        assert!(watched.blocked.is_none() && !watched.changed);
        assert_eq!(watched.audit[0].action, "warn");

        let mut allowed = check(body, &[]);
        allowed.merge_webhook(
            &hook(OnFailure::FailOpen, Action::Block),
            &sent,
            Ok(br#"{"action":"allow"}"#),
        );
        assert!(allowed.blocked.is_none() && allowed.audit.is_empty());
    }

    #[test]
    fn webhook_failures_follow_on_failure() {
        let body = two_messages();
        let sent = WebhookRequest::new("d", "p", "t", "/v1/messages", &body);
        let outcomes: [Result<&[u8], String>; 2] = [
            Err("timed out after 300 ms".into()),
            Ok(b"<html>502</html>"),
        ];
        for bytes in outcomes {
            let mut closed = check(body.clone(), &[]);
            let cause = closed.merge_webhook(
                &hook(OnFailure::FailClosed, Action::Block),
                &sent,
                bytes.clone(),
            );
            assert!(cause.is_some_and(|c| c.contains("https://guard.example.com")));
            assert!(
                closed
                    .blocked
                    .is_some_and(|b| b.message.contains("fail_closed"))
            );
            assert_eq!(closed.audit[0].action, "block");
            assert_eq!(closed.audit[0].kind, "unavailable");

            let mut open = check(body.clone(), &[]);
            open.merge_webhook(&hook(OnFailure::FailOpen, Action::Block), &sent, bytes);
            assert!(open.blocked.is_none() && !open.changed);
            assert_eq!(open.audit[0].action, "skipped");
        }
    }
}
