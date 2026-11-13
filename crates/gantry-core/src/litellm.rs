//! `gantry import litellm`: turns a LiteLLM proxy `config.yaml` into a Gantry policy, with a report of what could
//! not be carried across. Written from LiteLLM's public docs only (read 2026-11-13):
//! https://docs.litellm.ai/docs/proxy/configs, https://docs.litellm.ai/docs/proxy/reliability,
//! https://docs.litellm.ai/docs/proxy/config_settings, https://docs.litellm.ai/docs/proxy/virtual_keys.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

/// What `import` made: the policy text and one line per thing it could not map or that needs a hand.
#[derive(Debug)]
pub struct Imported {
    pub policy: String,
    pub report: Vec<String>,
}

/// One provider of the policy being built.
struct Provider {
    name: String,
    kind: &'static str,
    url: Option<String>,
    key_env: Option<String>,
    allow_private: bool,
    api_version: Option<String>,
    region: Option<String>,
    models: Vec<String>,
    /// Azure deployments or Bedrock model IDs, by the model name Gantry uses.
    upstream: BTreeMap<String, String>,
    retries: Option<u64>,
}

/// One `model_list` entry, placed.
struct Deployment {
    provider: usize,
    /// The model name sent to the provider (a key of `upstream` for azure and bedrock).
    model: String,
    weight: u64,
    /// The price the config gives (true), or the one of the model it names (false).
    price: Option<(Value, bool)>,
}

/// The API an alias's deployments must share.
fn api(kind: &str) -> &'static str {
    match kind {
        "anthropic" | "bedrock" | "vertex_anthropic" => "messages",
        "gemini" | "vertex" => "gemini",
        _ => "chat",
    }
}

/// Default base URL and key variable of the LiteLLM provider prefixes Gantry can serve. Base URLs as in
/// docs/providers.md "Base URLs at a glance".
fn prefix(name: &str) -> Option<(&'static str, Option<&'static str>, &'static str)> {
    Some(match name {
        "openai" | "text-completion-openai" => (
            "openai",
            Some("https://api.openai.com"),
            "OPENAI_PROVIDER_KEY",
        ),
        "anthropic" => (
            "anthropic",
            Some("https://api.anthropic.com"),
            "ANTHROPIC_PROVIDER_KEY",
        ),
        "azure" => ("azure", None, "AZURE_OPENAI_API_KEY"),
        "bedrock" => ("bedrock", None, ""),
        "gemini" => (
            "gemini",
            Some("https://generativelanguage.googleapis.com/v1beta"),
            "GEMINI_API_KEY",
        ),
        "vertex_ai" => ("vertex", None, "VERTEX_ACCESS_TOKEN"),
        "groq" => (
            "openai",
            Some("https://api.groq.com/openai/v1"),
            "GROQ_API_KEY",
        ),
        "mistral" => ("openai", Some("https://api.mistral.ai"), "MISTRAL_API_KEY"),
        "together_ai" => (
            "openai",
            Some("https://api.together.ai/v1"),
            "TOGETHER_API_KEY",
        ),
        "fireworks_ai" => (
            "openai",
            Some("https://api.fireworks.ai/inference/v1"),
            "FIREWORKS_API_KEY",
        ),
        "deepseek" => (
            "openai",
            Some("https://api.deepseek.com"),
            "DEEPSEEK_API_KEY",
        ),
        "openrouter" => (
            "openai",
            Some("https://openrouter.ai/api/v1"),
            "OPENROUTER_API_KEY",
        ),
        "ollama" | "ollama_chat" => ("openai", Some("http://127.0.0.1:11434/v1"), ""),
        "lm_studio" => ("openai", Some("http://127.0.0.1:1234/v1"), ""),
        "hosted_vllm" => ("openai", None, ""),
        _ => return None,
    })
}

/// Whether a URL points at this machine or a private network, which Gantry serves only with `allow_private`.
fn private(url: &str) -> bool {
    let host = url
        .split("://")
        .nth(1)
        .unwrap_or(url)
        .split(['/', ':'])
        .next()
        .unwrap_or("");
    host == "localhost"
        || host.starts_with("127.")
        || host.starts_with("10.")
        || host.starts_with("192.168.")
        || host.ends_with(".local")
        || host
            .strip_prefix("172.")
            .and_then(|r| r.split('.').next()?.parse::<u8>().ok())
            .is_some_and(|b| (16..32).contains(&b))
}

fn text(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// `os.environ/NAME` is LiteLLM's way to name a variable; Gantry reads keys from the environment only.
fn env_ref(value: &Value) -> Option<String> {
    text(value)?.strip_prefix("os.environ/").map(str::to_string)
}

/// `[{"a": ["b", "c"]}]` (or `{a: [b]}`) as pairs.
fn fallback_pairs(value: &Value) -> Vec<(String, Vec<String>)> {
    let maps: Vec<&Map<String, Value>> = match value {
        Value::Array(items) => items.iter().filter_map(Value::as_object).collect(),
        Value::Object(map) => vec![map],
        _ => Vec::new(),
    };
    maps.into_iter()
        .flat_map(|m| m.iter())
        .map(|(k, v)| {
            let to = match v {
                Value::Array(s) => s.iter().filter_map(text).collect(),
                other => text(other).into_iter().collect(),
            };
            (k.clone(), to)
        })
        .collect()
}

fn map(pairs: Vec<(&str, Value)>) -> Value {
    Value::Object(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// The workspace builds serde_json with arbitrary_precision, which serializes a number as a private struct; this
/// writes numbers as numbers so the YAML says `input: 2.5`, not a mapping.
struct Plain<'a>(&'a Value);

impl serde::Serialize for Plain<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{SerializeMap, SerializeSeq};
        match self.0 {
            Value::Number(n) => match (n.as_u64(), n.as_i64(), n.as_f64()) {
                (Some(u), _, _) => s.serialize_u64(u),
                (_, Some(i), _) => s.serialize_i64(i),
                (_, _, Some(f)) => s.serialize_f64(f),
                _ => s.serialize_str(&n.to_string()),
            },
            Value::Array(items) => {
                let mut seq = s.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(&Plain(item))?;
                }
                seq.end()
            }
            Value::Object(fields) => {
                let mut map = s.serialize_map(Some(fields.len()))?;
                for (k, v) in fields {
                    map.serialize_entry(k, &Plain(v))?;
                }
                map.end()
            }
            other => other.serialize(s),
        }
    }
}

fn list(items: impl IntoIterator<Item = String>) -> Value {
    Value::Array(items.into_iter().map(Value::from).collect())
}

/// Dollars per token to dollars per million tokens, without float noise.
fn per_mtok(value: &Value) -> Option<f64> {
    let dollars = value.as_f64()?;
    format!("{:.10e}", dollars * 1e6).parse().ok()
}

/// A price as the policy file writes it under `prices:`.
fn price_value(p: &crate::usage::Price) -> Value {
    let mut fields = vec![("input", Value::from(p.input)), ("output", p.output.into())];
    for (key, value) in [
        ("cache_read", p.cache_read),
        ("cache_write", p.cache_write),
        ("cache_write_1h", p.cache_write_1h),
        ("per_image", p.per_image),
    ] {
        if let Some(v) = value {
            fields.push((key, v.into()));
        }
    }
    for (key, value) in [("max_output", p.max_output), ("max_context", p.max_context)] {
        if let Some(v) = value {
            fields.push((key, v.into()));
        }
    }
    if let Some(long) = &p.long_context {
        fields.push((
            "long_context",
            map(vec![
                ("above_prompt_tokens", long.above_prompt_tokens.into()),
                ("price", price_value(&long.price)),
            ]),
        ));
    }
    map(fields)
}

/// Writes a deployment's price under the name Gantry knows it by, unless the config set none or the tables already
/// price that name (a price the config wrote by hand always wins).
fn priced(
    prices: &mut BTreeMap<String, Value>,
    name: &str,
    d: &Deployment,
    report: &mut Vec<String>,
) {
    let Some((price, given)) = &d.price else {
        if crate::usage::price_for(name, &BTreeMap::new()).is_none() {
            report.push(format!("model {name}: no price is known for it or for the model it runs, so its usage is recorded with cost unknown and a budget or a tpm limit refuses it. Add prices: {name}: {{ input: <usd per million>, output: <usd per million>, max_output: <tokens> }}, or set model_info.base_model in the LiteLLM config and import again."));
        }
        return;
    };
    if *given || crate::usage::price_for(name, &BTreeMap::new()).is_none() {
        prices.insert(name.to_string(), price.clone());
    }
}

/// Turns a LiteLLM proxy config into a Gantry policy. `keys` is an optional export of LiteLLM virtual keys (a JSON
/// list, `{"keys": [...]}`, or CSV with a header): keys cannot move (LiteLLM keeps hashes), so they become team
/// rules and the `gantry key new` lines to reissue them.
pub fn import(config: &str, keys: Option<&str>) -> Result<Imported, String> {
    let root: Value = crate::config::from_yaml(config)
        .map_err(|err| format!("the LiteLLM config is not YAML Gantry can read: {err}."))?;
    let root = root
        .as_object()
        .ok_or("the LiteLLM config must be a mapping with a model_list.")?;
    let mut report = Vec::new();
    let get =
        |section: &str, key: &str| -> Option<&Value> { root.get(section)?.as_object()?.get(key) };
    let retries = get("router_settings", "num_retries")
        .or_else(|| get("litellm_settings", "num_retries"))
        .and_then(Value::as_u64)
        .map(|n| {
            if n > 5 {
                report.push(format!(
                    "num_retries: {n} is more than Gantry's 5; each provider gets retries: 5."
                ));
            }
            n.min(5)
        });
    let entries = root
        .get("model_list")
        .and_then(Value::as_array)
        .ok_or("the LiteLLM config has no model_list, so there is nothing to serve. Give the config.yaml the proxy starts with.")?;

    let mut providers: Vec<Provider> = Vec::new();
    // Deployments by the model name callers send, in the order written.
    let mut groups: Vec<(String, Vec<Deployment>)> = Vec::new();
    let mut prices: BTreeMap<String, Value> = BTreeMap::new();
    for (at, entry) in entries.iter().enumerate() {
        let Some(name) = entry.get("model_name").and_then(text) else {
            report.push(format!("model_list[{at}] has no model_name; skipped."));
            continue;
        };
        let params = entry.get("litellm_params").and_then(Value::as_object);
        let Some(model) = params.and_then(|p| p.get("model")).and_then(text) else {
            report.push(format!(
                "model_list[{at}] ({name}) has no litellm_params.model; skipped."
            ));
            continue;
        };
        let param = |key: &str| params.and_then(|p| p.get(key));
        let (pre, upstream) = match model.split_once('/') {
            Some((pre, rest)) if prefix(pre).is_some() => (pre.to_string(), rest.to_string()),
            // A bare name: LiteLLM picks the provider from the name, as Gantry's docs do for these two.
            _ if model.starts_with("claude") => ("anthropic".into(), model.clone()),
            _ if !model.contains('/') => ("openai".into(), model.clone()),
            _ => {
                report.push(format!(
                    "model_list[{at}] ({name}): provider \"{}\" has no Gantry kind; not mapped. If it speaks the OpenAI API, add it as kind: openai with its url.",
                    model.split('/').next().unwrap_or_default()
                ));
                continue;
            }
        };
        let Some((kind, default_url, default_env)) = prefix(&pre) else {
            continue;
        };
        let kind = if kind == "vertex" && upstream.starts_with("claude") {
            "vertex_anthropic"
        } else {
            kind
        };
        if kind == "vertex" && !upstream.starts_with("gemini") {
            report.push(format!(
                "model_list[{at}] ({name}): {model} on Vertex AI is not served by Gantry (kind: vertex serves Gemini, vertex_anthropic serves Claude); not mapped."
            ));
            continue;
        }
        let url = match kind {
            "vertex" | "vertex_anthropic" => {
                let publisher = if kind == "vertex" {
                    "google"
                } else {
                    "anthropic"
                };
                let project = param("vertex_project").and_then(text);
                let location = param("vertex_location")
                    .and_then(text)
                    .unwrap_or_else(|| "us-central1".into());
                match project {
                    Some(project) => Some(format!(
                        "https://{location}-aiplatform.googleapis.com/v1/projects/{project}/locations/{location}/publishers/{publisher}"
                    )),
                    None => {
                        report.push(format!(
                            "model_list[{at}] ({name}): vertex_ai needs vertex_project; not mapped."
                        ));
                        continue;
                    }
                }
            }
            _ => param("api_base")
                .and_then(|v| {
                    env_ref(v)
                        .map(|e| format!("os.environ/{e}"))
                        .or_else(|| text(v))
                })
                .or(default_url.map(str::to_string)),
        };
        if let Some(u) = url.as_deref().filter(|u| u.starts_with("os.environ/")) {
            report.push(format!(
                "model_list[{at}] ({name}): api_base is read from {}, and Gantry needs the URL in the file; not mapped. Write the URL in the policy.",
                &u[11..]
            ));
            continue;
        }
        if url.is_none() && kind != "bedrock" {
            report.push(format!(
                "model_list[{at}] ({name}): {kind} needs api_base; not mapped."
            ));
            continue;
        }
        let allow_private = url.as_deref().is_some_and(private);
        let key_env = match param("api_key") {
            Some(v) => match env_ref(v) {
                Some(var) => Some(var),
                None => {
                    let var = format!("{}_PROVIDER_KEY", pre.to_ascii_uppercase());
                    report.push(format!(
                        "model_list[{at}] ({name}): api_key is written in the config; Gantry reads provider keys from the environment only. Set {var} to it."
                    ));
                    Some(var)
                }
            },
            None if kind == "bedrock" || (allow_private && default_env.is_empty()) => None,
            None => Some(if default_env.is_empty() {
                format!("{}_PROVIDER_KEY", pre.to_ascii_uppercase())
            } else {
                default_env.to_string()
            }),
        };
        let api_version = param("api_version").and_then(text);
        let region = match kind {
            "bedrock" => Some(param("aws_region_name").and_then(text).unwrap_or_else(|| {
                report.push(format!(
                    "model_list[{at}] ({name}): no aws_region_name; region us-east-1 was written. Check it."
                ));
                "us-east-1".into()
            })),
            _ => None,
        };
        for limit in ["rpm", "tpm", "max_parallel_requests"] {
            if param(limit).is_some() {
                report.push(format!(
                    "model_list[{at}] ({name}): {limit} is a limit per deployment in LiteLLM; Gantry limits people, teams and keys (rate: on a rule, tpm: on a key). Not mapped."
                ));
            }
        }
        if kind == "bedrock"
            && (param("aws_access_key_id").is_some() || param("aws_secret_access_key").is_some())
        {
            report.push(format!(
                "model_list[{at}] ({name}): Gantry signs Bedrock requests with AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY from its own environment; the keys named in the config were not carried."
            ));
        }
        let found = providers.iter().position(|p| {
            p.kind == kind
                && p.url == url
                && p.key_env == key_env
                && p.api_version == api_version
                && p.region == region
        });
        let provider = found.unwrap_or_else(|| {
            let base = pre.replace('_', "-");
            let taken = providers
                .iter()
                .filter(|p| p.name == base || p.name.starts_with(&format!("{base}-")))
                .count();
            providers.push(Provider {
                name: if taken == 0 {
                    base
                } else {
                    format!("{base}-{}", taken + 1)
                },
                kind,
                url: url.clone(),
                key_env: key_env.clone(),
                allow_private,
                api_version: api_version.clone(),
                region: region.clone(),
                models: Vec::new(),
                upstream: BTreeMap::new(),
                retries,
            });
            providers.len() - 1
        });
        let weight = param("weight")
            .and_then(Value::as_u64)
            .unwrap_or(1)
            .clamp(1, 1000);
        let info = entry.get("model_info");
        let cost = |key: &str| {
            info.and_then(|i| i.get(key))
                .or_else(|| param(key))
                .and_then(per_mtok)
        };
        let price = match (cost("input_cost_per_token"), cost("output_cost_per_token")) {
            (Some(input), Some(output)) => Some((
                map(vec![("input", input.into()), ("output", output.into())]),
                true,
            )),
            // A deployment named by its owner (Azure's `gpt-4o-eu`) is priced as the model it runs: base_model when
            // the config says it, else the LiteLLM model string, else the name callers send.
            _ => {
                let base = info.and_then(|i| i.get("base_model")).and_then(text);
                let stripped = base
                    .as_deref()
                    .and_then(|b| b.split_once('/'))
                    .map(|(_, rest)| rest.to_string());
                let undated = upstream.split('@').next().map(str::to_string);
                [
                    base,
                    stripped,
                    Some(model.clone()),
                    Some(upstream.clone()),
                    undated,
                    Some(name.clone()),
                ]
                .into_iter()
                .flatten()
                .find_map(|c| crate::usage::price_for(&c, &BTreeMap::new()))
                .map(|p| (price_value(&p), false))
            }
        };
        let deployment = Deployment {
            provider,
            model: upstream,
            weight,
            price,
        };
        match groups.iter_mut().find(|(n, _)| *n == name) {
            Some((_, list)) => list.push(deployment),
            None => groups.push((name, vec![deployment])),
        }
    }

    // A model name with a named fallback must be an alias: that is where Gantry keeps them.
    let mut named: BTreeMap<String, (Option<String>, Option<String>)> = BTreeMap::new();
    let served: BTreeSet<String> = groups.iter().map(|(n, _)| n.clone()).collect();
    for (field, context) in [
        ("context_window_fallbacks", true),
        ("content_policy_fallbacks", false),
    ] {
        for section in ["router_settings", "litellm_settings"] {
            for (from, to) in get(section, field).map(fallback_pairs).unwrap_or_default() {
                let Some(first) = to.first().filter(|t| served.contains(*t)) else {
                    report.push(format!("{section}.{field}: {from} -> {to:?} names no model of model_list; not mapped."));
                    continue;
                };
                if !served.contains(&from) {
                    report.push(format!(
                        "{section}.{field}: {from} is not a model of model_list; not mapped."
                    ));
                    continue;
                }
                if to.len() > 1 {
                    report.push(format!("{section}.{field}: {from} -> {to:?}: Gantry follows one named fallback, {first}; the rest were dropped."));
                }
                let slot = named.entry(from).or_default();
                if context {
                    slot.0 = Some(first.clone());
                } else {
                    slot.1 = Some(first.clone());
                }
            }
        }
    }
    for section in ["router_settings", "litellm_settings"] {
        for (from, to) in get(section, "fallbacks")
            .map(fallback_pairs)
            .unwrap_or_default()
        {
            report.push(format!(
                "{section}.fallbacks: {from} -> {to:?} not mapped. Gantry fails over only between deployments that speak the same API. If {from} and the fallback are both OpenAI-compatible (or both Anthropic), add the fallback's deployment to alias {from} (it then also takes a share of traffic), or give each provider of {from} fallback: <provider> for the same model. A fallback from an OpenAI model to an Anthropic one, or the reverse, has no equivalent: the client retries with the other model."
            ));
        }
    }
    let balance = match get("router_settings", "routing_strategy")
        .and_then(text)
        .as_deref()
    {
        None | Some("simple-shuffle") => "round_robin",
        Some("least-busy") => "least_busy",
        Some(other) => {
            report.push(format!("router_settings.routing_strategy: {other} has no Gantry equivalent; aliases use round_robin."));
            "round_robin"
        }
    };
    let cooldown = get("router_settings", "cooldown_time")
        .and_then(Value::as_f64)
        .map(|s| (s.ceil() as u64).min(3600));

    let mut aliases = Vec::new();
    let mut listed: BTreeMap<String, usize> = BTreeMap::new();
    let alias_names: BTreeSet<String> = groups
        .iter()
        .filter(|(name, list)| {
            list.len() > 1
                || named.contains_key(name)
                || (!matches!(providers[list[0].provider].kind, "azure" | "bedrock")
                    && list[0].model != *name)
        })
        .map(|(n, _)| n.clone())
        .collect();
    // Model names listed directly come first: a name belongs to one provider.
    for (name, list) in groups.iter().filter(|(n, _)| !alias_names.contains(n)) {
        let d = &list[0];
        let p = &mut providers[d.provider];
        if matches!(p.kind, "azure" | "bedrock") {
            p.upstream.insert(name.clone(), d.model.clone());
        }
        p.models.push(name.clone());
        listed.insert(name.clone(), d.provider);
        priced(&mut prices, name, d, &mut report);
    }
    for (name, list) in groups.iter().filter(|(n, _)| alias_names.contains(n)) {
        if !crate::config::valid_name(name) {
            report.push(format!("model_name {name}: an alias name takes letters, digits, '.', '-', '_' and '@' only; not mapped. Rename it."));
            continue;
        }
        let first_api = api(providers[list[0].provider].kind);
        let mut deployments = Vec::new();
        for d in list {
            let p = &mut providers[d.provider];
            if api(p.kind) != first_api {
                report.push(format!("model_name {name}: deployment {} on {} speaks another API than the first one; Gantry's aliases take one API. Dropped from the alias.", d.model, p.name));
                continue;
            }
            let mut sent = d.model.clone();
            if matches!(p.kind, "azure" | "bedrock") {
                // The name is a key of the provider's map, so a provider of its own gets a name of its own.
                if listed.get(&sent).is_some_and(|i| *i != d.provider)
                    || alias_names.contains(&sent)
                {
                    sent = format!("{}@{}", d.model, p.name);
                }
                p.upstream.insert(sent.clone(), d.model.clone());
            }
            if !listed.contains_key(&sent) && !alias_names.contains(&sent) {
                p.models.push(sent.clone());
                listed.insert(sent.clone(), d.provider);
            }
            priced(&mut prices, &sent, d, &mut report);
            let mut entry = vec![
                ("provider", Value::from(p.name.clone())),
                ("model", Value::from(sent)),
            ];
            if d.weight != 1 {
                entry.push(("weight", d.weight.into()));
            }
            deployments.push(map(entry));
        }
        let mut alias = vec![("name", Value::from(name.clone()))];
        if balance != "round_robin" {
            alias.push(("balance", balance.into()));
        }
        if let Some(c) = cooldown {
            alias.push(("cooldown_seconds", c.into()));
        }
        if let Some((context, content)) = named.get(name) {
            if let Some(c) = context {
                alias.push(("context_window_fallback", c.clone().into()));
            }
            if let Some(c) = content {
                alias.push(("content_policy_fallback", c.clone().into()));
            }
        }
        alias.push(("deployments", Value::Array(deployments)));
        aliases.push(map(alias));
    }
    // ponytail: an OpenAI-API provider whose only model another provider lists (two regions of gpt-4o) lists it
    // as `<model>@<provider>`, so it has a model of its own; its alias sends the real name. A caller that sends
    // the `@` name directly reaches the provider with it, which the provider refuses.
    for (i, p) in providers.iter_mut().enumerate() {
        if !p.models.is_empty() {
            continue;
        }
        let Some(model) = groups
            .iter()
            .flat_map(|(_, l)| l)
            .find(|d| d.provider == i)
            .map(|d| d.model.clone())
        else {
            continue;
        };
        let own = format!("{model}@{}", p.name);
        report.push(format!(
            "provider {}: {model} is listed by another provider, so this one lists it as {own}; callers reach it through the alias.",
            p.name
        ));
        p.models.push(own);
    }
    let mut out_providers = Vec::new();
    for p in &providers {
        let mut entry = vec![
            ("name", Value::from(p.name.clone())),
            ("kind", Value::from(p.kind)),
        ];
        if let Some(url) = &p.url {
            entry.push(("url", url.clone().into()));
        }
        if let Some(env) = &p.key_env {
            entry.push(("key_env", env.clone().into()));
        }
        if p.allow_private {
            entry.push(("allow_private", true.into()));
        }
        if let Some(v) = &p.api_version {
            entry.push(("api_version", v.clone().into()));
        }
        if let Some(r) = &p.region {
            entry.push(("region", r.clone().into()));
        }
        entry.push(("models", list(p.models.clone())));
        if !p.upstream.is_empty() {
            let field = if p.kind == "azure" {
                "deployments"
            } else {
                "model_ids"
            };
            entry.push((
                field,
                Value::Object(
                    p.upstream
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone().into()))
                        .collect(),
                ),
            ));
        }
        if let Some(n) = p.retries.filter(|n| *n > 0) {
            entry.push(("retries", n.into()));
        }
        out_providers.push(map(entry));
    }

    let names: Vec<String> = groups
        .iter()
        .map(|(n, _)| n.clone())
        .filter(|n| {
            listed.contains_key(n)
                || aliases
                    .iter()
                    .any(|a| a.get("name").and_then(text).as_deref() == Some(n.as_str()))
        })
        .collect();
    let mut rules = match keys {
        Some(export) => key_rules(export, &names, &mut report)?,
        None => Vec::new(),
    };
    rules.push(map(vec![
        ("name", "everyone".into()),
        ("principals", map(vec![("any", true.into())])),
        ("models", list(names.clone())),
    ]));

    for (section, known) in [
        (
            "router_settings",
            &[
                "routing_strategy",
                "num_retries",
                "cooldown_time",
                "fallbacks",
                "context_window_fallbacks",
                "content_policy_fallbacks",
            ][..],
        ),
        (
            "litellm_settings",
            &[
                "num_retries",
                "fallbacks",
                "context_window_fallbacks",
                "content_policy_fallbacks",
            ][..],
        ),
        ("general_settings", &[][..]),
    ] {
        for key in root
            .get(section)
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(|m| m.keys())
        {
            if known.contains(&key.as_str()) {
                continue;
            }
            report.push(match key.as_str() {
                "master_key" => "general_settings.master_key: Gantry has no master key. Make an admin key: gantry key new <name> --team <team> --admin.".into(),
                "database_url" => "general_settings.database_url: not needed. Gantry keeps keys in gantry.keys.yaml and records in its audit log.".into(),
                "drop_params" => "litellm_settings.drop_params: Gantry never drops a parameter silently; an unknown one passes through or is refused.".into(),
                "cache" | "cache_params" => format!("{section}.{key}: Gantry caches per rule in memory: add cache: {{ ttl_seconds: N }} to a rule."),
                "success_callback" | "failure_callback" | "callbacks" => format!("{section}.{key}: Gantry writes every request to its audit log and serves Prometheus metrics; see https://gantry-docs.eliran.me/operations/observability/."),
                "redis_host" | "redis_port" | "redis_password" => format!("{section}.{key}: Gantry runs on one node and keeps cooldowns in memory."),
                _ => format!("{section}.{key}: not mapped."),
            });
        }
    }
    for key in root.keys() {
        if ![
            "model_list",
            "router_settings",
            "litellm_settings",
            "general_settings",
        ]
        .contains(&key.as_str())
        {
            report.push(format!("{key}: not mapped."));
        }
    }

    let mut policy = vec![
        ("version", Value::from(1)),
        ("providers", Value::Array(out_providers)),
    ];
    if !aliases.is_empty() {
        policy.push(("aliases", Value::Array(aliases)));
    }
    policy.push(("rules", Value::Array(rules)));
    if !prices.is_empty() {
        policy.push(("prices", Value::Object(prices.into_iter().collect())));
    }
    // One line per value, as a person would write it: no folded `>-` blocks for a long provider URL.
    let body = serde_saphyr::to_string_with_options(
        &Plain(&map(policy)),
        serde_saphyr::ser_options! { prefer_block_scalars: false },
    )
    .map_err(|err| format!("the policy could not be written: {err}."))?;
    Ok(Imported {
        policy: format!(
            "# Imported from a LiteLLM config by `gantry import litellm`. Check it with `gantry check`.\n{body}"
        ),
        report,
    })
}

/// Rows of a key export: JSON (a list, or `{"keys": [...]}`, or `{"data": [...]}`) or CSV with a header row.
fn key_rows(export: &str) -> Result<Vec<BTreeMap<String, serde_json::Value>>, String> {
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(export) {
        let rows = json
            .as_array()
            .or_else(|| json["keys"].as_array())
            .or_else(|| json["data"].as_array())
            .ok_or("the key export is JSON but holds no list of keys (a list, or under \"keys\" or \"data\").")?;
        return Ok(rows
            .iter()
            .filter_map(|r| r.as_object())
            .map(|r| r.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .collect());
    }
    // ponytail: one record per line (no line breaks inside quotes); a list column (models) is read with ',', ';'
    // or ' ' between names.
    let mut lines = export.lines().filter(|l| !l.trim().is_empty());
    let header = csv_fields(lines.next().ok_or("the key export is empty.")?);
    Ok(lines
        .map(|line| {
            header
                .iter()
                .cloned()
                .zip(csv_fields(line).into_iter().map(serde_json::Value::from))
                .collect()
        })
        .collect())
}

/// The fields of one CSV line: a field in double quotes may hold commas, and `""` in it is one quote.
fn csv_fields(line: &str) -> Vec<String> {
    let (mut fields, mut field, mut quoted) = (Vec::new(), String::new(), false);
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => fields.push(std::mem::take(&mut field).trim().to_string()),
            c => field.push(c),
        }
    }
    fields.push(field.trim().to_string());
    fields
}

/// One rule per team in the export, listing what its keys may use, and a reissue line per key.
fn key_rules(
    export: &str,
    names: &[String],
    report: &mut Vec<String>,
) -> Result<Vec<Value>, String> {
    let rows = key_rows(export)?;
    let s = |row: &BTreeMap<String, serde_json::Value>, key: &str| -> Option<String> {
        match row.get(key)? {
            serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
            serde_json::Value::Number(n) => Some(n.to_string()),
            _ => None,
        }
    };
    let mut teams: BTreeMap<String, Option<BTreeSet<String>>> = BTreeMap::new();
    for row in &rows {
        let team = s(row, "team_alias")
            .or_else(|| s(row, "team_id"))
            .unwrap_or_else(|| "default".into());
        let team: String = team
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || "._-@".contains(c) {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        let person = s(row, "key_alias")
            .or_else(|| s(row, "user_email"))
            .or_else(|| s(row, "user_id"))
            .or_else(|| s(row, "key_name"))
            .unwrap_or_else(|| "unnamed".into());
        let models: Vec<String> = match row.get("models") {
            Some(serde_json::Value::Array(m)) => m
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
            Some(serde_json::Value::String(m)) => m
                .split([';', ' ', ','])
                .filter(|x| !x.is_empty())
                .map(str::to_string)
                .collect(),
            _ => Vec::new(),
        };
        let slot = teams
            .entry(team.clone())
            .or_insert_with(|| Some(BTreeSet::new()));
        match slot {
            // An empty list in LiteLLM is every model.
            Some(set) if !models.is_empty() => {
                set.extend(models.iter().filter(|m| names.contains(m)).cloned())
            }
            _ => *slot = None,
        }
        let mut line = format!("gantry key new {person} --team {team}");
        if let Some(usd) = s(row, "max_budget") {
            match s(row, "budget_duration").as_deref() {
                Some("1d" | "24h") => line.push_str(&format!(" --budget {usd}/day")),
                Some("30d" | "1mo" | "1m") => line.push_str(&format!(" --budget {usd}/month")),
                other => report.push(format!("key {person}: max_budget {usd} per {} has no Gantry period (day or month); not mapped.", other.unwrap_or("lifetime"))),
            }
        }
        if let Some(day) = s(row, "expires").and_then(|e| e.get(..10).map(str::to_string)) {
            if crate::policy::expiry_passed(&day, &crate::audit::timestamp()) {
                report.push(format!(
                    "key {person}: expired on {day} in LiteLLM; not reissued."
                ));
                continue;
            }
            line.push_str(&format!(" --expires {day}"));
        }
        let kept: Vec<&String> = models.iter().filter(|m| names.contains(m)).collect();
        if !kept.is_empty() {
            let kept: Vec<&str> = kept.iter().map(|m| m.as_str()).collect();
            line.push_str(&format!(" --models {}", kept.join(",")));
        }
        if kept.len() < models.len() {
            report.push(format!("key {person}: its model list names models this config does not serve here ({}); they were left out.", models.iter().filter(|m| !names.contains(m)).cloned().collect::<Vec<_>>().join(", ")));
        }
        if let Some(tpm) = s(row, "tpm_limit") {
            line.push_str(&format!(" --tpm {tpm}"));
        }
        report.push(format!("key {person}: reissue with `{line}` (LiteLLM keeps only key hashes, so keys cannot move)."));
        if let Some(rpm) = s(row, "rpm_limit") {
            report.push(format!("key {person}: rpm_limit {rpm} has no per-key equivalent; a rule's rate: {{ rpm: {rpm} }} limits each person."));
        }
    }
    Ok(teams
        .into_iter()
        .map(|(team, models)| {
            let models = match models {
                None => list(["*".to_string()]),
                Some(set) => list(set),
            };
            map(vec![
                ("name", format!("team-{team}").into()),
                ("principals", map(vec![("team", team.into())])),
                ("models", models),
            ])
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn an_alias_bomb_is_refused_not_expanded() -> TestResult {
        // A config a user brings may be hostile: nine levels of ten aliases each would be a billion strings.
        let mut bomb = String::from("a: &a [lol, lol, lol, lol, lol, lol, lol, lol, lol, lol]\n");
        for (name, prev) in ["b", "c", "d", "e", "f", "g", "h", "i"]
            .iter()
            .zip(["a", "b", "c", "d", "e", "f", "g", "h"])
        {
            bomb.push_str(&format!(
                "{name}: &{name} [*{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}]\n"
            ));
        }
        bomb.push_str("model_list: *i\n");
        let started = std::time::Instant::now();
        let refused = import(&bomb, None)
            .err()
            .ok_or("the alias bomb was accepted")?;
        assert!(
            refused.starts_with("the LiteLLM config is not YAML Gantry can read"),
            "{refused}"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        Ok(())
    }

    #[test]
    fn yes_no_and_on_stay_text_in_a_litellm_config() -> TestResult {
        let config = CONFIG.replacen("model_list:", "on: yes\nno: off\nmodel_list:", 1);
        let imported = import(&config, None)?;
        let report = imported.report.join("\n");
        assert!(
            report.contains("on: not mapped.") && report.contains("no: not mapped."),
            "{report}"
        );
        Ok(())
    }

    /// The shapes of LiteLLM's docs: two deployments behind one name, Azure, Bedrock, Anthropic, a local server,
    /// router and litellm settings.
    const CONFIG: &str = r#"
model_list:
  - model_name: gpt-4o
    litellm_params:
      model: openai/gpt-4o
      api_key: os.environ/OPENAI_API_KEY
  - model_name: smart
    litellm_params:
      model: azure/prod-gpt-4o
      api_base: https://acme.openai.azure.com/
      api_version: "2024-10-21"
      api_key: os.environ/AZURE_API_KEY
      rpm: 60
  - model_name: smart
    litellm_params:
      model: azure/prod-gpt-4o
      api_base: https://acme-eu.openai.azure.com/
      api_version: "2024-10-21"
      api_key: os.environ/AZURE_EU_API_KEY
      weight: 2
  - model_name: claude
    litellm_params:
      model: anthropic/claude-sonnet-5-5
      api_key: os.environ/ANTHROPIC_API_KEY
    model_info:
      input_cost_per_token: 0.000002
      output_cost_per_token: 0.00001
  - model_name: claude-bedrock
    litellm_params:
      model: bedrock/us.anthropic.claude-sonnet-5-5-v1:0
      aws_region_name: us-west-2
  - model_name: llama
    litellm_params:
      model: ollama/llama3
      api_base: http://localhost:11434
  - model_name: gpt-4o-long
    litellm_params:
      model: openai/gpt-4o-long
      api_key: os.environ/OPENAI_API_KEY
  - model_name: claude-vertex
    litellm_params:
      model: vertex_ai/claude-sonnet-5-5
      vertex_project: p
router_settings:
  routing_strategy: least-busy
  cooldown_time: 30
  num_retries: 2
  redis_host: redis
litellm_settings:
  fallbacks: [{"gpt-4o": ["claude"]}]
  context_window_fallbacks: [{"gpt-4o": ["gpt-4o-long"]}]
  drop_params: true
general_settings:
  master_key: os.environ/LITELLM_MASTER_KEY
  database_url: os.environ/DATABASE_URL
"#;

    fn check(policy: &str, keys: &str) -> Result<crate::config::Loaded, String> {
        crate::config::load_texts(
            std::path::Path::new("imported.policy.yaml"),
            policy,
            std::path::Path::new("gantry.keys.yaml"),
            keys,
        )
        .map_err(|e| format!("{}\n{policy}", e.join("\n")))
    }

    #[test]
    fn a_litellm_config_becomes_a_policy_that_passes_check() -> TestResult {
        let imported = import(CONFIG, None)?;
        let loaded = check(&imported.policy, "keys: []\n")?;
        let p = &imported.policy;
        // Two deployments behind one name became an alias, least busy, with the cooldown and the named fallback.
        assert_eq!(loaded.aliases.len(), 5, "{p}");
        assert!(
            p.contains("balance: least_busy") && p.contains("cooldown_seconds: 30"),
            "{p}"
        );
        assert!(p.contains("context_window_fallback: gpt-4o-long"), "{p}");
        assert!(p.contains("weight: 2"), "{p}");
        // Keys stay in the environment, named as the config named them.
        for env in [
            "OPENAI_API_KEY",
            "AZURE_API_KEY",
            "AZURE_EU_API_KEY",
            "ANTHROPIC_API_KEY",
        ] {
            assert!(p.contains(&format!("key_env: {env}")), "{env}\n{p}");
        }
        assert!(
            p.contains("allow_private: true") && p.contains("region: us-west-2"),
            "{p}"
        );
        assert!(
            p.contains("api_version: 2024-10-21") || p.contains("api_version: '2024-10-21'"),
            "{p}"
        );
        assert!(
            p.contains("input: 2.0") && p.contains("output: 10.0"),
            "{p}"
        );
        assert!(p.contains("retries: 2"), "{p}");
        let report = imported.report.join("\n");
        for says in [
            "fallbacks: gpt-4o",
            "rpm is a limit per deployment",
            "master_key",
            "database_url",
            "drop_params",
            "redis_host",
        ] {
            assert!(report.contains(says), "{says} missing from:\n{report}");
        }
        Ok(())
    }

    #[test]
    fn a_key_export_becomes_team_rules_and_reissue_lines() -> TestResult {
        let export = r#"[
            {"key_alias": "maya", "team_alias": "payments", "models": ["gpt-4o"], "max_budget": 20, "budget_duration": "30d", "tpm_limit": 1000},
            {"key_alias": "omer", "team_alias": "support", "models": [], "expires": "2027-01-01T00:00:00Z"},
            {"key_alias": "old", "team_alias": "support", "expires": "2020-01-01"}
        ]"#;
        let imported = import(CONFIG, Some(export))?;
        check(&imported.policy, "keys: []\n")?;
        assert!(
            imported.policy.contains("team: payments") && imported.policy.contains("\"*\""),
            "{}",
            imported.policy
        );
        let report = imported.report.join("\n");
        assert!(
            report.contains("gantry key new maya --team payments --budget 20/month"),
            "{report}"
        );
        assert!(
            report.contains("gantry key new omer --team support --expires 2027-01-01"),
            "{report}"
        );
        // UX13 q2: a key that has expired is not given a line `gantry key new` would refuse.
        assert!(
            report.contains("key old: expired on 2020-01-01 in LiteLLM; not reissued.")
                && !report.contains("gantry key new old"),
            "{report}"
        );
        assert!(
            report.contains("--budget 20/month --models gpt-4o --tpm 1000`"),
            "{report}"
        );
        let csv = "key_alias,team_alias,models\nana,ops,gpt-4o;claude\n";
        let imported = import(CONFIG, Some(csv))?;
        check(&imported.policy, "keys: []\n")?;
        assert!(imported.policy.contains("team: ops"));
        // UX13 q3: a quoted list column holds commas, and the columns after it stay in place.
        let csv = "key_alias,team_alias,models,max_budget,budget_duration\nana,ops,\"gpt-4o,claude\",20,30d\n";
        let imported = import(CONFIG, Some(csv))?;
        let report = imported.report.join("\n");
        assert!(
            report.contains(
                "gantry key new ana --team ops --budget 20/month --models gpt-4o,claude`"
            ),
            "{report}"
        );
        Ok(())
    }

    #[test]
    fn two_regions_of_one_model_become_one_alias_that_passes_check() -> TestResult {
        let config = "model_list:\n  - model_name: gpt-4o\n    litellm_params: { model: openai/gpt-4o, api_base: https://east.example/v1, api_key: os.environ/EAST }\n  - model_name: gpt-4o\n    litellm_params: { model: openai/gpt-4o, api_base: https://west.example/v1, api_key: os.environ/WEST }\n";
        let imported = import(config, None)?;
        let loaded = check(&imported.policy, "keys: []\n")?;
        assert_eq!((loaded.providers.len(), loaded.aliases.len()), (2, 1));
        assert!(imported.report.join("\n").contains("gpt-4o@openai-2"));
        Ok(())
    }

    /// The docs-shaped config of the round 13 review: two Azure regions of one model under deployment names the
    /// price table does not know, Claude on Vertex AI, and a key export with teams.
    const AZURE_CONFIG: &str = r#"
model_list:
  - model_name: gpt-4o
    litellm_params:
      model: azure/gpt-4o-eu
      api_base: http://127.0.0.1:20551/
      api_key: os.environ/AZURE_API_KEY_EU
      api_version: "2024-10-21"
  - model_name: gpt-4o
    litellm_params:
      model: azure/gpt-4o-us
      api_base: http://127.0.0.1:20552/
      api_key: os.environ/AZURE_API_KEY_US
      api_version: "2024-10-21"
    model_info:
      base_model: azure/gpt-4o-mini
  - model_name: gpt-4o-mini
    litellm_params:
      model: openai/gpt-4o-mini
      api_base: http://127.0.0.1:20551/v1
      api_key: os.environ/OPENAI_API_KEY
  - model_name: reports
    litellm_params:
      model: azure/reports-prod
      api_base: http://127.0.0.1:20551/
      api_key: os.environ/AZURE_API_KEY_EU
      api_version: "2024-10-21"
    model_info:
      base_model: azure/gpt-4o
  - model_name: claude-sonnet
    litellm_params:
      model: vertex_ai/claude-sonnet-4-5@20250929
      vertex_project: my-proj
      vertex_location: us-east5
  - model_name: llama3
    litellm_params:
      model: ollama/llama3
      api_base: http://127.0.0.1:20552
router_settings:
  routing_strategy: simple-shuffle
  cooldown_time: 30
"#;

    #[test]
    fn renamed_deployments_keep_the_price_of_their_model_so_a_budget_passes_check() -> TestResult {
        let export = r#"[{"key_alias":"maya","team_alias":"payments","models":["gpt-4o","gpt-4o-mini","reports"]}]"#;
        let imported = import(AZURE_CONFIG, Some(export))?;
        let budgeted = imported.policy.replace(
            "- name: team-payments\n",
            "- name: team-payments\n  budget: { usd: 10, per: month }\n",
        );
        let budgeted = budgeted.replace(
            "- name: everyone\n",
            "- name: everyone\n  budget: { usd: 10, per: month }\n",
        );
        assert_eq!(budgeted.matches("budget:").count(), 2, "{budgeted}");
        let loaded = check(&budgeted, "keys: []\n")?;
        let prices = loaded.policy.prices();
        // Named after the model the config says it is: the model_name, or base_model when given.
        let eu = prices.get("gpt-4o-eu").ok_or("no price for gpt-4o-eu")?;
        assert_eq!((eu.input, eu.output), (2.5, 10.0), "{budgeted}");
        let us = prices.get("gpt-4o-us").ok_or("no price for gpt-4o-us")?;
        assert_eq!((us.input, us.output), (0.15, 0.6), "{budgeted}");
        let reports = prices.get("reports").ok_or("no price for reports")?;
        assert_eq!(reports.input, 2.5, "{budgeted}");
        // A model the table already prices by the name Gantry sends gets no entry of its own.
        assert!(!prices.contains_key("gpt-4o-mini"), "{budgeted}");
        Ok(())
    }

    #[test]
    fn claude_on_vertex_becomes_a_vertex_anthropic_provider() -> TestResult {
        let imported = import(AZURE_CONFIG, None)?;
        let loaded = check(&imported.policy, "keys: []\n")?;
        let p = &imported.policy;
        assert!(
            p.contains("kind: vertex_anthropic")
                && p.contains("url: https://us-east5-aiplatform.googleapis.com/v1/projects/my-proj/locations/us-east5/publishers/anthropic"),
            "{p}"
        );
        let alias = loaded
            .aliases
            .iter()
            .find(|a| a.name == "claude-sonnet")
            .ok_or("no alias claude-sonnet")?;
        assert_eq!(alias.deployments[0].model, "claude-sonnet-4-5@20250929");
        let report = imported.report.join("\n");
        assert!(!report.contains("Vertex"), "{report}");
        Ok(())
    }

    #[test]
    fn a_config_without_a_model_list_is_refused_with_the_reason() {
        let err = import("general_settings: {}\n", None)
            .err()
            .unwrap_or_default();
        assert!(err.contains("model_list"), "{err}");
        assert!(import("[1, 2]", None).is_err());
    }
}
