//! Policy versions kept in the store (`store.policy_from: store`): what the console and the admin API share to
//! check a draft, save it, approve it, roll back to an earlier one, show what changed, and replay recent requests
//! against a draft before it goes live.
//!
//! The store keeps each version's whole text and knows nothing of its shape, so the policy may grow new sections
//! without a change here: a draft is checked by the same `config::load_texts` that `gantry check` runs on a file.

use std::{io::BufRead, path::Path, sync::Arc};

use serde_json::{Map, Value};

use crate::{
    config::{self, Loaded, PolicyFrom},
    policy::{Decision, Policy, Principal},
    store::{self, NewVersion, PolicyVersion, Store, VersionError},
};

/// Why a change to the policy versions was not made, with what to tell the person.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The draft does not pass `gantry check`: each problem names its line and the fix.
    Invalid(Vec<String>),
    /// The policy is kept in the file here (or there is no store): nothing can be saved through Gantry.
    ReadOnly(String),
    /// The person may not do this (approve their own version).
    Forbidden(String),
    /// The versions moved on since the person read them.
    Conflict(String),
    /// No such version.
    Unknown(String),
    /// The store could not be reached.
    Store(String),
}

impl Refused {
    pub fn message(&self) -> String {
        match self {
            Self::Invalid(problems) => problems.join("\n"),
            Self::ReadOnly(m)
            | Self::Forbidden(m)
            | Self::Conflict(m)
            | Self::Unknown(m)
            | Self::Store(m) => m.clone(),
        }
    }
}

impl From<VersionError> for Refused {
    fn from(err: VersionError) -> Self {
        match err {
            VersionError::Conflict(m) => Self::Conflict(m),
            VersionError::Store(m) => Self::Store(m),
        }
    }
}

/// What a policy file names a reader to do when the policy is kept in the file.
pub fn read_only_message(policy_path: &Path) -> String {
    format!(
        "the policy is kept in {} (store.policy_from is file, the default), so it is changed there and reviewed in git, not through Gantry. To edit it here, set `policy_from: store` in its store: section and restart: the file is then imported as version 1.",
        policy_path.display()
    )
}

/// The store that keeps the policy of `policy_path` as versions, or why there is none.
pub fn store_for(policy_path: &Path) -> Result<Arc<dyn Store>, Refused> {
    store::policy_store(policy_path)
        .ok_or_else(|| Refused::ReadOnly(read_only_message(policy_path)))
}

/// Checks a draft exactly as `gantry check` checks a file, and as the reload would take it: problems that need a
/// restart (the audit path, MCP servers, the store's connection) are refused too, so no version goes live that
/// a gateway would then reject.
pub fn check(
    policy_path: &Path,
    keys_path: &Path,
    text: &str,
    current: &Loaded,
) -> Result<Loaded, Vec<String>> {
    let keys = store::attached(keys_path)
        .map(|s| s.keys_text())
        .or_else(|| config::read_keys(keys_path).ok().flatten())
        .unwrap_or_default();
    let draft = config::load_texts(policy_path, text, keys_path, &keys)?;
    let restart = config::needs_restart(current, &draft);
    if !restart.is_empty() {
        return Err(restart
            .into_iter()
            .map(|reason| format!("{}: {reason}", policy_path.display()))
            .collect());
    }
    Ok(draft)
}

/// The store, its live version and the policy that version loads.
type Start = (Arc<dyn Store>, Option<PolicyVersion>, Loaded);

/// The version in force and the policy it loads, for a change to start from.
fn live(policy_path: &Path, keys_path: &Path) -> Result<Start, Refused> {
    let store = store_for(policy_path)?;
    let live = store.live_policy();
    let loaded = config::load(policy_path, Some(keys_path)).map_err(Refused::Invalid)?;
    Ok((store, live, loaded))
}

/// Saves `text` as a new version drafted on `base` (the live version the person started from). It goes live at
/// once, or waits for a second admin when the live version sets `store.approval: true`.
pub fn propose(
    policy_path: &Path,
    keys_path: &Path,
    text: &str,
    base: Option<i64>,
    note: &str,
    by: &str,
) -> Result<PolicyVersion, Refused> {
    let (store, live, loaded) = live(policy_path, keys_path)?;
    let live_id = live.as_ref().map(|v| v.id);
    if base != live_id {
        return Err(Refused::Conflict(stale(base, live_id)));
    }
    if live.as_ref().is_some_and(|v| v.text == text) {
        return Err(Refused::Conflict(
            "the draft is the same as the live version, so there is nothing to save. Change something first.".into(),
        ));
    }
    check(policy_path, keys_path, text, &loaded).map_err(Refused::Invalid)?;
    Ok(store.add_policy_version(&NewVersion {
        text: text.to_string(),
        base,
        note: note.trim().to_string(),
        by: by.to_string(),
        pending: approval_needed(&loaded),
    })?)
}

/// Whether a new version waits for an approval: the live version says so.
pub fn approval_needed(live: &Loaded) -> bool {
    live.store.as_ref().is_some_and(|s| s.approval)
}

fn stale(base: Option<i64>, live: Option<i64>) -> String {
    let word = |v: Option<i64>| v.map_or_else(|| "none".to_string(), |v| format!("version {v}"));
    format!(
        "the draft started from {} and {} is live now: someone saved a change meanwhile. Open the live version, make the change again on it, and save.",
        word(base),
        word(live)
    )
}

/// Approves a pending version, which puts it live, or rejects it. Nobody approves their own version.
pub fn decide(
    policy_path: &Path,
    keys_path: &Path,
    id: i64,
    approve: bool,
    by: &str,
) -> Result<PolicyVersion, Refused> {
    let (store, live, loaded) = live(policy_path, keys_path)?;
    let version = find(&store, id)?;
    if version.state != store::PENDING {
        return Err(Refused::Conflict(format!(
            "version {id} is {}, not waiting for approval, so it cannot be approved or rejected.",
            version.state
        )));
    }
    if approve && version.created_by == by {
        return Err(Refused::Forbidden(format!(
            "version {id} was saved by {by}, and approval needs a second admin. Ask another admin to approve it, or reject it."
        )));
    }
    if approve {
        let live_id = live.as_ref().map(|v| v.id);
        if version.base != live_id {
            return Err(Refused::Conflict(format!(
                "version {id} was drafted on {} and {} is live now, so approving it would undo that change. Reject it and draft the change again on the live version.",
                version
                    .base
                    .map_or_else(|| "none".into(), |b| format!("version {b}")),
                live_id.map_or_else(|| "none".into(), |l| format!("version {l}"))
            )));
        }
        // Checked again: the keys or the running gateway may have changed since it was saved.
        check(policy_path, keys_path, &version.text, &loaded).map_err(Refused::Invalid)?;
    }
    Ok(store.decide_policy_version(id, approve, by)?)
}

/// Saves the text of an earlier version as a new version, which goes live at once or waits for approval as any
/// other change does. Nothing is rewritten: the history keeps both.
pub fn rollback(
    policy_path: &Path,
    keys_path: &Path,
    id: i64,
    by: &str,
) -> Result<PolicyVersion, Refused> {
    let store = store_for(policy_path)?;
    let version = find(&store, id)?;
    let live = store.live_policy().map(|v| v.id);
    propose(
        policy_path,
        keys_path,
        &version.text,
        live,
        &format!("Roll back to version {id}"),
        by,
    )
}

/// One version by its number.
pub fn find(store: &Arc<dyn Store>, id: i64) -> Result<PolicyVersion, Refused> {
    let held = |store: &Arc<dyn Store>| {
        store
            .policy_versions()
            .ok()
            .and_then(|all| all.iter().find(|v| v.id == id).cloned())
    };
    if let Some(found) = held(store) {
        return Ok(found);
    }
    // Saved on another gateway since this one last polled.
    store.refresh_policy().map_err(Refused::Store)?;
    store
        .policy_versions()
        .map_err(Refused::Store)?
        .iter()
        .find(|v| v.id == id)
        .cloned()
        .ok_or_else(|| {
            Refused::Unknown(format!(
                "there is no policy version {id}. The versions page lists them."
            ))
        })
}

/// What a version changed: the version it was drafted on, or nothing for the first.
pub fn base_text(store: &Arc<dyn Store>, version: &PolicyVersion) -> String {
    version
        .base
        .and_then(|b| find(store, b).ok())
        .map(|b| b.text)
        .unwrap_or_default()
}

/// The live version's number when the policy file differs from it, the policy being kept in the store: the
/// console warns, so the file and the store never disagree in silence.
pub fn file_differs(policy_path: &Path) -> Option<i64> {
    let live = store::policy_store(policy_path)?.live_policy()?;
    let file = std::fs::read_to_string(policy_path).ok()?;
    (file != live.text).then_some(live.id)
}

/// Whether this policy file is served from the store's versions.
pub fn from_store(loaded: &Loaded) -> bool {
    loaded
        .store
        .as_ref()
        .is_some_and(|s| s.policy_from == PolicyFrom::Store)
}

/// Lines that differ between two texts, with two lines around each change: (line number, text, kind), kind being
/// "", "add" or "del". A removed line comes before the line that replaces it, as a code diff reads.
pub fn diff(old: &str, new: &str) -> Vec<(usize, String, &'static str)> {
    let (a, b): (Vec<&str>, Vec<&str>) = (old.lines().collect(), new.lines().collect());
    // ponytail: a full LCS table, quadratic in lines. Policies are hundreds of lines; a Myers diff if they reach tens of thousands.
    let mut same = vec![vec![0u32; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            same[i][j] = if a[i] == b[j] {
                same[i + 1][j + 1] + 1
            } else {
                same[i + 1][j].max(same[i][j + 1])
            };
        }
    }
    let mut all = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        if i < a.len() && j < b.len() && a[i] == b[j] {
            all.push((j + 1, a[i], ""));
            (i, j) = (i + 1, j + 1);
        } else if i < a.len() && (j == b.len() || same[i + 1][j] >= same[i][j + 1]) {
            all.push((i + 1, a[i], "del"));
            i += 1;
        } else {
            all.push((j + 1, b[j], "add"));
            j += 1;
        }
    }
    let near = |k: usize| {
        all[k.saturating_sub(2)..(k + 3).min(all.len())]
            .iter()
            .any(|(_, _, kind)| !kind.is_empty())
    };
    (0..all.len())
        .filter(|&k| near(k))
        .map(|k| (all[k].0, all[k].1.to_string(), all[k].2))
        .collect()
}

/// A diff as text, `+` and `-` before changed lines, for the admin API.
pub fn diff_text(old: &str, new: &str) -> String {
    diff(old, new)
        .into_iter()
        .map(|(_, line, kind)| {
            let mark = match kind {
                "add" => '+',
                "del" => '-',
                _ => ' ',
            };
            format!("{mark} {line}\n")
        })
        .collect()
}

// ---------------------------------------------------------------- structured edits

/// The policy text as a tree, for an edit the console makes from a form.
fn tree(text: &str) -> Result<Map<String, Value>, String> {
    match serde_saphyr::from_str::<Value>(text) {
        Ok(Value::Object(map)) => Ok(map),
        Ok(_) => Err("the live policy is not a YAML mapping. Fix it in the editor first.".into()),
        Err(err) => Err(format!(
            "the live policy does not read as YAML ({err}). Fix it in the editor first."
        )),
    }
}

/// One top-level section of the policy text as JSON: `null` when the policy has none.
pub fn section(text: &str, name: &str) -> Result<Value, String> {
    Ok(tree(text)?.remove(name).unwrap_or(Value::Null))
}

/// Replaces a top-level section of the policy text with `value`, or removes it for `None`. Returns the new text.
pub fn set_section(text: &str, name: &str, value: Option<Value>) -> Result<String, String> {
    let mut map = tree(text)?;
    match value {
        Some(value) => {
            map.insert(name.to_string(), value);
        }
        None => {
            map.remove(name);
        }
    }
    Ok(to_yaml(&Value::Object(map)))
}

/// Puts the entry named `item` into the list section `name` (replacing one of that name, else appending), or
/// removes it for `None`. Returns the new text.
pub fn set_item(
    text: &str,
    name: &str,
    item: &str,
    value: Option<Value>,
) -> Result<String, String> {
    let mut map = tree(text)?;
    let list = map.entry(name).or_insert_with(|| Value::Array(Vec::new()));
    let Value::Array(list) = list else {
        return Err(format!(
            "the policy's {name} is not a list. Fix it in the editor or with PUT /admin/policy."
        ));
    };
    let at = list
        .iter()
        .position(|e| e.get("name").and_then(Value::as_str) == Some(item));
    match (value, at) {
        (Some(mut value), at) => {
            let Value::Object(entry) = &mut value else {
                return Err(format!("an entry of {name} is a JSON object."));
            };
            match entry.get("name").and_then(Value::as_str) {
                None => {
                    entry.insert("name".into(), item.into());
                }
                Some(named) if named != item => {
                    return Err(format!(
                        "the entry is named \"{named}\" but the path names \"{item}\". Send the same name, or leave name out."
                    ));
                }
                Some(_) => {}
            }
            match at {
                Some(at) => list[at] = value,
                None => list.push(value),
            }
        }
        (None, Some(at)) => {
            list.remove(at);
        }
        (None, None) => {
            return Err(format!(
                "the policy has no entry named \"{item}\" under {name}."
            ));
        }
    }
    Ok(to_yaml(&Value::Object(map)))
}

/// Adds `model` to provider `provider`, with a price in US dollars per million tokens (input, output) and other
/// names callers may send for it. Returns the new text. Comments of the policy are not kept by a form edit: the
/// editor keeps them.
pub fn add_model(
    text: &str,
    provider: &str,
    model: &str,
    price: Option<(f64, f64)>,
    aliases: &[String],
) -> Result<String, String> {
    let mut map = tree(text)?;
    let Some(Value::Array(providers)) = map.get_mut("providers") else {
        return Err("the policy has no providers list. Add a provider in the editor first.".into());
    };
    let Some(entry) = providers
        .iter_mut()
        .filter_map(Value::as_object_mut)
        .find(|p| p.get("name").and_then(Value::as_str) == Some(provider))
    else {
        return Err(format!(
            "there is no provider \"{provider}\" in the policy. Pick one from the list."
        ));
    };
    let models = entry
        .entry("models")
        .or_insert_with(|| Value::Array(Vec::new()));
    let Value::Array(models) = models else {
        return Err(format!(
            "provider \"{provider}\" lists its models in a form this page does not change. Edit it in the editor."
        ));
    };
    if models.iter().any(|m| m.as_str() == Some(model)) {
        return Err(format!(
            "provider \"{provider}\" already serves \"{model}\". Change its price instead."
        ));
    }
    models.push(model.into());
    if let Some(price) = price {
        set_price_in(&mut map, model, price);
    }
    if !aliases.is_empty() {
        let list = map
            .entry("aliases")
            .or_insert_with(|| Value::Array(Vec::new()));
        let Value::Array(list) = list else {
            return Err("the policy's aliases are not a list. Fix them in the editor.".into());
        };
        for alias in aliases {
            list.push(serde_json::json!({
                "name": alias,
                "deployments": [{ "provider": provider, "model": model }],
            }));
        }
    }
    Ok(to_yaml(&Value::Object(map)))
}

/// Sets the price of `model` in US dollars per million tokens (input, output). Returns the new text.
pub fn set_price(text: &str, model: &str, price: (f64, f64)) -> Result<String, String> {
    let mut map = tree(text)?;
    set_price_in(&mut map, model, price);
    Ok(to_yaml(&Value::Object(map)))
}

fn set_price_in(map: &mut Map<String, Value>, model: &str, (input, output): (f64, f64)) {
    let prices = map
        .entry("prices")
        .or_insert_with(|| Value::Object(Map::new()));
    if !prices.is_object() {
        *prices = Value::Object(Map::new());
    }
    if let Value::Object(prices) = prices {
        let number = |n: f64| serde_json::Number::from_f64(n).map_or(Value::Null, Value::Number);
        let entry = prices
            .entry(model)
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(entry) = entry {
            entry.insert("input".into(), number(input));
            entry.insert("output".into(), number(output));
        } else {
            *entry = serde_json::json!({ "input": number(input), "output": number(output) });
        }
    }
}

/// YAML for a tree, block style, with short lists and maps of plain values on one line as the docs write them.
pub fn to_yaml(value: &Value) -> String {
    let mut out = String::new();
    write_value(value, 0, &mut out);
    out
}

fn scalar(value: &Value) -> Option<String> {
    Some(match value {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => {
            let plain = !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_./@".contains(c))
                && !s.starts_with(['-', '.', '@'])
                && s.parse::<f64>().is_err()
                && ![
                    "true", "false", "yes", "no", "on", "off", "null", "y", "n", "~",
                ]
                .contains(&s.to_ascii_lowercase().as_str());
            if plain {
                s.clone()
            } else {
                // A JSON string is a YAML double-quoted string.
                Value::String(s.clone()).to_string()
            }
        }
        _ => return None,
    })
}

/// A list or map of plain values, short enough for one line: `[a, b]` or `{ k: v }`.
fn flow(value: &Value) -> Option<String> {
    let text = match value {
        Value::Array(items) => {
            let parts: Option<Vec<String>> = items.iter().map(scalar).collect();
            format!("[{}]", parts?.join(", "))
        }
        Value::Object(map) if !map.is_empty() => {
            let parts: Option<Vec<String>> = map
                .iter()
                .map(|(k, v)| {
                    Some(format!(
                        "{}: {}",
                        scalar(&Value::String(k.clone()))?,
                        scalar(v)?
                    ))
                })
                .collect();
            format!("{{ {} }}", parts?.join(", "))
        }
        _ => return None,
    };
    (text.len() <= 80).then_some(text)
}

fn write_value(value: &Value, depth: usize, out: &mut String) {
    let pad = "  ".repeat(depth);
    match value {
        Value::Object(map) => {
            for (key, item) in map {
                let key = scalar(&Value::String(key.clone())).unwrap_or_default();
                write_entry(&format!("{pad}{key}:"), item, depth, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                match item {
                    Value::Object(map) if !map.is_empty() => {
                        // The first field goes on the dash line, the rest under it.
                        let mut first = true;
                        for (key, field) in map {
                            let key = scalar(&Value::String(key.clone())).unwrap_or_default();
                            let lead = if first {
                                format!("{pad}- {key}:")
                            } else {
                                format!("{pad}  {key}:")
                            };
                            first = false;
                            write_entry(&lead, field, depth + 1, out);
                        }
                    }
                    _ => write_entry(&format!("{pad}-"), item, depth, out),
                }
            }
        }
        _ => {
            out.push_str(&pad);
            out.push_str(&scalar(value).unwrap_or_default());
            out.push('\n');
        }
    }
}

/// `lead` (a key or a dash), then the value on the same line or the lines under it.
fn write_entry(lead: &str, value: &Value, depth: usize, out: &mut String) {
    out.push_str(lead);
    if let Some(text) = scalar(value).or_else(|| flow(value)) {
        out.push(' ');
        out.push_str(&text);
        out.push('\n');
    } else if matches!(value, Value::Array(a) if a.is_empty()) {
        out.push_str(" []\n");
    } else if matches!(value, Value::Object(m) if m.is_empty()) {
        out.push_str(" {}\n");
    } else {
        out.push('\n');
        write_value(value, depth + 1, out);
    }
}

// ---------------------------------------------------------------- dry run

/// One recent request the draft decides differently.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Replayed {
    pub id: String,
    pub time: String,
    pub person: String,
    pub team: String,
    pub model: String,
    /// "allow", or the refusal code it got.
    pub was: String,
    /// "allow", or the refusal code the draft would give.
    pub now: String,
    pub rule_was: String,
    pub rule_now: String,
}

/// What replaying recent requests against a draft found.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct DryRun {
    pub since: String,
    /// Requests decided by the policy (allowed, or refused for the rule or the model) that were replayed.
    pub replayed: usize,
    /// Requests refused before the policy decided (an unknown key, a budget, a guardrail, a kill switch), which a
    /// policy change does not decide again here.
    pub skipped: usize,
    /// Allowed then, refused by the draft.
    pub now_refused: Vec<Replayed>,
    /// Refused then by the policy, allowed by the draft.
    pub now_allowed: Vec<Replayed>,
    /// Allowed both times, by another rule: its budget, rate limits and guardrails apply now.
    pub other_rule: Vec<Replayed>,
}

/// The codes a policy decision refuses with. Other refusals happen before or after it and are not replayed.
const POLICY_CODES: [&str; 3] = ["no_rule", "model_not_allowed", "unknown_model"];

/// What the draft decides for one caller and model, as a request record would say it.
fn decided(draft: &Loaded, who: &Principal, model: &str) -> (String, String) {
    match draft.policy.decide(who, model) {
        Decision::Allow(rule) => {
            let served = draft
                .providers
                .iter()
                .any(|p| p.models.iter().any(|m| m == model))
                || draft.aliases.iter().any(|a| a.name == model);
            let code = if served { "allow" } else { "unknown_model" };
            (code.into(), rule.name.clone())
        }
        Decision::NoRule => ("no_rule".into(), String::new()),
        Decision::ModelNotAllowed(rule) | Decision::KeyModelNotAllowed(rule) => {
            ("model_not_allowed".into(), rule.name.clone())
        }
    }
}

/// Replays the request records at or after `since` (a record timestamp) against `draft`. `keys` is the policy in
/// force, for each key's own model list.
pub fn dry_run(records: impl BufRead, since: &str, draft: &Loaded, keys: &Policy) -> DryRun {
    let mut run = DryRun {
        since: since.to_string(),
        ..DryRun::default()
    };
    let text = |r: &Value, k: &str| {
        r.get(k)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    for line in records.lines().map_while(Result::ok) {
        let Ok(record) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        if record.get("event").is_some() || text(&record, "time").as_str() < since {
            continue;
        }
        let (person, model, key) = (
            text(&record, "person"),
            text(&record, "model"),
            text(&record, "key"),
        );
        let was = match (text(&record, "verdict").as_str(), text(&record, "code")) {
            ("allow", _) => "allow".to_string(),
            (_, code) if POLICY_CODES.contains(&code.as_str()) => code,
            _ => String::new(),
        };
        if was.is_empty() || model.is_empty() || person.is_empty() || person == "unknown" {
            run.skipped += 1;
            continue;
        }
        let who = keys
            .entries()
            .map(|(_, p)| p)
            .find(|p| !key.is_empty() && p.key == key)
            .cloned()
            .unwrap_or_else(|| Principal {
                name: person.clone(),
                team: text(&record, "team"),
                key: key.clone(),
                ..Principal::default()
            });
        run.replayed += 1;
        let (now, rule_now) = decided(draft, &who, &model);
        let rule_was = text(&record, "rule");
        let replayed = Replayed {
            id: text(&record, "id"),
            time: text(&record, "time"),
            person,
            team: who.team.clone(),
            model,
            was: was.clone(),
            now: now.clone(),
            rule_was: rule_was.clone(),
            rule_now: rule_now.clone(),
        };
        match (was == "allow", now == "allow") {
            (true, false) => run.now_refused.push(replayed),
            (false, true) => run.now_allowed.push(replayed),
            (true, true) if rule_was != rule_now => run.other_rule.push(replayed),
            _ => {}
        }
    }
    run
}

/// The record timestamp `hours` ago, for [`dry_run`].
pub fn hours_ago(hours: u64) -> String {
    let then = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(hours.saturating_mul(3600)))
        .unwrap_or(std::time::UNIX_EPOCH);
    crate::audit::rfc3339(then)
}

/// Replays the last `hours` of the audit log at `audit_path` (with its sealed segments) against `draft`.
pub fn dry_run_log(
    audit_path: &Path,
    hours: u64,
    draft: &Loaded,
    keys: &Policy,
) -> Result<DryRun, String> {
    let reader = crate::audit::chain_reader(audit_path).map_err(|err| {
        format!(
            "the audit log at {} cannot be read: {err}. Check its permissions.",
            audit_path.display()
        )
    })?;
    Ok(dry_run(reader, &hours_ago(hours), draft, keys))
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const POLICY: &str = "version: 1
# The providers.
providers:
  - name: openai
    kind: openai
    url: https://api.openai.com
    key_env: OPENAI_API_KEY
    models: [gpt-4o, gpt-4o-mini]
rules:
  - name: payments
    principals: { team: payments }
    models: [gpt-4o, gpt-4o-mini]
    budget: { usd: 20.5, per: month }
  - name: everyone
    principals: { any: true }
    models: [gpt-4o-mini]
prices:
  gpt-4o: { input: 2.5, output: 10 }
";

    fn load(text: &str) -> Result<Loaded, String> {
        let dir = std::env::temp_dir().join(format!("gantry-versions-{}", std::process::id()));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let keys = "keys:\n  - name: maya.cohen\n    team: payments\n    sha256: 1111111111111111111111111111111111111111111111111111111111111111\n    models: [gpt-4o]\n  - name: dana.levi\n    team: interns\n    sha256: 2222222222222222222222222222222222222222222222222222222222222222\n";
        config::load_texts(
            &dir.join("gantry.policy.yaml"),
            text,
            &dir.join("gantry.keys.yaml"),
            keys,
        )
        .map_err(|e| e.join("\n"))
    }

    #[test]
    fn a_form_edit_writes_yaml_that_loads_to_the_same_policy_plus_the_change() -> TestResult {
        let before = load(POLICY)?;
        let same = to_yaml(&Value::Object(tree(POLICY)?));
        let again = load(&same)?;
        // The form drops comments, so rules move up a line; nothing else changes.
        let unlined = |l: &Loaded| {
            l.policy
                .rule_list()
                .iter()
                .map(|r| crate::policy::Rule {
                    line: 0,
                    ..r.clone()
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(unlined(&again), unlined(&before), "{same}");
        assert_eq!(again.policy.prices(), before.policy.prices());

        let added = add_model(
            POLICY,
            "openai",
            "o3",
            Some((2.0, 8.0)),
            &["reasoning".into()],
        )?;
        let after = load(&added)?;
        assert_eq!(
            after.providers[0].models,
            vec!["gpt-4o", "gpt-4o-mini", "o3"]
        );
        assert_eq!(
            after.policy.prices().get("o3").map(|p| (p.input, p.output)),
            Some((2.0, 8.0))
        );
        assert_eq!(after.aliases[0].name, "reasoning");
        assert_eq!(after.aliases[0].deployments[0].model, "o3");

        let priced = set_price(&added, "gpt-4o", (3.0, 12.0))?;
        let after = load(&priced)?;
        assert_eq!(
            after
                .policy
                .prices()
                .get("gpt-4o")
                .map(|p| (p.input, p.output)),
            Some((3.0, 12.0))
        );

        let twice = add_model(POLICY, "openai", "gpt-4o", None, &[])
            .err()
            .unwrap_or_default();
        assert!(twice.contains("already serves"), "{twice}");
        let nowhere = add_model(POLICY, "groq", "x", None, &[])
            .err()
            .unwrap_or_default();
        assert!(nowhere.contains("no provider \"groq\""), "{nowhere}");
        // A name YAML would read as another type stays a string.
        assert_eq!(
            to_yaml(&serde_json::json!({ "a": "yes", "b": "1.5", "c": "" })),
            "a: \"yes\"\nb: \"1.5\"\nc: \"\"\n"
        );
        Ok(())
    }

    #[test]
    fn a_diff_shows_changed_lines_with_their_neighbours() {
        let old = "a\nb\nc\nd\ne\nf\ng\nh\n";
        let new = "a\nb\nc\nd\nE\nf\ng\nh\n";
        let lines = diff(old, new);
        let kinds: Vec<(&str, &str)> = lines.iter().map(|(_, l, k)| (l.as_str(), *k)).collect();
        assert_eq!(
            kinds,
            vec![
                ("c", ""),
                ("d", ""),
                ("e", "del"),
                ("E", "add"),
                ("f", ""),
                ("g", "")
            ]
        );
        assert_eq!(diff_text("x\n", "y\n"), "- x\n+ y\n");
        assert!(diff(old, old).is_empty());
    }

    #[test]
    fn a_dry_run_lists_the_requests_a_draft_decides_differently() -> TestResult {
        let live = load(POLICY)?;
        let maya = live
            .policy
            .entries()
            .find(|(_, p)| p.name == "maya.cohen")
            .map(|(_, p)| p.key.clone())
            .ok_or("maya")?;
        let log = [
            format!(r#"{{"n":1,"id":"r1","time":"2026-11-14T08:00:00.000Z","person":"maya.cohen","team":"payments","key":"{maya}","model":"gpt-4o","verdict":"allow","code":null,"rule":"payments"}}"#),
            r#"{"n":2,"id":"r2","time":"2026-11-14T08:01:00.000Z","person":"dana.levi","team":"interns","key":"22222222","model":"gpt-4o","verdict":"refused","code":"model_not_allowed","rule":"everyone"}"#.to_string(),
            r#"{"n":3,"id":"r3","time":"2026-11-14T08:02:00.000Z","person":"dana.levi","team":"interns","key":"22222222","model":"gpt-4o-mini","verdict":"allow","code":null,"rule":"everyone"}"#.to_string(),
            r#"{"n":4,"id":"r4","time":"2026-11-14T08:03:00.000Z","person":"unknown","team":null,"key":"33333333","model":"gpt-4o","verdict":"refused","code":"unknown_key","rule":null}"#.to_string(),
            r#"{"n":5,"event":"config_loaded","time":"2026-11-14T08:04:00.000Z"}"#.to_string(),
            r#"{"n":6,"id":"r0","time":"2026-11-13T08:00:00.000Z","person":"dana.levi","team":"interns","key":"22222222","model":"gpt-4o","verdict":"refused","code":"model_not_allowed","rule":"everyone"}"#.to_string(),
        ]
        .join("\n");
        // The draft takes gpt-4o from payments, gives it to everyone else, and adds a rule above for interns.
        let draft = load(&POLICY.replace(
            "    models: [gpt-4o, gpt-4o-mini]\n    budget",
            "    models: [gpt-4o-mini]\n    budget",
        ).replace(
            "  - name: everyone\n    principals: { any: true }\n    models: [gpt-4o-mini]",
            "  - name: interns\n    principals: { team: interns }\n    models: [gpt-4o, gpt-4o-mini]\n  - name: everyone\n    principals: { any: true }\n    models: [gpt-4o-mini]",
        ))?;
        let run = dry_run(
            log.as_bytes(),
            "2026-11-14T00:00:00.000Z",
            &draft,
            &live.policy,
        );
        assert_eq!((run.replayed, run.skipped), (3, 1), "{run:?}");
        assert_eq!(run.now_refused.len(), 1, "{run:?}");
        assert_eq!(
            (
                run.now_refused[0].id.as_str(),
                run.now_refused[0].now.as_str()
            ),
            ("r1", "model_not_allowed")
        );
        assert_eq!(run.now_allowed.len(), 1, "{run:?}");
        assert_eq!(
            (
                run.now_allowed[0].id.as_str(),
                run.now_allowed[0].rule_now.as_str()
            ),
            ("r2", "interns")
        );
        assert_eq!(run.other_rule.len(), 1, "{run:?}");
        assert_eq!(run.other_rule[0].id, "r3");
        Ok(())
    }
}
