//! Changes to the keys file: a key is added by appending its entry, and removed by a replace that only happens
//! while the file is still exactly as it was read. `gantry key new` and the server's admin API both come here,
//! so the file is changed one way whoever changes it.

use std::{io::Write, path::Path};

use crate::{
    config, id,
    policy::{Budget, KeyOptions},
};

/// What a key may carry besides its name and team.
#[derive(Clone, Debug, Default)]
pub struct Attributes {
    /// May sign in to the console and call the admin API.
    pub admin: bool,
    /// UTC date or time from which the key is refused, as `expires` in the keys file takes it.
    pub expires: Option<String>,
    pub budget: Option<Budget>,
    /// The models this key may use, within its rule's.
    pub models: Option<Vec<String>>,
    /// Most tokens this key may use per minute.
    pub tpm: Option<u32>,
    /// The key's organization, empty for none.
    pub org: String,
    /// The end customer every request with the key is for.
    pub customer: Option<String>,
    /// Tags every request with the key carries.
    pub tags: Vec<String>,
    /// Most requests the key may have in flight at once.
    pub parallel: Option<u32>,
    /// The console role the key signs in with.
    pub role: Option<String>,
    /// rpm, metadata, routes, source addresses.
    pub options: KeyOptions,
}

/// A key that was just made. `key` is shown once and kept nowhere.
#[derive(Debug)]
pub struct Issued {
    pub key: String,
    pub sha256: String,
    /// The name already had a key, and both now work.
    pub rotated: bool,
}

/// The entry a revocation removed.
#[derive(Debug, PartialEq, Eq)]
pub struct Revoked {
    pub name: String,
    pub team: String,
    pub sha256: String,
}

/// Makes a key and adds its entry to the end of the keys file, creating the file if there is none.
pub fn issue(name: &str, team: &str, keys: &Path) -> Result<Issued, String> {
    issue_with(name, team, &Attributes::default(), keys)
}

/// `issue`, for a key with attributes: admin, an expiry, a budget.
pub fn issue_with(
    name: &str,
    team: &str,
    attributes: &Attributes,
    keys: &Path,
) -> Result<Issued, String> {
    let key = id::new_key()?;
    let rotated = add_with(name, team, &key, attributes, keys)?;
    Ok(Issued {
        sha256: id::sha256_hex(key.as_bytes()),
        key,
        rotated,
    })
}

/// Adds the entry of a key made by the caller. Returns whether the name already had a key.
/// A save or another writer landing in the middle is retried for about a second: the key has not been shown yet,
/// so trying again is safe. Anything else stops at once.
pub fn add_key(name: &str, team: &str, key: &str, keys: &Path) -> Result<bool, String> {
    add_entry(name, team, key, false, keys)
}

/// `add_key`, for a key that may also be an admin's: it may sign in to the console and call the admin API.
pub fn add_entry(
    name: &str,
    team: &str,
    key: &str,
    admin: bool,
    keys: &Path,
) -> Result<bool, String> {
    let attributes = Attributes {
        admin,
        ..Attributes::default()
    };
    add_with(name, team, key, &attributes, keys)
}

/// `add_key`, for a key with attributes.
pub fn add_with(
    name: &str,
    team: &str,
    key: &str,
    attributes: &Attributes,
    keys: &Path,
) -> Result<bool, String> {
    if let Some(Err(problem)) = attributes.expires.as_deref().map(config::issuable_expiry) {
        return Err(format!(
            "{problem}. Nothing was changed and no key was made."
        ));
    }
    if attributes
        .budget
        .is_some_and(|b| !b.usd.is_finite() || b.usd <= 0.0)
    {
        return Err("a budget is a number of US dollars above 0, for example 20/month. Nothing was changed and no key was made.".into());
    }
    if attributes
        .models
        .as_ref()
        .is_some_and(|m| m.is_empty() || !m.iter().all(|n| config::valid_name(n) || n == "*"))
    {
        return Err("models lists the model names this key may use, at least one, each in letters, digits, '.', '-', '_' and '@', for example gpt-4o-mini,o3. Nothing was changed and no key was made.".into());
    }
    if attributes
        .tpm
        .is_some_and(|t| !(1..=1_000_000_000).contains(&t))
    {
        return Err("tpm is the number of tokens this key may use per minute, 1 to 1000000000, for example 200000. Nothing was changed and no key was made.".into());
    }
    if let Some(bad) = std::iter::once(&attributes.org)
        .filter(|o| !o.is_empty())
        .chain(attributes.customer.iter())
        .chain(attributes.role.iter())
        .chain(attributes.tags.iter())
        .find(|n| !config::valid_name(n))
    {
        return Err(format!(
            "\"{bad}\" is not a name Gantry accepts for org, customer, role or tags: use letters, digits, dots, dashes, underscores and @ only, at most 100 characters. Nothing was changed and no key was made."
        ));
    }
    if attributes.tags.len() > config::MAX_TAGS {
        return Err(format!(
            "a key carries at most {} tags. Nothing was changed and no key was made.",
            config::MAX_TAGS
        ));
    }
    if attributes
        .parallel
        .is_some_and(|p| !(1..=100_000).contains(&p))
    {
        return Err("parallel is the most requests the key may have in flight at once, 1 to 100000, for example 4. Nothing was changed and no key was made.".into());
    }
    if !config::valid_name(name) || !config::valid_name(team) {
        return Err("a name and a team use letters, digits, dots, dashes, underscores and @ only, at most 100 characters, for example maya.cohen and payments.".into());
    }
    if let Some(problem) = config::key_options_problem(&attributes.options) {
        return Err(format!(
            "{problem}. Nothing was changed and no key was made."
        ));
    }
    let hash = id::sha256_hex(key.as_bytes());
    if let Some(store) = crate::store::attached(keys) {
        return store.add_key(&config::KeyEntry {
            name: name.to_string(),
            team: team.to_string(),
            sha256: hash,
            admin: attributes.admin,
            expires: attributes.expires.clone(),
            budget: attributes.budget,
            models: attributes.models.clone(),
            tpm: attributes.tpm,
            org: attributes.org.clone(),
            customer: attributes.customer.clone(),
            tags: attributes.tags.clone(),
            parallel: attributes.parallel,
            role: attributes.role.clone(),
            options: attributes.options.clone(),
        });
    }
    let entry = entry_text(name, team, &hash, attributes);
    // Set once this run's entry has gone into the file, with whether the name already had a key.
    let mut appended = None;
    match retried(|| add(name, keys, &entry, &hash, &mut appended)) {
        Ok(rotated) => Ok(rotated),
        Err(err) if appended.is_none() => Err(err),
        // The entry went in and the key cannot be shown. It is taken out again, so the file does not keep an entry
        // whose key nobody has.
        Err(err) => match retried(|| remove(keys, &hash)) {
            Ok(_) => Err(format!(
                "{err}\nThe entry this run added is not in the file any more. Run the command again."
            )),
            Err(_) => Err(format!(
                "{err}\nThe entry this run added for {name} (sha256 {}...) may still be in {}. Its key was never shown, so it works for nobody: remove that entry.",
                &hash[..16],
                keys.display()
            )),
        },
    }
}

/// A keys file holding `entries`, written as `gantry key new` writes them: how a store hands its keys to the
/// loader, so they are checked by the same rules as a file.
pub fn keys_text(entries: &[config::KeyEntry]) -> String {
    let mut text = String::from(
        "# Keys from the store. Change them with `gantry key` or the admin API.\nkeys:",
    );
    text.push_str(if entries.is_empty() { " []\n" } else { "\n" });
    for entry in entries {
        let attributes = Attributes {
            admin: entry.admin,
            expires: entry.expires.clone(),
            budget: entry.budget,
            models: entry.models.clone(),
            tpm: entry.tpm,
            org: entry.org.clone(),
            customer: entry.customer.clone(),
            tags: entry.tags.clone(),
            parallel: entry.parallel,
            role: entry.role.clone(),
            options: entry.options.clone(),
        };
        text.push_str(&entry_text(
            &entry.name,
            &entry.team,
            &entry.sha256,
            &attributes,
        ));
    }
    text
}

/// One entry of the keys list, indented by two spaces.
fn entry_text(name: &str, team: &str, hash: &str, attributes: &Attributes) -> String {
    let mut entry = format!("  - name: {name}\n    team: {team}\n    sha256: {hash}\n");
    if attributes.admin {
        entry.push_str("    admin: true\n");
    }
    if let Some(expires) = &attributes.expires {
        entry.push_str(&format!("    expires: {expires}\n"));
    }
    if let Some(budget) = attributes.budget {
        let zone = budget
            .per
            .tz
            .map_or(String::new(), |tz| format!(", tz: {tz}"));
        let per = crate::policy::Period {
            tz: None,
            ..budget.per
        };
        entry.push_str(&format!(
            "    budget: {{ usd: {}, per: {}{zone} }}\n",
            budget.usd,
            per.word()
        ));
    }
    if let Some(models) = &attributes.models {
        // Quoted, so a name YAML reads specially (`@x`, `yes`) stays a name.
        let quoted: Vec<String> = models.iter().map(|m| format!("\"{m}\"")).collect();
        entry.push_str(&format!("    models: [{}]\n", quoted.join(", ")));
    }
    if let Some(tpm) = attributes.tpm {
        entry.push_str(&format!("    tpm: {tpm}\n"));
    }
    if !attributes.org.is_empty() {
        entry.push_str(&format!("    org: {}\n", attributes.org));
    }
    if let Some(customer) = &attributes.customer {
        entry.push_str(&format!("    customer: \"{customer}\"\n"));
    }
    if !attributes.tags.is_empty() {
        let quoted: Vec<String> = attributes.tags.iter().map(|t| format!("\"{t}\"")).collect();
        entry.push_str(&format!("    tags: [{}]\n", quoted.join(", ")));
    }
    if let Some(parallel) = attributes.parallel {
        entry.push_str(&format!("    parallel: {parallel}\n"));
    }
    if let Some(role) = &attributes.role {
        entry.push_str(&format!("    role: {role}\n"));
    }
    let o = &attributes.options;
    if let Some(rpm) = o.rpm {
        entry.push_str(&format!("    rpm: {rpm}\n"));
    }
    // Lists and maps are written as JSON, which YAML reads as written: a value YAML reads specially stays text.
    let json = |value: serde_json::Value| value.to_string();
    if !o.metadata.is_empty() {
        let map: serde_json::Map<String, serde_json::Value> = o
            .metadata
            .iter()
            .map(|(k, v)| (k.clone(), v.clone().into()))
            .collect();
        entry.push_str(&format!("    metadata: {}\n", json(map.into())));
    }
    if !o.routes.is_empty() {
        entry.push_str(&format!("    routes: {}\n", json(o.routes.clone().into())));
    }
    if !o.from.is_empty() {
        let from: Vec<String> = o.from.iter().map(ToString::to_string).collect();
        entry.push_str(&format!("    from: {}\n", json(from.into())));
    }
    if let Some(prefix) = &o.replaced_by {
        entry.push_str(&format!("    replaced_by: \"{prefix}\"\n"));
    }
    entry
}

/// A key's options as one JSON object, for a store column. `None` when the key has none.
pub fn options_json(options: &KeyOptions) -> Option<String> {
    if options.is_empty() {
        return None;
    }
    let mut map = serde_json::Map::new();
    if let Some(rpm) = options.rpm {
        map.insert("rpm".into(), rpm.into());
    }
    if !options.metadata.is_empty() {
        let metadata: serde_json::Map<String, serde_json::Value> = options
            .metadata
            .iter()
            .map(|(k, v)| (k.clone(), v.clone().into()))
            .collect();
        map.insert("metadata".into(), metadata.into());
    }
    if !options.routes.is_empty() {
        map.insert("routes".into(), options.routes.clone().into());
    }
    if !options.from.is_empty() {
        let from: Vec<String> = options.from.iter().map(ToString::to_string).collect();
        map.insert("from".into(), from.into());
    }
    if let Some(prefix) = &options.replaced_by {
        map.insert("replaced_by".into(), prefix.clone().into());
    }
    Some(serde_json::Value::Object(map).to_string())
}

/// The options `options_json` wrote. Anything it cannot read is an error, never a key with fewer limits.
pub fn options_from_json(text: &str) -> Result<KeyOptions, String> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|err| format!("a key's options are not JSON: {err}"))?;
    let wrong = |what: &str| format!("a key's options hold a {what} Gantry cannot read");
    let number = |name: &str| -> Result<Option<u32>, String> {
        value
            .get(name)
            .map(|n| {
                n.as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or_else(|| wrong(name))
            })
            .transpose()
    };
    let list = |name: &str| -> Result<Vec<String>, String> {
        value.get(name).map_or(Ok(Vec::new()), |l| {
            l.as_array()
                .ok_or_else(|| wrong(name))?
                .iter()
                .map(|v| v.as_str().map(str::to_string).ok_or_else(|| wrong(name)))
                .collect()
        })
    };
    let metadata = match value.get("metadata") {
        None => Default::default(),
        Some(m) => m
            .as_object()
            .ok_or_else(|| wrong("metadata"))?
            .iter()
            .map(|(k, v)| {
                Ok((
                    k.clone(),
                    v.as_str().ok_or_else(|| wrong("metadata"))?.to_string(),
                ))
            })
            .collect::<Result<_, String>>()?,
    };
    Ok(KeyOptions {
        rpm: number("rpm")?,
        metadata,
        routes: list("routes")?,
        from: config::cidrs(&list("from")?)?,
        replaced_by: value
            .get("replaced_by")
            .map(|p| {
                p.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| wrong("replaced_by"))
            })
            .transpose()?,
    })
}

/// Changes the one entry whose hash starts with `prefix` to what `change` makes of it. Returns the entry before and
/// after, or `Ok(None)` when no entry has that prefix. The entry keeps its name, team and hash, and the result is
/// checked by the loader's rules before anything is written; in a file, only that entry's lines are replaced, and
/// only while the file is as it was read.
pub fn update(
    keys: &Path,
    prefix: &str,
    change: &dyn Fn(&mut config::KeyEntry),
) -> Result<Option<(config::KeyEntry, config::KeyEntry)>, String> {
    let prefix = prefix.to_ascii_lowercase();
    if prefix.len() < 8 || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("name the key by at least the first 8 hex characters of its hash, as `GET /admin/keys` lists it.".into());
    }
    retried(|| update_once(keys, &prefix, change))
}

fn update_once(
    keys: &Path,
    prefix: &str,
    change: &dyn Fn(&mut config::KeyEntry),
) -> Result<Option<(config::KeyEntry, config::KeyEntry)>, String> {
    let store = crate::store::attached(keys);
    let seen = match &store {
        Some(store) => Seen {
            text: Some(store.keys_text()),
            stamp: None,
        },
        None => look(keys)?,
    };
    let Some(text) = &seen.text else {
        return Ok(None);
    };
    let entries = config::key_entries(keys, text).map_err(|problems| {
        format!(
            "{} has a problem, so nothing was changed. Fix it first:\n{}",
            keys.display(),
            problems.join("\n")
        )
    })?;
    let mut matching = entries.iter().filter(|e| e.sha256.starts_with(prefix));
    let Some(before) = matching.next() else {
        return Ok(None);
    };
    if matching.next().is_some() {
        return Err(format!(
            "more than one key hash starts with {prefix}. Give more of the hash. Nothing was changed."
        ));
    }
    let mut after = before.clone();
    change(&mut after);
    // Who the key is for and which key it is are not changed here: a new name is a new key.
    after.name.clone_from(&before.name);
    after.team.clone_from(&before.team);
    after.sha256.clone_from(&before.sha256);
    // The organization too: moving a key to another tenant is issuing it a new key there.
    after.org.clone_from(&before.org);
    let attributes = |e: &config::KeyEntry| Attributes {
        admin: e.admin,
        expires: e.expires.clone(),
        budget: e.budget,
        models: e.models.clone(),
        tpm: e.tpm,
        org: e.org.clone(),
        customer: e.customer.clone(),
        tags: e.tags.clone(),
        parallel: e.parallel,
        role: e.role.clone(),
        options: e.options.clone(),
    };
    let new_entry = entry_text(&after.name, &after.team, &after.sha256, &attributes(&after));
    // The changed entry must load by itself exactly as meant, or nothing is written.
    let alone = format!("keys:\n{new_entry}");
    match config::key_entries(keys, &alone) {
        Ok(read) if read.first() == Some(&after) => {}
        Ok(_) => {
            return Err("the change could not be written so that it reads back the same. Nothing was changed. Report this as a bug.".into());
        }
        Err(problems) => {
            return Err(format!(
                "{}. Nothing was changed.",
                problems
                    .iter()
                    .map(|p| p.split_once(": ").map_or(p.as_str(), |(_, rest)| rest))
                    .collect::<Vec<_>>()
                    .join(" ")
                    .trim_end_matches('.')
            ));
        }
    }
    if let Some(store) = store {
        return match store.update_key(&after)? {
            true => Ok(Some((before.clone(), after))),
            false => Ok(None),
        };
    }
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let unclear = || {
        format!(
            "the entry for {} in {} is not written as `gantry key new` writes entries, so it was not changed. Change it by hand. Nothing was changed.",
            before.name,
            keys.display()
        )
    };
    let at = lines
        .iter()
        .position(|line| line.contains(&before.sha256))
        .ok_or_else(unclear)?;
    let indent = |line: &str| line.len() - line.trim_start().len();
    let start = (0..=at)
        .rev()
        .find(|&i| lines[i].trim_start().starts_with("- "))
        .ok_or_else(unclear)?;
    let depth = indent(lines[start]);
    let end = (at + 1..lines.len())
        .find(|&i| !lines[i].trim().is_empty() && indent(lines[i]) <= depth)
        .unwrap_or(lines.len());
    let indented: String = new_entry
        .split_inclusive('\n')
        .map(|line| format!("{}{}", " ".repeat(depth), &line[2..]))
        .collect();
    let rest: String = lines[..start].concat() + &indented + &lines[end..].concat();
    // Whatever the text looked like, the result must be the same file with exactly this one entry changed.
    let now = config::key_entries(keys, &rest).map_err(|_| unclear())?;
    let expected: Vec<&config::KeyEntry> = entries
        .iter()
        .map(|e| if e.sha256 == after.sha256 { &after } else { e })
        .collect();
    if now.iter().collect::<Vec<_>>() != expected {
        return Err(unclear());
    }
    replace(keys, &seen, &rest)?;
    Ok(Some((before.clone(), after)))
}

/// Removes the one entry whose hash starts with `prefix`. `Ok(None)` when no entry has it.
pub fn revoke(keys: &Path, prefix: &str) -> Result<Option<Revoked>, String> {
    let prefix = prefix.to_ascii_lowercase();
    if prefix.len() < 8 || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("name the key by at least the first 8 hex characters of its hash, as `GET /admin/keys` lists it.".into());
    }
    if let Some(store) = crate::store::attached(keys) {
        return store.revoke(&prefix);
    }
    retried(|| remove(keys, &prefix))
}

fn retried<T>(mut attempt: impl FnMut() -> Result<T, String>) -> Result<T, String> {
    let mut last = String::new();
    for _ in 0..20 {
        match attempt() {
            Ok(done) => return Ok(done),
            Err(err) if transient(&err) => {
                last = err;
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(err) => return Err(err),
        }
    }
    Err(last)
}

/// Messages of a refusal that a moment later may not happen again.
fn transient(message: &str) -> bool {
    [
        "is being changed by someone else right now",
        "exists and is empty",
        "was saved by someone else",
        "was changed by someone else",
        "was created by someone else",
        // A save caught half written reads as a file that does not load, or as no file at all.
        "has a problem, so nothing was changed",
        "No such file",
        "no longer loads",
    ]
    .iter()
    .any(|phrase| message.contains(phrase))
}

/// Puts one entry in the keys file. Returns whether the name already had a key. `appended` is set once the entry
/// is in: a retry after that looks for the entry first, since adding it again would be refused as a duplicate.
fn add(
    name: &str,
    keys: &Path,
    entry: &str,
    hash: &str,
    appended: &mut Option<bool>,
) -> Result<bool, String> {
    if let Some(rotated) = *appended
        && shown(keys, hash)?
    {
        return Ok(rotated);
    }
    // A new key never rewrites a keys file someone else may be saving: its entry goes at the end, or the file is
    // created when there is none. Rewriting raced with editors and could bring back a key removed by hand.
    let seen = look(keys)?;
    let rotated = match &seen.text {
        None => {
            let text = format!(
                "# Keys Gantry accepts. Only the SHA-256 of each key is kept here. Add keys with `gantry key new`.\nkeys:\n{entry}"
            );
            create(keys, &text)?;
            false
        }
        Some(text) => {
            let rotated = existing_names(text).any(|existing| existing == name);
            let before = if text.ends_with('\n') { "" } else { "\n" };
            match keys_line(text) {
                Some("[]") => {
                    // An empty list written as `keys: []` cannot take an entry at its end, so this one case is
                    // rewritten, and only while the file is still exactly as read. It holds no key that could be lost.
                    let started: String = text
                        .split_inclusive('\n')
                        .map(|line| match keys_line(line) {
                            Some("[]") if line.ends_with('\n') => "keys:\n",
                            Some("[]") => "keys:",
                            _ => line,
                        })
                        .collect();
                    let before = if started.ends_with('\n') { "" } else { "\n" };
                    let full = format!("{started}{before}{entry}");
                    checked(keys, &full)?;
                    replace(keys, &seen, &full)?;
                }
                Some(rest) if rest.starts_with('[') => {
                    // A file that does not load is reported by its own problem first.
                    checked(keys, text)?;
                    return Err(format!(
                        "{}: the keys list is written on one line (`keys: [...]`), and `gantry key new` adds to a list written one entry per line. Write it as `keys:` followed by one `- name:` entry per key, then run the command again. Nothing was changed and no key was made.",
                        keys.display()
                    ));
                }
                Some(_) => {
                    // The entry follows the indentation of the entries already there, so a list indented by four
                    // spaces or none at all takes it too.
                    let depth = text
                        .lines()
                        .find(|line| line.trim_start().starts_with("- "))
                        .map_or(2, |line| line.len() - line.trim_start().len());
                    let indented: String = entry
                        .split_inclusive('\n')
                        .map(|line| format!("{}{}", " ".repeat(depth), &line[2..]))
                        .collect();
                    let addition = format!("{before}{indented}");
                    checked(keys, &format!("{text}{addition}"))?;
                    append(keys, &addition)?;
                }
                None => {
                    // Only comments so far: the list starts here.
                    let addition = format!("{before}keys:\n{entry}");
                    checked(keys, &format!("{text}{addition}"))?;
                    append(keys, &addition)?;
                }
            }
            rotated
        }
    };
    *appended = Some(rotated);
    // The key is shown only once it is in the file. A save that replaced the file meanwhile would have dropped it.
    if !shown(keys, hash)? {
        return Err(format!(
            "{} was saved by someone else while the key was being added, and the new entry is not in it. No key was made. Run the command again.",
            keys.display()
        ));
    }
    Ok(rotated)
}

/// What follows `keys:` on the line that starts the list, without a comment, if the text has such a line.
fn keys_line(text: &str) -> Option<&str> {
    text.lines()
        .find_map(|line| line.split('#').next()?.strip_prefix("keys:"))
        .map(str::trim)
}

/// Whether the keys file loads and holds this hash.
fn shown(keys: &Path, hash: &str) -> Result<bool, String> {
    let now = config::read_keys(keys)?.unwrap_or_default();
    if !config::keys_problems(keys, &now).is_empty() {
        // Two writers in the same file at once can mix their bytes, or a save is caught half done. The key is not
        // shown, and a retry tells whether the file settled or needs a look.
        return Err(format!(
            "{} no longer loads after the key was added: someone saved it at the same moment. No key was made. Run `gantry check` on the policy, and fix the keys file if it still does not load.",
            keys.display()
        ));
    }
    Ok(now.contains(hash))
}

/// Takes the entry out of the text and puts the rest in place of the file, if nobody changed it meanwhile.
fn remove(keys: &Path, prefix: &str) -> Result<Option<Revoked>, String> {
    let seen = look(keys)?;
    let Some(text) = &seen.text else {
        return Ok(None);
    };
    let entries = config::key_entries(keys, text).map_err(|problems| {
        format!(
            "{} has a problem, so nothing was changed. Fix it first:\n{}",
            keys.display(),
            problems.join("\n")
        )
    })?;
    let mut matching = entries.iter().filter(|e| e.sha256.starts_with(prefix));
    let Some(found) = matching.next() else {
        return Ok(None);
    };
    if matching.next().is_some() {
        return Err(format!(
            "more than one key hash starts with {prefix}. Give more of the hash. Nothing was changed."
        ));
    }
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let unclear = || {
        format!(
            "the entry for {} in {} is not written as `gantry key new` writes entries, so it was not removed. Remove it by hand. Nothing was changed.",
            found.name,
            keys.display()
        )
    };
    let at = lines
        .iter()
        .position(|line| line.contains(&found.sha256))
        .ok_or_else(unclear)?;
    let indent = |line: &str| line.len() - line.trim_start().len();
    // The entry runs from its `- ` line to the next line at that depth or shallower.
    let start = (0..=at)
        .rev()
        .find(|&i| lines[i].trim_start().starts_with("- "))
        .ok_or_else(unclear)?;
    let depth = indent(lines[start]);
    let end = (at + 1..lines.len())
        .find(|&i| !lines[i].trim().is_empty() && indent(lines[i]) <= depth)
        .unwrap_or(lines.len());
    let rest: String = lines[..start].concat() + &lines[end..].concat();
    // Whatever the text looked like, the result must be the same file less exactly this one key.
    let left = config::key_entries(keys, &rest).map_err(|_| unclear())?;
    if left.len() + 1 != entries.len() || left.iter().any(|e| e.sha256 == found.sha256) {
        return Err(unclear());
    }
    replace(keys, &seen, &rest)?;
    Ok(Some(Revoked {
        name: found.name.clone(),
        team: found.team.clone(),
        sha256: found.sha256.clone(),
    }))
}

/// Refuses a change that would leave a keys file `gantry serve` cannot load: a key "added" to it would take
/// every caller down.
fn checked(keys: &Path, text: &str) -> Result<(), String> {
    let problems = config::keys_problems(keys, text);
    if problems.is_empty() {
        return Ok(());
    }
    Err(format!(
        "{} has a problem, so nothing was changed and no key was added. Fix it first:\n{}",
        keys.display(),
        problems.join("\n")
    ))
}

/// Adds text to the end of an existing keys file in one write. It never creates the file and never truncates it.
fn append(keys: &Path, text: &str) -> Result<(), String> {
    let cannot = |err: std::io::Error| {
        format!(
            "{} cannot be written: {err}. Nothing was changed, and no key was made.",
            keys.display()
        )
    };
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(keys)
        .map_err(cannot)?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(cannot)
}

/// Creates a keys file that does not exist yet, readable by its owner only, whole or not at all: the text is written
/// under another name and then linked in place, which fails if a file appeared meanwhile. Creating the file and then
/// writing into it let an editor's save land in between, and the two writes mixed.
fn create(keys: &Path, text: &str) -> Result<(), String> {
    let temporary = keys.with_extension(format!("{}.new", &id::decision_id()[10..]));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let written = options
        .open(&temporary)
        .and_then(|mut file| {
            file.write_all(text.as_bytes())
                .and_then(|()| file.sync_all())
        })
        .and_then(|()| std::fs::hard_link(&temporary, keys));
    let _ = std::fs::remove_file(&temporary);
    written.map_err(|err| {
        if std::fs::symlink_metadata(keys).is_ok_and(|m| m.file_type().is_symlink()) {
            // The name is a link to a file that does not exist: it reads as no file, and it cannot be linked over.
            format!("{} is a symbolic link to a file that does not exist. Create the file it points to, or name the real keys file with --keys. Nothing was changed and no key was made.", keys.display())
        } else if err.kind() == std::io::ErrorKind::AlreadyExists {
            format!("{} was created by someone else while the key was being added. Nothing was changed and no key was made. Run the command again.", keys.display())
        } else {
            format!("{} cannot be created: {err}. Nothing was changed, and no key was made.", keys.display())
        }
    })
}

/// A keys file as it was when it was read: its text, and what identifies that state of the file on disk.
struct Seen {
    /// `None` when there is no file.
    text: Option<String>,
    stamp: Option<Stamp>,
}

/// Length, time of last change and, on Unix, the file's identity. An edit in place changes the first two, a replaced file the third.
type Stamp = (u64, Option<std::time::SystemTime>, u64);

fn stamp(keys: &Path) -> std::io::Result<Option<Stamp>> {
    match std::fs::metadata(keys) {
        Ok(meta) => {
            #[cfg(unix)]
            let id = std::os::unix::fs::MetadataExt::ino(&meta);
            #[cfg(not(unix))]
            let id = 0;
            Ok(Some((meta.len(), meta.modified().ok(), id)))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

/// Reads the keys file, and refuses a state that could be a save in progress.
fn look(keys: &Path) -> Result<Seen, String> {
    let unreadable = |err: std::io::Error| {
        format!(
            "{}: the keys file exists and cannot be read: {err}. Fix the file or its permissions. Nothing was changed.",
            keys.display()
        )
    };
    let before = stamp(keys).map_err(unreadable)?;
    let text = config::read_keys(keys)?;
    let after = stamp(keys).map_err(unreadable)?;
    let busy = || {
        format!(
            "{} is being changed by someone else right now. Nothing was changed and no key was made. Run the command again.",
            keys.display()
        )
    };
    if before != after || before.is_some() != text.is_some() {
        return Err(busy());
    }
    if text.as_ref().is_some_and(|text| text.trim().is_empty()) {
        return Err(format!(
            "{} exists and is empty. If someone is saving it right now, run the command again. If it is meant to be empty, delete it and run the command again. Nothing was changed and no key was made.",
            keys.display()
        ));
    }
    Ok(Seen {
        text,
        stamp: before,
    })
}

/// Puts `text` in place of the keys file, but only if the file is still exactly as `seen`.
/// Removing an entry by hand is how a key is revoked, so an edit made meanwhile must never be lost or undone.
fn replace(keys: &Path, seen: &Seen, text: &str) -> Result<(), String> {
    let cannot_write = |err: std::io::Error| {
        format!(
            "{} cannot be written: {err}. Nothing was changed.",
            keys.display()
        )
    };
    // Written beside the file and moved into place, so a crash cannot leave half a keys file. The temporary file
    // has a name nobody can guess and must not exist yet, so a link planted under that name is not followed.
    // ponytail: a symlinked keys file is replaced by a plain file here. Only `keys: []` and revocations rewrite.
    let temporary = keys.with_extension(format!("{}.tmp", &id::decision_id()[10..]));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        // The file keeps the permissions it had. A new one is readable by its owner only.
        let mode = std::fs::metadata(keys).map_or(0o600, |m| m.permissions().mode() & 0o777);
        options.mode(mode);
    }
    let written = options
        .open(&temporary)
        .and_then(|mut file| file.write_all(text.as_bytes()).and_then(|()| file.sync_all()))
        .map_err(cannot_write)
        .and_then(|()| {
            let now = look(keys)?;
            if now.stamp != seen.stamp || now.text != seen.text {
                return Err(format!(
                    "{} was changed by someone else meanwhile. Nothing was changed. Run the command again.",
                    keys.display()
                ));
            }
            std::fs::rename(&temporary, keys).map_err(cannot_write)
        });
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written
}

/// The names in a keys file, read from its text.
fn existing_names(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .filter_map(|line| {
            line.trim_start()
                .trim_start_matches("- ")
                .strip_prefix("name:")
        })
        .map(str::trim)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn keys_file(name: &str, text: &str) -> std::io::Result<PathBuf> {
        let dir = std::env::temp_dir().join(format!("gantry-keys-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("gantry.keys.yaml");
        std::fs::write(&path, text)?;
        Ok(path)
    }

    const TWO: &str = "keys:\n  - name: a\n    team: t\n    sha256: aa\n  - name: b\n    team: t\n    sha256: bb\n";

    #[test]
    fn a_key_removed_by_hand_while_a_key_is_added_stays_removed() -> TestResult {
        let path = keys_file("revoked", TWO)?;
        let seen = look(&path)?;
        // An admin revokes b by deleting its entry, after `key new` read the file and before it writes.
        let revoked = "keys:\n  - name: a\n    team: t\n    sha256: aa\n";
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&path, revoked)?;
        let err = replace(
            &path,
            &seen,
            &format!("{TWO}  - name: c\n    team: t\n    sha256: cc\n"),
        )
        .err()
        .ok_or("the edit was overwritten")?;
        assert!(err.contains("changed by someone else"), "{err}");
        assert_eq!(
            std::fs::read_to_string(&path)?,
            revoked,
            "the revoked key came back"
        );
        Ok(())
    }

    #[test]
    fn an_admin_key_is_appended_marked_admin() -> TestResult {
        let hash = |k: &str| id::sha256_hex(k.as_bytes());
        let text = format!(
            "keys:\n  - name: a\n    team: t\n    sha256: {}\n",
            hash("a")
        );
        let path = keys_file("admin", &text)?;
        assert!(!add_entry("noa", "ops", "gantry_noa", true, &path)?);
        add_key("dan", "ops", "gantry_dan", &path)?;
        let after = std::fs::read_to_string(&path)?;
        assert!(after.starts_with(&text));
        let entries = config::key_entries(&path, &after).map_err(|e| e.join("\n"))?;
        let admins: Vec<&str> = entries
            .iter()
            .filter(|e| e.admin)
            .map(|e| e.name.as_str())
            .collect();
        assert_eq!(admins, ["noa"]);
        Ok(())
    }

    #[test]
    fn a_file_saved_again_with_the_same_text_still_counts_as_changed() -> TestResult {
        let path = keys_file("resaved", TWO)?;
        let seen = look(&path)?;
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&path, TWO)?;
        assert!(replace(&path, &seen, TWO).is_err());
        Ok(())
    }

    #[test]
    fn a_keys_file_caught_empty_in_the_middle_of_a_save_is_not_taken_for_a_new_one() -> TestResult {
        // What `key new` sees for an instant when an editor saves in place: the file exists and holds nothing.
        let path = keys_file("midsave", "")?;
        let err = look(&path).err().ok_or("an empty file was accepted")?;
        assert!(err.contains("exists and is empty"), "{err}");
        assert!(issue("maya", "payments", &path).is_err());
        assert_eq!(std::fs::read_to_string(&path)?, "", "the file was replaced");
        Ok(())
    }

    #[test]
    fn every_key_option_is_written_and_read_back_and_a_wrong_one_makes_no_key() -> TestResult {
        let path = keys_file("options", "keys:\n")?;
        let options = KeyOptions {
            rpm: Some(60),
            metadata: [("owner".to_string(), "maya: ops # not a comment".to_string())].into(),
            routes: vec!["/v1/chat/completions".into()],
            from: vec!["10.0.0.0/8".parse()?, "2001:db8::/32".parse()?],
            replaced_by: None,
        };
        // The hierarchy's fields are written beside the options, a tag YAML reads specially ("yes") as text.
        let attributes = Attributes {
            options: options.clone(),
            tags: vec!["batch".into(), "yes".into()],
            parallel: Some(4),
            ..Attributes::default()
        };
        issue_with("ci", "t", &attributes, &path)?;
        let text = std::fs::read_to_string(&path)?;
        let entries = config::key_entries(&path, &text).map_err(|e| e.join("\n"))?;
        assert_eq!(entries[0].options, options);
        assert_eq!(entries[0].tags, attributes.tags);
        assert_eq!(entries[0].parallel, Some(4));
        let json = options_json(&options).ok_or("options were written as nothing")?;
        assert_eq!(options_from_json(&json)?, options);
        assert_eq!(options_json(&KeyOptions::default()), None);
        assert!(options_from_json(r#"{"rpm": "many"}"#).is_err());
        let with = |options: KeyOptions| Attributes {
            options,
            ..Attributes::default()
        };
        for attributes in [
            with(KeyOptions {
                rpm: Some(0),
                ..KeyOptions::default()
            }),
            Attributes {
                parallel: Some(100_001),
                ..Attributes::default()
            },
            with(KeyOptions {
                routes: vec!["v1/chat".into()],
                ..KeyOptions::default()
            }),
            Attributes {
                tags: vec!["two words".into()],
                ..Attributes::default()
            },
            with(KeyOptions {
                metadata: [("k".to_string(), "x".repeat(300))].into(),
                ..KeyOptions::default()
            }),
        ] {
            assert!(issue_with("cd", "t", &attributes, &path).is_err());
        }
        assert_eq!(std::fs::read_to_string(&path)?, text);
        Ok(())
    }

    #[test]
    fn an_update_changes_one_entry_and_keeps_every_other_line() -> TestResult {
        let path = keys_file(
            "update",
            "# hand notes stay\nkeys:\n  - name: a\n    team: t\n    sha256: aaaaaaaa00000000000000000000000000000000000000000000000000000000\n    tpm: 100 # a note\n  - name: b\n    team: t\n    sha256: bbbbbbbb00000000000000000000000000000000000000000000000000000000\n",
        )?;
        let changed = update(&path, "aaaaaaaa", &|e| {
            e.tpm = None;
            e.options.rpm = Some(30);
            e.tags = vec!["eval".into()];
            // Name and team are not changed by an update.
            e.name = "someone-else".into();
        })?
        .ok_or("the key was not found")?;
        assert_eq!(changed.0.tpm, Some(100));
        assert_eq!((changed.1.tpm, changed.1.options.rpm), (None, Some(30)));
        let text = std::fs::read_to_string(&path)?;
        assert!(text.starts_with("# hand notes stay\n"), "{text}");
        let entries = config::key_entries(&path, &text).map_err(|e| e.join("\n"))?;
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "a");
        assert_eq!(entries[0].tags, ["eval"]);
        assert_eq!(entries[1].name, "b");
        assert!(update(&path, "cccccccc", &|_| {})?.is_none());
        let refused = update(&path, "bbbbbbbb", &|e| e.options.rpm = Some(0));
        assert!(refused.is_err_and(|e| e.contains("rpm is") && e.contains("Nothing was changed")));
        assert_eq!(std::fs::read_to_string(&path)?, text);
        Ok(())
    }

    #[test]
    fn a_key_is_written_with_its_expiry_and_budget() -> TestResult {
        let path = keys_file("attrs", "keys:\n")?;
        let attributes = Attributes {
            admin: false,
            expires: Some("2099-12-31".into()),
            budget: Some(Budget {
                usd: 2.5,
                per: crate::policy::Period::Day,
            }),
            models: Some(vec!["gpt-4o-mini".into(), "o3".into()]),
            tpm: Some(5000),
            org: "acme".into(),
            customer: Some("globex-shop".into()),
            tags: vec!["ci".into(), "search".into()],
            parallel: Some(4),
            role: Some("finance".into()),
            options: KeyOptions::default(),
        };
        issue_with("ci", "t", &attributes, &path)?;
        let text = std::fs::read_to_string(&path)?;
        let entries = config::key_entries(&path, &text).map_err(|e| e.join("\n"))?;
        assert_eq!(entries[0].expires, attributes.expires);
        assert_eq!(entries[0].budget, attributes.budget);
        assert_eq!(entries[0].models, attributes.models);
        assert_eq!(entries[0].tpm, attributes.tpm);
        assert_eq!(entries[0].org, attributes.org);
        assert_eq!(entries[0].customer, attributes.customer);
        assert_eq!(entries[0].tags, attributes.tags);
        assert_eq!(entries[0].parallel, attributes.parallel);
        assert_eq!(entries[0].role, attributes.role);
        let bad = Attributes {
            expires: Some("soon".into()),
            ..Attributes::default()
        };
        assert!(issue_with("cd", "t", &bad, &path).is_err());
        // UX11 n3: a past date makes a key that is refused on its first request, so none is made.
        let past = Attributes {
            expires: Some("2020-01-01".into()),
            ..Attributes::default()
        };
        let err = issue_with("cd", "t", &past, &path)
            .err()
            .ok_or("a key was issued already expired")?;
        assert!(err.contains("2020-01-01 has passed"), "{err}");
        assert_eq!(std::fs::read_to_string(&path)?, text);
        Ok(())
    }

    #[test]
    fn nothing_is_left_behind_when_the_change_is_refused() -> TestResult {
        let path = keys_file("clean", TWO)?;
        let seen = look(&path)?;
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&path, "keys:\n")?;
        assert!(replace(&path, &seen, TWO).is_err());
        let dir = path.parent().ok_or("no folder")?;
        let names: Vec<String> = std::fs::read_dir(dir)?
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["gantry.keys.yaml"], "{names:?}");
        Ok(())
    }

    /// An editor that saves the keys file by reading it, deleting it and writing what it read, again and again,
    /// while keys are added: no key the editor keeps may be lost, and the key the editor removed must never come
    /// back. The editor writes back what it finds, so a file `key new` wiped stays wiped and is seen at the end.
    /// The race runs for a number of saves, not for a time, so a slow machine runs the same race, only longer.
    #[test]
    fn key_new_racing_an_editor_never_loses_or_restores_a_key() -> TestResult {
        let base: String = (0..20)
            .map(|i| format!("  - name: kept{i}\n    team: t\n    sha256: {i:064x}\n"))
            .collect();
        let saved = format!("keys:\n{base}");
        let path = keys_file(
            "race",
            &format!(
                "{saved}  - name: revoked\n    team: t\n    sha256: {:064x}\n",
                99
            ),
        )?;
        // The admin revokes the key once before the race.
        std::fs::write(&path, &saved)?;
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let runners: Vec<_> = (0..4)
            .map(|n| {
                let (path, stop) = (path.clone(), stop.clone());
                std::thread::spawn(move || {
                    let mut i = 0;
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        i += 1;
                        let _ = issue(&format!("new{n}-{i}"), "t", &path);
                    }
                    i
                })
            })
            .collect();
        let mut saves = 0;
        while saves < 300 {
            // Only this thread deletes the file, so it is always there to read.
            let text = std::fs::read_to_string(&path)?;
            std::fs::remove_file(&path)?;
            std::fs::write(&path, &text)?;
            saves += 1;
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let tries: usize = runners.into_iter().filter_map(|r| r.join().ok()).sum();
        assert!(tries >= 4, "the runs did not race the editor");
        let text = std::fs::read_to_string(&path)?;
        for i in 0..20 {
            assert!(
                text.contains(&format!("name: kept{i}\n")),
                "kept{i} was lost after {tries} runs:\n{text}"
            );
        }
        assert!(!text.contains("revoked"), "a revoked key came back");
        let dir = path.parent().ok_or("no folder")?;
        let left: Vec<String> = std::fs::read_dir(dir)?
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != "gantry.keys.yaml")
            .collect();
        assert!(left.is_empty(), "files left behind: {left:?}");
        Ok(())
    }

    /// A keys file that appears between `key new` finding no file and putting its own in place is never replaced:
    /// it can be an editor's save of every key, caught in the instant between deleting and writing.
    #[test]
    fn a_keys_file_that_appears_while_one_is_created_is_never_replaced() -> TestResult {
        let path = keys_file("appeared", TWO)?;
        let err = create(&path, "keys:\n  - name: c\n    team: t\n    sha256: cc\n")
            .err()
            .ok_or("the file that appeared was replaced")?;
        assert!(err.contains("was created by someone else"), "{err}");
        assert_eq!(std::fs::read_to_string(&path)?, TWO, "the file was changed");
        let dir = path.parent().ok_or("no folder")?;
        assert_eq!(std::fs::read_dir(dir)?.count(), 1, "files left behind");
        Ok(())
    }

    /// A change that keeps the file's length, time and identity is still seen, by its text.
    #[test]
    fn a_change_that_keeps_the_length_and_time_still_stops_a_rewrite() -> TestResult {
        let path = keys_file("same-stamp", TWO)?;
        let seen = look(&path)?;
        let modified = std::fs::metadata(&path)?.modified()?;
        // An edit in place to text of the same length, with the file's time put back.
        std::fs::write(&path, TWO.replace("sha256: bb", "sha256: dd"))?;
        std::fs::File::options()
            .write(true)
            .open(&path)?
            .set_modified(modified)?;
        assert_eq!(stamp(&path)?, seen.stamp, "the stamp should look unchanged");
        assert!(replace(&path, &seen, TWO).is_err(), "the edit was undone");
        assert!(std::fs::read_to_string(&path)?.contains("sha256: dd"));
        Ok(())
    }

    /// A retry after this run's own entry went in finds the entry and shows the key, instead of refusing its own
    /// entry as a duplicate and leaving it behind unshown.
    #[test]
    fn a_retry_after_its_own_append_shows_the_key() -> TestResult {
        let hash = id::sha256_hex(b"gantry_retry");
        let start = format!(
            "keys:\n{}  - name: maya\n    team: t\n    sha256: {hash}\n",
            entry("a", 1)
        );
        let entry = format!("  - name: maya\n    team: t\n    sha256: {hash}\n");
        let path = keys_file("retry", &start)?;
        let mut appended = Some(false);
        assert!(!add("maya", &path, &entry, &hash, &mut appended)?);
        // A run that did not add it is still refused: the entry belongs to someone else's key.
        let err = add("maya", &path, &entry, &hash, &mut None)
            .err()
            .ok_or("a duplicate was added")?;
        assert!(err.contains("listed twice"), "{err}");
        assert_eq!(std::fs::read_to_string(&path)?, start);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_link_to_no_file_is_refused_as_such() -> TestResult {
        let path = keys_file("dangling", "")?;
        std::fs::remove_file(&path)?;
        std::os::unix::fs::symlink(path.with_file_name("missing.yaml"), &path)?;
        let err = issue("maya", "t", &path).err().ok_or("a key was made")?;
        assert!(
            err.contains("symbolic link to a file that does not exist"),
            "{err}"
        );
        Ok(())
    }

    /// List shapes `gantry check` accepts are extended, or refused with the shape named.
    #[test]
    fn every_list_shape_check_accepts_takes_a_key_or_is_named() -> TestResult {
        let one = |indent: &str| {
            format!(
                "keys:\n{indent}- name: a\n{indent}  team: t\n{indent}  sha256: {:064x}\n",
                1
            )
        };
        for (name, text) in [
            ("spaced-empty", "keys:  []\n".to_string()),
            ("empty-comment", "keys: [] # none yet\n".to_string()),
            ("four", one("    ")),
            ("column0", one("")),
            ("no-final-newline", one("  ").trim_end().to_string()),
        ] {
            let path = keys_file(name, &text)?;
            issue("maya", "t", &path).map_err(|e| format!("{name}: {e}"))?;
            let after = std::fs::read_to_string(&path)?;
            let entries = config::key_entries(&path, &after).map_err(|e| e.join("\n"))?;
            assert!(entries.iter().any(|e| e.name == "maya"), "{name}: {after}");
        }
        let flow = format!("keys: [{{name: a, team: t, sha256: {:064x}}}]\n", 1);
        let path = keys_file("flow", &flow)?;
        let err = issue("maya", "t", &path)
            .err()
            .ok_or("a flow list was changed")?;
        assert!(err.contains("written on one line"), "{err}");
        assert_eq!(std::fs::read_to_string(&path)?, flow);
        Ok(())
    }

    /// Many runs at once: every key that was shown is in the file.
    #[test]
    fn every_key_shown_by_concurrent_runs_is_in_the_file() -> TestResult {
        let path = keys_file("concurrent", "keys:\n")?;
        let runners: Vec<_> = (0..8)
            .map(|n| {
                let path = path.clone();
                std::thread::spawn(move || {
                    (0..10)
                        .filter(|i| issue(&format!("p{n}-{i}"), "t", &path).is_ok())
                        .map(|i| format!("p{n}-{i}"))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let shown: Vec<String> = runners
            .into_iter()
            .filter_map(|r| r.join().ok())
            .flatten()
            .collect();
        let text = std::fs::read_to_string(&path)?;
        for name in &shown {
            assert!(
                text.contains(&format!("name: {name}\n")),
                "{name} was shown but is not in the file"
            );
        }
        assert_eq!(
            shown.len(),
            80,
            "appends do not conflict, so every run succeeds"
        );
        assert!(
            config::keys_problems(&path, &text).is_empty(),
            "the file no longer loads"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_keys_file_stays_a_symlink() -> TestResult {
        let target = keys_file(
            "link-target",
            &format!("keys:\n  - name: a\n    team: t\n    sha256: {:064x}\n", 1),
        )?;
        let link = target.with_file_name("link.yaml");
        std::os::unix::fs::symlink(&target, &link)?;
        issue("maya", "t", &link)?;
        assert!(std::fs::symlink_metadata(&link)?.file_type().is_symlink());
        assert!(std::fs::read_to_string(&target)?.contains("name: maya"));
        Ok(())
    }

    fn entry(name: &str, n: u32) -> String {
        format!("  - name: {name}\n    team: t\n    sha256: {n:064x}\n")
    }

    #[test]
    fn revoking_by_prefix_removes_that_entry_only() -> TestResult {
        let hash = |n: u32| format!("{n:08x}{}", "0".repeat(56));
        let line = |name: &str, n: u32| {
            format!("  - name: {name}\n    team: t\n    sha256: {}\n", hash(n))
        };
        let text = format!(
            "# our keys\nkeys:\n{}    admin: true\n{}  # the bot\n{}",
            line("a", 1),
            line("b", 2),
            line("c", 3)
        );
        let path = keys_file("revoke-one", &text)?;
        let gone = revoke(&path, &hash(2)[..8])?.ok_or("nothing was revoked")?;
        assert_eq!(gone.name, "b");
        let left = std::fs::read_to_string(&path)?;
        assert_eq!(
            left,
            format!(
                "# our keys\nkeys:\n{}    admin: true\n  # the bot\n{}",
                line("a", 1),
                line("c", 3)
            )
        );
        assert!(revoke(&path, &hash(2)[..8])?.is_none());
        let first = revoke(&path, &hash(1)[..8])?.ok_or("a was not revoked")?;
        assert_eq!(first.name, "a");
        assert!(
            !std::fs::read_to_string(&path)?.contains("admin"),
            "the flag stayed behind"
        );
        assert!(revoke(&path, "zz").is_err());
        Ok(())
    }

    #[test]
    fn a_prefix_two_keys_share_removes_nothing() -> TestResult {
        let text = format!("keys:\n{}{}", entry("a", 1), entry("b", 2));
        let path = keys_file("revoke-two", &text)?;
        let err = revoke(&path, "00000000")
            .err()
            .ok_or("an ambiguous prefix was used")?;
        assert!(err.contains("more than one"), "{err}");
        assert_eq!(std::fs::read_to_string(&path)?, text);
        Ok(())
    }
}
