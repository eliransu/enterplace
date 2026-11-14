//! Secrets that a `*_env` variable points at in a secret manager instead of holding: `OPENAI_KEY=vault://...`.
//!
//! The open source gateway only recognizes such a reference, and refuses to start on one with the fix. A binary that
//! can read secret managers installs a [`Source`]; every reference in the environment is then fetched once at start,
//! read from memory on each lookup, and fetched again when asked ([`refresh`]): on reload and on the binary's own
//! schedule. A fetch that fails at start stops the start; one that fails later keeps the value in hand.

use std::{
    collections::HashMap,
    sync::{
        Arc, OnceLock, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

/// The forms a reference takes, as a variable's value.
pub const SCHEMES: [&str; 4] = ["vault://", "aws-sm://", "gcp-sm://", "azure-kv://"];

/// Whether a variable's value points at a secret manager rather than holding the secret.
pub fn is_reference(value: &str) -> bool {
    let value = value.trim();
    SCHEMES.iter().any(|s| value.starts_with(s))
}

/// Reads secret managers. Errors name the cause and the fix, and never hold a secret.
pub trait Source: Send + Sync {
    fn fetch(&self, reference: &str) -> Result<String, String>;
}

static SOURCE: OnceLock<Arc<dyn Source>> = OnceLock::new();
/// Values by reference.
static CACHE: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();
/// Moves on each refresh that changed a value, so the gateway knows to take the new keys.
static GENERATION: AtomicU64 = AtomicU64::new(0);

fn cache() -> &'static RwLock<HashMap<String, String>> {
    CACHE.get_or_init(RwLock::default)
}

/// Lets references be read. Once per process; false if a source was installed already.
pub fn install(source: Arc<dyn Source>) -> bool {
    SOURCE.set(source).is_ok()
}

/// A variable of the process environment, with a reference replaced by the secret it points at. A reference not
/// fetched (no source, or [`load`] not run) is `None`, as an unset variable is: it is never handed on as a key.
pub fn var(name: &str) -> Option<String> {
    let value = std::env::var(name).ok()?;
    if !is_reference(&value) {
        return Some(value);
    }
    let cache = match cache().read() {
        Ok(cache) => cache,
        Err(poisoned) => poisoned.into_inner(),
    };
    cache.get(value.trim()).cloned()
}

/// The references in the process environment, as (variable, reference).
fn references() -> Vec<(String, String)> {
    let mut found: Vec<(String, String)> = std::env::vars()
        .filter(|(_, v)| is_reference(v))
        .map(|(k, v)| (k, v.trim().to_string()))
        .collect();
    found.sort();
    found
}

/// Fetches every reference in the environment, at start. `Err` names each one that failed, or says that this
/// binary cannot read secret managers.
pub fn load() -> Result<usize, String> {
    let found = references();
    if found.is_empty() {
        return Ok(0);
    }
    let Some(source) = SOURCE.get() else {
        let names: Vec<&str> = found.iter().map(|(k, _)| k.as_str()).collect();
        return Err(format!(
            "{} hold{} a secret manager reference ({}), and this Gantry does not read secret managers. Reading Vault, AWS Secrets Manager, Google Secret Manager and Azure Key Vault in `gantry serve` is a licensed feature: run the Gantry image with a license that has `secrets`, or put the secret itself in the variable.",
            names.join(", "),
            if names.len() == 1 { "s" } else { "" },
            SCHEMES.join(", ")
        ));
    };
    let mut values = HashMap::new();
    let mut failed = Vec::new();
    for (name, reference) in &found {
        if values.contains_key(reference) {
            continue;
        }
        match source.fetch(reference) {
            Ok(value) => {
                values.insert(reference.clone(), value);
            }
            Err(err) => failed.push(format!("{name} ({reference}): {err}")),
        }
    }
    if !failed.is_empty() {
        return Err(format!(
            "Gantry could not read {} secret{} it was pointed at, so it does not start: {}",
            failed.len(),
            if failed.len() == 1 { "" } else { "s" },
            failed.join("; ")
        ));
    }
    let count = values.len();
    match cache().write() {
        Ok(mut cache) => *cache = values,
        Err(poisoned) => *poisoned.into_inner() = values,
    }
    Ok(count)
}

/// Fetches every reference again. A value that changed is taken; one that cannot be read keeps the value in hand,
/// and the failure is returned for the log. Without a source, or with nothing to read, it does nothing.
pub fn refresh() -> Vec<String> {
    let Some(source) = SOURCE.get() else {
        return Vec::new();
    };
    let mut failed = Vec::new();
    let mut fresh = Vec::new();
    for (name, reference) in references() {
        match source.fetch(&reference) {
            Ok(value) => fresh.push((reference, value)),
            Err(err) => failed.push(format!(
                "{name} ({reference}): {err}. Gantry keeps the value it read before."
            )),
        }
    }
    let mut cache = match cache().write() {
        Ok(cache) => cache,
        Err(poisoned) => poisoned.into_inner(),
    };
    let mut changed = false;
    for (reference, value) in fresh {
        if cache.get(&reference) != Some(&value) {
            cache.insert(reference, value);
            changed = true;
        }
    }
    if changed {
        GENERATION.fetch_add(1, Ordering::SeqCst);
    }
    failed
}

/// How many refreshes have changed a value so far.
pub fn generation() -> u64 {
    GENERATION.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_are_told_from_secrets() {
        assert!(is_reference("vault://secret/data/gantry#openai"));
        assert!(is_reference(" aws-sm://prod/openai"));
        assert!(is_reference("gcp-sm://projects/p/secrets/s"));
        assert!(is_reference("azure-kv://vault/secret"));
        assert!(!is_reference("sk-abc"));
        assert!(!is_reference("https://vault.example.com"));
    }
}
