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
/// Secrets read, by the name of the variable that points at them.
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
/// read (no source, or [`load`] not run) is `None`, as an unset variable is: it is never handed on as a key.
pub fn var(name: &str) -> Option<String> {
    let read = match cache().read() {
        Ok(cache) => cache.get(name).cloned(),
        Err(poisoned) => poisoned.into_inner().get(name).cloned(),
    };
    if read.is_some() {
        return read;
    }
    std::env::var(name).ok().filter(|v| !is_reference(v))
}

/// The references among `vars`, as (variable, reference), in name order.
fn references(vars: impl Iterator<Item = (String, String)>) -> Vec<(String, String)> {
    let mut found: Vec<(String, String)> = vars
        .filter(|(_, v)| is_reference(v))
        .map(|(k, v)| (k, v.trim().to_string()))
        .collect();
    found.sort();
    found
}

/// Reads every reference in the process environment, at start. `Err` names each one that failed, or says that this
/// binary cannot read secret managers.
pub fn load() -> Result<usize, String> {
    load_from(std::env::vars())
}

/// [`load`], from the variables given: for an embedder that passes its own environment, and for tests.
pub fn load_from(vars: impl Iterator<Item = (String, String)>) -> Result<usize, String> {
    let found = references(vars);
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
    let mut by_reference: HashMap<&str, String> = HashMap::new();
    let mut values = HashMap::new();
    let mut failed = Vec::new();
    for (name, reference) in &found {
        let value = match by_reference.get(reference.as_str()) {
            Some(value) => Ok(value.clone()),
            None => source.fetch(reference),
        };
        match value {
            Ok(value) => {
                by_reference.insert(reference, value.clone());
                values.insert(name.clone(), value);
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
    let count = by_reference.len();
    match cache().write() {
        Ok(mut cache) => *cache = values,
        Err(poisoned) => *poisoned.into_inner() = values,
    }
    Ok(count)
}

/// Reads every reference again. A value that changed is taken; one that cannot be read keeps the value in hand,
/// and the failure is returned for the log. Without a source, or with nothing to read, it does nothing.
pub fn refresh() -> Vec<String> {
    refresh_from(std::env::vars())
}

/// [`refresh`], from the variables given.
pub fn refresh_from(vars: impl Iterator<Item = (String, String)>) -> Vec<String> {
    let Some(source) = SOURCE.get() else {
        return Vec::new();
    };
    let mut failed = Vec::new();
    let mut fresh = Vec::new();
    for (name, reference) in references(vars) {
        match source.fetch(&reference) {
            Ok(value) => fresh.push((name, value)),
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
    for (name, value) in fresh {
        if cache.get(&name) != Some(&value) {
            cache.insert(name, value);
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

    #[test]
    fn without_a_source_a_reference_stops_the_start_with_the_fix() {
        // No source is installed in this test binary: the open source gateway.
        let err = load_from(
            [(
                "OPENAI_KEY".to_string(),
                "vault://secret/data/x#k".to_string(),
            )]
            .into_iter(),
        )
        .err()
        .unwrap_or_default();
        assert!(
            err.contains("OPENAI_KEY holds a secret manager reference"),
            "{err}"
        );
        assert!(err.contains("licensed feature"), "{err}");
        assert_eq!(
            load_from([("A".to_string(), "sk".to_string())].into_iter()),
            Ok(0)
        );
    }
}
