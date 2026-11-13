//! Serving from the policy and keys files, and changing to a new version of them without a restart.
//!
//! Once a second, and at once on SIGHUP, the SHA-256 of both files is read. A different hash on either is a change.
//! A change is checked as `gantry check` checks it, recorded in the audit chain, and only then used: the policy and
//! the keys switch together, in one swap. A change that fails is recorded once and not used.

use std::{
    collections::{BTreeSet, HashMap},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, mpsc},
    time::Duration,
};

use axum::Router;
use gantry_core::{
    audit::{self, AuditLog},
    config::{self, Kind, Loaded},
    guard,
    id::{hex, sha256_hex},
    policy::Policy,
    sigv4,
    store::{self, Store},
};
use serde_json::{Map, Value, json};

use crate::{Audit, Config, Live, ProviderRoute, Secret, Snapshot, Timeouts, build, key_header};

/// What made Gantry look at the files.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trigger {
    Start,
    /// The once-a-second check, or a change made through the admin API.
    FileChange,
    Signal,
}

impl Trigger {
    fn word(self) -> &'static str {
        match self {
            Trigger::Start => "start",
            Trigger::FileChange => "file_change",
            Trigger::Signal => "signal",
        }
    }
}

/// The outcome of looking at the files.
#[derive(Debug)]
pub enum Reload {
    /// Both files are as the version in use was read.
    Unchanged,
    /// A new version is recorded and in use.
    Loaded,
    /// The files on disk are not used, for these reasons. The version in use stays.
    Rejected(Vec<String>),
}

/// Hashes of the two files on disk. `None` for a file that is not there.
type Prints = (Option<String>, Option<String>);

struct Current {
    loaded: Loaded,
    /// The files as the version in use was read from them.
    prints: Prints,
    /// The files rejected since the version in use was loaded, so each pair is recorded once and not every second.
    rejected: HashMap<Prints, Vec<String>>,
    /// Hashes of the providers' key files as last read. A key file's path needs a restart to change, so the list
    /// keeps its order for the life of the process.
    key_prints: Vec<Option<String>>,
}

/// Watches the files and swaps the version in use. One per served policy file.
pub struct Reloader {
    policy_path: PathBuf,
    keys_path: PathBuf,
    live: Live,
    log: Arc<AuditLog>,
    // Held for the whole of a check, so two checks never record or swap at once.
    current: Mutex<Current>,
    // The hashes of a rejected version on disk, for the health check. Apart from `current`, so the health check
    // never waits for a check to finish.
    shown: Mutex<Option<Prints>>,
    wake: Mutex<Option<mpsc::Sender<Trigger>>>,
    /// Where the keys come from when the policy has `store:`, in place of the keys file.
    store: Option<Arc<dyn Store>>,
}

impl std::fmt::Debug for Reloader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Reloader")
    }
}

/// A server ready to serve from the files: the router, what watches the files, and the audit log.
pub struct Governed {
    pub router: Router,
    pub reloader: Arc<Reloader>,
    pub log: Arc<AuditLog>,
    /// The version Gantry started with.
    pub loaded: Loaded,
    /// Serves `GET /metrics`, for a listener of its own (`gantry serve --metrics`).
    pub metrics: Router,
    /// The one-time setup link's token, when the keys file had no admin key at start.
    pub setup: Option<String>,
}

/// Name, team and first 8 hex characters of each key's hash: how a record names a key without giving it away.
fn key_set(policy: &Policy) -> BTreeSet<(String, String, String)> {
    policy
        .entries()
        .map(|(hash, who)| (who.name.clone(), who.team.clone(), hex(&hash[..4])))
        .collect()
}

fn key_list<'a>(keys: impl Iterator<Item = &'a (String, String, String)>) -> Value {
    keys.map(|(name, team, prefix)| json!({ "name": name, "team": team, "sha256_prefix": prefix }))
        .collect()
}

/// The fields every configuration record starts with.
fn config_record(
    event: &str,
    trigger: Trigger,
    before: (Option<&str>, Option<&str>),
) -> Map<String, Value> {
    let mut record = Map::new();
    record.insert("event".into(), event.into());
    record.insert("time".into(), audit::timestamp().into());
    record.insert("trigger".into(), trigger.word().into());
    record.insert("policy_sha256_before".into(), before.0.into());
    record.insert("keys_sha256_before".into(), before.1.into());
    record
}

fn loaded_record(
    trigger: Trigger,
    before: (Option<&str>, Option<&str>),
    old_keys: &BTreeSet<(String, String, String)>,
    new: &Loaded,
) -> Map<String, Value> {
    let mut record = config_record("config_loaded", trigger, before);
    let new_keys = key_set(&new.policy);
    record.insert("policy_sha256".into(), new.policy_sha256.clone().into());
    record.insert("keys_sha256".into(), new.keys_sha256.clone().into());
    // The policy text holds no secrets, so each version is kept whole: the log is its history.
    record.insert("policy".into(), new.policy_text.clone().into());
    record.insert("keys_added".into(), key_list(new_keys.difference(old_keys)));
    record.insert(
        "keys_removed".into(),
        key_list(old_keys.difference(&new_keys)),
    );
    record
}

/// Reads a file whole. `Ok(None)` when it is not there.
fn read(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!(
            "{}: cannot be read: {err}. Fix the file or its permissions.",
            path.display()
        )),
    }
}

/// The provider key in a `key_file`, trimmed. A missing or empty file is an error that names the file.
fn read_key_file(provider: &str, path: &Path) -> Result<Secret, String> {
    let text = std::fs::read_to_string(path).map_err(|err| {
        format!(
            "the key for provider \"{provider}\" cannot be read from {}: {err}. The policy file says it is in that file: put the key there.",
            path.display()
        )
    })?;
    let key = text.trim();
    if key.is_empty() {
        return Err(format!(
            "the key file of provider \"{provider}\", {}, is empty. Put the provider key in it.",
            path.display()
        ));
    }
    Ok(Secret::new(key))
}

/// The hash of each provider's key file, so a change shows without keeping the keys themselves.
fn key_prints(loaded: &Loaded) -> Vec<Option<String>> {
    loaded
        .providers
        .iter()
        .filter_map(|p| p.key_file.as_deref())
        .map(|path| std::fs::read(path).ok().map(|bytes| sha256_hex(&bytes)))
        .collect()
}

/// Connects to the store when the policy has `store:`, and serves the keys file's path from it, so every reader
/// and writer of the keys (command line, admin API, console) uses the database. `None` without `store:`.
pub fn open_store(
    policy_path: &Path,
    keys_path: &Path,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<Arc<dyn Store>>, String> {
    let text = match std::fs::read_to_string(policy_path) {
        Ok(text) if config::names_store(&text) => text,
        // Not a store, or a policy that does not read: `config::load` reports it as it always has.
        _ => return Ok(None),
    };
    let setting = config::load_texts(policy_path, &text, keys_path, "")
        .map_err(|errors| errors.join("\n"))?
        .store
        .ok_or("the policy's store section could not be read. Run `gantry check` on it.")?;
    let variable = &setting.postgres_url_env;
    let url = env(variable).filter(|v| !v.trim().is_empty()).ok_or_else(|| {
        format!(
            "the policy keeps keys, kill switches and budgets in Postgres, and {variable} (its postgres_url_env) is not set. Set it to the connection string (`export {variable}=postgres://user:password@host:5432/database`) and start again."
        )
    })?;
    let opened: Arc<dyn Store> = crate::store::open(variable, &url)?;
    store::attach(keys_path, &opened);
    Ok(Some(opened))
}

/// Starts serving from the files: checks them, opens and verifies the audit log, records the version Gantry starts
/// with, and builds the router. `provider_key` gives the value of an environment variable, so tests need not set any.
pub fn governed(
    policy_path: &Path,
    keys_path: Option<&Path>,
    provider_key: &dyn Fn(&str) -> Option<String>,
) -> Result<Governed, String> {
    let keys_file = keys_path.map_or_else(|| config::keys_path_for(policy_path), Path::to_path_buf);
    let shared = open_store(policy_path, &keys_file, provider_key)?;
    let loaded = config::load(policy_path, keys_path).map_err(|errors| errors.join("\n"))?;
    let unset = guard::unset_webhook_env(loaded.policy.rule_list(), &|variable| {
        provider_key(variable).is_some_and(|value| !value.trim().is_empty())
    });
    if !unset.is_empty() {
        return Err(unset.join("\n"));
    }
    let mut providers = Vec::new();
    for provider in &loaded.providers {
        let set = |variable: &str| provider_key(variable).filter(|value| !value.trim().is_empty());
        let (key, aws) = if provider.kind == Kind::Bedrock {
            // Read from the environment, as the AWS SDKs do, and never through the aws command.
            let (Some(id), Some(secret)) = (set("AWS_ACCESS_KEY_ID"), set("AWS_SECRET_ACCESS_KEY"))
            else {
                return Err(format!(
                    "provider \"{}\" is on Amazon Bedrock, and AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY is not set. Set both (and AWS_SESSION_TOKEN for temporary credentials) and start again.",
                    provider.name
                ));
            };
            let credentials = sigv4::Credentials {
                access_key_id: id.trim().to_string(),
                secret_access_key: secret.trim().to_string(),
                session_token: set("AWS_SESSION_TOKEN").map(|t| t.trim().to_string()),
            };
            (None, Some(credentials))
        } else if let Some(path) = &provider.key_file {
            (Some(read_key_file(&provider.name, path)?), None)
        } else if provider.key_env.is_empty() {
            // `gantry check` allows this only for a model server on this machine or a private network.
            (None, None)
        } else {
            let variable = &provider.key_env;
            let key = set(variable).ok_or_else(|| {
                format!(
                    "the key for provider \"{}\" is not set. The policy file says it is in the environment variable {variable}: set it (`export {variable}=...`) and start again.",
                    provider.name
                )
            })?;
            (Some(Secret::new(key.trim())), None)
        };
        providers.push(ProviderRoute {
            name: provider.name.clone(),
            kind: provider.kind,
            url: provider.url.clone(),
            key,
            models: provider.models.clone(),
            upstream_models: provider.upstream_models.clone(),
            api_version: provider.api_version.clone(),
            region: provider.region.clone(),
            aws,
            fallback: provider.fallback.clone(),
            retries: provider.retries,
            accept_chat: provider.accept_chat,
            accept_messages: provider.accept_messages,
        });
    }
    let mut mcp = Vec::new();
    for server in &loaded.mcp {
        let mut headers = Vec::new();
        for (header, variable) in &server.headers_env {
            let value = provider_key(variable).filter(|v| !v.trim().is_empty()).ok_or_else(|| {
                format!(
                    "MCP server \"{}\" sends header {header} from the environment variable {variable}, which is not set. Set it (`export {variable}=...`) and start again.",
                    server.name
                )
            })?;
            headers.push((header.clone(), Secret::new(value.trim())));
        }
        mcp.push(crate::McpRoute {
            name: server.name.clone(),
            url: server.url.clone(),
            headers,
        });
    }
    let log = Arc::new(AuditLog::open(&loaded.audit_path)?);
    // The whole chain is checked before serving: Gantry does not add records to a log it cannot vouch for.
    // ponytail: this reads the whole file at every start. When logs grow past a few gigabytes, checkpoint the verified prefix.
    let last = if std::fs::metadata(&loaded.audit_path).is_ok_and(|m| m.is_file() && m.len() > 0) {
        audit::verify_full(&loaded.audit_path, None)
            .map_err(|err| {
                format!("{err} Gantry does not start on an audit log that does not hold. Move the file aside to keep it, and start again to begin a new chain.")
            })?
            .last_config
    } else {
        None
    };
    // "Before" is the version the log last recorded, so a change made while Gantry was stopped shows.
    let (before, old_keys) = match &last {
        Some(last) => (
            (
                Some(last.policy_sha256.as_str()),
                Some(last.keys_sha256.as_str()),
            ),
            last.keys.clone(),
        ),
        None => ((None, None), BTreeSet::new()),
    };
    log.append_record(&loaded_record(Trigger::Start, before, &old_keys, &loaded))
        .map_err(|err| {
            format!(
                "the audit log at {} cannot be written: {err}. Gantry does not start without recording the version it starts with.",
                loaded.audit_path.display()
            )
        })?;
    // First run: no one can sign in to the console yet, so a one-time link makes the first admin.
    let setup =
        (!loaded.policy.entries().any(|(_, p)| p.admin)).then(|| gantry_core::id::random_hex(24));
    let config = Config {
        providers,
        audit: Some(Audit {
            log: log.clone(),
            provider: String::new(),
            policy_sha256: loaded.policy_sha256.clone(),
            keys_sha256: loaded.keys_sha256.clone(),
        }),
        policy: Some(loaded.policy.clone()),
        timeouts: Timeouts::default(),
        console: Some(gantry_console::ConsoleConfig {
            policy: policy_path.to_path_buf(),
            keys: loaded.keys_path.clone(),
            audit: loaded.audit_path.clone(),
            log: Some(log.clone()),
        }),
        spent_from: Some(loaded.audit_path.clone()),
        aliases: loaded.aliases.clone(),
        // From the process environment: `provider_key` answers for provider keys, and tests stub it.
        traces: crate::TraceExport::from_env(|name| std::env::var(name).ok())?,
        setup: setup.clone(),
        mcp,
        store: shared.clone(),
        ..Config::default()
    };
    let prints = (
        Some(loaded.policy_sha256.clone()),
        loaded.keys_file_found.then(|| loaded.keys_sha256.clone()),
    );
    let (router, reloader, metrics) = build(config, |live| {
        Some(Arc::new(Reloader {
            policy_path: policy_path.to_path_buf(),
            keys_path: loaded.keys_path.clone(),
            live: live.clone(),
            log: log.clone(),
            current: Mutex::new(Current {
                key_prints: key_prints(&loaded),
                loaded: loaded.clone(),
                prints,
                rejected: HashMap::new(),
            }),
            shown: Mutex::new(None),
            wake: Mutex::new(None),
            store: shared.clone(),
        }))
    })
    .map_err(|err| err.to_string())?;
    let reloader = reloader.ok_or("the reloader was not built")?;
    Ok(Governed {
        router,
        reloader,
        log,
        loaded,
        metrics,
        setup,
    })
}

impl Reloader {
    /// Starts a thread that checks the files once a second, and at once after `signal`. It stops when the
    /// reloader is dropped.
    pub fn watch(self: &Arc<Self>) {
        let (tell, wake) = mpsc::channel();
        if let Ok(mut slot) = self.wake.lock() {
            *slot = Some(tell);
        }
        let weak = Arc::downgrade(self);
        let spawned = std::thread::Builder::new()
            .name("gantry-reload".into())
            .spawn(move || {
                loop {
                    let trigger = match wake.recv_timeout(Duration::from_secs(1)) {
                        Ok(trigger) => trigger,
                        Err(mpsc::RecvTimeoutError::Timeout) => Trigger::FileChange,
                        Err(mpsc::RecvTimeoutError::Disconnected) => return,
                    };
                    let Some(reloader) = weak.upgrade() else {
                        return;
                    };
                    reloader.check(trigger);
                }
            });
        if let Err(err) = spawned {
            eprintln!(
                "gantry: the thread that watches the policy and keys files could not be started: {err}. Changes need a restart until Gantry is started again."
            );
        }
    }

    /// Asks the watching thread to check the files now, as SIGHUP does.
    pub fn signal(&self) {
        if let Ok(slot) = self.wake.lock() {
            if let Some(tell) = slot.as_ref() {
                let _ = tell.send(Trigger::Signal);
            }
        }
    }

    pub(crate) fn keys_path(&self) -> &Path {
        &self.keys_path
    }

    /// The hashes of the files on disk, if they were rejected and are still there.
    pub fn rejected(&self) -> Option<(Option<String>, Option<String>)> {
        self.shown.lock().ok().and_then(|shown| shown.clone())
    }

    fn show(&self, prints: Option<Prints>) {
        if let Ok(mut shown) = self.shown.lock() {
            *shown = prints;
        }
    }

    /// Looks at both files and, if either changed, checks them and uses them or records why not.
    pub fn check(&self, trigger: Trigger) -> Reload {
        let mut current = match self.current.lock() {
            Ok(current) => current,
            Err(poisoned) => poisoned.into_inner(),
        };
        let keys_now = key_prints(&current.loaded);
        if keys_now != current.key_prints {
            self.rotate(&current.loaded);
            current.key_prints = keys_now;
        }
        let keys = match &self.store {
            // From memory: the store's poll keeps it current, and a database that is down keeps the keys known.
            Some(store) => Ok(Some(store.keys_text().into_bytes())),
            None => read(&self.keys_path),
        };
        let policy = read(&self.policy_path);
        let print = |file: &Result<Option<Vec<u8>>, String>| match file {
            Ok(bytes) => bytes.as_deref().map(sha256_hex),
            // Unreadable is a state of its own, never the same as a file Gantry read.
            Err(err) => Some(format!("unreadable: {err}")),
        };
        let prints = (print(&policy), print(&keys));
        if prints == current.prints {
            // Back to the version in use, perhaps after a rejected save was undone.
            self.show(None);
            return Reload::Unchanged;
        }
        if let Some(problems) = current.rejected.get(&prints) {
            let problems = problems.clone();
            self.show(Some(prints));
            return Reload::Rejected(problems);
        }
        // A setup that started without a keys file may still have none: that is no keys, as at start.
        let keys = match keys {
            Ok(None) if current.prints.1.is_none() => Ok(Some(Vec::new())),
            keys => keys,
        };
        match self.evaluate(&current.loaded, policy, keys) {
            Ok(new) => self.use_version(&mut current, trigger, prints, new),
            Err(problems) => self.reject(&mut current, trigger, prints, problems),
        }
    }

    fn evaluate(
        &self,
        old: &Loaded,
        policy: Result<Option<Vec<u8>>, String>,
        keys: Result<Option<Vec<u8>>, String>,
    ) -> Result<Loaded, Vec<String>> {
        let text = |file: Result<Option<Vec<u8>>, String>, path: &Path, what: &str| match file {
            Ok(Some(bytes)) => String::from_utf8(bytes).map_err(|_| {
                format!(
                    "{}: the {what} is not UTF-8 text. Save it as UTF-8.",
                    path.display()
                )
            }),
            Ok(None) => Err(format!(
                "{}: the {what} is missing. Gantry keeps the version it has. Put the file back, or save a new one that passes `gantry check`.",
                path.display()
            )),
            Err(err) => Err(err),
        };
        let (policy, keys) = (
            text(policy, &self.policy_path, "policy file"),
            text(keys, &self.keys_path, "keys file"),
        );
        let (policy, keys) = match (policy, keys) {
            (Ok(policy), Ok(keys)) => (policy, keys),
            (policy, keys) => {
                return Err([policy.err(), keys.err()].into_iter().flatten().collect());
            }
        };
        let new = config::load_texts(&self.policy_path, &policy, &self.keys_path, &keys)?;
        let unset = guard::unset_webhook_env(new.policy.rule_list(), &|variable| {
            std::env::var(variable).is_ok_and(|value| !value.trim().is_empty())
        });
        if !unset.is_empty() {
            return Err(unset);
        }
        let reasons = config::needs_restart(old, &new);
        if reasons.is_empty() {
            Ok(new)
        } else {
            Err(reasons
                .into_iter()
                .map(|reason| format!("{}: {reason}", self.policy_path.display()))
                .collect())
        }
    }

    fn use_version(
        &self,
        current: &mut Current,
        trigger: Trigger,
        prints: Prints,
        new: Loaded,
    ) -> Reload {
        let old_version = match self.live.read() {
            Ok(version) => version.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        // The providers keep their URLs and keys, which do not change without a restart, and take the new models.
        let mut providers = Vec::new();
        for provider in &new.providers {
            match old_version
                .providers
                .iter()
                .find(|p| p.name == provider.name)
            {
                Some(old) => {
                    let mut upstream = old.clone();
                    upstream.models = provider.models.clone();
                    // Routing follows the file at once. The URL, the key and what signs it wait for a restart.
                    upstream.upstream_models = provider.upstream_models.clone();
                    upstream.fallback = provider.fallback.clone();
                    upstream.retries = provider.retries;
                    upstream.accept_chat = provider.accept_chat;
                    upstream.accept_messages = provider.accept_messages;
                    providers.push(upstream);
                }
                None => {
                    return self.reject(
                        current,
                        trigger,
                        prints,
                        vec![format!(
                            "provider \"{}\" is new. Restart Gantry to add it.",
                            provider.name
                        )],
                    );
                }
            }
        }
        let old = &current.loaded;
        let record = loaded_record(
            trigger,
            (Some(&old.policy_sha256), Some(&old.keys_sha256)),
            &key_set(&old.policy),
            &new,
        );
        // Recorded first, used second: no request is decided by a version the chain does not show before it.
        if let Err(err) = self.log.append_record(&record) {
            let problem = format!(
                "the audit log could not record the new version: {err}. It is not used. Gantry keeps the version it has."
            );
            eprintln!("gantry: {problem}");
            return Reload::Rejected(vec![problem]);
        }
        let version = Arc::new(Snapshot {
            policy: Some(new.policy.clone()),
            providers,
            aliases: new.aliases.clone(),
            policy_sha256: new.policy_sha256.clone(),
            keys_sha256: new.keys_sha256.clone(),
        });
        match self.live.write() {
            Ok(mut live) => *live = version,
            Err(poisoned) => *poisoned.into_inner() = version,
        }
        println!(
            "gantry: now using policy {} and keys {} ({}): {}, {}.",
            &new.policy_sha256[..8],
            &new.keys_sha256[..8],
            trigger.word(),
            gantry_core::count(new.policy.rules(), "rule"),
            gantry_core::count(new.policy.keys(), "key"),
        );
        current.loaded = new;
        current.prints = prints;
        current.rejected.clear();
        self.show(None);
        Reload::Loaded
    }

    /// Reads the key files again and puts their keys in place, leaving the rest of the version in use as it is.
    /// A request already sent keeps the key it was sent with. A file that cannot be used keeps the key in use.
    fn rotate(&self, loaded: &Loaded) {
        let old = match self.live.read() {
            Ok(version) => version.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        let mut providers = old.providers.clone();
        let mut changed = false;
        for upstream in &mut providers {
            let Some(path) = loaded
                .providers
                .iter()
                .find(|p| p.name == upstream.name)
                .and_then(|p| p.key_file.as_deref())
            else {
                continue;
            };
            let key = read_key_file(&upstream.name, path)
                .and_then(|key| key_header(upstream.kind, &key).map_err(|err| err.to_string()));
            match key {
                Ok(key) if upstream.key.as_ref() != Some(&key) => {
                    upstream.key = Some(key);
                    changed = true;
                    println!(
                        "gantry: provider \"{}\" now uses the key in {}.",
                        upstream.name,
                        path.display()
                    );
                }
                Ok(_) => {}
                Err(err) => eprintln!("gantry: {err} Gantry keeps the key it has."),
            }
        }
        if !changed {
            return;
        }
        let version = Arc::new(Snapshot {
            policy: old.policy.clone(),
            providers,
            aliases: old.aliases.clone(),
            policy_sha256: old.policy_sha256.clone(),
            keys_sha256: old.keys_sha256.clone(),
        });
        match self.live.write() {
            Ok(mut live) => *live = version,
            Err(poisoned) => *poisoned.into_inner() = version,
        }
    }

    fn reject(
        &self,
        current: &mut Current,
        trigger: Trigger,
        prints: Prints,
        problems: Vec<String>,
    ) -> Reload {
        for problem in &problems {
            eprintln!("{problem}");
        }
        let old = &current.loaded;
        eprintln!(
            "gantry: the change to {} or {} is not used: {} above. Gantry keeps deciding with the version it has (policy {}, keys {}) and uses the next save that passes `gantry check`.",
            self.policy_path.display(),
            self.keys_path.display(),
            gantry_core::count(problems.len(), "problem"),
            &old.policy_sha256[..8],
            &old.keys_sha256[..8],
        );
        let mut record = config_record(
            "config_rejected",
            trigger,
            (Some(&old.policy_sha256), Some(&old.keys_sha256)),
        );
        record.insert("policy_sha256".into(), prints.0.clone().into());
        record.insert("keys_sha256".into(), prints.1.clone().into());
        record.insert("problem_count".into(), problems.len().into());
        record.insert("problems".into(), problems.clone().into());
        if let Err(err) = self.log.append_record(&record) {
            // Not remembered as recorded, so the next check tries to record it again.
            eprintln!("gantry: the audit log could not record the rejected change: {err}.");
            return Reload::Rejected(problems);
        }
        self.show(Some(prints.clone()));
        current.rejected.insert(prints, problems.clone());
        Reload::Rejected(problems)
    }
}
