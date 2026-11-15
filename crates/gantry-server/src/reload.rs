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
    /// A new live version in the store, when the policy is kept there.
    Store,
}

impl Trigger {
    fn word(self) -> &'static str {
        match self {
            Trigger::Start => "start",
            Trigger::FileChange => "file_change",
            Trigger::Signal => "signal",
            Trigger::Store => "store",
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
    /// The generation of each credential a provider names, as last read: a rotation shows as a new one.
    credential_prints: Vec<i64>,
    /// How many times secrets read from secret managers had changed when the keys were last taken.
    secrets: u64,
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
    /// The sealed credentials file without a store, held so it stays open for every reader of the keys path.
    _vault: Option<Arc<dyn gantry_core::store::Credentials>>,
    /// The organizations whose chains are open, and what a reload that adds one opens and tells.
    orgs: Mutex<BTreeSet<String>>,
    new_org: NewOrg,
    /// Whether this gateway can seal each person's MCP credentials: a server that keeps them needs it.
    mcp_seals: bool,
}

type Seal = Arc<dyn gantry_core::insights::Seal>;

/// What an organization added by a reload needs: a request index copier on the store, and the embedding binary told.
#[derive(Clone, Default)]
struct NewOrg {
    index: Option<(Arc<crate::store::PgStore>, Option<Seal>)>,
    tell: Option<Arc<dyn Fn(OrgChain) + Send + Sync>>,
    /// The runtime the gateway started on: reloads run on a thread of their own, and the copier and what the
    /// binary starts for the chain run there.
    runtime: Option<tokio::runtime::Handle>,
    /// The organizations' copiers, held for the life of the gateway: each stops once nothing holds it.
    copiers: Arc<Mutex<Vec<Arc<crate::insights::PgIndex>>>>,
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

/// A rotation of a secret read from a secret manager, or a refresh that failed: the variable, its reference and the
/// manager, never the value. The error a source gives never holds one either.
fn secret_record(change: &gantry_core::secrets::Change<'_>) -> Map<String, Value> {
    let mut record = Map::new();
    let event = if change.error.is_some() {
        "secret_refresh_failed"
    } else {
        "secret_rotated"
    };
    record.insert("event".into(), event.into());
    record.insert("time".into(), audit::timestamp().into());
    record.insert("variable".into(), change.variable.into());
    record.insert("reference".into(), change.reference.into());
    record.insert("source".into(), change.source.into());
    if let Some(error) = change.error {
        record.insert("code".into(), "secret_refresh_failed".into());
        record.insert("reason".into(), error.into());
    }
    record
}

/// The number of the store's live version, when the policy is kept in the store and `text` is that version.
fn live_version(policy_path: &Path, text: &str) -> Option<i64> {
    store::policy_store(policy_path)
        .and_then(|s| s.live_policy())
        .filter(|v| v.text == text)
        .map(|v| v.id)
}

fn loaded_record(
    policy_path: &Path,
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
    // Kept in the store: which version this is, so the chain names it as the versions page does.
    if let Some(id) = live_version(policy_path, &new.policy_text) {
        record.insert("policy_version".into(), id.into());
    }
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

/// The generation of each credential the providers name, in their order. -1 for one the store does not hold.
fn credential_prints(
    store: Option<&Arc<dyn gantry_core::store::Credentials>>,
    loaded: &Loaded,
) -> Vec<i64> {
    let Some(store) = store else {
        return Vec::new();
    };
    let held = store.credentials().unwrap_or_default();
    loaded
        .providers
        .iter()
        .filter_map(|p| p.credential.as_deref())
        .map(|name| {
            held.iter()
                .find(|c| c.name == name)
                .map_or(-1, |c| c.generation)
        })
        .collect()
}

/// Connects to the store when the policy has `store:`, and serves the keys file's path from it, so every reader
/// and writer of the keys (command line, admin API, console) uses the database. `None` without `store:`.
pub fn open_store(
    policy_path: &Path,
    keys_path: &Path,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<Arc<dyn Store>>, String> {
    Ok(open_postgres(policy_path, keys_path, env)?.map(|pg| -> Arc<dyn Store> { pg }))
}

fn open_postgres(
    policy_path: &Path,
    keys_path: &Path,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<Arc<crate::store::PgStore>>, String> {
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
    let opened = crate::store::open(variable, &url)?;
    opened.share_cache(setting.answer_cache);
    if let Some(master) = crate::MasterKey::from_env(env)? {
        opened.unlock(master)?;
    }
    let shared: Arc<dyn Store> = opened.clone();
    store::attach(keys_path, &shared);
    if setting.policy_from == config::PolicyFrom::Store {
        keep_policy_in_store(policy_path, &text, &shared)?;
    }
    Ok(Some(opened))
}

/// Serves the policy from the store's live version. The first gateway on an empty store imports the file as
/// version 1. A file that differs from the live version is not used, and Gantry says so at every start, so the two
/// never disagree in silence.
fn keep_policy_in_store(
    policy_path: &Path,
    file_text: &str,
    shared: &Arc<dyn Store>,
) -> Result<(), String> {
    if shared.live_policy().is_none() {
        let imported = shared.add_policy_version(&store::NewVersion {
            text: file_text.to_string(),
            base: None,
            note: format!("Imported from {} at first start", policy_path.display()),
            by: "gantry".into(),
            pending: false,
        });
        match imported {
            Ok(v) => println!(
                "gantry: the policy is kept in the store from now on: {} is version {}. Edit it in the console or with PUT /admin/policy.",
                policy_path.display(),
                v.id
            ),
            // Another gateway imported its file first: that one is version 1.
            Err(store::VersionError::Conflict(_)) => {}
            Err(store::VersionError::Store(err)) => return Err(err),
        }
    }
    store::attach_policy(policy_path, shared);
    match shared.live_policy() {
        Some(live) if live.text != file_text => eprintln!(
            "gantry: the policy is kept in the store (store.policy_from: store) and version {} is live there. {} differs from it and only its store: section is read. Export the live version with GET /admin/policy to update the file, or import the file as a new version with PUT /admin/policy.",
            live.id,
            policy_path.display()
        ),
        Some(_) => {}
        None => {
            return Err("the store holds no live policy version, and the file could not be imported. Check the database and start again.".into());
        }
    }
    Ok(())
}

/// Starts serving from the files: checks them, opens and verifies the audit log, records the version Gantry starts
/// with, and builds the router. `provider_key` gives the value of an environment variable, so tests need not set any.
pub fn governed(
    policy_path: &Path,
    keys_path: Option<&Path>,
    provider_key: &dyn Fn(&str) -> Option<String>,
) -> Result<Governed, String> {
    governed_with(policy_path, keys_path, provider_key, &|_| {
        Ok(crate::Extension::default())
    })
}

/// The route to one provider: its address, and the key or the signing it is sent with, read now. `env` gives
/// environment variables, so tests need not set any.
fn route(
    provider: &config::Provider,
    provider_key: &dyn Fn(&str) -> Option<String>,
    shared: Option<&Arc<dyn gantry_core::store::Credentials>>,
    policy_path: &Path,
    policy_text: &str,
) -> Result<ProviderRoute, String> {
    let set = |variable: &str| provider_key(variable).filter(|value| !value.trim().is_empty());
    let proxy = match &provider.proxy_env {
        Some(variable) => Some(Secret::new(set(variable).ok_or_else(|| {
            format!(
                "provider \"{}\" goes through the proxy in the environment variable {variable}, which is not set. Set it (`export {variable}=http://proxy.internal:3128`) and start again.",
                provider.name
            )
        })?)),
        None => None,
    };
    // Cloud sign-in goes through the provider's proxy too: an egress proxy is often the only way out.
    let via = proxy.as_ref().map(|p| p.0.as_str());
    let (key, aws, google) = if provider.kind.aws() {
        // The AWS default chain, as the SDKs read it, and never through the aws command.
        let region = provider.region.as_deref().unwrap_or_default();
        let aws = crate::cloud::aws_via(
            &provider.name,
            region,
            provider.role_arn.as_deref(),
            provider_key,
            via,
        )?;
        println!(
            "gantry: provider \"{}\" signs with AWS credentials from {}.",
            provider.name,
            aws.source()
        );
        (None, Some(aws), None)
    } else if let Some(path) = &provider.key_file {
        (Some(read_key_file(&provider.name, path)?), None, None)
    } else if let Some(name) = &provider.credential {
        let store =
            shared.ok_or("a provider names a credential, and this gateway keeps none: the policy has no store: section and no master key is set (GANTRY_MASTER_KEY or GANTRY_MASTER_KEY_FILE). gantry start makes one; set it and start again.")?;
        let value = store
            .credential_value(name)
            .map_err(|err| {
                format!(
                    "provider \"{}\" takes its key from credential \"{name}\", and {err}",
                    provider.name
                )
            })?
            .ok_or_else(|| {
                crate::credentials::unknown(
                    policy_path,
                    policy_text,
                    &provider.name,
                    name,
                    &store.credentials().unwrap_or_default(),
                )
            })?;
        (Some(Secret::new(value)), None, None)
    } else if provider.key_env.is_empty() && provider.kind == Kind::Azure {
        let entra = crate::cloud::entra_via(&provider.name, provider_key, via)?;
        println!(
            "gantry: provider \"{}\" signs in to Microsoft Entra ID with {}.",
            provider.name,
            entra.source()
        );
        (None, None, Some(entra))
    } else if provider.key_env.is_empty() && provider.kind.google_auth() {
        let google = crate::cloud::google_via(&provider.name, provider_key, via)?;
        println!(
            "gantry: provider \"{}\" signs in to Google Cloud with {}.",
            provider.name,
            google.source()
        );
        (None, None, Some(google))
    } else if provider.key_env.is_empty() {
        // `gantry check` allows this only for a model server on this machine or a private network.
        (None, None, None)
    } else {
        let variable = &provider.key_env;
        let key = set(variable).ok_or_else(|| {
            format!(
                "the key for provider \"{}\" is not set. The policy file says it is in the environment variable {variable}: set it (`export {variable}=...`) and start again.",
                provider.name
            )
        })?;
        (Some(Secret::new(key.trim())), None, None)
    };
    let mut keys = Vec::new();
    for source in &provider.keys {
        let value = match source {
            config::KeySource::Env(variable) => set(variable).ok_or_else(|| {
                format!(
                    "a key of provider \"{}\" is not set. The policy file says it is in the environment variable {variable}: set it (`export {variable}=...`) and start again.",
                    provider.name
                )
            })?,
            config::KeySource::Credential(name) => shared
                .ok_or("a provider names a credential, and this gateway keeps none: the policy has no store: section and no master key is set (GANTRY_MASTER_KEY or GANTRY_MASTER_KEY_FILE). gantry start makes one; set it and start again.")?
                .credential_value(name)
                .map_err(|err| format!("a key of provider \"{}\" is credential \"{name}\", and {err}", provider.name))?
                .ok_or_else(|| format!("a key of provider \"{}\" is credential \"{name}\", and the store holds none by that name. Add it in the console or with the admin API, or fix the name.", provider.name))?,
        };
        keys.push(Secret::new(value.trim()));
    }
    let mut headers = Vec::new();
    for (header, variable) in &provider.headers_env {
        let value = set(variable).ok_or_else(|| {
            format!(
                "provider \"{}\" sends header {header} from the environment variable {variable}, which is not set. Set it (`export {variable}=...`) and start again.",
                provider.name
            )
        })?;
        headers.push((header.clone(), Secret::new(value.trim())));
    }
    // watsonx.ai takes an IAM token, which IBM Cloud trades for the API key the policy points at.
    let (key, google) = match (provider.kind, key) {
        (Kind::Watsonx, Some(api_key)) => {
            let token = crate::cloud::ibm_via(&provider.name, &api_key.0, provider_key, via)?;
            (None, Some(token))
        }
        (_, key) => (key, google),
    };
    // The demo model speaks the chat completions API, answered inside the gateway (`demo.rs`); Claude Code's
    // messages requests are translated to it, as for any chat completions provider that accepts them.
    let demo = provider.kind == Kind::Demo;
    Ok(ProviderRoute {
        name: provider.name.clone(),
        kind: if demo { Kind::OpenAi } else { provider.kind },
        url: provider.url.clone(),
        key,
        models: provider.models.clone(),
        upstream_models: provider.upstream_models.clone(),
        api_version: provider.api_version.clone(),
        region: provider.region.clone(),
        aws,
        google,
        fallback: provider.fallback.clone(),
        retries: provider.retries,
        accept_chat: provider.accept_chat,
        accept_messages: provider.accept_messages || demo,
        timeouts: provider.timeouts,
        keys,
        least_used_key: provider.least_used_key,
        key_weights: provider.key_weights.clone(),
        key_quarantine: provider.key_quarantine_seconds.map(Duration::from_secs),
        headers,
        proxy,
        batch: provider.batch.clone(),
        project_id: provider.project_id.clone(),
        chat_as_responses: provider.chat_as_responses,
        oci: provider
            .oci_signing
            .as_ref()
            .map(|oci| oci_signer(&provider.name, oci, &set))
            .transpose()?,
    })
}

/// The OCI API signing key a provider names, read from its file or environment variable once, at start.
fn oci_signer(
    name: &str,
    oci: &gantry_core::config::OciSigning,
    set: &dyn Fn(&str) -> Option<String>,
) -> Result<Arc<crate::oci::Signer>, String> {
    let pem = match (&oci.key_file, &oci.key_env) {
        (Some(path), _) => std::fs::read_to_string(path).map_err(|err| {
            format!(
                "provider \"{name}\" signs with the OCI API key in {}, which cannot be read: {err}. Fix the path or its permissions and start again.",
                path.display()
            )
        })?,
        (None, Some(variable)) => set(variable).ok_or_else(|| {
            format!(
                "provider \"{name}\" signs with the OCI API key in the environment variable {variable}, which is not set. Set it to the key's PEM text and start again."
            )
        })?,
        (None, None) => return Err(format!("provider \"{name}\" has oci_signing without key_file or key_env. Add one.")),
    };
    crate::oci::Signer::from_pem(&oci.key_id(), &pem)
        .map(Arc::new)
        .map_err(|why| format!("provider \"{name}\": {why}"))
}

/// What a binary that embeds the gateway builds its additions from, once the files are checked and the store is open.
pub struct Host<'a> {
    /// The Postgres store when the policy has `store:`, for tables of the binary's own
    /// ([`PgStore::migrate`](crate::store::PgStore::migrate), [`PgStore::connect`](crate::store::PgStore::connect)).
    pub postgres: Option<&'a Arc<crate::store::PgStore>>,
    /// The keys file's path. Keys are read and changed through it (`gantry_core::keyfile`), from the store when there is one.
    pub keys: &'a Path,
    pub policy: &'a Path,
    /// The audit log this gateway writes, and its path, for a binary that reads the records back, seals the log or
    /// retires old segments (`gantry_core::audit::{chain_reader, retire}`).
    pub audit: &'a Arc<AuditLog>,
    pub audit_path: &'a Path,
    /// With a store: the number of the last record of this audit log the request index has copied (the console's
    /// request log). A binary that removes records from the disk, as one shipping sealed segments elsewhere does,
    /// removes none past it: the copier reads them from the disk, so their rows would never be copied.
    pub request_index: Option<Arc<std::sync::atomic::AtomicU64>>,
    /// The policy in force, after every reload. Empty while `extend` runs: read it later.
    pub policy_now: crate::PolicyNow,
    /// With `audit: { per_org: true }`: each organization's chain open at start, for a binary that exports, retains
    /// or ships each chain as it does the install's.
    pub org_chains: Vec<OrgChain>,
}

/// One organization's audit chain (`audit: { per_org: true }`).
#[derive(Clone)]
pub struct OrgChain {
    pub org: String,
    pub log: Arc<AuditLog>,
    pub path: PathBuf,
    /// With a store: the last record of this chain the request index has copied, as `Host::request_index`.
    pub request_index: Option<Arc<std::sync::atomic::AtomicU64>>,
}

/// The request index of every gateway on the store, and where bodies are kept, when there are.
type Served = (
    Option<Arc<dyn gantry_core::insights::Index>>,
    Option<Arc<dyn gantry_core::insights::Bodies>>,
);

/// The MCP servers of a policy as the gateway reaches them: each credential read from the environment, and a stdio
/// server's command checked against the commands this gateway's own environment lets it start.
fn mcp_routes(
    servers: &[gantry_core::mcp::Server],
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Vec<crate::McpRoute>, String> {
    use gantry_core::mcp::{STDIO_ALLOW_ENV, Transport, UserAuth};
    let mut mcp = Vec::new();
    for server in servers {
        let read = |variable: &str, what: &str| {
            env(variable)
                .filter(|v| !v.trim().is_empty())
                .map(|v| Secret::new(v.trim()))
                .ok_or_else(|| {
                    format!(
                        "MCP server \"{}\" {what} the environment variable {variable}, which is not set. Set it (`export {variable}=...`) and start again.",
                        server.name
                    )
                })
        };
        let mut headers = Vec::new();
        for (header, variable) in &server.headers_env {
            headers.push((
                header.clone(),
                read(variable, &format!("sends header {header} from"))?,
            ));
        }
        let oauth_client_secret = match &server.user_auth {
            Some(
                UserAuth::OAuth {
                    client_secret_env: Some(variable),
                    ..
                }
                | UserAuth::Exchange {
                    client_secret_env: Some(variable),
                    ..
                },
            ) => Some(read(variable, "takes its OAuth client secret from")?),
            _ => None,
        };
        let mut stdio_env = Vec::new();
        if let Transport::Stdio {
            command, env: vars, ..
        } = &server.transport
        {
            let allowed = env(STDIO_ALLOW_ENV).unwrap_or_default();
            if !allowed.split(',').any(|path| path.trim() == command) {
                return Err(format!(
                    "MCP server \"{}\" starts {command}, which this gateway may not run: {STDIO_ALLOW_ENV} does not list it. The policy cannot choose what the gateway runs; whoever runs the gateway does. Add the path to {STDIO_ALLOW_ENV} in the gateway's environment (comma separated absolute paths) and start again, or remove the server.",
                    server.name
                ));
            }
            for (child, variable) in vars {
                stdio_env.push((
                    child.clone(),
                    read(variable, &format!("gives its process {child} from"))?,
                ));
            }
        }
        mcp.push(crate::McpRoute {
            name: server.name.clone(),
            url: server.url.clone(),
            headers,
            user_auth: server.user_auth.clone(),
            tool_changes: server.tool_changes,
            oauth_client_secret,
            transport: server.transport.clone(),
            stdio_env,
            call_price_usd: server.call_price_usd,
            tool_prices: server.tool_prices.clone(),
        });
    }
    Ok(mcp)
}

/// `governed`, with what an embedding binary adds: `extend` runs before the router is built.
pub fn governed_with(
    policy_path: &Path,
    keys_path: Option<&Path>,
    provider_key: &dyn Fn(&str) -> Option<String>,
    extend: &(dyn Fn(Host<'_>) -> Result<crate::Extension, String> + Sync),
) -> Result<Governed, String> {
    let keys_file = keys_path.map_or_else(|| config::keys_path_for(policy_path), Path::to_path_buf);
    let postgres = open_postgres(policy_path, &keys_file, provider_key)?;
    let shared = postgres.clone().map(|pg| -> Arc<dyn Store> { pg });
    // Without a store, credentials are sealed in a file beside the policy, under the master key `gantry start` made.
    // A master key that does not read stops the start only when a provider needs it, as for MCP credentials below.
    let master = if postgres.is_none() {
        match crate::MasterKey::from_env(provider_key) {
            Ok(master) => master,
            Err(err) if !config::credentials_named(policy_path).is_empty() => {
                return Err(err);
            }
            Err(_) => None,
        }
    } else {
        None
    };
    let vault = match (&postgres, master) {
        (None, Some(master)) => {
            let vault: Arc<dyn gantry_core::store::Credentials> =
                Arc::new(crate::credentials::FileVault::new(policy_path, master));
            store::attach_credentials(&keys_file, &vault);
            Some(vault)
        }
        _ => None,
    };
    let loaded = config::load(policy_path, keys_path).map_err(|errors| errors.join("\n"))?;
    let unset = guard::unset_webhook_env(loaded.policy.rule_list(), &|variable| {
        provider_key(variable).is_some_and(|value| !value.trim().is_empty())
    });
    if !unset.is_empty() {
        return Err(unset.join("\n"));
    }
    let mut providers = Vec::new();
    for provider in &loaded.providers {
        providers.push(route(
            provider,
            provider_key,
            store::credentials_for(&keys_file).as_ref(),
            policy_path,
            &loaded.policy_text,
        )?);
    }
    let mcp = mcp_routes(&loaded.mcp, provider_key)?;
    // Each person's MCP credentials are sealed with the store's master key, or without a store with the gateway's.
    // Read whenever it is set, so a server with user_auth can be added by a reload.
    let mcp_master = if postgres.is_none() {
        match crate::MasterKey::from_env(provider_key) {
            Ok(master) => master.map(Arc::new),
            Err(err)
                if loaded
                    .mcp
                    .iter()
                    .any(|s| crate::mcp::keeps_credentials(&s.user_auth)) =>
            {
                return Err(err);
            }
            Err(_) => None,
        }
    } else {
        None
    };
    let mcp_seals = postgres.is_some() || mcp_master.is_some();
    let mcp_setup = crate::McpSetup {
        postgres: postgres.clone(),
        file: Some(policy_path.with_file_name("gantry.mcp.json")),
        master: mcp_master,
        sso: loaded
            .sso
            .as_ref()
            .is_some_and(|sso| sso.self_issue.is_some()),
        audit_path: Some(loaded.audit_path.clone()),
    };
    let mut log = AuditLog::open(&loaded.audit_path)?;
    if loaded.audit_per_org {
        log = log.per_org(loaded.policy.orgs())?;
    }
    let log = Arc::new(log);
    // Weak: the observer is process-wide, and must not keep a log (and its lock) open after the server drops it.
    let to_log = Arc::downgrade(&log);
    gantry_core::secrets::observe(Arc::new(move |change| {
        if let Some(log) = to_log.upgrade() {
            log.append_record_then(&secret_record(change), |_| {});
        }
    }));
    // The whole chain is checked before serving: Gantry does not add records to a log it cannot vouch for.
    // ponytail: this reads the whole file at every start. When logs grow past a few gigabytes, checkpoint the verified prefix.
    let last = if audit::has_records(&loaded.audit_path) {
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
    log.append_record(&loaded_record(policy_path, Trigger::Start, before, &old_keys, &loaded))
        .map_err(|err| {
            format!(
                "the audit log at {} cannot be written: {err}. Gantry does not start without recording the version it starts with.",
                loaded.audit_path.display()
            )
        })?;
    // Bodies are kept only sealed: capture needs the master key, and is refused at start without one.
    // Read only when something needs it: the store (which read it already) or a rule that captures.
    let capturing = loaded
        .policy
        .rule_list()
        .iter()
        .any(|r| r.limits.capture.is_some());
    let master = if capturing || postgres.is_some() {
        crate::MasterKey::from_env(provider_key)?
    } else {
        None
    };
    let problems = crate::insights::capture_problems(loaded.policy.rule_list(), master.is_some());
    if !problems.is_empty() {
        return Err(problems.join("\n"));
    }
    let seal = master
        .map(|m| -> Arc<dyn gantry_core::insights::Seal> { Arc::new(crate::insights::Sealer(m)) });
    let mut request_index = None;
    let mut org_chains: Vec<OrgChain> = log
        .org_logs()
        .into_iter()
        .map(|(org, log)| OrgChain {
            path: audit::org_path(&loaded.audit_path, &org),
            org,
            log,
            request_index: None,
        })
        .collect();
    let known_orgs: BTreeSet<String> = org_chains.iter().map(|c| c.org.clone()).collect();
    let mut new_org = NewOrg {
        index: postgres.clone().map(|pg| (pg, seal.clone())),
        runtime: tokio::runtime::Handle::try_current().ok(),
        ..NewOrg::default()
    };
    let (index, bodies): Served = match &postgres {
        Some(pg) => {
            let index =
                crate::insights::PgIndex::open(pg.clone(), &loaded.audit_path, seal.clone(), true)?;
            request_index = Some(index.copied());
            // Each organization's chain is a replica of its own in the request log: its rows are copied the same way.
            for chain in &mut org_chains {
                let copier =
                    crate::insights::PgIndex::open(pg.clone(), &chain.path, seal.clone(), true)?;
                chain.request_index = Some(copier.copied());
                new_org
                    .copiers
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(copier);
            }
            let bodies = seal
                .is_some()
                .then(|| -> Arc<dyn gantry_core::insights::Bodies> { index.clone() });
            (Some(index), bodies)
        }
        None => (
            None,
            seal.map(|seal| -> Arc<dyn gantry_core::insights::Bodies> {
                Arc::new(gantry_core::insights::FileBodies::beside(
                    &loaded.audit_path,
                    seal,
                ))
            }),
        ),
    };
    gantry_core::insights::attach(&loaded.audit_path, index, bodies.clone());
    // First run: no one can sign in to the console yet, so a one-time link makes the first admin.
    let setup =
        (!loaded.policy.entries().any(|(_, p)| p.admin)).then(|| gantry_core::id::random_hex(24));
    let policy_now = crate::PolicyNow::default();
    let extension = extend(Host {
        postgres: postgres.as_ref(),
        keys: &loaded.keys_path,
        policy: policy_path,
        audit: &log,
        audit_path: &loaded.audit_path,
        request_index,
        policy_now: policy_now.clone(),
        org_chains,
    })?;
    new_org.tell = extension.on_org.clone();
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
        mcp_setup,
        store: shared.clone(),
        bodies,
        extension,
        ..Config::default()
    };
    let prints = (
        Some(loaded.policy_sha256.clone()),
        loaded.keys_file_found.then(|| loaded.keys_sha256.clone()),
    );
    let (router, reloader, metrics) = build(config, |live| {
        policy_now.set(live);
        Some(Arc::new(Reloader {
            policy_path: policy_path.to_path_buf(),
            keys_path: loaded.keys_path.clone(),
            live: live.clone(),
            log: log.clone(),
            current: Mutex::new(Current {
                key_prints: key_prints(&loaded),
                credential_prints: credential_prints(
                    store::credentials_for(&loaded.keys_path).as_ref(),
                    &loaded,
                ),
                secrets: gantry_core::secrets::generation(),
                loaded: loaded.clone(),
                prints,
                rejected: HashMap::new(),
            }),
            shown: Mutex::new(None),
            wake: Mutex::new(None),
            store: shared.clone(),
            _vault: vault.clone(),
            orgs: Mutex::new(known_orgs.clone()),
            new_org: new_org.clone(),
            mcp_seals,
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

    pub(crate) fn audit_path(&self) -> PathBuf {
        match self.current.lock() {
            Ok(current) => current.loaded.audit_path.clone(),
            Err(poisoned) => poisoned.into_inner().loaded.audit_path.clone(),
        }
    }

    pub(crate) fn policy_path(&self) -> &Path {
        &self.policy_path
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
        // A reload asked for (SIGHUP, the admin API) reads the secret managers again too.
        if trigger == Trigger::Signal {
            for problem in gantry_core::secrets::refresh() {
                eprintln!("gantry: {problem}");
            }
        }
        let keys_now = key_prints(&current.loaded);
        let credentials_now = credential_prints(
            store::credentials_for(&self.keys_path).as_ref(),
            &current.loaded,
        );
        let secrets_now = gantry_core::secrets::generation();
        if keys_now != current.key_prints
            || credentials_now != current.credential_prints
            || secrets_now != current.secrets
        {
            self.rotate(&current.loaded);
            current.key_prints = keys_now;
            current.credential_prints = credentials_now;
            current.secrets = secrets_now;
        }
        let keys = match &self.store {
            // From memory: the store's poll keeps it current, and a database that is down keeps the keys known.
            Some(store) => Ok(Some(store.keys_text().into_bytes())),
            None => read(&self.keys_path),
        };
        let kept = store::policy_store(&self.policy_path);
        let policy = match &kept {
            // From memory, as the keys are: a version saved on any gateway shows here within the store's poll.
            Some(store) => Ok(store.live_policy().map(|v| v.text.into_bytes())),
            None => read(&self.policy_path),
        };
        let trigger = match (&kept, trigger) {
            (Some(_), Trigger::FileChange) => Trigger::Store,
            (_, trigger) => trigger,
        };
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
            gantry_core::secrets::var(variable).is_some_and(|value| !value.trim().is_empty())
        });
        if !unset.is_empty() {
            return Err(unset);
        }
        // Bodies can be kept only where a sealed body store was opened at start.
        let sealed = gantry_core::insights::attached(&old.audit_path)
            .bodies
            .is_some();
        let problems = crate::insights::capture_problems(new.policy.rule_list(), sealed);
        if !problems.is_empty() {
            return Err(problems);
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
        // A provider reached as before keeps its route (and its key and signing) and takes the new models and routing.
        // A new provider, or one whose address or key changed, gets a route built now. Requests already sent keep
        // the route they were sent on.
        let mut providers = Vec::new();
        for provider in &new.providers {
            let kept = current
                .loaded
                .providers
                .iter()
                .find(|p| p.name == provider.name)
                .filter(|p| config::same_connection(p, provider))
                .and_then(|_| {
                    old_version
                        .providers
                        .iter()
                        .find(|p| p.name == provider.name)
                });
            let upstream = match kept {
                Some(old) => {
                    let mut upstream = old.clone();
                    upstream.models = provider.models.clone();
                    upstream.upstream_models = provider.upstream_models.clone();
                    upstream.fallback = provider.fallback.clone();
                    upstream.retries = provider.retries;
                    upstream.accept_chat = provider.accept_chat;
                    upstream.accept_messages = provider.accept_messages;
                    upstream.chat_as_responses = provider.chat_as_responses;
                    upstream
                }
                None => {
                    let built = route(
                        provider,
                        &gantry_core::secrets::var,
                        store::credentials_for(&self.keys_path).as_ref(),
                        &self.policy_path,
                        &new.policy_text,
                    )
                    .and_then(|r| crate::upstream_of(&r).map_err(|err| err.to_string()));
                    match built {
                        Ok(upstream) => upstream,
                        Err(err) => {
                            return self.reject(current, trigger, prints, vec![err]);
                        }
                    }
                }
            };
            providers.push(upstream);
        }
        if let Err(err) = self.open_orgs(&new) {
            return self.reject(current, trigger, prints, vec![err]);
        }
        // The MCP servers as before keep their list, so the gateway keeps their sessions; a change builds a new one.
        let mcp =
            if current.loaded.mcp == new.mcp {
                old_version.mcp.clone()
            } else {
                let built =
                    mcp_routes(&new.mcp, &gantry_core::secrets::var).and_then(|routes| {
                        match new.mcp.iter().find(|s| {
                            crate::mcp::keeps_credentials(&s.user_auth) && !self.mcp_seals
                        }) {
                            Some(server) => Err(format!(
                                "MCP server \"{}\" has user_auth, and {}",
                                server.name,
                                crate::mcp::keep::NO_SEALER
                            )),
                            None => Ok(routes),
                        }
                    });
                match built {
                    Ok(routes) => Arc::new(routes),
                    Err(err) => return self.reject(current, trigger, prints, vec![err]),
                }
            };
        let old = &current.loaded;
        let record = loaded_record(
            &self.policy_path,
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
            policy: crate::mapped_prices(Some(new.policy.clone()), &providers),
            providers,
            aliases: new.aliases.clone(),
            policy_sha256: new.policy_sha256.clone(),
            keys_sha256: new.keys_sha256.clone(),
            mcp,
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
        current.key_prints = key_prints(&new);
        current.credential_prints =
            credential_prints(store::credentials_for(&self.keys_path).as_ref(), &new);
        current.loaded = new;
        current.prints = prints;
        current.rejected.clear();
        self.show(None);
        Reload::Loaded
    }

    /// Opens the chain of each organization the new version adds (`audit: { per_org: true }`), before any request
    /// can be recorded in it, copies it into the request index as those open at start are, and tells the embedding
    /// binary, which exports, retains and ships it.
    fn open_orgs(&self, new: &Loaded) -> Result<(), String> {
        if !new.audit_per_org {
            return Ok(());
        }
        let mut known = self
            .orgs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for org in new.policy.orgs() {
            if known.contains(org) {
                continue;
            }
            let Some(log) = self.log.open_org(org)? else {
                return Ok(());
            };
            let path = audit::org_path(&new.audit_path, org);
            let _runtime = self.new_org.runtime.as_ref().map(|r| r.enter());
            let request_index = match &self.new_org.index {
                Some((pg, seal)) => {
                    let copier =
                        crate::insights::PgIndex::open(pg.clone(), &path, seal.clone(), true)?;
                    let copied = copier.copied();
                    self.new_org
                        .copiers
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push(copier);
                    Some(copied)
                }
                None => None,
            };
            known.insert(org.clone());
            if let Some(tell) = &self.new_org.tell {
                tell(OrgChain {
                    org: org.clone(),
                    log,
                    path,
                    request_index,
                });
            }
        }
        Ok(())
    }

    /// The providers of the version in use that name a credential, with its name.
    pub(crate) fn credentials_in_use(&self) -> Vec<(String, String)> {
        let current = match self.current.lock() {
            Ok(current) => current,
            Err(poisoned) => poisoned.into_inner(),
        };
        current
            .loaded
            .providers
            .iter()
            .filter_map(|p| p.credential.clone().map(|c| (p.name.clone(), c)))
            .collect()
    }

    /// Reads the key files and the credentials again and puts their keys in place, leaving the rest of the version in use as it is.
    /// A request already sent keeps the key it was sent with. A file that cannot be used keeps the key in use.
    fn rotate(&self, loaded: &Loaded) {
        let old = match self.live.read() {
            Ok(version) => version.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        let mut providers = old.providers.clone();
        let mut changed = false;
        for upstream in &mut providers {
            let Some(provider) = loaded.providers.iter().find(|p| p.name == upstream.name) else {
                continue;
            };
            let credentials = store::credentials_for(&self.keys_path);
            let (key, from) = match (&provider.key_file, &provider.credential, &credentials) {
                (Some(path), _, _) => (
                    read_key_file(&upstream.name, path),
                    path.display().to_string(),
                ),
                (None, Some(name), Some(store)) => (
                    match store.credential_value(name) {
                        Ok(Some(value)) => Ok(Secret::new(value)),
                        Ok(None) => Err(format!(
                            "credential \"{name}\" of provider \"{}\" was removed from the store. Add it again in the console or with POST /admin/credentials; a restart would fail without it.",
                            upstream.name
                        )),
                        Err(err) => Err(err),
                    },
                    format!("credential \"{name}\""),
                ),
                // A key in a variable changes only when it points at a secret manager that rotated it.
                (None, None, _) if !provider.key_env.is_empty() && upstream.key.is_some() => (
                    gantry_core::secrets::var(&provider.key_env)
                        .filter(|v| !v.trim().is_empty())
                        .map(|v| Secret::new(v.trim()))
                        .ok_or_else(|| format!("{} is no longer set.", provider.key_env)),
                    provider.key_env.clone(),
                ),
                _ => continue,
            };
            let key =
                key.and_then(|key| key_header(upstream.kind, &key).map_err(|err| err.to_string()));
            match key {
                Ok(key) if upstream.key.as_ref() != Some(&key) => {
                    upstream.key = Some(key);
                    changed = true;
                    println!(
                        "gantry: provider \"{}\" now uses the key in {from}.",
                        upstream.name
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
            mcp: old.mcp.clone(),
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
