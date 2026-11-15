//! The store: what several gateways share while they run (keys, kill switches, spend, rate limits, deployment
//! cooldowns and console sessions), so two or more processes act as one gateway. The policy stays a file, reviewed in
//! git, unless `store.policy_from: store` keeps it here as versions the console and the admin API edit. Postgres is the one backend today; the interface
//! names no database, so another (D1 or Durable Objects on Cloudflare) can be added behind it.

use std::{
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant},
};

use crate::{config::KeyEntry, keyfile::Revoked, kill::Kill, policy::Period};

/// The answer of a call that waits on the database, on the request path.
pub type Pending<T> = Pin<Box<dyn Future<Output = Result<T, String>> + Send>>;

/// One spend counter: a team, person or key (`team:payments`), for a day or a month, in one period (`2026-11`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Bucket {
    pub scope: String,
    pub per: Period,
    pub period: String,
}

/// What a request adds to a bucket when its answer ends: what it cost, and its reservation given back (negative).
#[derive(Clone, Debug, PartialEq)]
pub struct Change {
    pub bucket: Bucket,
    pub spent: f64,
    pub reserved: f64,
}

/// What a reservation found.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Reserve {
    Done,
    /// It would pass the limit: what is spent and held now, for the refusal.
    Over {
        spent: f64,
        reserved: f64,
    },
}

/// What a lease on a rate limit found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lease {
    /// `n` of the limit, at least what was needed, for this gateway to spend within [`LEASE`]. `grant` names it,
    /// to give back what was not used.
    Granted { grant: i64, n: u64 },
    /// The limit is reached: seconds until the oldest slice leaves the minute.
    Over { wait: u64 },
}

/// How long a gateway may spend a lease. The store counts it in the minute for half a second longer, so a lease
/// spent at its last moment is still counted.
pub const LEASE: Duration = Duration::from_secs(1);

/// A provider credential as anyone may see it: never its value, which is kept sealed under the master key.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Credential {
    pub name: String,
    /// The vendor it is a key for, such as openai or anthropic, as the admin gave it.
    pub provider: String,
    /// `...` and the last 4 characters of the value, so a person can tell which key it is.
    pub fingerprint: String,
    pub created_by: String,
    pub created_at: String,
    pub rotated_by: Option<String>,
    pub rotated_at: Option<String>,
    /// One more at each rotation, so a gateway knows to read the value again.
    #[serde(skip)]
    pub generation: i64,
}

/// What a store that keeps no credentials answers.
pub const NO_CREDENTIALS: &str = "this store keeps no provider credentials. Keep the provider key in an environment variable with key_env, or use the Postgres store.";

/// What a store that keeps no policy versions answers.
pub const NO_VERSIONS: &str = "this store keeps no policy versions. Use the Postgres store with `store: { postgres_url_env: DATABASE_URL, policy_from: store }`.";

/// One version of the policy kept in the store. The text holds no secrets: provider keys stay in the environment,
/// in key files or in sealed credentials.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyVersion {
    pub id: i64,
    pub text: String,
    pub sha256: String,
    /// The live version it was drafted on, `None` for the first.
    pub base: Option<i64>,
    pub note: String,
    pub created_by: String,
    pub created_at: String,
    /// [`PENDING`], [`LIVE`], [`RETIRED`] (was live, replaced) or [`REJECTED`].
    pub state: String,
    /// Who approved or rejected it. A version that went live without approval has none.
    pub decided_by: Option<String>,
    pub decided_at: Option<String>,
}

pub const PENDING: &str = "pending";
pub const LIVE: &str = "live";
pub const RETIRED: &str = "retired";
pub const REJECTED: &str = "rejected";

/// A version to add.
#[derive(Clone, Debug)]
pub struct NewVersion {
    pub text: String,
    /// The live version the draft started from: it is added only while that one is still live.
    pub base: Option<i64>,
    pub note: String,
    pub by: String,
    /// Waits for an approval instead of going live.
    pub pending: bool,
}

/// Why a version change was not made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionError {
    /// The versions moved on since the caller read them, or the change does not apply to this version: try again
    /// from what is live now.
    Conflict(String),
    /// The store could not be reached or keeps no versions.
    Store(String),
}

impl std::fmt::Display for VersionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict(m) | Self::Store(m) => f.write_str(m),
        }
    }
}

/// Shared state. Reads come from memory, refreshed in the background, so a request never waits on the database
/// for a key or a kill switch, and a database that is down leaves the last state in force.
/// One gateway's (or, summed, the others') load on a deployment: requests in flight, and the requests and tokens
/// sent in the wall-clock minute `minute` (seconds since the epoch over 60).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeploymentLoad {
    pub in_flight: u32,
    pub minute: i64,
    pub requests: u32,
    pub tokens: u64,
}

/// A budget raise: more room on the budgets of one scope until a time, asked for by a person and decided by an
/// admin. It ends by itself.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Raise {
    pub id: String,
    /// The counter whose budgets it raises: `team:payments`, `person:maya`, `key:1a2b3c4d`.
    pub scope: String,
    pub usd: f64,
    /// A UTC date or time, as a key's `expires`: from then on the raise no longer counts.
    pub until: String,
    pub reason: String,
    pub requested_by: String,
    pub requested_at: String,
    /// [`PENDING`], `approved` or [`REJECTED`].
    pub state: String,
    pub decided_by: Option<String>,
    pub decided_at: Option<String>,
}

pub const APPROVED: &str = "approved";

impl Raise {
    /// Whether the raise adds to its scope's budgets at `now` (a record timestamp).
    pub fn active(&self, now: &str) -> bool {
        self.state == APPROVED && !crate::policy::expiry_passed(&self.until, now)
    }
}

/// One gateway on the store, as its heartbeat says.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Replica {
    /// Its name on the store, new at each start.
    pub gateway: String,
    pub host: String,
    pub version: String,
    pub started: String,
    /// When its heartbeat was last written.
    pub seen: String,
    /// Whether it wrote a heartbeat within the last 10 seconds.
    pub healthy: bool,
    /// The store schema it knows: each namespace and how many migrations of it.
    pub schema: String,
}

/// A cached answer as the store keeps it for every gateway.
#[derive(Clone, Debug, PartialEq)]
pub struct CachedAnswer {
    pub key: [u8; 32],
    /// The rule and the person or team it was made for: read back only in the same scope.
    pub scope: String,
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
    /// The decision that asked the provider for it.
    pub origin: String,
    pub cost: f64,
    /// How long it is served from now.
    pub ttl: Duration,
    /// The semantic partition and embedding, when the rule has a semantic cache.
    pub vector: Option<([u8; 32], Vec<f32>)>,
}

/// The most embeddings of one partition a semantic lookup compares: the newest ones.
// ponytail: a bounded scan of stored vectors, compared in the gateway. pgvector with an index when a partition
// needs more than this.
pub const MAX_SHARED_VECTORS: i64 = 512;

pub trait Store: Send + Sync + std::fmt::Debug {
    /// The budget raises, from memory, polled. `None` when this store keeps none.
    fn raises(&self) -> Option<Arc<Vec<Raise>>> {
        None
    }
    /// Adds a raise, or replaces the one with its id. Blocks until written.
    fn put_raise(&self, _raise: &Raise) -> Result<(), String> {
        Err("this store keeps no budget raises.".into())
    }
    /// Every gateway that wrote a heartbeat to the store in the last day, newest start first.
    fn replicas(&self) -> Pending<Vec<Replica>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    /// Whether cached answers are kept in this store (`store.answer_cache: true`), so every gateway serves them.
    fn shares_cache(&self) -> bool {
        false
    }
    /// The answer cached under `key` for `scope`, if one is and has not run out.
    fn cache_get(&self, _key: [u8; 32], _scope: String) -> Pending<Option<CachedAnswer>> {
        Box::pin(async { Ok(None) })
    }
    /// Keeps an answer for every gateway. Does not wait.
    fn cache_put(&self, _answer: CachedAnswer) {}
    /// The newest embeddings of `partition` (at most [`MAX_SHARED_VECTORS`]) with the key of each one's answer.
    fn cache_vectors(&self, _partition: [u8; 32]) -> Pending<Vec<([u8; 32], Vec<f32>)>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    /// The keys, written as a keys file, so they are checked by the same rules as one.
    fn keys_text(&self) -> String;
    fn kills(&self) -> Arc<Vec<Kill>>;
    /// Adds a key's entry. Returns whether the name already had a key. Blocks until the database answers.
    fn add_key(&self, entry: &KeyEntry) -> Result<bool, String>;
    /// Removes the one key whose hash starts with `prefix`. `Ok(None)` when no key has it.
    fn revoke(&self, prefix: &str) -> Result<Option<Revoked>, String>;
    /// Turns a switch on, or replaces the reason of the same switch. Returns the switch it replaced.
    fn set_kill(&self, kill: &Kill) -> Result<Option<Kill>, String>;
    /// Turns a switch off. Returns it, or `None` when it was not on.
    fn clear_kill(&self, scope: &str, value: &str) -> Result<Option<Kill>, String>;
    /// Holds `usd` in `bucket` in one atomic step, unless spent plus held plus `usd` would pass `limit`.
    /// `Err` when the database cannot be reached: the request is then refused, never let through unchecked.
    fn reserve(&self, bucket: Bucket, usd: f64, limit: f64) -> Pending<Reserve>;
    /// Applies what requests cost and gives back what they held. Does not wait: it is retried while the database
    /// is away, and a hold that is never given back keeps counting, which errs on the side of the budget.
    fn settle(&self, changes: Vec<Change>);
    /// Takes at least `need` and at most `want` of `limit` per minute for `scope`, in one atomic step: no two
    /// gateways together are granted more than `limit` in any minute. `Err` when the database cannot be reached.
    fn lease(&self, scope: String, need: u64, want: u64, limit: u64) -> Pending<Lease>;
    /// Gives `n` of a grant back (a negative `n` takes more). Does not wait: gathered and written twice a second.
    fn give_back(&self, grant: i64, n: i64);
    /// Deployments that failed on any gateway, and until when they cool down. From memory, polled.
    fn cooling(&self) -> Arc<std::collections::HashMap<String, Instant>>;
    /// A deployment failed here: every gateway passes it over for `cooldown`. Does not wait.
    fn cooled(&self, deployment: &str, cooldown: Duration);
    /// A deployment that was cooling down answered: every gateway may use it again. Does not wait.
    fn warmed(&self, deployment: &str);
    /// Whether session pins and deployment latency are shared through this store, so every gateway pins a session
    /// to the same deployment and ranks deployments on the same numbers. Without, each gateway keeps its own.
    fn shares_routing(&self) -> bool {
        false
    }
    /// The deployment `session` is pinned to on any gateway, if it sent within `idle`. From memory.
    fn pinned(&self, _session: &str, _idle: Duration) -> Option<String> {
        None
    }
    /// Pins `session` to `deployment` on every gateway. Does not wait: written with the next poll.
    fn pin(&self, _session: &str, _deployment: &str) {}
    /// Each deployment's 90th percentile time to first byte, in milliseconds, over the recent answers of every
    /// gateway. From memory, polled.
    fn latency(&self) -> Arc<std::collections::HashMap<String, u32>> {
        Arc::default()
    }
    /// A deployment answered here after `ms`: one sample every gateway ranks it on. Does not wait.
    fn observed(&self, _deployment: &str, _ms: u32) {}
    /// What every other gateway has in flight and has sent this minute to each deployment, for its `max_parallel`,
    /// `rpm` and `tpm`. From memory, polled.
    fn deployment_load(&self) -> Arc<std::collections::HashMap<String, DeploymentLoad>> {
        Arc::default()
    }
    /// This gateway's load on a deployment now, for the others. Does not wait: written on the next poll.
    fn publish_load(&self, _deployment: &str, _load: DeploymentLoad) {}
    /// Whether this gateway runs the health probe of `deployment` now. One gateway at a time holds each, for `ttl`
    /// after it last took it; without a store every gateway probes its own.
    fn probe_lease(&self, _deployment: String, _ttl: Duration) -> Pending<bool> {
        Box::pin(async { Ok(true) })
    }
    /// The sessions events plugins ended and whose refusal still lasts, by the key each was ended under: when it
    /// runs out and the guardrail that ended it. From memory, polled, so a request never waits on the store for it.
    fn ended_sessions(&self) -> Arc<std::collections::HashMap<String, (Instant, String)>> {
        Arc::default()
    }
    /// Ends a session for every gateway on the store, for `ttl`. Does not wait: retried while the database is
    /// away. The others learn of it with their next poll.
    fn end_events_session(&self, _key: String, _by: String, _ttl: Duration) {}
    /// Opens a console session, by the SHA-256 of its ID, for `who`, ending after `ttl`.
    fn open_session(&self, id_sha256: String, who: String, ttl: Duration) -> Pending<()>;
    /// Who a console session is for, or `None` when it is unknown, ended or expired.
    fn session(&self, id_sha256: String) -> Pending<Option<String>>;
    /// Ends a console session on every gateway. Does not wait: retried while the database is away.
    fn end_session(&self, id_sha256: String);
    /// Replaces the settings of the key with `entry.sha256` (name, team and hash stay). `Ok(false)` when there is
    /// no such key. Blocks until the database answers.
    fn update_key(&self, _entry: &KeyEntry) -> Result<bool, String> {
        Err("this store cannot change a key in place. Revoke it and issue a new one.".into())
    }
    /// Whether the store can be reached now, or why not. Asked by `GET /readyz`, so it answers from memory.
    fn reachable(&self) -> Result<(), String> {
        Ok(())
    }
    /// What `scope` (`key:1a2b3c4d`) has spent and holds, as `(per, period, spent, reserved)` for the current day
    /// and month, across every gateway on the store.
    fn spend(&self, _scope: String) -> Pending<Vec<(String, String, f64, f64)>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    /// The provider credentials, from memory. `Err` names why there are none to show: the feature is off.
    fn credentials(&self) -> Result<Arc<Vec<Credential>>, String> {
        Err(NO_CREDENTIALS.into())
    }
    /// Seals `value` and adds it as a new credential. `Ok(None)` when the name is taken. Blocks until written.
    fn add_credential(
        &self,
        _name: &str,
        _provider: &str,
        _value: &str,
        _by: &str,
    ) -> Result<Option<Credential>, String> {
        Err(NO_CREDENTIALS.into())
    }
    /// Seals `value` in place of the credential's. `Ok(None)` when there is no such credential.
    fn rotate_credential(
        &self,
        _name: &str,
        _value: &str,
        _by: &str,
    ) -> Result<Option<Credential>, String> {
        Err(NO_CREDENTIALS.into())
    }
    /// Removes a credential. `Ok(None)` when there was none.
    fn remove_credential(&self, _name: &str) -> Result<Option<Credential>, String> {
        Err(NO_CREDENTIALS.into())
    }
    /// Every policy version, newest first, from memory: refreshed by the poll, so every gateway sees a change
    /// within a second. `Err` when this store keeps none.
    fn policy_versions(&self) -> Result<Arc<Vec<PolicyVersion>>, String> {
        Err(NO_VERSIONS.into())
    }
    /// Reads the policy versions from the database now instead of at the next poll: for a version another gateway
    /// saved a moment ago. Blocks until the database answers.
    fn refresh_policy(&self) -> Result<(), String> {
        Ok(())
    }
    /// The live policy version, from memory. `None` before the first one is added.
    fn live_policy(&self) -> Option<PolicyVersion> {
        self.policy_versions()
            .ok()?
            .iter()
            .find(|v| v.state == LIVE)
            .cloned()
    }
    /// Adds a version, live at once or pending, only while `base` is still the live version. Blocks until written.
    fn add_policy_version(&self, _new: &NewVersion) -> Result<PolicyVersion, VersionError> {
        Err(VersionError::Store(NO_VERSIONS.into()))
    }
    /// Puts a pending version live (`approve`), only while the version it was drafted on is still live, or rejects
    /// it. Blocks until written.
    fn decide_policy_version(
        &self,
        _id: i64,
        _approve: bool,
        _by: &str,
    ) -> Result<PolicyVersion, VersionError> {
        Err(VersionError::Store(NO_VERSIONS.into()))
    }
    /// The value of a credential, opened with the master key, for the gateway to send. `Ok(None)` when there is
    /// no such credential.
    fn credential_value(&self, _name: &str) -> Result<Option<String>, String> {
        Err(NO_CREDENTIALS.into())
    }
}

/// `...` and the last 4 characters of a credential's value: enough to tell keys apart, far too little to use one.
pub fn fingerprint(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let tail: String = chars[chars.len().saturating_sub(4)..].iter().collect();
    format!("...{tail}")
}

/// Why a credential value cannot be kept, or `None` when it can. A value goes in an HTTP header.
pub fn credential_value_problem(value: &str) -> Option<&'static str> {
    if value.trim().is_empty() {
        Some("the value is empty. Paste the provider key.")
    } else if value.len() > 4096 {
        Some("the value is longer than 4096 bytes, which no provider key is. Paste the key alone.")
    } else if value.trim().len() < 8 {
        Some(
            "the value is shorter than 8 characters, which no provider key is. Paste the whole key.",
        )
    } else if value.trim().chars().any(|c| c.is_control() || c == ' ') {
        Some(
            "the value holds a space, a line break or another character a provider key never has. Paste the key alone.",
        )
    } else {
        None
    }
}

// Every reader and writer of the keys file (the command line, the admin API, the console) names it by its path, so
// the store serving that path is found there and none of them needs to be told about it.
static ATTACHED: Mutex<Vec<(PathBuf, Weak<dyn Store>)>> = Mutex::new(Vec::new());

/// Serves the keys named by `keys` and the kill switches beside them from `store`, for as long as it lives.
pub fn attach(keys: &Path, store: &Arc<dyn Store>) {
    let mut attached = ATTACHED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    attached.retain(|(path, store)| path != keys && store.strong_count() > 0);
    attached.push((keys.to_path_buf(), Arc::downgrade(store)));
}

// The policy files whose policy is kept in a store (`store.policy_from: store`), so `config::policy_text` reads the
// live version for every reader that names the file.
static POLICIES: Mutex<Vec<(PathBuf, Weak<dyn Store>)>> = Mutex::new(Vec::new());

/// Serves the policy named by `policy` from `store`'s live version, for as long as the store lives.
pub fn attach_policy(policy: &Path, store: &Arc<dyn Store>) {
    let mut attached = POLICIES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    attached.retain(|(path, store)| path != policy && store.strong_count() > 0);
    attached.push((policy.to_path_buf(), Arc::downgrade(store)));
}

/// The store that keeps the policy named by `policy`, if one does.
pub fn policy_store(policy: &Path) -> Option<Arc<dyn Store>> {
    POLICIES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .rev()
        .find(|(path, _)| path == policy)
        .and_then(|(_, store)| store.upgrade())
}

/// The store that serves the keys file at `keys`, if one does.
pub fn attached(keys: &Path) -> Option<Arc<dyn Store>> {
    find(|path| path == keys)
}

/// The store that serves the kill switches file at `kills`, if one does.
pub fn attached_kills(kills: &Path) -> Option<Arc<dyn Store>> {
    find(|path| crate::kill::path_beside(path) == kills)
}

fn find(matches: impl Fn(&Path) -> bool) -> Option<Arc<dyn Store>> {
    ATTACHED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .rev()
        .find(|(path, _)| matches(path))
        .and_then(|(_, store)| store.upgrade())
}
