//! The Postgres store: keys, kill switches and spend shared by every gateway pointed at one database.
//!
//! Keys and kill switches are read from memory. A task polls a version row every 500 ms and reloads them when it
//! changes, so a request never waits on the database for them, and a database that is down leaves the last state
//! in force. Only a request under a budget reaches the database: one atomic statement reserves its estimate, and
//! one more settles it when the answer ends.
//!
//! Rate limits are leased: a gateway takes a slice of a minute's allowance in one atomic statement, spends it from
//! memory for a second, and gives back what it did not use. Deployment cooldowns are written when a deployment
//! fails and read with the poll. Console sessions are rows, looked up on each console page.
//!
//! Every change is one statement, never a transaction: the one connection is shared by every request, and a
//! statement sent by another request while a transaction is open would become part of it.

use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use enterplace_core::{
    config::KeyEntry,
    id,
    keyfile::{self, Revoked},
    kill::Kill,
    policy::{Budget, Period},
    store::{
        self as core_store, Bucket, CachedAnswer, Change, Credential, DeploymentLoad, InForce,
        LEASE, Lease, NewVersion, Pending, PolicyVersion, Raise, Replica, Reserve, Store,
        VersionError,
    },
};

use crate::credentials::{MasterKey, NO_MASTER};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_postgres::{
    Client, NoTls,
    config::SslMode,
    tls::{ChannelBinding, MakeTlsConnect, TlsConnect, TlsStream},
    types::Type,
};
use tokio_rustls::rustls;

/// The Postgres client a [`PgStore::connect`] connection is, for a binary that embeds the gateway: it uses the same
/// version without naming the crate itself.
pub use tokio_postgres;

/// How often the versions of the keys and the kill switches are read: a change reaches every gateway within this
/// plus the reloader's second for keys, and within this for kill switches, under the 1 second the switches promise.
pub(crate) const POLL: Duration = Duration::from_millis(500);

/// The longest a call waits for the database before it counts as down.
pub(crate) const WAIT: Duration = Duration::from_secs(5);

/// How long a settlement is retried while the database is away. A hold never given back keeps counting against
/// its budget until the period ends, which errs on the side of the budget.
pub(crate) const SETTLE_FOR: Duration = Duration::from_secs(600);

/// The schema, one migration per entry, applied in order. `enterplace_schema` holds the number of each one applied.
/// Never edit an entry that has shipped: add one.
const MIGRATIONS: &[&str] = &[
    "
CREATE TABLE enterplace_keys (
    id bigserial PRIMARY KEY,
    sha256 text NOT NULL UNIQUE,
    name text NOT NULL,
    team text NOT NULL,
    admin boolean NOT NULL DEFAULT false,
    expires text,
    budget_usd double precision,
    budget_per text,
    models text[],
    tpm integer,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE enterplace_kills (
    scope text NOT NULL,
    value text NOT NULL,
    reason text NOT NULL,
    set_by text NOT NULL,
    set_at text NOT NULL,
    PRIMARY KEY (scope, value)
);
CREATE TABLE enterplace_spend (
    scope text NOT NULL,
    per text NOT NULL,
    period text NOT NULL,
    spent double precision NOT NULL DEFAULT 0,
    reserved double precision NOT NULL DEFAULT 0,
    PRIMARY KEY (scope, per, period)
);
CREATE TABLE enterplace_versions (name text PRIMARY KEY, version bigint NOT NULL);
INSERT INTO enterplace_versions VALUES ('keys', 0), ('kills', 0);
", "
CREATE TABLE enterplace_rate_grants (
    id bigserial PRIMARY KEY,
    scope text NOT NULL,
    until timestamptz NOT NULL,
    n bigint NOT NULL
);
CREATE INDEX enterplace_rate_grants_scope ON enterplace_rate_grants (scope, until);
CREATE TABLE enterplace_cooldowns (deployment text PRIMARY KEY, until timestamptz NOT NULL);
CREATE TABLE enterplace_sessions (sha256 text PRIMARY KEY, who text NOT NULL, expires timestamptz NOT NULL);
INSERT INTO enterplace_versions VALUES ('cooldowns', 0);
",
    "
CREATE TABLE enterplace_credentials (
    name text PRIMARY KEY,
    provider text NOT NULL,
    sealed bytea NOT NULL,
    fingerprint text NOT NULL,
    created_by text NOT NULL,
    created_at text NOT NULL,
    rotated_by text,
    rotated_at text,
    generation bigint NOT NULL DEFAULT 1
);
CREATE TABLE enterplace_master (id integer PRIMARY KEY CHECK (id = 1), sealed bytea NOT NULL);
INSERT INTO enterplace_versions VALUES ('credentials', 0);
",
    "
ALTER TABLE enterplace_keys ADD COLUMN org text, ADD COLUMN customer text, ADD COLUMN tags text[],
    ADD COLUMN parallel integer, ADD COLUMN role text;
",
    // Migration 5: rpm, metadata, routes, source ranges and rotation of each key (the hierarchy's org, customer, tags,
    // parallel and role have their own columns from migration 4), as the JSON object
    // `keyfile::options_json` writes. One column, so the next key setting needs no migration.
    "
ALTER TABLE enterplace_keys ADD COLUMN options text;
",
    // Migration 6: the newest Enterplace version that has migrated this database, so an older one can tell whether it
    // may run beside it (`newer_allowed`).
    "
CREATE TABLE enterplace_writer (id integer PRIMARY KEY CHECK (id = 1), version text NOT NULL);
",
    // Migration 7: small settings the console keeps for every gateway on the store, such as the first-run choice.
    "
CREATE TABLE enterplace_settings (name text PRIMARY KEY, value text NOT NULL, updated_at timestamptz NOT NULL DEFAULT now());
",
    // Migration 8: failed console sign-ins per source address and account, and until when each is locked out, so
    // every gateway counts and refuses together.
    "
CREATE TABLE enterplace_sign_in_failures (
    scope text PRIMARY KEY,
    failures integer NOT NULL,
    since timestamptz NOT NULL,
    locked_until timestamptz
);
",
];

/// Whether an Enterplace of version `own` may use a database whose schema an Enterplace of version `writer` moved ahead of it.
/// Every migration is additive (expand), and a change that removes or renames what an older binary reads (contract)
/// waits two minor versions, so a binary one minor version behind the writer still finds everything it uses. A
/// rolling upgrade therefore runs N and N+1 side by side; N beside N+2 is refused. A writer that is not strictly
/// newer is refused too: the same version cannot have written a schema this binary does not know.
fn newer_allowed(own: &str, writer: &str) -> bool {
    let (Some(own), Some(writer)) = (semver(own), semver(writer)) else {
        return false;
    };
    let one_step =
        (writer.0 == own.0 && writer.1 <= own.1 + 1) || (writer.0 == own.0 + 1 && writer.1 == 0);
    writer > own && one_step
}

/// Major, minor and patch of a version such as `0.2.1` or `0.2.1-rc.1`.
fn semver(version: &str) -> Option<(u64, u64, u64)> {
    let core = version.split(['-', '+']).next()?;
    let mut parts = core.split('.').map(|n| n.parse::<u64>().ok());
    Some((parts.next()??, parts.next()??, parts.next()??))
}

/// The version recorded by the newest Enterplace that migrated this database, if any. Only called once migration 6
/// has run, so the table is there.
async fn writer(
    tx: &tokio_postgres::Transaction<'_>,
) -> Result<Option<String>, tokio_postgres::Error> {
    tx.query_opt("SELECT version FROM enterplace_writer WHERE id = 1", &[])
        .await?
        .map(|row| row.try_get(0))
        .transpose()
}

/// The policy versions' table, in a namespace of its own (`enterplace_migrations`), so it never competes with the
/// numbering of the core schema above. Never edit an entry that has shipped: add one.
const POLICY_MIGRATIONS: &[&str] = &["
CREATE TABLE enterplace_policy_versions (
    id bigserial PRIMARY KEY,
    text text NOT NULL,
    sha256 text NOT NULL,
    base bigint,
    note text NOT NULL,
    created_by text NOT NULL,
    created_at text NOT NULL,
    state text NOT NULL,
    decided_by text,
    decided_at text
);
INSERT INTO enterplace_versions VALUES ('policy', 0) ON CONFLICT (name) DO NOTHING;
"];

/// Session pins and each gateway's latency samples, in a namespace of their own (`enterplace_routing`). Never edit an
/// entry that has shipped: add one.
const ROUTING_MIGRATIONS: &[&str] = &["
CREATE TABLE enterplace_affinity (session text PRIMARY KEY, deployment text NOT NULL, seen timestamptz NOT NULL);
CREATE INDEX enterplace_affinity_seen ON enterplace_affinity (seen);
CREATE TABLE enterplace_latency (
    deployment text NOT NULL,
    gateway text NOT NULL,
    samples integer[] NOT NULL,
    updated timestamptz NOT NULL,
    PRIMARY KEY (deployment, gateway)
);
", "
CREATE TABLE enterplace_probe_leases (deployment text PRIMARY KEY, gateway text NOT NULL, until timestamptz NOT NULL);
", "
CREATE TABLE enterplace_deployment_load (
    deployment text NOT NULL,
    gateway text NOT NULL,
    in_flight integer NOT NULL,
    minute bigint NOT NULL,
    requests integer NOT NULL,
    tokens bigint NOT NULL,
    updated timestamptz NOT NULL,
    PRIMARY KEY (deployment, gateway)
);
", "
CREATE TABLE enterplace_gateway_health (gateway text PRIMARY KEY, report text NOT NULL, updated timestamptz NOT NULL);
"];

/// What gateways share for high availability beyond the tables above, in a namespace of its own (`enterplace_ha`): each
/// gateway's heartbeat, the answer cache with its embeddings, and budget raises. Never edit an entry that has
/// shipped: add one.
const HA_MIGRATIONS: &[&str] = &["
CREATE TABLE enterplace_replicas (
    gateway text PRIMARY KEY,
    host text NOT NULL,
    version text NOT NULL,
    schema text NOT NULL,
    started timestamptz NOT NULL,
    seen timestamptz NOT NULL
);
CREATE TABLE enterplace_answer_cache (
    key bytea PRIMARY KEY,
    scope text NOT NULL,
    status integer NOT NULL,
    content_type text,
    body bytea NOT NULL,
    origin text NOT NULL,
    cost float8 NOT NULL,
    expires timestamptz NOT NULL,
    used timestamptz NOT NULL
);
CREATE INDEX enterplace_answer_cache_expires ON enterplace_answer_cache (expires);
CREATE TABLE enterplace_answer_vectors (
    key bytea PRIMARY KEY REFERENCES enterplace_answer_cache (key) ON DELETE CASCADE,
    partition bytea NOT NULL,
    vector real[] NOT NULL,
    created timestamptz NOT NULL
);
CREATE INDEX enterplace_answer_vectors_partition ON enterplace_answer_vectors (partition, created DESC);
CREATE TABLE enterplace_raises (id text PRIMARY KEY, body text NOT NULL);
INSERT INTO enterplace_versions VALUES ('raises', 0) ON CONFLICT (name) DO NOTHING;
", "
ALTER TABLE enterplace_replicas ADD COLUMN policy_version bigint, ADD COLUMN refused_version bigint, ADD COLUMN refused text;
"];

/// Most bytes of answers the store keeps. Past it the least recently used go first, at the next clean-up.
// ponytail: one fixed size. A setting when someone needs another.
const SHARED_CACHE_BYTES: i64 = 1024 * 1024 * 1024;

/// A gateway writes its heartbeat every this many polls (2 seconds), and counts as healthy for 10 seconds after.
pub(crate) const HEARTBEAT_EVERY: u64 = 4;
pub(crate) const HEALTHY_FOR_SECS: f64 = 10.0;

/// The version of the sessions events plugins ended, in a namespace of its own (`enterplace_events`). The sessions
/// themselves are rows of `enterplace_sessions` whose `who` starts with `events:`, under a key no console session has.
/// Never edit an entry that has shipped: add one.
const EVENTS_MIGRATIONS: &[&str] =
    &["INSERT INTO enterplace_versions VALUES ('events', 0) ON CONFLICT (name) DO NOTHING;"];

/// What marks a row of `enterplace_sessions` as a session an events plugin ended, before the guardrail's name.
pub(crate) const ENDED: &str = "events:";

/// A gateway's load on a deployment counts this long after it last wrote it: one that stopped holds nothing.
pub(crate) const LOAD_FOR_SECS: f64 = 10.0;

/// A pin written this long ago is written again when its session sends, so the others know it is still in use. A
/// session that keeps sending costs one write per gateway in this time.
pub(crate) const PIN_TOUCH: Duration = Duration::from_secs(300);

/// A gateway's latency samples count this long after it last wrote them: one that stopped is forgotten.
pub(crate) const LATENCY_FOR_SECS: f64 = 600.0;

/// Pins written up to this long before the last read are read again: a write is stamped before it commits, so one
/// committed late is still picked up.
pub(crate) const PIN_OVERLAP_SECS: f64 = 5.0;

/// Expired pins and stale latency rows are deleted every this many polls (a minute).
pub(crate) const CLEAN_EVERY: u64 = 120;

/// The columns of a policy version, in the order `version_of` reads them.
const VERSION_COLUMNS: &str =
    "id, text, sha256, base, note, created_by, created_at, state, decided_by, decided_at";

/// Serializes changes to the policy versions across every gateway on the database.
const POLICY_LOCK: i64 = 7_349_127_342;

/// What the master key seals once per database, so a gateway with another master key is refused at start rather
/// than at the first credential it cannot open.
pub(crate) const MASTER_CHECK: (&str, &[u8]) = ("enterplace master key check", b"enterplace");

/// The columns of a credential anyone may see, in the order `credential_of` reads them.
const SHOWN: &str =
    "name, provider, fingerprint, created_by, created_at, rotated_by, rotated_at, generation";

/// How much longer than its [`LEASE`] the store counts a grant in the minute, in milliseconds: a gateway's clock
/// and the database's may drift apart a little within one second, and a lease is spent by the gateway's.
pub(crate) const LEASE_MARGIN_MS: u64 = 500;

/// The store, with the runtime its connection and poller run on. Its own runtime, so the command line (which
/// blocks) and the server (which awaits) can both call it, and a busy server does not delay the poll.
pub struct PgStore {
    runtime: Mutex<Option<tokio::runtime::Runtime>>,
    handle: tokio::runtime::Handle,
    inner: Arc<Inner>,
}

impl std::fmt::Debug for PgStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The connection string holds a password: it is never printed.
        f.write_str("PgStore")
    }
}

impl Drop for PgStore {
    fn drop(&mut self) {
        self.close();
    }
}

struct Inner {
    config: tokio_postgres::Config,
    tls: Option<Rustls>,
    /// The variable that holds the connection string, for messages.
    env: String,
    client: RwLock<Option<Arc<Client>>>,
    /// The versions of keys, kill switches, cooldowns and credentials last read.
    seen: Mutex<Option<(i64, i64, i64, i64)>>,
    /// One refresh at a time: a slow one finishing after a newer one would put older keys back for a poll.
    refreshing: tokio::sync::Mutex<()>,
    /// One poll round at a time: a round asked for with `poll_now` starts after any already under way, so what that
    /// one took to write is in the database before this one reads.
    polling: tokio::sync::Mutex<()>,
    keys: RwLock<String>,
    kills: RwLock<Arc<Vec<Kill>>>,
    cooling: RwLock<Arc<HashMap<String, Instant>>>,
    /// What gateways give back of their rate-limit grants, by grant, until the next poll writes it.
    returns: Mutex<HashMap<i64, i64>>,
    /// Each credential with its value as sealed. Opened only when a gateway sends it.
    credentials: RwLock<Arc<Vec<Sealed>>>,
    /// Set once, at start, after it opened the database's check value.
    master: std::sync::OnceLock<MasterKey>,
    /// Every policy version, newest first, and the version of the list last read.
    policies: RwLock<Arc<Vec<PolicyVersion>>>,
    policies_seen: Mutex<Option<i64>>,
    /// The sessions events plugins ended, and the version of them last read.
    ended: RwLock<Arc<HashMap<String, (Instant, String)>>>,
    ended_seen: Mutex<Option<i64>>,
    /// Set while the database cannot be reached, so the outage is reported once and its end once.
    down: AtomicBool,
    /// This gateway's name on the latency rows, new at each start.
    gateway: String,
    /// Session pins by SHA-256 of the session: the deployment, when the session last sent, and when the pin was
    /// last written to the database.
    pins: RwLock<HashMap<String, Pinned>>,
    /// Pins made here and not written yet. A read does not overwrite them.
    pins_out: Mutex<HashMap<String, String>>,
    /// The database's clock at the last read of the pins, in seconds since 1970.
    pins_read: Mutex<f64>,
    /// This gateway's last answers by deployment, in milliseconds, and whether a new one came since the last write.
    samples: Mutex<HashMap<String, (std::collections::VecDeque<u32>, bool)>>,
    /// Each deployment's 90th percentile over every gateway's samples.
    latency: RwLock<Arc<HashMap<String, u32>>>,
    /// This gateway's load on each deployment, changed since the last write.
    load_out: Mutex<HashMap<String, DeploymentLoad>>,
    /// Every other gateway's load on each deployment, summed.
    load: RwLock<Arc<HashMap<String, DeploymentLoad>>>,
    /// This gateway's health report, when it changed since the last write, and every other gateway's.
    health_out: Mutex<Option<String>>,
    health: RwLock<Arc<Vec<String>>>,
    polls: std::sync::atomic::AtomicU64,
    /// Budget raises, and the version of them last read.
    raises: RwLock<Arc<Vec<Raise>>>,
    raises_seen: Mutex<Option<i64>>,
    /// What this gateway runs of the policy, for its heartbeat.
    in_force: Mutex<InForce>,
    /// Set from `store.answer_cache`: cached answers are kept in the database.
    shares_cache: AtomicBool,
}

/// A session pin: the deployment, when the session last sent, and when the pin was last written.
type Pinned = (String, Instant, Instant);

/// A credential and its value as sealed.
type Sealed = (Credential, Vec<u8>);

pub(crate) fn read<T: Clone>(lock: &RwLock<T>) -> T {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

pub(crate) fn write<T>(lock: &RwLock<T>, value: T) {
    *lock
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = value;
}

/// Connects to the database named by the connection string in `env` (as read by the caller), creates or updates
/// its tables, and reads the keys and kill switches. Fails, naming the fix, if any of that cannot be done.
pub fn open(env: &str, url: &str) -> Result<Arc<PgStore>, String> {
    let fallback = std::env::var("PGSSLMODE").ok();
    let (config, tls) = connection_with(env, url, fallback.as_deref())?;
    if tls.is_none() && !socket(&config) {
        eprintln!(
            "warning: {env} says sslmode=disable, so the connection to the store is not encrypted: key hashes, kill switches and spend cross the network in plain text. Use it only on a network you trust, such as a cluster's own Postgres; remove sslmode=disable to encrypt it."
        );
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("enterplace-store")
        .enable_all()
        .build()
        .map_err(|err| {
            format!("the store's thread could not be started: {err}. Report this as a bug.")
        })?;
    let inner = Arc::new(Inner {
        config,
        tls,
        env: env.to_string(),
        client: RwLock::new(None),
        seen: Mutex::new(None),
        refreshing: tokio::sync::Mutex::new(()),
        polling: tokio::sync::Mutex::new(()),
        keys: RwLock::new(String::new()),
        kills: RwLock::new(Arc::new(Vec::new())),
        cooling: RwLock::default(),
        returns: Mutex::default(),
        credentials: RwLock::new(Arc::new(Vec::new())),
        master: std::sync::OnceLock::new(),
        policies: RwLock::default(),
        policies_seen: Mutex::new(None),
        ended: RwLock::default(),
        ended_seen: Mutex::new(None),
        down: AtomicBool::new(false),
        gateway: id::random_hex(8),
        pins: RwLock::default(),
        pins_out: Mutex::default(),
        pins_read: Mutex::new(0.0),
        samples: Mutex::default(),
        latency: RwLock::default(),
        load_out: Mutex::default(),
        load: RwLock::default(),
        health_out: Mutex::default(),
        health: RwLock::default(),
        polls: std::sync::atomic::AtomicU64::new(0),
        raises: RwLock::default(),
        raises_seen: Mutex::new(None),
        in_force: Mutex::new(InForce::default()),
        shares_cache: AtomicBool::new(false),
    });
    let store = PgStore {
        handle: runtime.handle().clone(),
        runtime: Mutex::new(Some(runtime)),
        inner: inner.clone(),
    };
    let first = inner.clone();
    store.wait(async move {
        let mut client = first
            .connect()
            .await
            .map_err(|err| unreachable(&first.env, &err))?;
        migrate(&mut client).await?;
        migrate_namespace(&mut client, "enterplace_policy", POLICY_MIGRATIONS).await?;
        migrate_namespace(&mut client, "enterplace_routing", ROUTING_MIGRATIONS).await?;
        migrate_namespace(&mut client, "enterplace_events", EVENTS_MIGRATIONS).await?;
        migrate_namespace(&mut client, "enterplace_ha", HA_MIGRATIONS).await?;
        write(&first.client, Some(Arc::new(client)));
        first.refresh().await.map_err(|err| {
            format!("the store's keys and kill switches could not be read: {err}. Check the database and start again.")
        })
    })?;
    let weak = Arc::downgrade(&inner);
    store.handle.spawn(async move {
        loop {
            tokio::time::sleep(POLL).await;
            let Some(inner) = weak.upgrade() else {
                return;
            };
            inner.round().await;
            inner.heartbeat().await;
        }
    });
    Ok(Arc::new(store))
}

/// Why the store could not be reached, and what to do about it.
fn unreachable(env: &str, err: &tokio_postgres::Error) -> String {
    let mut text = err.to_string();
    let mut source = std::error::Error::source(err);
    while let Some(cause) = source {
        let said = cause.to_string();
        if !text.contains(&said) {
            text = format!("{text}: {said}");
        }
        source = cause.source();
    }
    let name = text.contains("NotValidForName") || text.contains("not valid for name");
    let fix = if text.contains("invalid peer certificate") && name {
        format!(
            "The server's certificate does not name the host in {env}. Connect by the name on the certificate, or add sslmode=verify-ca to {env} to check the certificate's signer only."
        )
    } else if text.contains("invalid peer certificate") {
        format!(
            "The server's certificate is not signed by a certificate Enterplace trusts (the Mozilla roots built in, and sslrootcert if set). Add sslrootcert=/path/to/ca.pem to {env}, naming the CA that signed it: for Amazon RDS, the bundle at https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem."
        )
    } else if text.contains("does not support TLS") {
        format!(
            "The server offers no TLS. Turn TLS on in Postgres, or, on a network you trust, add sslmode=disable to {env}."
        )
    } else {
        format!(
            "Check that Postgres is up and that {env} holds the right connection string (postgres://user:password@host:5432/database)."
        )
    };
    format!("the store cannot be reached: {text}. Enterplace does not start without it. {fix}")
}

/// `connection_with` and no PGSSLMODE, as the tests call it.
#[cfg(test)]
fn connection(env: &str, url: &str) -> Result<(tokio_postgres::Config, Option<Rustls>), String> {
    connection_with(env, url, None)
}

/// The connection string, and the TLS it asks for. `sslmode` and `sslrootcert` are read here as libpq reads them
/// (tokio-postgres knows neither verify mode nor root files): `verify-full`, the default, checks the server's
/// certificate and name; `verify-ca` its signer only; `require` encrypts without checking, unless `sslrootcert`
/// is given, which makes it `verify-ca`; `disable` sends plain text. `sslrootcert` names a PEM file whose
/// certificates are trusted besides the Mozilla roots built in, or, for `verify-ca`, instead of them.
/// `fallback` is libpq's PGSSLMODE, the mode when the string names none. A platform that hands over a
/// connection string it builds (Render's internal one, with a self-signed certificate) cannot add `?sslmode=` to it.
fn connection_with(
    env: &str,
    url: &str,
    fallback: Option<&str>,
) -> Result<(tokio_postgres::Config, Option<Rustls>), String> {
    let (rest, mode, rootcert) = split_tls(url.trim());
    let (mode, said_by) = match (mode, fallback.map(str::trim).filter(|m| !m.is_empty())) {
        (Some(mode), _) => (Some(mode), env),
        (None, Some(fallback)) => (Some(fallback.to_string()), "PGSSLMODE"),
        (None, None) => (None, env),
    };
    let mut config = rest.parse::<tokio_postgres::Config>().map_err(|err| {
        // The error never repeats the string: it holds a password.
        format!(
            "{env} does not hold a Postgres connection string Enterplace can read ({err}). Write it as postgres://user:password@host:5432/database?sslmode=verify-full."
        )
    })?;
    let mode = mode.as_deref().unwrap_or("verify-full");
    if !matches!(mode, "disable" | "require" | "verify-ca" | "verify-full") {
        return Err(format!(
            "{said_by} says sslmode={mode}, which Enterplace does not take: it never falls back to plain text unasked. Use verify-full (the default), verify-ca, require or disable."
        ));
    }
    // A Unix socket (the Cloud SQL connector's /cloudsql/..., a local server) never leaves the machine, and
    // Postgres offers no TLS on one, as libpq knows: whatever sslmode says, it is plain and not warned about.
    if mode == "disable" || socket(&config) {
        config.ssl_mode(SslMode::Disable);
        return Ok((config, None));
    }
    config.ssl_mode(SslMode::Require);
    let extra = rootcert.map(|path| root_certs(env, &path)).transpose()?;
    let any_name = mode == "verify-ca" || (mode == "require" && extra.is_some());
    let mut roots = rustls::RootCertStore::empty();
    if !(any_name && extra.is_some()) {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    for cert in extra.unwrap_or_default() {
        roots.add(cert).map_err(|err| {
            format!("a certificate in the sslrootcert file of {env} cannot be used: {err}. Give the CA certificate in PEM form.")
        })?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|err| format!("TLS could not be set up: {err}. Report this as a bug."))?;
    let tls = if mode == "require" && !any_name {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Unchecked(provider)))
    } else if any_name {
        let verifier =
            rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .map_err(|err| format!("TLS could not be set up from the sslrootcert file of {env}: {err}. Give the CA certificate in PEM form."))?;
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyName(verifier)))
    } else {
        builder.with_root_certificates(roots)
    }
    .with_no_client_auth();
    Ok((
        config,
        Some(Rustls(tokio_rustls::TlsConnector::from(Arc::new(tls)))),
    ))
}

/// Whether every host the string names is a Unix socket directory.
#[cfg(unix)]
fn socket(config: &tokio_postgres::Config) -> bool {
    let hosts = config.get_hosts();
    !hosts.is_empty()
        && hosts
            .iter()
            .all(|host| matches!(host, tokio_postgres::config::Host::Unix(_)))
}

#[cfg(not(unix))]
fn socket(_: &tokio_postgres::Config) -> bool {
    false
}

/// The certificates of an `sslrootcert` file.
fn root_certs(
    env: &str,
    path: &str,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    let unreadable = |err: String| {
        format!(
            "sslrootcert in {env} names {path}, which cannot be read as PEM certificates: {err}. Give the CA certificate or bundle in PEM form (-----BEGIN CERTIFICATE-----), for Amazon RDS the bundle at https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem."
        )
    };
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|err| unreadable(err.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| unreadable(err.to_string()))?;
    if certs.is_empty() {
        return Err(unreadable("it holds no certificate".into()));
    }
    Ok(certs)
}

/// Takes `sslmode` and `sslrootcert` out of a connection string, in URL or key=value form. The rest is returned
/// as written.
fn split_tls(url: &str) -> (String, Option<String>, Option<String>) {
    let (mut mode, mut root) = (None, None);
    let mut take = |key: &str, value: String| match key {
        "sslmode" => {
            mode = Some(value);
            true
        }
        "sslrootcert" => {
            root = Some(value);
            true
        }
        _ => false,
    };
    if url.starts_with("postgres://") || url.starts_with("postgresql://") {
        let Some((base, query)) = url.split_once('?') else {
            return (url.to_string(), None, None);
        };
        let mut kept = Vec::new();
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            if !take(key, percent_decoded(value)) {
                kept.push(pair);
            }
        }
        let rest = if kept.is_empty() {
            base.to_string()
        } else {
            format!("{base}?{}", kept.join("&"))
        };
        return (rest, mode, root);
    }
    // key=value pairs, a value perhaps in single quotes with backslash escapes. Every stop is an ASCII byte, so
    // each slice falls on a character boundary.
    let bytes = url.as_bytes();
    let mut kept = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && bytes[i] != b'=' && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let key = &url[start..i];
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value = Vec::new();
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && bytes[i] == b'\'' {
                i += 1;
                while i < bytes.len() && bytes[i] != b'\'' {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        i += 1;
                    }
                    value.push(bytes[i]);
                    i += 1;
                }
                i += 1;
            } else {
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                    value.push(bytes[i]);
                    i += 1;
                }
            }
        }
        let end = i.min(bytes.len());
        if !take(key, String::from_utf8_lossy(&value).into_owned()) {
            kept.push(&url[start..end]);
        }
    }
    (kept.join(" "), mode, root)
}

/// A URL query value with its %XX escapes decoded.
fn percent_decoded(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = bytes
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match (bytes[i], hex) {
            (b'%', Some(byte)) => {
                out.push(byte);
                i += 3;
            }
            (byte, _) => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `sslmode=require` without a root file: encrypted, the certificate not checked, as libpq does.
#[derive(Debug)]
struct Unchecked(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for Unchecked {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// `sslmode=verify-ca`: the certificate must be signed by a trusted root, and may name any host.
#[derive(Debug)]
struct AnyName(Arc<rustls::client::WebPkiServerVerifier>);

impl rustls::client::danger::ServerCertVerifier for AnyName {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        use rustls::{CertificateError, Error};
        // The chain is checked before the name, so a name error means the signer was trusted.
        match self
            .0
            .verify_server_cert(end_entity, intermediates, server_name, ocsp, now)
        {
            Err(Error::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
            )) => Ok(rustls::client::danger::ServerCertVerified::assertion()),
            other => other,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

/// Set by `enterplace serve --no-migrate`: every migration list is compared with the database and never applied.
static NO_MIGRATE: AtomicBool = AtomicBool::new(false);

/// Makes this process check the store's schema instead of changing it (`enterplace serve --no-migrate`): a start on a
/// database that is behind is refused, naming `enterplace store migrate`. For clusters where serving pods may not run
/// DDL; the migration runs as its own step (an init container, a Helm Job).
pub fn set_no_migrate(on: bool) {
    NO_MIGRATE.store(on, Ordering::Relaxed);
}

fn no_migrate() -> bool {
    NO_MIGRATE.load(Ordering::Relaxed)
}

async fn exists(
    tx: &tokio_postgres::Transaction<'_>,
    table: &str,
) -> Result<bool, tokio_postgres::Error> {
    tx.query_one("SELECT to_regclass($1) IS NOT NULL", &[&table])
        .await?
        .try_get(0)
}

/// With `--no-migrate`: fine when the tables are current, refused when they are behind.
fn stale(what: &str, applied: i32, known: i32) -> Result<(), String> {
    if applied >= known {
        return Ok(());
    }
    Err(format!(
        "the store's schema is behind: {what} tables are at version {applied} and this Enterplace ({}) needs {known}. It was started with --no-migrate, so it changes no table. Run `enterplace store migrate --policy <policy>` with the same version and environment (an init container or the Helm chart's migration Job), then start again.",
        enterplace_core::VERSION
    ))
}

/// Creates or updates the tables, one Enterplace at a time, and refuses a database a newer Enterplace has written.
async fn migrate(client: &mut Client) -> Result<(), String> {
    let failed = |err: tokio_postgres::Error| {
        format!(
            "the store's tables could not be created or updated: {err}. The connection string's user needs CREATE on the database. Fix that and start again."
        )
    };
    let check_only = no_migrate();
    let tx = client.transaction().await.map_err(failed)?;
    let there = !check_only || exists(&tx, "enterplace_schema").await.map_err(failed)?;
    if !check_only {
        // Two replicas starting together would both create the tables: the second waits here for the first.
        tx.batch_execute(
            "SELECT pg_advisory_xact_lock(7349127341); CREATE TABLE IF NOT EXISTS enterplace_schema (version integer NOT NULL);",
        )
        .await
        .map_err(failed)?;
    }
    let applied: i32 = if there {
        tx.query_one(
            "SELECT coalesce(max(version), 0) FROM enterplace_schema",
            &[],
        )
        .await
        .map_err(failed)?
        .try_get(0)
        .map_err(failed)?
    } else {
        0
    };
    let known = i32::try_from(MIGRATIONS.len()).unwrap_or(i32::MAX);
    let own = enterplace_core::VERSION;
    if applied > known {
        let by = writer(&tx).await.map_err(failed)?;
        if !by.as_deref().is_some_and(|by| newer_allowed(own, by)) {
            return Err(format!(
                "the store was written by a newer Enterplace ({}, schema version {applied}; this one is {own} and knows up to {known}). Enterplace versions share one database only one minor version apart. Run the same Enterplace version as the other gateways on this database (or upgrade this one), or point it at another database.",
                by.as_deref().unwrap_or("version unknown")
            ));
        }
    }
    if check_only {
        return stale("the gateway's own", applied, known);
    }
    for (number, sql) in MIGRATIONS.iter().enumerate().skip(applied as usize) {
        tx.batch_execute(sql).await.map_err(failed)?;
        let version = i32::try_from(number + 1).unwrap_or(i32::MAX);
        tx.execute("INSERT INTO enterplace_schema VALUES ($1)", &[&version])
            .await
            .map_err(failed)?;
    }
    // The newest version to start on this database is what an older binary compares itself with. An older one
    // never lowers it.
    let by = writer(&tx).await.map_err(failed)?;
    if by.is_none_or(|by| semver(own) > semver(&by)) {
        tx.execute(
            "INSERT INTO enterplace_writer VALUES (1, $1) ON CONFLICT (id) DO UPDATE SET version = excluded.version",
            &[&own],
        )
        .await
        .map_err(failed)?;
    }
    tx.commit().await.map_err(failed)
}

impl Inner {
    async fn connect(&self) -> Result<Client, tokio_postgres::Error> {
        match &self.tls {
            Some(tls) => {
                let (client, connection) = self.config.connect(tls.clone()).await?;
                tokio::spawn(connection);
                Ok(client)
            }
            None => {
                let (client, connection) = self.config.connect(NoTls).await?;
                tokio::spawn(connection);
                Ok(client)
            }
        }
    }

    /// The connection, if it is open. The request path never connects: it is refused at once instead of waiting.
    /// Takes or keeps the probe lease of `deployment` for `ttl`: free, expired, or already this gateway's.
    async fn probe_lease(&self, deployment: &str, ttl: Duration) -> Result<bool, String> {
        let client = self.client()?;
        let row = client
            .query_opt(
                "INSERT INTO enterplace_probe_leases (deployment, gateway, until) VALUES ($1, $2, now() + make_interval(secs => $3)) \
                 ON CONFLICT (deployment) DO UPDATE SET gateway = excluded.gateway, until = excluded.until \
                 WHERE enterplace_probe_leases.until < now() OR enterplace_probe_leases.gateway = excluded.gateway RETURNING 1",
                &[&deployment, &self.gateway, &ttl.as_secs_f64()],
            )
            .await
            .map_err(|e| format!("the probe lease could not be taken: {e}"))?;
        Ok(row.is_some())
    }

    fn client(&self) -> Result<Arc<Client>, String> {
        read(&self.client)
            .filter(|client| !client.is_closed())
            .ok_or_else(|| "the connection to Postgres is down".to_string())
    }

    /// The connection, opened again if it was lost.
    async fn ensure(&self) -> Result<Arc<Client>, String> {
        if let Ok(client) = self.client() {
            return Ok(client);
        }
        let client = Arc::new(self.connect().await.map_err(|err| err.to_string())?);
        write(&self.client, Some(client.clone()));
        Ok(client)
    }

    /// One round of the poller: what changed is read, and what this gateway gave back and measured is written.
    async fn round(&self) {
        let _one = self.polling.lock().await;
        self.poll().await;
        self.flush_returns().await;
        self.flush_routing().await;
    }

    /// One poll: reloads what changed, and reports the database going away or coming back.
    async fn poll(&self) {
        match tokio::time::timeout(WAIT, self.refresh()).await {
            Ok(Ok(())) => {
                if self.down.swap(false, Ordering::Relaxed) {
                    eprintln!(
                        "enterplace: the store is reachable again. Budgeted requests are served again."
                    );
                }
            }
            result => {
                let err = match result {
                    Ok(Err(err)) => err,
                    _ => format!("no answer within {} seconds", WAIT.as_secs()),
                };
                write(&self.client, None);
                if !self.down.swap(true, Ordering::Relaxed) {
                    eprintln!(
                        "enterplace: the store cannot be reached: {err}. Known keys and kill switches stay as they were, and requests under a budget are refused (store_unavailable) until it is back. Check Postgres and {}.",
                        self.env
                    );
                }
            }
        }
    }

    /// Reads the versions, and the keys or kill switches whose version changed.
    async fn refresh(&self) -> Result<(), String> {
        let _one = self.refreshing.lock().await;
        let client = self.ensure().await?;
        let rows = client
            .query("SELECT name, version FROM enterplace_versions", &[])
            .await
            .map_err(|err| err.to_string())?;
        let version = |name: &str| {
            rows.iter()
                .find(|row| row.try_get::<_, &str>(0).is_ok_and(|n| n == name))
                .and_then(|row| row.try_get::<_, i64>(1).ok())
                .unwrap_or(0)
        };
        let now = (
            version("keys"),
            version("kills"),
            version("cooldowns"),
            version("credentials"),
        );
        let seen = *self
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if seen.is_none_or(|(keys, _, _, _)| keys != now.0) {
            write(
                &self.keys,
                keyfile::keys_text(&self.read_keys(&client).await?),
            );
        }
        if seen.is_none_or(|(_, kills, _, _)| kills != now.1) {
            write(&self.kills, Arc::new(self.read_kills(&client).await?));
        }
        if seen.is_none_or(|(_, _, cooldowns, _)| cooldowns != now.2) {
            write(&self.cooling, Arc::new(self.read_cooling(&client).await?));
        }
        if seen.is_none_or(|(_, _, _, credentials)| credentials != now.3) {
            let rows = client
                .query(
                    &format!("SELECT {SHOWN}, sealed FROM enterplace_credentials ORDER BY name"),
                    &[],
                )
                .await
                .map_err(|err| err.to_string())?;
            let mut all = Vec::with_capacity(rows.len());
            for row in &rows {
                let sealed: Vec<u8> = row.try_get(8).map_err(|err| err.to_string())?;
                all.push((credential_of(row)?, sealed));
            }
            write(&self.credentials, Arc::new(all));
        }
        *self
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(now);
        let policy = version("policy");
        let seen = *self
            .policies_seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if seen != Some(policy) {
            // ponytail: every version's whole text is held in memory and read again on each change. Fine for
            // hundreds of versions; page the list when someone keeps thousands.
            let rows = client
                .query(
                    &format!(
                        "SELECT {VERSION_COLUMNS} FROM enterplace_policy_versions ORDER BY id DESC"
                    ),
                    &[],
                )
                .await
                .map_err(|err| err.to_string())?;
            let all: Result<Vec<_>, String> = rows.iter().map(version_of).collect();
            write(&self.policies, Arc::new(all?));
            *self
                .policies_seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(policy);
        }
        let ended = version("events");
        let seen = *self
            .ended_seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if seen != Some(ended) {
            // ponytail: every ended session is read again when one more ends. Fine for thousands; read only the
            // rows newer than the last read when plugins end sessions by the second.
            let rows = client
                .query(
                    "SELECT sha256, who, extract(epoch FROM expires - clock_timestamp())::float8 FROM enterplace_sessions \
                     WHERE who LIKE 'events:%' AND expires > clock_timestamp()",
                    &[],
                )
                .await
                .map_err(|err| err.to_string())?;
            let now = Instant::now();
            let mut all = HashMap::with_capacity(rows.len());
            for row in rows {
                let field = |err: tokio_postgres::Error| err.to_string();
                let who: String = row.try_get(1).map_err(field)?;
                let left: f64 = row.try_get(2).map_err(field)?;
                all.insert(
                    row.try_get(0).map_err(field)?,
                    (
                        now + Duration::try_from_secs_f64(left).unwrap_or_default(),
                        who.strip_prefix(ENDED).unwrap_or(&who).to_string(),
                    ),
                );
            }
            write(&self.ended, Arc::new(all));
            *self
                .ended_seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(ended);
        }
        let raises = version("raises");
        let seen = *self
            .raises_seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if seen != Some(raises) {
            let rows = client
                .query("SELECT body FROM enterplace_raises ORDER BY id", &[])
                .await
                .map_err(|err| err.to_string())?;
            let all: Vec<Raise> = rows
                .iter()
                .filter_map(|row| row.try_get::<_, &str>(0).ok())
                .filter_map(|body| serde_json::from_str(body).ok())
                .collect();
            write(&self.raises, Arc::new(all));
            *self
                .raises_seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(raises);
        }
        self.read_routing(&client).await
    }

    /// Writes this gateway's heartbeat, and now and then clears what ran out: gateways gone for a day, answers
    /// past their time, and the least recently used answers beyond the cache's size.
    async fn heartbeat(&self) {
        let polls = self.polls.load(Ordering::Relaxed);
        if polls % HEARTBEAT_EVERY != 0 {
            return;
        }
        let Ok(client) = self.client() else {
            return;
        };
        let host = std::env::var("HOSTNAME").unwrap_or_default();
        let schema = PgStore::migration_lists()
            .iter()
            .map(|(namespace, list)| format!("{namespace} {}", list.len()))
            .collect::<Vec<_>>()
            .join(", ");
        let state = self
            .in_force
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let (refused_version, refused) = match &state.refused {
            Some((_, version, why)) => (*version, Some(why.clone())),
            None => (None, None),
        };
        let _ = tokio::time::timeout(
            WAIT,
            client.execute(
                "INSERT INTO enterplace_replicas (gateway, host, version, schema, started, seen, policy_version, refused_version, refused) \
                 VALUES ($1, $2, $3, $4, clock_timestamp(), clock_timestamp(), $5, $6, $7) \
                 ON CONFLICT (gateway) DO UPDATE SET seen = excluded.seen, policy_version = excluded.policy_version, \
                 refused_version = excluded.refused_version, refused = excluded.refused",
                &[&self.gateway, &host, &enterplace_core::VERSION, &schema, &state.version, &refused_version, &refused],
            ),
        )
        .await;
        if polls % CLEAN_EVERY != 0 {
            return;
        }
        let _ = tokio::time::timeout(
            WAIT,
            client.batch_execute(&format!(
                "DELETE FROM enterplace_replicas WHERE seen < clock_timestamp() - interval '1 day'; \
                 DELETE FROM enterplace_answer_cache WHERE expires < clock_timestamp(); \
                 DELETE FROM enterplace_answer_cache WHERE key IN (SELECT key FROM (SELECT key, \
                   sum(octet_length(body)) OVER (ORDER BY used DESC, key) AS total FROM enterplace_answer_cache) t \
                   WHERE total > {SHARED_CACHE_BYTES});"
            )),
        )
        .await;
    }

    /// Reads the pins written since the last read (another gateway's sessions) and every gateway's latency.
    async fn read_routing(&self, client: &Client) -> Result<(), String> {
        let since = *self
            .pins_read
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let idle = crate::alias::SESSION_IDLE.as_secs_f64();
        // The first row is the database's clock, the next read's starting point; the rest are the pins.
        let rows = client
            .query(
                "SELECT NULL::text, NULL::text, extract(epoch FROM clock_timestamp())::float8 \
                 UNION ALL \
                 SELECT session, deployment, extract(epoch FROM clock_timestamp() - seen)::float8 FROM enterplace_affinity \
                 WHERE seen > to_timestamp($1) - $2 * interval '1 second' AND seen > clock_timestamp() - $3 * interval '1 second'",
                &[&since, &PIN_OVERLAP_SECS, &idle],
            )
            .await
            .map_err(|err| err.to_string())?;
        let now = Instant::now();
        let pending = self
            .pins_out
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        {
            let mut pins = self
                .pins
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for row in &rows {
                let field = |err: tokio_postgres::Error| err.to_string();
                let session: Option<String> = row.try_get(0).map_err(field)?;
                let seconds: f64 = row.try_get(2).map_err(field)?;
                let Some(session) = session else {
                    *self
                        .pins_read
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = seconds;
                    continue;
                };
                if pending.contains_key(&session) {
                    continue;
                }
                let deployment: String = row.try_get(1).map_err(field)?;
                let at = now
                    .checked_sub(Duration::try_from_secs_f64(seconds).unwrap_or_default())
                    .unwrap_or(now);
                // A pin this gateway made or saw later stays: the row read is older.
                if pins
                    .get(&session)
                    .is_some_and(|(d, seen, _)| *d == deployment && *seen > at)
                {
                    continue;
                }
                crate::alias::bounded_insert(&mut pins, session, (deployment, at, at), now, |p| {
                    p.1
                });
            }
        }
        let rows = client
            .query(
                "SELECT deployment, samples FROM enterplace_latency WHERE updated > clock_timestamp() - $1 * interval '1 second'",
                &[&LATENCY_FOR_SECS],
            )
            .await
            .map_err(|err| err.to_string())?;
        let mut all: HashMap<String, std::collections::VecDeque<u32>> = HashMap::new();
        for row in &rows {
            let field = |err: tokio_postgres::Error| err.to_string();
            let deployment: String = row.try_get(0).map_err(field)?;
            let samples: Vec<i32> = row.try_get(1).map_err(field)?;
            all.entry(deployment)
                .or_default()
                .extend(samples.into_iter().map(|ms| u32::try_from(ms).unwrap_or(0)));
        }
        let p90 = all
            .iter()
            .filter_map(|(d, samples)| Some((d.clone(), crate::alias::percentile(samples, 90)?)))
            .collect();
        write(&self.latency, Arc::new(p90));
        // The others' load on each deployment: in flight now, and sent in this minute.
        let minute = crate::alias::minute_now();
        let rows = client
            .query(
                "SELECT deployment, sum(in_flight)::bigint, coalesce(sum(requests) FILTER (WHERE minute = $3), 0)::bigint, \
                 coalesce(sum(tokens) FILTER (WHERE minute = $3), 0)::bigint FROM enterplace_deployment_load \
                 WHERE gateway <> $1 AND updated > clock_timestamp() - $2 * interval '1 second' GROUP BY deployment",
                &[&self.gateway, &LOAD_FOR_SECS, &minute],
            )
            .await
            .map_err(|err| err.to_string())?;
        let mut load = HashMap::new();
        for row in &rows {
            let field = |err: tokio_postgres::Error| err.to_string();
            let count =
                |i: usize| -> Result<i64, String> { row.try_get::<_, i64>(i).map_err(field) };
            load.insert(
                row.try_get::<_, String>(0).map_err(field)?,
                DeploymentLoad {
                    in_flight: u32::try_from(count(1)?).unwrap_or(0),
                    minute,
                    requests: u32::try_from(count(2)?).unwrap_or(0),
                    tokens: u64::try_from(count(3)?).unwrap_or(0),
                },
            );
        }
        write(&self.load, Arc::new(load));
        // What the other gateways know of each deployment, for the deployment health view.
        let rows = client
            .query(
                "SELECT report FROM enterplace_gateway_health WHERE gateway <> $1 AND updated > clock_timestamp() - $2 * interval '1 second' ORDER BY gateway",
                &[&self.gateway, &LOAD_FOR_SECS],
            )
            .await
            .map_err(|err| err.to_string())?;
        let reports = rows
            .iter()
            .filter_map(|row| row.try_get::<_, String>(0).ok())
            .collect();
        write(&self.health, Arc::new(reports));
        Ok(())
    }

    /// Writes the pins made and the latency measured here since the last poll, and now and then deletes what has
    /// expired. Lost if the database is away: pins are made again by the next request, samples by the next answer.
    async fn flush_routing(&self) {
        let Ok(client) = self.client() else {
            return;
        };
        let pins = std::mem::take(
            &mut *self
                .pins_out
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        if !pins.is_empty() {
            let (sessions, deployments): (Vec<String>, Vec<String>) = pins.into_iter().unzip();
            let _ = tokio::time::timeout(
                WAIT,
                client.query_typed(
                    "INSERT INTO enterplace_affinity (session, deployment, seen) \
                     SELECT s, d, clock_timestamp() FROM unnest($1::text[], $2::text[]) AS t(s, d) \
                     ON CONFLICT (session) DO UPDATE SET deployment = excluded.deployment, seen = excluded.seen",
                    &[(&sessions, Type::TEXT_ARRAY), (&deployments, Type::TEXT_ARRAY)],
                ),
            )
            .await;
        }
        let changed: Vec<(String, String)> = self
            .samples
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter_mut()
            .filter(|(_, (_, dirty))| *dirty)
            .map(|(d, (samples, dirty))| {
                *dirty = false;
                let text: Vec<String> = samples.iter().map(u32::to_string).collect();
                (d.clone(), text.join(","))
            })
            .collect();
        if !changed.is_empty() {
            let (deployments, samples): (Vec<String>, Vec<String>) = changed.into_iter().unzip();
            let _ = tokio::time::timeout(
                WAIT,
                client.query_typed(
                    "INSERT INTO enterplace_latency (deployment, gateway, samples, updated) \
                     SELECT d, $3, string_to_array(s, ',')::integer[], clock_timestamp() FROM unnest($1::text[], $2::text[]) AS t(d, s) \
                     ON CONFLICT (deployment, gateway) DO UPDATE SET samples = excluded.samples, updated = excluded.updated",
                    &[
                        (&deployments, Type::TEXT_ARRAY),
                        (&samples, Type::TEXT_ARRAY),
                        (&self.gateway, Type::TEXT),
                    ],
                ),
            )
            .await;
        }
        let load = std::mem::take(
            &mut *self
                .load_out
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        if !load.is_empty() {
            let deployments: Vec<String> = load.keys().cloned().collect();
            let column = |f: fn(&DeploymentLoad) -> i64| -> Vec<i64> {
                deployments
                    .iter()
                    .map(|d| load.get(d).map_or(0, f))
                    .collect()
            };
            let columns = (
                deployments.clone(),
                column(|l| i64::from(l.in_flight)),
                column(|l| l.minute),
                column(|l| i64::from(l.requests)),
                column(|l| i64::try_from(l.tokens).unwrap_or(i64::MAX)),
            );
            let _ = tokio::time::timeout(
                WAIT,
                client.query_typed(
                    "INSERT INTO enterplace_deployment_load (deployment, gateway, in_flight, minute, requests, tokens, updated) \
                     SELECT d, $6, f::integer, m, r::integer, t, clock_timestamp() FROM unnest($1::text[], $2::int8[], $3::int8[], $4::int8[], $5::int8[]) AS x(d, f, m, r, t) \
                     ON CONFLICT (deployment, gateway) DO UPDATE SET in_flight = excluded.in_flight, minute = excluded.minute, \
                     requests = excluded.requests, tokens = excluded.tokens, updated = excluded.updated",
                    &[
                        (&columns.0, Type::TEXT_ARRAY),
                        (&columns.1, Type::INT8_ARRAY),
                        (&columns.2, Type::INT8_ARRAY),
                        (&columns.3, Type::INT8_ARRAY),
                        (&columns.4, Type::INT8_ARRAY),
                        (&self.gateway, Type::TEXT),
                    ],
                ),
            )
            .await;
        }
        let report = self
            .health_out
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(report) = report {
            let _ = tokio::time::timeout(
                WAIT,
                client.execute(
                    "INSERT INTO enterplace_gateway_health (gateway, report, updated) VALUES ($1, $2, clock_timestamp()) \
                     ON CONFLICT (gateway) DO UPDATE SET report = excluded.report, updated = excluded.updated",
                    &[&self.gateway, &report],
                ),
            )
            .await;
        }
        if self.polls.fetch_add(1, Ordering::Relaxed) % CLEAN_EVERY == 0 {
            let _ = tokio::time::timeout(
                WAIT,
                client.execute(
                    "DELETE FROM enterplace_gateway_health WHERE updated < clock_timestamp() - $1 * interval '1 second'",
                    &[&LOAD_FOR_SECS],
                ),
            )
            .await;
            let idle = crate::alias::SESSION_IDLE.as_secs_f64();
            // Sessions that ran out: a console's, and the ones events plugins ended.
            let _ = tokio::time::timeout(
                WAIT,
                client.execute("DELETE FROM enterplace_sessions WHERE expires < now()", &[]),
            )
            .await;
            // Failed sign-ins long past any window, whose lockout, if any, has ended.
            let _ = tokio::time::timeout(
                WAIT,
                client.execute(
                    "DELETE FROM enterplace_sign_in_failures WHERE since < now() - interval '1 day' AND coalesce(locked_until, since) < now()",
                    &[],
                ),
            )
            .await;
            let _ = tokio::time::timeout(
                WAIT,
                client.execute(
                    "DELETE FROM enterplace_affinity WHERE seen < clock_timestamp() - $1 * interval '1 second'",
                    &[&idle],
                ),
            )
            .await;
            let _ = tokio::time::timeout(
                WAIT,
                client.execute(
                    "DELETE FROM enterplace_latency WHERE updated < clock_timestamp() - $1 * interval '1 second'",
                    &[&LATENCY_FOR_SECS],
                ),
            )
            .await;
            let _ = tokio::time::timeout(
                WAIT,
                client.execute(
                    "DELETE FROM enterplace_deployment_load WHERE updated < clock_timestamp() - $1 * interval '1 second'",
                    &[&LOAD_FOR_SECS],
                ),
            )
            .await;
            let now = Instant::now();
            self.pins
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .retain(|_, (_, at, _)| now.duration_since(*at) < crate::alias::SESSION_IDLE);
        }
    }

    /// Runs `work` in a transaction of its own connection, under the policy lock, then reads the versions again so
    /// this gateway sees the change at once.
    async fn policy_change<T: Send + 'static>(
        &self,
        work: impl for<'t> FnOnce(
            &'t tokio_postgres::Transaction<'t>,
        )
            -> Pin<Box<dyn Future<Output = Result<T, VersionError>> + Send + 't>>
        + Send,
    ) -> Result<T, VersionError> {
        let down = |err: String| {
            VersionError::Store(format!(
                "the policy version could not be written to the store: {err}. Nothing was changed. Check that Postgres is up and {} is right, then try again.",
                self.env
            ))
        };
        let mut client = self.connect().await.map_err(|err| down(err.to_string()))?;
        let tx = client
            .transaction()
            .await
            .map_err(|err| down(err.to_string()))?;
        tx.execute("SELECT pg_advisory_xact_lock($1)", &[&POLICY_LOCK])
            .await
            .map_err(|err| down(err.to_string()))?;
        let done = work(&tx).await?;
        tx.execute(
            "UPDATE enterplace_versions SET version = version + 1 WHERE name = 'policy'",
            &[],
        )
        .await
        .map_err(|err| down(err.to_string()))?;
        tx.commit().await.map_err(|err| down(err.to_string()))?;
        // Written. If reading it back fails, the poll picks it up within half a second.
        let _ = self.refresh().await;
        Ok(done)
    }

    async fn read_keys(&self, client: &Client) -> Result<Vec<KeyEntry>, String> {
        let rows = client
            .query(
                "SELECT name, team, sha256, admin, expires, budget_usd, budget_per, models, tpm, org, customer, tags, parallel, role, options FROM enterplace_keys ORDER BY id",
                &[],
            )
            .await
            .map_err(|err| err.to_string())?;
        let mut keys = Vec::with_capacity(rows.len());
        for row in rows {
            let field = |err: tokio_postgres::Error| err.to_string();
            let usd: Option<f64> = row.try_get(5).map_err(field)?;
            let per: Option<String> = row.try_get(6).map_err(field)?;
            let tpm: Option<i32> = row.try_get(8).map_err(field)?;
            let parallel: Option<i32> = row.try_get(12).map_err(field)?;
            let org: Option<String> = row.try_get(9).map_err(field)?;
            let tags: Option<Vec<String>> = row.try_get(11).map_err(field)?;
            let options: Option<String> = row.try_get(14).map_err(field)?;
            keys.push(KeyEntry {
                name: row.try_get(0).map_err(field)?,
                team: row.try_get(1).map_err(field)?,
                sha256: row.try_get(2).map_err(field)?,
                admin: row.try_get(3).map_err(field)?,
                expires: row.try_get(4).map_err(field)?,
                budget: usd.map(|usd| Budget {
                    usd,
                    // Only Enterplace writes this column. A word no version writes is read as a day, the tightest common
                    // period.
                    per: per
                        .as_deref()
                        .and_then(Period::from_word)
                        .unwrap_or(Period::Day),
                }),
                models: row.try_get(7).map_err(field)?,
                // A value out of range becomes 0, which the loader refuses: the change is then not used at all.
                tpm: tpm.map(|t| u32::try_from(t).unwrap_or(0)),
                org: org.unwrap_or_default(),
                customer: row.try_get(10).map_err(field)?,
                tags: tags.unwrap_or_default(),
                parallel: parallel.map(|t| u32::try_from(t).unwrap_or(0)),
                role: row.try_get(13).map_err(field)?,
                // Unreadable options stop the refresh: the last keys stay in force, never one with fewer limits.
                options: options
                    .as_deref()
                    .map(keyfile::options_from_json)
                    .transpose()?
                    .unwrap_or_default(),
            });
        }
        Ok(keys)
    }

    async fn read_kills(&self, client: &Client) -> Result<Vec<Kill>, String> {
        let rows = client
            .query(
                "SELECT scope, value, reason, set_by, set_at FROM enterplace_kills ORDER BY set_at, scope, value",
                &[],
            )
            .await
            .map_err(|err| err.to_string())?;
        rows.iter().map(kill_of).collect()
    }

    /// Deployments cooling down, with the time left read from the database's clock, so the gateways' clocks
    /// need not agree.
    async fn read_cooling(&self, client: &Client) -> Result<HashMap<String, Instant>, String> {
        let rows = client
            .query(
                "SELECT deployment, extract(epoch FROM until - clock_timestamp())::float8 FROM enterplace_cooldowns \
                 WHERE until > clock_timestamp()",
                &[],
            )
            .await
            .map_err(|err| err.to_string())?;
        let now = Instant::now();
        let mut cooling = HashMap::with_capacity(rows.len());
        for row in rows {
            let field = |err: tokio_postgres::Error| err.to_string();
            let left: f64 = row.try_get(1).map_err(field)?;
            cooling.insert(
                row.try_get(0).map_err(field)?,
                now + Duration::try_from_secs_f64(left).unwrap_or_default(),
            );
        }
        Ok(cooling)
    }

    /// One lease, in one round trip. Several statements in one simple query run as one transaction, each with a
    /// fresh snapshot: the advisory lock orders the gateways leasing one scope, and the sum after it sees every
    /// grant committed before. The text is built here because a simple query takes no parameters: the scope goes in
    /// as hex and every other value is a number.
    async fn lease(&self, scope: &str, need: u64, want: u64, limit: u64) -> Result<Lease, String> {
        let client = self.client()?;
        let hash = id::sha256(scope.as_bytes());
        let lock = i64::from_be_bytes([
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
        ]);
        let scope = format!(
            "convert_from(decode('{}', 'hex'), 'UTF8')",
            id::hex(scope.as_bytes())
        );
        let number = |n: u64| i64::try_from(n).unwrap_or(i64::MAX);
        let (need, want, limit) = (number(need), number(want), number(limit));
        let hold = u64::try_from(LEASE.as_millis()).unwrap_or(1000) + LEASE_MARGIN_MS;
        // A request admitted under a grant is admitted at most a lease after it, and the grant is counted until
        // then and a margin more. So the grants counted from a minute before now hold every request admitted in the
        // last minute, and a new grant is taken only if they and it fit the limit.
        let sql = format!(
            "SELECT pg_advisory_xact_lock({lock}); \
             DELETE FROM enterplace_rate_grants WHERE scope = {scope} AND until < clock_timestamp() - interval '61 seconds'; \
             WITH used AS (SELECT coalesce(sum(n), 0) AS n, min(until) AS first FROM enterplace_rate_grants \
               WHERE scope = {scope} AND until >= clock_timestamp() - interval '60 seconds'), \
             got AS (INSERT INTO enterplace_rate_grants (scope, until, n) \
               SELECT {scope}, clock_timestamp() + interval '{hold} milliseconds', least({want}, {limit} - used.n) \
               FROM used WHERE used.n + {need} <= {limit} RETURNING id, n) \
             SELECT (SELECT id FROM got), (SELECT n FROM got), \
               (SELECT ceil(extract(epoch FROM first + interval '60 seconds' - clock_timestamp()))::bigint FROM used)"
        );
        let answers = client
            .simple_query(&sql)
            .await
            .map_err(|err| err.to_string())?;
        let row = answers
            .iter()
            .rev()
            .find_map(|answer| match answer {
                tokio_postgres::SimpleQueryMessage::Row(row) => Some(row),
                _ => None,
            })
            .ok_or("the lease statement returned no row")?;
        let number = |at: usize| row.get(at).and_then(|v| v.parse::<i64>().ok());
        Ok(match (number(0), number(1)) {
            (Some(grant), Some(n)) => Lease::Granted {
                grant,
                n: u64::try_from(n).unwrap_or(0),
            },
            _ => Lease::Over {
                wait: number(2).map_or(1, |w| u64::try_from(w).unwrap_or(1).max(1)),
            },
        })
    }

    /// Writes what was given back since the last poll. Lost if the database is away: a grant then counts in full
    /// until it leaves the minute, which errs on the side of the limit.
    async fn flush_returns(&self) {
        let returns = std::mem::take(
            &mut *self
                .returns
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        if returns.is_empty() {
            return;
        }
        let Ok(client) = self.client() else {
            return;
        };
        let (grants, given): (Vec<i64>, Vec<i64>) = returns.into_iter().unzip();
        let _ = tokio::time::timeout(
            WAIT,
            client.query_typed(
                "UPDATE enterplace_rate_grants AS g SET n = greatest(g.n - r.given, 0) \
                 FROM unnest($1::int8[], $2::int8[]) AS r(id, given) WHERE g.id = r.id",
                &[(&grants, Type::INT8_ARRAY), (&given, Type::INT8_ARRAY)],
            ),
        )
        .await;
    }

    async fn reserve(&self, bucket: &Bucket, usd: f64, limit: f64) -> Result<Reserve, String> {
        if bucket.per.sliding {
            return self.reserve_sliding(bucket, usd, limit).await;
        }
        let client = self.client()?;
        let per = bucket.per.word();
        let params: [(&(dyn tokio_postgres::types::ToSql + Sync), Type); 5] = [
            (&bucket.scope, Type::TEXT),
            (&per, Type::TEXT),
            (&bucket.period, Type::TEXT),
            (&usd, Type::FLOAT8),
            (&limit, Type::FLOAT8),
        ];
        // One statement, so two gateways reserving at once are ordered by the row lock and never both pass.
        // A request costing more than the whole budget inserts nothing.
        let done = client
            .query_typed(
                "INSERT INTO enterplace_spend AS s (scope, per, period, reserved) SELECT $1, $2, $3, $4 WHERE $4 <= $5 \
                 ON CONFLICT (scope, per, period) DO UPDATE SET reserved = s.reserved + excluded.reserved \
                 WHERE s.spent + s.reserved + excluded.reserved <= $5 RETURNING 1",
                &params,
            )
            .await
            .map_err(|err| err.to_string())?;
        if !done.is_empty() {
            return Ok(Reserve::Done);
        }
        let row = client
            .query_typed(
                "SELECT spent, reserved FROM enterplace_spend WHERE scope = $1 AND per = $2 AND period = $3",
                &params[..3],
            )
            .await
            .map_err(|err| err.to_string())?;
        let (spent, reserved) = row.first().map_or((0.0, 0.0), |row| {
            (row.try_get(0).unwrap_or(0.0), row.try_get(1).unwrap_or(0.0))
        });
        Ok(Reserve::Over { spent, reserved })
    }

    /// `reserve` for a sliding window: the sum of its slots from the window's start, and the hold in the current
    /// slot. Several slots cannot be checked by one row lock, so an advisory lock on the counter orders the gateways,
    /// taken in the first statement of one round trip so the sum is read after it (each statement of a simple query
    /// reads afresh). Slots wholly before the window that hold nothing are deleted on the way.
    async fn reserve_sliding(
        &self,
        bucket: &Bucket,
        usd: f64,
        limit: f64,
    ) -> Result<Reserve, String> {
        if !usd.is_finite() || !limit.is_finite() {
            return Err(format!(
                "a reservation of {usd} against a limit of {limit} is not a number of dollars"
            ));
        }
        let client = self.client()?;
        let per = bucket.per.word();
        let hash = id::sha256(format!("{}\n{per}", bucket.scope).as_bytes());
        let lock = i64::from_be_bytes([
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
        ]);
        let text = |value: &str| {
            format!(
                "convert_from(decode('{}', 'hex'), 'UTF8')",
                id::hex(value.as_bytes())
            )
        };
        let (scope, per, slot, from) = (
            text(&bucket.scope),
            text(&per),
            text(&bucket.period),
            text(&bucket.per.window_start_label(&bucket.period)),
        );
        let sql = format!(
            "SELECT pg_advisory_xact_lock({lock}); \
             DELETE FROM enterplace_spend WHERE scope = {scope} AND per = {per} AND period < {from} AND reserved <= 0; \
             WITH used AS (SELECT coalesce(sum(CASE WHEN period >= {from} THEN spent ELSE 0 END), 0) AS spent, \
               coalesce(sum(reserved), 0) AS reserved FROM enterplace_spend WHERE scope = {scope} AND per = {per}), \
             got AS (INSERT INTO enterplace_spend AS s (scope, per, period, reserved) \
               SELECT {scope}, {per}, {slot}, {usd}::float8 FROM used WHERE used.spent + used.reserved + {usd}::float8 <= {limit}::float8 \
               ON CONFLICT (scope, per, period) DO UPDATE SET reserved = s.reserved + excluded.reserved RETURNING 1) \
             SELECT (SELECT count(*) FROM got), used.spent, used.reserved FROM used"
        );
        let answers = client
            .simple_query(&sql)
            .await
            .map_err(|err| err.to_string())?;
        let row = answers
            .iter()
            .rev()
            .find_map(|answer| match answer {
                tokio_postgres::SimpleQueryMessage::Row(row) => Some(row),
                _ => None,
            })
            .ok_or("the sliding reservation returned no row")?;
        let number = |at: usize| row.get(at).and_then(|v| v.parse::<f64>().ok());
        Ok(match number(0) {
            Some(n) if n > 0.0 => Reserve::Done,
            _ => Reserve::Over {
                spent: number(1).unwrap_or(0.0),
                reserved: number(2).unwrap_or(0.0),
            },
        })
    }

    async fn settle(&self, changes: &[Change]) -> Result<(), String> {
        // One row per bucket: one statement may not update a row twice.
        let mut merged: BTreeMap<&Bucket, (f64, f64)> = BTreeMap::new();
        for change in changes {
            let sum = merged.entry(&change.bucket).or_default();
            sum.0 += change.spent;
            sum.1 += change.reserved;
        }
        let scope: Vec<&str> = merged.keys().map(|b| b.scope.as_str()).collect();
        let per: Vec<String> = merged.keys().map(|b| b.per.word()).collect();
        let period: Vec<&str> = merged.keys().map(|b| b.period.as_str()).collect();
        let spent: Vec<f64> = merged.values().map(|v| v.0).collect();
        let reserved: Vec<f64> = merged.values().map(|v| v.1).collect();
        // A hold is given back to the row its reservation made, and rows are never deleted, so a negative
        // `reserved` never inserts a row.
        self.client()?
            .query_typed(
                "INSERT INTO enterplace_spend AS s (scope, per, period, spent, reserved) \
                 SELECT * FROM unnest($1::text[], $2::text[], $3::text[], $4::float8[], $5::float8[]) \
                 ON CONFLICT (scope, per, period) DO UPDATE \
                 SET spent = s.spent + excluded.spent, reserved = greatest(s.reserved + excluded.reserved, 0)",
                &[
                    (&scope, Type::TEXT_ARRAY),
                    (&per, Type::TEXT_ARRAY),
                    (&period, Type::TEXT_ARRAY),
                    (&spent, Type::FLOAT8_ARRAY),
                    (&reserved, Type::FLOAT8_ARRAY),
                ],
            )
            .await
            .map(|_| ())
            .map_err(|err| err.to_string())
    }
}

fn version_of(row: &tokio_postgres::Row) -> Result<PolicyVersion, String> {
    let f = |err: tokio_postgres::Error| err.to_string();
    Ok(PolicyVersion {
        id: row.try_get(0).map_err(f)?,
        text: row.try_get(1).map_err(f)?,
        sha256: row.try_get(2).map_err(f)?,
        base: row.try_get(3).map_err(f)?,
        note: row.try_get(4).map_err(f)?,
        created_by: row.try_get(5).map_err(f)?,
        created_at: row.try_get(6).map_err(f)?,
        state: row.try_get(7).map_err(f)?,
        decided_by: row.try_get(8).map_err(f)?,
        decided_at: row.try_get(9).map_err(f)?,
    })
}

fn sql(err: tokio_postgres::Error) -> VersionError {
    VersionError::Store(format!(
        "the store refused the policy change: {err}. Nothing was changed. Try again; if it repeats, check the database."
    ))
}

/// The live version's id inside a policy change.
async fn live_id(tx: &tokio_postgres::Transaction<'_>) -> Result<Option<i64>, VersionError> {
    let row = tx
        .query_opt(
            "SELECT id FROM enterplace_policy_versions WHERE state = 'live'",
            &[],
        )
        .await
        .map_err(sql)?;
    row.map(|r| r.try_get(0)).transpose().map_err(sql)
}

fn credential_of(row: &tokio_postgres::Row) -> Result<Credential, String> {
    let field = |err: tokio_postgres::Error| err.to_string();
    Ok(Credential {
        name: row.try_get(0).map_err(field)?,
        provider: row.try_get(1).map_err(field)?,
        fingerprint: row.try_get(2).map_err(field)?,
        created_by: row.try_get(3).map_err(field)?,
        created_at: row.try_get(4).map_err(field)?,
        rotated_by: row.try_get(5).map_err(field)?,
        rotated_at: row.try_get(6).map_err(field)?,
        generation: row.try_get(7).map_err(field)?,
    })
}

fn kill_of(row: &tokio_postgres::Row) -> Result<Kill, String> {
    let field = |err: tokio_postgres::Error| err.to_string();
    Ok(Kill {
        scope: row.try_get(0).map_err(field)?,
        value: row.try_get(1).map_err(field)?,
        reason: row.try_get(2).map_err(field)?,
        by: row.try_get(3).map_err(field)?,
        at: row.try_get(4).map_err(field)?,
    })
}

/// Applies `migrations` in order under `namespace`, one Enterplace at a time, and refuses a database a newer binary has
/// written. The version of each namespace is its row in `enterplace_migrations`, apart from the gateway's own tables.
async fn migrate_namespace(
    client: &mut Client,
    namespace: &str,
    migrations: &[&str],
) -> Result<(), String> {
    let failed = |err: tokio_postgres::Error| {
        format!(
            "the {namespace} tables could not be created or updated: {err}. The connection string's user needs CREATE on the database. Fix that and start again."
        )
    };
    let check_only = no_migrate();
    let tx = client.transaction().await.map_err(failed)?;
    let there = !check_only || exists(&tx, "enterplace_migrations").await.map_err(failed)?;
    if !check_only {
        tx.batch_execute(
            "SELECT pg_advisory_xact_lock(7349127341); CREATE TABLE IF NOT EXISTS enterplace_migrations (namespace text PRIMARY KEY, version integer NOT NULL);",
        )
        .await
        .map_err(failed)?;
    }
    let row = if there {
        tx.query_opt(
            "SELECT version FROM enterplace_migrations WHERE namespace = $1",
            &[&namespace],
        )
        .await
        .map_err(failed)?
    } else {
        None
    };
    let applied: i32 = row
        .map(|r| r.try_get(0))
        .transpose()
        .map_err(failed)?
        .unwrap_or(0);
    let known = i32::try_from(migrations.len()).unwrap_or(i32::MAX);
    if applied > known {
        let by = writer(&tx).await.map_err(failed)?;
        if !by
            .as_deref()
            .is_some_and(|by| newer_allowed(enterplace_core::VERSION, by))
        {
            return Err(format!(
                "the {namespace} tables were written by a newer version ({}, schema version {applied}; this one is {} and knows up to {known}). Versions share one database only one minor version apart. Run the same version as the other gateways on this database (or upgrade this one), or point it at another database.",
                by.as_deref().unwrap_or("version unknown"),
                enterplace_core::VERSION
            ));
        }
    }
    if check_only {
        return stale(namespace, applied, known);
    }
    for (number, sql) in migrations
        .iter()
        .enumerate()
        .skip(usize::try_from(applied).unwrap_or(0))
    {
        tx.batch_execute(sql).await.map_err(failed)?;
        let version = i32::try_from(number + 1).unwrap_or(i32::MAX);
        tx.execute(
            "INSERT INTO enterplace_migrations VALUES ($1, $2) ON CONFLICT (namespace) DO UPDATE SET version = excluded.version",
            &[&namespace, &version],
        )
        .await
        .map_err(failed)?;
    }
    tx.commit().await.map_err(failed)
}

/// For a binary that embeds the gateway and keeps tables of its own in the store's database.
impl PgStore {
    /// Stops the store's thread, which closes its connection and every [`connect`](Self::connect) one. Calls after
    /// it are refused as a store that stopped. A gateway that is done with its store before the process ends calls
    /// it: the tasks that hold the store keep it, and its connections, open otherwise.
    pub fn close(&self) {
        let runtime = self
            .runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        // Dropping a runtime waits for its tasks, which is refused inside another runtime (a test, the server).
        if let Some(runtime) = runtime {
            runtime.shutdown_background();
        }
    }

    /// Every migration list of the open source store, by namespace (`core` is the gateway's own schema). The
    /// release check compares their fingerprints with the previous tag's (`release/migrations.txt`).
    #[doc(hidden)]
    pub fn migration_lists() -> Vec<(&'static str, &'static [&'static str])> {
        vec![
            ("core", MIGRATIONS),
            ("enterplace_policy", POLICY_MIGRATIONS),
            ("enterplace_routing", ROUTING_MIGRATIONS),
            ("enterplace_ha", HA_MIGRATIONS),
            (crate::batch::NAMESPACE, crate::batch::MIGRATIONS),
            (crate::insights::NAMESPACE, crate::insights::MIGRATIONS),
            ("mcp", crate::mcp::keep::MIGRATIONS),
        ]
    }

    /// The fingerprint file of `lists`: a line per namespace with how many migrations it has and a hash of them.
    #[doc(hidden)]
    pub fn migration_manifest(lists: &[(&str, &[&str])]) -> String {
        let mut out = String::from(
            "# Store migrations by namespace: entries, SHA-256 of them. Written by a test (see RELEASING.md), read by\n# scripts/version.py: a change since the previous tag needs a minor version bump.\n",
        );
        for (namespace, migrations) in lists {
            let hash = enterplace_core::id::sha256_hex(migrations.join("\0").as_bytes());
            out += &format!("{namespace} {} {hash}\n", migrations.len());
        }
        out
    }

    /// Checks the fingerprint file at `path` against `lists`, or writes it when ENTERPLACE_WRITE_MIGRATIONS is set.
    /// `Err` says how to bring it up to date. For the manifest test of each crate that keeps migrations.
    #[doc(hidden)]
    pub fn check_migration_manifest(
        path: &std::path::Path,
        lists: &[(&str, &[&str])],
        test: &str,
    ) -> Result<(), String> {
        let now = Self::migration_manifest(lists);
        if std::env::var_os("ENTERPLACE_WRITE_MIGRATIONS").is_some() {
            return std::fs::write(path, now).map_err(|err| format!("{}: {err}", path.display()));
        }
        if std::fs::read_to_string(path).is_ok_and(|kept| kept == now) {
            return Ok(());
        }
        Err(format!(
            "{} does not match the store migrations in the code. If a migration was added, write it again with ENTERPLACE_WRITE_MIGRATIONS=1 {test}, commit it, and bump the minor version once a release tag exists (scripts/version.py checks). If a shipped migration was edited, undo that: add a new entry instead.",
            path.display()
        ))
    }
    /// A new connection to the store's database, with the store's TLS settings. Its own, so it may hold a
    /// transaction: the store's shared connection never does. Its I/O runs on the store's thread.
    pub async fn connect(&self) -> Result<Client, String> {
        let inner = self.inner.clone();
        let env = self.inner.env.clone();
        self.handle
            .spawn(async move { inner.connect().await })
            .await
            .map_err(|_| "the store stopped before it answered".to_string())?
            .map_err(|err| unreachable(&env, &err))
    }

    /// Creates or updates tables of `namespace` (for example `enterprise`): entry N of `migrations` runs once, in
    /// order, on the first start that knows it. Never edit an entry that has shipped: add one. Blocks until done.
    pub fn migrate(
        &self,
        namespace: &str,
        migrations: &'static [&'static str],
    ) -> Result<(), String> {
        let inner = self.inner.clone();
        let namespace = namespace.to_string();
        self.wait(async move {
            let mut client = inner
                .connect()
                .await
                .map_err(|err| unreachable(&inner.env, &err))?;
            migrate_namespace(&mut client, &namespace, migrations).await
        })
    }
}

impl PgStore {
    /// Turns provider credentials on with the customer's master key. The first gateway seals a check value with it;
    /// every later one must open that value, so a wrong key is refused here, at start, with the fix.
    pub fn unlock(&self, master: MasterKey) -> Result<(), String> {
        let check = master.seal(MASTER_CHECK.0, MASTER_CHECK.1)?;
        let inner = self.inner.clone();
        let stored = self
            .wait(async move {
                let client = inner.ensure().await?;
                client
                    .execute(
                        "INSERT INTO enterplace_master (id, sealed) VALUES (1, $1) ON CONFLICT (id) DO NOTHING",
                        &[&check],
                    )
                    .await
                    .map_err(|err| err.to_string())?;
                let row = client
                    .query_one("SELECT sealed FROM enterplace_master WHERE id = 1", &[])
                    .await
                    .map_err(|err| err.to_string())?;
                row.try_get::<_, Vec<u8>>(0).map_err(|err| err.to_string())
            })
            .map_err(|err| {
                format!(
                    "the master key could not be checked against the store: {err}. Check that Postgres is up and {} is right, then start again.",
                    self.inner.env
                )
            })?;
        if master.open(MASTER_CHECK.0, &stored).ok().as_deref() != Some(MASTER_CHECK.1) {
            return Err(format!(
                "{} is not the key the provider credentials in this store were sealed with: it does not open the store's check value. Set the master key the other gateways on this database use, and start again. A master key that is lost cannot be recovered: then remove the credentials (DELETE FROM enterplace_credentials; DELETE FROM enterplace_master;) and add them again under a new one.",
                crate::credentials::MASTER_ENV
            ));
        }
        let _ = self.inner.master.set(master);
        Ok(())
    }

    pub(crate) fn master(&self) -> Result<&MasterKey, String> {
        self.inner.master.get().ok_or_else(|| NO_MASTER.to_string())
    }

    /// One credential statement: `sql` with `params`, returning the credential it touched, if any. The version
    /// of credentials goes up with it, so every gateway reads the change at its next poll.
    fn credential_change(
        &self,
        sql: String,
        params: Vec<Box<dyn tokio_postgres::types::ToSql + Send + Sync>>,
    ) -> Result<Option<Credential>, String> {
        self.change("credential", move |client| {
            Box::pin(async move {
                let refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = params
                    .iter()
                    .map(|p| p.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync))
                    .collect();
                let rows = client
                    .query(
                        &format!(
                            "WITH touched AS ({sql} RETURNING {SHOWN}), \
                             bumped AS (UPDATE enterplace_versions SET version = version + 1 \
                               WHERE name = 'credentials' AND EXISTS (SELECT 1 FROM touched)) \
                             SELECT * FROM touched"
                        ),
                        &refs,
                    )
                    .await
                    .map_err(|err| err.to_string())?;
                rows.first().map(credential_of).transpose()
            })
        })
    }
}

impl PgStore {
    /// Runs `work` on the store's runtime and blocks until it ends. For callers that block anyway: the command
    /// line, and the admin API and console, which change keys on a blocking thread.
    fn wait<T: Send + 'static>(
        &self,
        work: impl Future<Output = Result<T, String>> + Send + 'static,
    ) -> Result<T, String> {
        let (tell, told) = std::sync::mpsc::sync_channel(1);
        self.handle.spawn(async move {
            let done = tokio::time::timeout(WAIT, work)
                .await
                .unwrap_or_else(|_| Err(format!("no answer within {} seconds", WAIT.as_secs())));
            let _ = tell.send(done);
        });
        told.recv()
            .map_err(|_| "the store stopped before it answered".to_string())?
    }

    /// [`wait`](Self::wait) for a policy change, whose refusals keep their kind.
    fn wait_version<T: Send + 'static>(
        &self,
        work: impl Future<Output = Result<T, VersionError>> + Send + 'static,
    ) -> Result<T, VersionError> {
        let (tell, told) = std::sync::mpsc::sync_channel(1);
        self.handle.spawn(async move {
            let done = tokio::time::timeout(WAIT, work).await.unwrap_or_else(|_| {
                Err(VersionError::Store(format!(
                    "the store gave no answer within {} seconds. Nothing may have been changed: reload the versions page and check.",
                    WAIT.as_secs()
                )))
            });
            let _ = tell.send(done);
        });
        told.recv().map_err(|_| {
            VersionError::Store("the store stopped before it answered. Try again.".into())
        })?
    }

    /// Runs `work` on the store's runtime, given up after [`WAIT`], for a caller on the request path to await.
    fn ask<T: Send + 'static>(
        &self,
        work: impl Future<Output = Result<T, String>> + Send + 'static,
    ) -> Pending<T> {
        let task = self.handle.spawn(async move {
            tokio::time::timeout(WAIT, work)
                .await
                .unwrap_or_else(|_| Err(format!("no answer within {} seconds", WAIT.as_secs())))
        });
        Box::pin(async move {
            task.await
                .map_err(|_| "the store stopped before it answered".to_string())?
        })
    }

    /// Runs `work` on the store's runtime without waiting for it, tried again each second while the database is
    /// away, for up to [`SETTLE_FOR`].
    fn retried<F>(&self, what: &'static str, work: impl Fn(Arc<Inner>) -> F + Send + 'static)
    where
        F: Future<Output = Result<(), String>> + Send,
    {
        let inner = self.inner.clone();
        self.handle.spawn(async move {
            let started = tokio::time::Instant::now();
            loop {
                // ponytail: an answer lost after the statement committed makes the retry apply it twice. Rare (the
                // connection must drop in that instant); an idempotency key per request fixes it if it shows.
                let err = match tokio::time::timeout(WAIT, work(inner.clone())).await {
                    Ok(Ok(())) => return,
                    Ok(Err(err)) => err,
                    Err(_) => format!("no answer within {} seconds", WAIT.as_secs()),
                };
                if started.elapsed() >= SETTLE_FOR {
                    eprintln!(
                        "enterplace: {what} could not be written to the store for {} minutes ({err}). It is dropped.",
                        SETTLE_FOR.as_secs() / 60
                    );
                    return;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }

    /// A change: one statement, then the keys and switches read again, so this gateway applies it at once.
    fn change<T: Send + 'static>(
        &self,
        what: &'static str,
        statement: impl FnOnce(Arc<Client>) -> Pin<Box<dyn Future<Output = Result<T, String>> + Send>>
        + Send
        + 'static,
    ) -> Result<T, String> {
        let inner = self.inner.clone();
        let env = self.inner.env.clone();
        self.wait(async move {
            let client = inner.ensure().await?;
            let done = statement(client).await?;
            // The change is made. If reading it back fails, the poll picks it up within half a second.
            let _ = inner.refresh().await;
            Ok(done)
        })
        .map_err(|err| {
            format!(
                "the {what} could not be written to the store: {err}. Nothing was changed. Check that Postgres is up and {env} is right, then try again."
            )
        })
    }
}

impl PgStore {
    /// Keeps cached answers in the database (`store.answer_cache`), so every gateway on it serves them.
    pub fn share_cache(&self, yes: bool) {
        self.inner.shares_cache.store(yes, Ordering::Relaxed);
    }
}

fn key32(bytes: Vec<u8>) -> Option<[u8; 32]> {
    bytes.try_into().ok()
}

impl core_store::Credentials for PgStore {
    fn credentials(&self) -> Result<Arc<Vec<Credential>>, String> {
        self.master()?;
        Ok(Arc::new(
            read(&self.inner.credentials)
                .iter()
                .map(|(c, _)| c.clone())
                .collect(),
        ))
    }

    fn add_credential(
        &self,
        name: &str,
        provider: &str,
        value: &str,
        by: &str,
    ) -> Result<Option<Credential>, String> {
        let sealed = self.master()?.seal(name, value.trim().as_bytes())?;
        self.credential_change(
            "INSERT INTO enterplace_credentials (name, provider, sealed, fingerprint, created_by, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (name) DO NOTHING"
                .into(),
            vec![
                Box::new(name.to_string()),
                Box::new(provider.to_string()),
                Box::new(sealed),
                Box::new(enterplace_core::store::fingerprint(value.trim())),
                Box::new(by.to_string()),
                Box::new(enterplace_core::audit::timestamp()),
            ],
        )
    }

    fn rotate_credential(
        &self,
        name: &str,
        value: &str,
        by: &str,
    ) -> Result<Option<Credential>, String> {
        let sealed = self.master()?.seal(name, value.trim().as_bytes())?;
        self.credential_change(
            "UPDATE enterplace_credentials SET sealed = $2, fingerprint = $3, rotated_by = $4, rotated_at = $5, \
             generation = generation + 1 WHERE name = $1"
                .into(),
            vec![
                Box::new(name.to_string()),
                Box::new(sealed),
                Box::new(enterplace_core::store::fingerprint(value.trim())),
                Box::new(by.to_string()),
                Box::new(enterplace_core::audit::timestamp()),
            ],
        )
    }

    fn remove_credential(&self, name: &str) -> Result<Option<Credential>, String> {
        self.master()?;
        self.credential_change(
            "DELETE FROM enterplace_credentials WHERE name = $1".into(),
            vec![Box::new(name.to_string())],
        )
    }

    fn credential_value(&self, name: &str) -> Result<Option<String>, String> {
        let master = self.master()?;
        let all = read(&self.inner.credentials);
        let Some((_, sealed)) = all.iter().find(|(c, _)| c.name == name) else {
            return Ok(None);
        };
        let value = master.open(name, sealed)?;
        String::from_utf8(value).map(Some).map_err(|_| {
            format!("credential \"{name}\" is not text. Rotate it with the key's value.")
        })
    }
}

impl Store for PgStore {
    fn raises(&self) -> Option<Arc<Vec<Raise>>> {
        Some(read(&self.inner.raises))
    }

    fn put_raise(&self, raise: &Raise) -> Result<(), String> {
        let (id, body) = (
            raise.id.clone(),
            serde_json::to_string(raise).map_err(|err| err.to_string())?,
        );
        self.change("budget raise", move |client| {
            Box::pin(async move {
                client
                    .execute(
                        "WITH put AS (INSERT INTO enterplace_raises VALUES ($1, $2) \
                           ON CONFLICT (id) DO UPDATE SET body = excluded.body RETURNING 1) \
                         UPDATE enterplace_versions SET version = version + 1 \
                           WHERE name = 'raises' AND EXISTS (SELECT 1 FROM put)",
                        &[&id, &body],
                    )
                    .await
                    .map(|_| ())
                    .map_err(|err| err.to_string())
            })
        })
    }

    fn replicas(&self) -> Pending<Vec<Replica>> {
        let inner = self.inner.clone();
        self.ask(async move {
            const TIME: &str = "'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'";
            let rows = inner
                .client()?
                .query(
                    &format!(
                        "SELECT gateway, host, version, schema, to_char(started AT TIME ZONE 'UTC', {TIME}), \
                         to_char(seen AT TIME ZONE 'UTC', {TIME}), \
                         seen > clock_timestamp() - $1 * interval '1 second', policy_version, refused_version, refused \
                         FROM enterplace_replicas ORDER BY started DESC, gateway"
                    ),
                    &[&HEALTHY_FOR_SECS],
                )
                .await
                .map_err(|err| err.to_string())?;
            rows.iter()
                .map(|row| {
                    let field = |err: tokio_postgres::Error| err.to_string();
                    Ok(Replica {
                        gateway: row.try_get(0).map_err(field)?,
                        host: row.try_get(1).map_err(field)?,
                        version: row.try_get(2).map_err(field)?,
                        schema: row.try_get(3).map_err(field)?,
                        started: row.try_get(4).map_err(field)?,
                        seen: row.try_get(5).map_err(field)?,
                        healthy: row.try_get(6).map_err(field)?,
                        policy_version: row.try_get(7).map_err(field)?,
                        refused_version: row.try_get(8).map_err(field)?,
                        refused: row.try_get(9).map_err(field)?,
                    })
                })
                .collect()
        })
    }

    fn report_policy(&self, state: &InForce) {
        *self
            .inner
            .in_force
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = state.clone();
    }

    fn shares_cache(&self) -> bool {
        self.inner.shares_cache.load(Ordering::Relaxed)
    }

    fn cache_get(&self, key: [u8; 32], scope: String) -> Pending<Option<CachedAnswer>> {
        let inner = self.inner.clone();
        self.ask(async move {
            // The scope is checked beside the key that already holds it, as the cache in memory does. Kept as its
            // hash: a scope holds a zero byte between the rule and the person, which Postgres text cannot.
            let hashed = id::sha256_hex(scope.as_bytes());
            let row = inner
                .client()?
                .query_opt(
                    "UPDATE enterplace_answer_cache SET used = clock_timestamp() \
                     WHERE key = $1 AND scope = $2 AND expires > clock_timestamp() \
                     RETURNING status, content_type, body, origin, cost, \
                       extract(epoch FROM expires - clock_timestamp())::float8",
                    &[&&key[..], &hashed],
                )
                .await
                .map_err(|err| err.to_string())?;
            let Some(row) = row else {
                return Ok(None);
            };
            let field = |err: tokio_postgres::Error| err.to_string();
            let status: i32 = row.try_get(0).map_err(field)?;
            let left: f64 = row.try_get(5).map_err(field)?;
            Ok(Some(CachedAnswer {
                key,
                scope,
                status: u16::try_from(status).unwrap_or(200),
                content_type: row.try_get(1).map_err(field)?,
                body: row.try_get(2).map_err(field)?,
                origin: row.try_get(3).map_err(field)?,
                cost: row.try_get(4).map_err(field)?,
                ttl: Duration::try_from_secs_f64(left).unwrap_or_default(),
                vector: None,
            }))
        })
    }

    fn cache_put(&self, answer: CachedAnswer) {
        let inner = self.inner.clone();
        // Not retried: an answer that is not kept is asked of the provider again, which is what no cache does.
        self.handle.spawn(async move {
            let Ok(client) = inner.client() else {
                return;
            };
            let (status, ttl) = (i32::from(answer.status), answer.ttl.as_secs_f64());
            let key = &answer.key[..];
            let scope = id::sha256_hex(answer.scope.as_bytes());
            let params: [&(dyn tokio_postgres::types::ToSql + Sync); 8] = [
                &key,
                &scope,
                &status,
                &answer.content_type,
                &answer.body,
                &answer.origin,
                &answer.cost,
                &ttl,
            ];
            let put = client.execute(
                "INSERT INTO enterplace_answer_cache VALUES ($1, $2, $3, $4, $5, $6, $7, \
                   clock_timestamp() + $8 * interval '1 second', clock_timestamp()) \
                 ON CONFLICT (key) DO UPDATE SET scope = excluded.scope, status = excluded.status, \
                   content_type = excluded.content_type, body = excluded.body, origin = excluded.origin, \
                   cost = excluded.cost, expires = excluded.expires, used = excluded.used",
                &params,
            );
            if !matches!(tokio::time::timeout(WAIT, put).await, Ok(Ok(_))) {
                return;
            }
            if let Some((partition, vector)) = &answer.vector {
                let _ = tokio::time::timeout(
                    WAIT,
                    client.execute(
                        "INSERT INTO enterplace_answer_vectors VALUES ($1, $2, $3, clock_timestamp()) \
                         ON CONFLICT (key) DO UPDATE SET partition = excluded.partition, \
                           vector = excluded.vector, created = excluded.created",
                        &[&&answer.key[..], &&partition[..], vector],
                    ),
                )
                .await;
            }
        });
    }

    fn cache_vectors(&self, partition: [u8; 32]) -> Pending<Vec<([u8; 32], Vec<f32>)>> {
        let inner = self.inner.clone();
        self.ask(async move {
            let rows = inner
                .client()?
                .query(
                    "SELECT v.key, v.vector FROM enterplace_answer_vectors v JOIN enterplace_answer_cache c USING (key) \
                     WHERE v.partition = $1 AND c.expires > clock_timestamp() ORDER BY v.created DESC LIMIT $2",
                    &[&&partition[..], &core_store::MAX_SHARED_VECTORS],
                )
                .await
                .map_err(|err| err.to_string())?;
            Ok(rows
                .iter()
                .filter_map(|row| Some((key32(row.try_get(0).ok()?)?, row.try_get(1).ok()?)))
                .collect())
        })
    }

    fn keeps_settings(&self) -> bool {
        true
    }

    fn setting(&self, name: &str) -> Result<Option<String>, String> {
        let (inner, name) = (self.inner.clone(), name.to_string());
        self.wait(async move {
            let client = inner.ensure().await?;
            let row = client
                .query_opt(
                    "SELECT value FROM enterplace_settings WHERE name = $1",
                    &[&name],
                )
                .await
                .map_err(|err| err.to_string())?;
            Ok(row.and_then(|r| r.try_get::<_, String>(0).ok()))
        })
    }

    fn set_setting(&self, name: &str, value: &str) -> Result<(), String> {
        let (inner, name, value) = (self.inner.clone(), name.to_string(), value.to_string());
        self.wait(async move {
            let client = inner.ensure().await?;
            client
                .execute(
                    "INSERT INTO enterplace_settings (name, value) VALUES ($1, $2) \
                     ON CONFLICT (name) DO UPDATE SET value = excluded.value, updated_at = now()",
                    &[&name, &value],
                )
                .await
                .map_err(|err| err.to_string())?;
            Ok(())
        })
    }

    fn keys_text(&self) -> String {
        read(&self.inner.keys)
    }

    fn kills(&self) -> Arc<Vec<Kill>> {
        read(&self.inner.kills)
    }

    fn add_key(&self, entry: &KeyEntry) -> Result<bool, String> {
        let entry = entry.clone();
        self.change("key", move |client| {
            Box::pin(async move {
                let per = entry.budget.map(|b| b.per.word());
                let tpm = entry.tpm.map(|t| i32::try_from(t).unwrap_or(i32::MAX));
                let parallel = entry.parallel.map(|t| i32::try_from(t).unwrap_or(i32::MAX));
                let org = (!entry.org.is_empty()).then_some(&entry.org);
                // The name is looked up in the snapshot before the insert: whether it already had a key.
                let row = client
                    .query_one(
                        "WITH added AS (\
                           INSERT INTO enterplace_keys (sha256, name, team, admin, expires, budget_usd, budget_per, models, tpm, org, customer, tags, parallel, role, options) \
                           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) ON CONFLICT (sha256) DO NOTHING RETURNING 1), \
                         bumped AS (UPDATE enterplace_versions SET version = version + 1 \
                           WHERE name = 'keys' AND EXISTS (SELECT 1 FROM added)) \
                         SELECT EXISTS (SELECT 1 FROM added), EXISTS (SELECT 1 FROM enterplace_keys WHERE name = $2)",
                        &[
                            &entry.sha256,
                            &entry.name,
                            &entry.team,
                            &entry.admin,
                            &entry.expires,
                            &entry.budget.map(|b| b.usd),
                            &per,
                            &entry.models,
                            &tpm,
                            &org,
                            &entry.customer,
                            &entry.tags,
                            &parallel,
                            &entry.role,
                            &keyfile::options_json(&entry.options),
                        ],
                    )
                    .await
                    .map_err(|err| err.to_string())?;
                let added: bool = row.try_get(0).map_err(|err| err.to_string())?;
                if !added {
                    return Err("a key with this hash is already in the store".into());
                }
                row.try_get(1).map_err(|err| err.to_string())
            })
        })
    }

    fn update_key(&self, entry: &KeyEntry) -> Result<bool, String> {
        let entry = entry.clone();
        self.change("key", move |client| {
            Box::pin(async move {
                let per = entry.budget.map(|b| b.per.word());
                let tpm = entry.tpm.map(|t| i32::try_from(t).unwrap_or(i32::MAX));
                let parallel = entry.parallel.map(|t| i32::try_from(t).unwrap_or(i32::MAX));
                let row = client
                    .query_one(
                        "WITH changed AS (UPDATE enterplace_keys SET admin = $2, expires = $3, budget_usd = $4, \
                           budget_per = $5, models = $6, tpm = $7, options = $8, customer = $9, tags = $10, \
                           parallel = $11, role = $12 WHERE sha256 = $1 RETURNING 1), \
                         bumped AS (UPDATE enterplace_versions SET version = version + 1 \
                           WHERE name = 'keys' AND EXISTS (SELECT 1 FROM changed)) \
                         SELECT EXISTS (SELECT 1 FROM changed)",
                        &[
                            &entry.sha256,
                            &entry.admin,
                            &entry.expires,
                            &entry.budget.map(|b| b.usd),
                            &per,
                            &entry.models,
                            &tpm,
                            &keyfile::options_json(&entry.options),
                            &entry.customer,
                            &entry.tags,
                            &parallel,
                            &entry.role,
                        ],
                    )
                    .await
                    .map_err(|err| err.to_string())?;
                row.try_get(0).map_err(|err| err.to_string())
            })
        })
    }

    fn reachable(&self) -> Result<(), String> {
        if self.inner.down.load(Ordering::Relaxed) {
            return Err(format!(
                "the store cannot be reached: check Postgres and {}",
                self.inner.env
            ));
        }
        self.inner.client().map(|_| ())
    }

    fn spend(&self, scope: String) -> Pending<Vec<(String, String, f64, f64)>> {
        let inner = self.inner.clone();
        self.ask(async move {
            let rows = inner
                .client()?
                .query(
                    "SELECT per, period, spent, reserved FROM enterplace_spend WHERE scope = $1 \
                     AND period IN (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD'), to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM'))",
                    &[&scope],
                )
                .await
                .map_err(|err| err.to_string())?;
            rows.iter()
                .map(|row| {
                    let field = |err: tokio_postgres::Error| err.to_string();
                    Ok((
                        row.try_get(0).map_err(field)?,
                        row.try_get(1).map_err(field)?,
                        row.try_get(2).map_err(field)?,
                        row.try_get(3).map_err(field)?,
                    ))
                })
                .collect()
        })
    }

    fn revoke(&self, prefix: &str) -> Result<Option<Revoked>, String> {
        let prefix = prefix.to_string();
        let ambiguous = format!(
            "more than one key hash starts with {prefix}. Give more of the hash. Nothing was changed."
        );
        let found = self.change("revocation", move |client| {
            Box::pin(async move {
                let row = client
                    .query_one(
                        "WITH matching AS (SELECT sha256 FROM enterplace_keys WHERE left(sha256, length($1)) = $1), \
                         gone AS (DELETE FROM enterplace_keys WHERE sha256 IN (SELECT sha256 FROM matching) \
                           AND (SELECT count(*) FROM matching) = 1 RETURNING name, team, sha256), \
                         bumped AS (UPDATE enterplace_versions SET version = version + 1 \
                           WHERE name = 'keys' AND EXISTS (SELECT 1 FROM gone)) \
                         SELECT (SELECT count(*) FROM matching), (SELECT name FROM gone), (SELECT team FROM gone), \
                           (SELECT sha256 FROM gone)",
                        &[&prefix],
                    )
                    .await
                    .map_err(|err| err.to_string())?;
                let field = |err: tokio_postgres::Error| err.to_string();
                let matching: i64 = row.try_get(0).map_err(field)?;
                let name: Option<String> = row.try_get(1).map_err(field)?;
                let team: Option<String> = row.try_get(2).map_err(field)?;
                let sha256: Option<String> = row.try_get(3).map_err(field)?;
                Ok((matching, name.zip(team).zip(sha256)))
            })
        })?;
        match found {
            (n, _) if n > 1 => Err(ambiguous),
            (_, Some(((name, team), sha256))) => Ok(Some(Revoked { name, team, sha256 })),
            _ => Ok(None),
        }
    }

    fn set_kill(&self, kill: &Kill) -> Result<Option<Kill>, String> {
        let kill = kill.clone();
        self.change("kill switch", move |client| {
            Box::pin(async move {
                let rows = client
                    .query(
                        "WITH old AS (SELECT scope, value, reason, set_by, set_at FROM enterplace_kills \
                           WHERE scope = $1 AND value = $2), \
                         up AS (INSERT INTO enterplace_kills VALUES ($1, $2, $3, $4, $5) ON CONFLICT (scope, value) \
                           DO UPDATE SET reason = excluded.reason, set_by = excluded.set_by, set_at = excluded.set_at), \
                         bumped AS (UPDATE enterplace_versions SET version = version + 1 WHERE name = 'kills') \
                         SELECT * FROM old",
                        &[&kill.scope, &kill.value, &kill.reason, &kill.by, &kill.at],
                    )
                    .await
                    .map_err(|err| err.to_string())?;
                rows.first().map(kill_of).transpose()
            })
        })
    }

    fn clear_kill(&self, scope: &str, value: &str) -> Result<Option<Kill>, String> {
        let (scope, value) = (scope.to_string(), value.to_string());
        self.change("kill switch", move |client| {
            Box::pin(async move {
                let rows = client
                    .query(
                        "WITH gone AS (DELETE FROM enterplace_kills WHERE scope = $1 AND value = $2 \
                           RETURNING scope, value, reason, set_by, set_at), \
                         bumped AS (UPDATE enterplace_versions SET version = version + 1 \
                           WHERE name = 'kills' AND EXISTS (SELECT 1 FROM gone)) \
                         SELECT * FROM gone",
                        &[&scope, &value],
                    )
                    .await
                    .map_err(|err| err.to_string())?;
                rows.first().map(kill_of).transpose()
            })
        })
    }

    fn reserve(&self, bucket: Bucket, usd: f64, limit: f64) -> Pending<Reserve> {
        let inner = self.inner.clone();
        self.ask(async move { inner.reserve(&bucket, usd, limit).await })
    }

    fn refresh_policy(&self) -> Result<(), String> {
        let inner = self.inner.clone();
        self.wait(async move { inner.refresh().await })
    }

    fn poll_now(&self) -> Result<(), String> {
        let inner = self.inner.clone();
        self.wait(async move {
            inner.round().await;
            if inner.down.load(Ordering::Relaxed) {
                return Err(format!(
                    "the store cannot be reached. Check Postgres and {}.",
                    inner.env
                ));
            }
            Ok(())
        })
    }

    fn policy_versions(&self) -> Result<Arc<Vec<PolicyVersion>>, String> {
        Ok(read(&self.inner.policies))
    }

    fn add_policy_version(&self, new: &NewVersion) -> Result<PolicyVersion, VersionError> {
        let (inner, new) = (self.inner.clone(), new.clone());
        self.wait_version(async move {
            inner
                .policy_change(move |tx| {
                    Box::pin(async move {
                        let live = live_id(tx).await?;
                        if live != new.base {
                            let word = |v: Option<i64>| {
                                v.map_or_else(|| "none".to_string(), |v| format!("version {v}"))
                            };
                            return Err(VersionError::Conflict(format!(
                                "the draft started from {} and {} is live now: someone saved a change meanwhile. Open the live version, make the change again on it, and save.",
                                word(new.base),
                                word(live)
                            )));
                        }
                        if !new.pending {
                            tx.execute(
                                "UPDATE enterplace_policy_versions SET state = 'retired' WHERE state = 'live'",
                                &[],
                            )
                            .await
                            .map_err(sql)?;
                        }
                        let state = if new.pending { core_store::PENDING } else { core_store::LIVE };
                        let row = tx
                            .query_one(
                                &format!(
                                    "INSERT INTO enterplace_policy_versions (text, sha256, base, note, created_by, created_at, state) \
                                     VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING {VERSION_COLUMNS}"
                                ),
                                &[
                                    &new.text,
                                    &id::sha256_hex(new.text.as_bytes()),
                                    &new.base,
                                    &new.note,
                                    &new.by,
                                    &enterplace_core::audit::timestamp(),
                                    &state,
                                ],
                            )
                            .await
                            .map_err(sql)?;
                        version_of(&row).map_err(VersionError::Store)
                    })
                })
                .await
        })
    }

    fn decide_policy_version(
        &self,
        version: i64,
        approve: bool,
        by: &str,
    ) -> Result<PolicyVersion, VersionError> {
        let (inner, by) = (self.inner.clone(), by.to_string());
        self.wait_version(async move {
            inner
                .policy_change(move |tx| {
                    Box::pin(async move {
                        let row = tx
                            .query_opt(
                                "SELECT state, base FROM enterplace_policy_versions WHERE id = $1",
                                &[&version],
                            )
                            .await
                            .map_err(sql)?
                            .ok_or_else(|| {
                                VersionError::Conflict(format!("there is no policy version {version}."))
                            })?;
                        let (state, base): (String, Option<i64>) =
                            (row.try_get(0).map_err(sql)?, row.try_get(1).map_err(sql)?);
                        if state != core_store::PENDING {
                            return Err(VersionError::Conflict(format!(
                                "version {version} is {state} now, not waiting for approval: someone decided it meanwhile."
                            )));
                        }
                        if approve {
                            if live_id(tx).await? != base {
                                return Err(VersionError::Conflict(format!(
                                    "version {version} was drafted on a version that is no longer live. Reject it and draft the change again on the live version."
                                )));
                            }
                            tx.execute(
                                "UPDATE enterplace_policy_versions SET state = 'retired' WHERE state = 'live'",
                                &[],
                            )
                            .await
                            .map_err(sql)?;
                        }
                        let state = if approve { core_store::LIVE } else { core_store::REJECTED };
                        let row = tx
                            .query_one(
                                &format!(
                                    "UPDATE enterplace_policy_versions SET state = $2, decided_by = $3, decided_at = $4 \
                                     WHERE id = $1 RETURNING {VERSION_COLUMNS}"
                                ),
                                &[&version, &state, &by, &enterplace_core::audit::timestamp()],
                            )
                            .await
                            .map_err(sql)?;
                        version_of(&row).map_err(VersionError::Store)
                    })
                })
                .await
        })
    }

    fn settle(&self, changes: Vec<Change>) {
        if changes.is_empty() {
            return;
        }
        let changes = Arc::new(changes);
        // A hold never given back keeps counting against its budget until the period ends.
        self.retried("spend", move |inner| {
            let changes = changes.clone();
            async move { inner.settle(&changes).await }
        });
    }

    fn lease(&self, scope: String, need: u64, want: u64, limit: u64) -> Pending<Lease> {
        let inner = self.inner.clone();
        self.ask(async move { inner.lease(&scope, need, want, limit).await })
    }

    fn give_back(&self, grant: i64, n: i64) {
        *self
            .inner
            .returns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(grant)
            .or_default() += n;
    }

    fn cooling(&self) -> Arc<HashMap<String, Instant>> {
        read(&self.inner.cooling)
    }

    fn cooled(&self, deployment: &str, cooldown: Duration) {
        let deployment = deployment.to_string();
        let ms = i64::try_from(cooldown.as_millis()).unwrap_or(i64::MAX);
        // Not retried: the deployment is passed over here at once, and a cooldown written late is worth little.
        let inner = self.inner.clone();
        self.handle.spawn(async move {
            let Ok(client) = inner.client() else {
                return;
            };
            let _ = tokio::time::timeout(
                WAIT,
                client.execute(
                    "WITH up AS (INSERT INTO enterplace_cooldowns AS c VALUES ($1, clock_timestamp() + $2 * interval '1 millisecond') \
                       ON CONFLICT (deployment) DO UPDATE SET until = greatest(c.until, excluded.until)) \
                     UPDATE enterplace_versions SET version = version + 1 WHERE name = 'cooldowns'",
                    &[&deployment, &(ms as f64)],
                ),
            )
            .await;
        });
    }

    fn warmed(&self, deployment: &str) {
        if !read(&self.inner.cooling).contains_key(deployment) {
            return;
        }
        {
            let mut cooling = self
                .inner
                .cooling
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !cooling.contains_key(deployment) {
                return;
            }
            Arc::make_mut(&mut cooling).remove(deployment);
        }
        let deployment = deployment.to_string();
        let inner = self.inner.clone();
        self.handle.spawn(async move {
            let Ok(client) = inner.client() else {
                return;
            };
            let _ = tokio::time::timeout(
                WAIT,
                client.execute(
                    "WITH gone AS (DELETE FROM enterplace_cooldowns WHERE deployment = $1 RETURNING 1) \
                     UPDATE enterplace_versions SET version = version + 1 WHERE name = 'cooldowns' AND EXISTS (SELECT 1 FROM gone)",
                    &[&deployment],
                ),
            )
            .await;
        });
    }

    fn shares_routing(&self) -> bool {
        true
    }

    fn probe_lease(&self, deployment: String, ttl: Duration) -> Pending<bool> {
        let inner = self.inner.clone();
        self.ask(async move { inner.probe_lease(&deployment, ttl).await })
    }

    fn pinned(&self, session: &str, idle: Duration) -> Option<String> {
        let key = id::sha256_hex(session.as_bytes());
        let now = Instant::now();
        self.inner
            .pins
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&key)
            .filter(|(_, at, _)| now.duration_since(*at) < idle)
            .map(|(deployment, _, _)| deployment.clone())
    }

    fn pin(&self, session: &str, deployment: &str) {
        // Sessions are kept by hash: the person and the session ID their client sent stay out of the database.
        let key = id::sha256_hex(session.as_bytes());
        let now = Instant::now();
        let mut pins = self
            .inner
            .pins
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((d, at, written)) = pins.get_mut(&key) {
            if d == deployment && now.duration_since(*written) < PIN_TOUCH {
                *at = now;
                return;
            }
        }
        crate::alias::bounded_insert(
            &mut pins,
            key.clone(),
            (deployment.to_string(), now, now),
            now,
            |p| p.1,
        );
        drop(pins);
        self.inner
            .pins_out
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key, deployment.to_string());
    }

    fn latency(&self) -> Arc<HashMap<String, u32>> {
        read(&self.inner.latency)
    }

    fn observed(&self, deployment: &str, ms: u32) {
        let mut samples = self
            .inner
            .samples
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (window, dirty) = samples.entry(deployment.to_string()).or_default();
        if window.len() == crate::alias::LATENCY_SAMPLES {
            window.pop_front();
        }
        window.push_back(ms);
        *dirty = true;
    }

    fn deployment_load(&self) -> Arc<HashMap<String, DeploymentLoad>> {
        read(&self.inner.load)
    }

    fn publish_health(&self, report: String) {
        *self
            .inner
            .health_out
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(report);
    }

    fn health_reports(&self) -> Arc<Vec<String>> {
        read(&self.inner.health)
    }

    fn publish_load(&self, deployment: &str, load: DeploymentLoad) {
        self.inner
            .load_out
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(deployment.to_string(), load);
    }

    fn ended_sessions(&self) -> Arc<HashMap<String, (Instant, String)>> {
        read(&self.inner.ended)
    }

    fn end_events_session(&self, key: String, by: String, ttl: Duration) {
        let seconds = ttl.as_secs_f64();
        self.retried("the end of a session", move |inner| {
            let (key, who) = (key.clone(), format!("{ENDED}{by}"));
            async move {
                inner
                    .client()?
                    .execute(
                        "WITH up AS (INSERT INTO enterplace_sessions AS s VALUES ($1, $2, now() + $3 * interval '1 second') \
                           ON CONFLICT (sha256) DO UPDATE SET expires = greatest(s.expires, excluded.expires)) \
                         UPDATE enterplace_versions SET version = version + 1 WHERE name = 'events'",
                        &[&key, &who, &seconds],
                    )
                    .await
                    .map(|_| ())
                    .map_err(|err| err.to_string())
            }
        });
    }

    fn open_session(&self, id_sha256: String, who: String, ttl: Duration) -> Pending<()> {
        let inner = self.inner.clone();
        let seconds = ttl.as_secs_f64();
        self.ask(async move {
            inner
                .client()?
                .execute(
                    "WITH old AS (DELETE FROM enterplace_sessions WHERE expires < now()) \
                     INSERT INTO enterplace_sessions VALUES ($1, $2, now() + $3 * interval '1 second')",
                    &[&id_sha256, &who, &seconds],
                )
                .await
                .map(|_| ())
                .map_err(|err| err.to_string())
        })
    }

    fn session(&self, id_sha256: String) -> Pending<Option<String>> {
        let inner = self.inner.clone();
        self.ask(async move {
            let row = inner
                .client()?
                .query_opt(
                    "SELECT who FROM enterplace_sessions WHERE sha256 = $1 AND expires > now()",
                    &[&id_sha256],
                )
                .await
                .map_err(|err| err.to_string())?;
            row.map(|row| row.try_get(0).map_err(|err| err.to_string()))
                .transpose()
        })
    }

    fn sign_in_lock(
        &self,
        scope: String,
        failed: Option<enterplace_core::store::SignInLimit>,
    ) -> Pending<Option<u64>> {
        let inner = self.inner.clone();
        self.ask(async move {
            let client = inner.client()?;
            let row = match failed {
                // One statement, so two gateways counting the same scope at once cannot both miss the limit.
                Some(limit) => client
                    .query_opt(
                        "INSERT INTO enterplace_sign_in_failures AS f (scope, failures, since) VALUES ($1, 1, now()) \
                         ON CONFLICT (scope) DO UPDATE SET \
                           failures = CASE WHEN f.since < now() - $2 * interval '1 second' THEN 1 ELSE f.failures + 1 END, \
                           since = CASE WHEN f.since < now() - $2 * interval '1 second' THEN now() ELSE f.since END, \
                           locked_until = CASE WHEN f.since >= now() - $2 * interval '1 second' AND f.failures + 1 >= $3 \
                             THEN now() + $4 * interval '1 second' ELSE f.locked_until END \
                         RETURNING extract(epoch FROM locked_until - now())::float8",
                        &[
                            &scope,
                            &limit.window.as_secs_f64(),
                            &i32::try_from(limit.max).unwrap_or(i32::MAX),
                            &limit.lock.as_secs_f64(),
                        ],
                    )
                    .await,
                None => client
                    .query_opt(
                        "SELECT extract(epoch FROM locked_until - now())::float8 FROM enterplace_sign_in_failures WHERE scope = $1",
                        &[&scope],
                    )
                    .await,
            }
            .map_err(|err| err.to_string())?;
            let left: Option<f64> = row
                .map(|row| row.try_get(0))
                .transpose()
                .map_err(|err| err.to_string())?
                .flatten();
            Ok(left.filter(|left| *left > 0.0).map(|left| left.ceil() as u64))
        })
    }

    fn sign_in_clear(&self, scope: String) {
        self.retried("a console sign-in", move |inner| {
            let scope = scope.clone();
            async move {
                inner
                    .client()?
                    .execute(
                        "DELETE FROM enterplace_sign_in_failures WHERE scope = $1",
                        &[&scope],
                    )
                    .await
                    .map(|_| ())
                    .map_err(|err| err.to_string())
            }
        });
    }

    fn end_session(&self, id_sha256: String) {
        self.retried("a console sign-out", move |inner| {
            let id_sha256 = id_sha256.clone();
            async move {
                inner
                    .client()?
                    .execute(
                        "DELETE FROM enterplace_sessions WHERE sha256 = $1",
                        &[&id_sha256],
                    )
                    .await
                    .map(|_| ())
                    .map_err(|err| err.to_string())
            }
        });
    }
}

/// rustls as tokio-postgres's TLS, so the store uses the same TLS and roots as the calls to providers.
#[derive(Clone)]
struct Rustls(tokio_rustls::TlsConnector);

impl<S> MakeTlsConnect<S> for Rustls
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = Tls<S>;
    type TlsConnect = Connect;
    type Error = rustls::pki_types::InvalidDnsNameError;

    fn make_tls_connect(&mut self, domain: &str) -> Result<Connect, Self::Error> {
        let name = rustls::pki_types::ServerName::try_from(domain.to_string())?;
        Ok(Connect(self.0.clone(), name))
    }
}

struct Connect(
    tokio_rustls::TlsConnector,
    rustls::pki_types::ServerName<'static>,
);

impl<S> TlsConnect<S> for Connect
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = Tls<S>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Tls<S>>> + Send>>;

    fn connect(self, stream: S) -> Self::Future {
        Box::pin(async move { self.0.connect(self.1, stream).await.map(Tls) })
    }
}

struct Tls<S>(tokio_rustls::client::TlsStream<S>);

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Tls<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Tls<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> TlsStream for Tls<S> {
    fn channel_binding(&self) -> ChannelBinding {
        // SCRAM works without it; binding to the certificate would need its hash algorithm parsed from it.
        ChannelBinding::none()
    }
}

/// A database of its own for one test, on the server ENTERPLACE_TEST_DATABASE_URL names, dropped when the test drops
/// this (a run left about 1 GB of them behind before). Reads as its connection string. A test that starts several
/// gateways on one database keeps the one guard for all of them, declared before them so it is dropped last. For
/// the store tests of this crate and of those built on it.
#[doc(hidden)]
pub struct TestDatabase {
    url: String,
    server: tokio_postgres::Config,
    name: String,
}

impl TestDatabase {
    /// A fresh database `name`. `None` (and a line saying so) when ENTERPLACE_TEST_DATABASE_URL is not set, so a
    /// machine without Postgres skips the test; CI sets it.
    pub async fn create(name: &str) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        let Ok(url) = std::env::var("ENTERPLACE_TEST_DATABASE_URL") else {
            eprintln!(
                "skipped {name}: ENTERPLACE_TEST_DATABASE_URL is not set. Set it to a Postgres connection string to run the store tests."
            );
            return Ok(None);
        };
        let server: tokio_postgres::Config = url.parse()?;
        let (client, connection) = server.connect(tokio_postgres::NoTls).await?;
        tokio::spawn(connection);
        // One statement each: several in one string run as a transaction, where these are refused.
        client
            .batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
            .await?;
        client
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .await?;
        // In key=value form, so a password needs no URL encoding.
        let quote = |s: &str| format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"));
        let host = match server.get_hosts().first() {
            Some(tokio_postgres::config::Host::Tcp(host)) => host.clone(),
            _ => "127.0.0.1".into(),
        };
        let password = server
            .get_password()
            .map(|p| String::from_utf8_lossy(p).to_string())
            .unwrap_or_default();
        let url = format!(
            "host={} port={} user={} password={} dbname={} sslmode=disable",
            quote(&host),
            server.get_ports().first().copied().unwrap_or(5432),
            quote(server.get_user().unwrap_or("postgres")),
            quote(&password),
            quote(name)
        );
        Ok(Some(Self {
            url,
            server,
            name: name.to_string(),
        }))
    }
}

impl std::ops::Deref for TestDatabase {
    type Target = String;

    fn deref(&self) -> &String {
        &self.url
    }
}

impl std::fmt::Display for TestDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.url)
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let (server, name) = (self.server.clone(), self.name.clone());
        // On a thread and runtime of its own: a test drops this inside its runtime, where waiting on another is
        // refused. FORCE closes what a store that was not closed still holds open.
        let dropped = std::thread::spawn(move || -> Result<(), String> {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            runtime.block_on(async {
                let (client, connection) = server
                    .connect(tokio_postgres::NoTls)
                    .await
                    .map_err(|e| e.to_string())?;
                tokio::spawn(connection);
                client
                    .batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
                    .await
                    .map_err(|e| e.to_string())
            })
        })
        .join();
        match dropped {
            Ok(Ok(())) => {}
            Ok(Err(e)) => eprintln!(
                "the test database {} was not dropped: {e}. Drop it by hand, or remove the test Postgres with its volume.",
                self.name
            ),
            Err(_) => eprintln!(
                "the test database {} was not dropped: the thread that drops it stopped. Drop it by hand, or remove the test Postgres with its volume.",
                self.name
            ),
        }
    }
}

/// The store a test of the shared state runs against: a Postgres database of its own (the default), or with
/// ENTERPLACE_TEST_STORE=cloudflare the Cloudflare store's own code (`deploy/cloudflare/src/store.ts`) on
/// node:sqlite, empty, in a process of its own that ends with this. Reads as its address. A policy written for the
/// Postgres store is changed to name the one chosen with [`policy`](Self::policy), and a gateway finds it with
/// [`env`](Self::env).
#[doc(hidden)]
pub enum TestStore {
    Postgres(Box<TestDatabase>),
    Cloudflare {
        url: String,
        server: std::process::Child,
    },
}

impl TestStore {
    /// `None` (and a line saying so) when the backend chosen has nothing to run on.
    pub async fn create(name: &str) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        if !Self::cloudflare() {
            return Ok(TestDatabase::create(name)
                .await?
                .map(|db| Self::Postgres(Box::new(db))));
        }
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy/cloudflare/test/store-server.ts");
        let mut server = std::process::Command::new("node")
            .arg("--no-warnings")
            .arg(&script)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map_err(|err| {
                format!(
                    "node could not be started for the Cloudflare store ({err}). Install Node.js 23.6 or later, which runs {} as it is.",
                    script.display()
                )
            })?;
        let mut port = String::new();
        if let Some(out) = server.stdout.take() {
            std::io::BufRead::read_line(&mut std::io::BufReader::new(out), &mut port)?;
        }
        let port: u16 = port
            .trim()
            .parse()
            .map_err(|_| format!("the Cloudflare store server said {port:?}, not its port"))?;
        Ok(Some(Self::Cloudflare {
            url: format!("http://127.0.0.1:{port}"),
            server,
        }))
    }

    /// Whether this run tests the Cloudflare store (ENTERPLACE_TEST_STORE=cloudflare).
    pub fn cloudflare() -> bool {
        std::env::var("ENTERPLACE_TEST_STORE").as_deref() == Ok("cloudflare")
    }

    /// `text`, a policy naming the Postgres store by ENTERPLACE_STORE_URL, naming the store this run tests.
    pub fn policy(text: &str) -> String {
        if Self::cloudflare() {
            text.replace("postgres_url_env: ENTERPLACE_STORE_URL", "cloudflare: true")
        } else {
            text.to_string()
        }
    }

    /// `url` for a gateway's `variable` when it is the one that names the store: ENTERPLACE_STORE_URL for
    /// Postgres, the Cloudflare store's variable for that one.
    pub fn env(variable: &str, url: &str) -> Option<String> {
        matches!(
            variable,
            "ENTERPLACE_STORE_URL" | crate::cloudflare_store::URL_ENV
        )
        .then(|| url.to_string())
    }

    /// The database of the features with tables of their own, on the store this run tests at `url`.
    pub fn db(url: &str) -> Result<crate::sql::Db, String> {
        if Self::cloudflare() {
            Ok(crate::sql::Db::Cloudflare(crate::cloudflare_store::open(
                url,
            )?))
        } else {
            Ok(crate::sql::Db::Postgres(open("ENTERPLACE_STORE_URL", url)?))
        }
    }

    /// The Cloudflare store at `url` or the Postgres store at it, as the store this run tests, for a test that
    /// drives a store without a gateway.
    pub fn open(url: &str) -> Result<Arc<dyn Store>, String> {
        if Self::cloudflare() {
            Ok(crate::cloudflare_store::open(url)?)
        } else {
            Ok(open("ENTERPLACE_STORE_URL", url)?)
        }
    }
}

impl std::ops::Deref for TestStore {
    type Target = String;

    fn deref(&self) -> &String {
        match self {
            Self::Postgres(db) => db,
            Self::Cloudflare { url, .. } => url,
        }
    }
}

impl std::fmt::Display for TestStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self)
    }
}

impl Drop for TestStore {
    fn drop(&mut self) {
        if let Self::Cloudflare { server, .. } = self {
            let _ = server.kill();
            let _ = server.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_migration_fingerprints_file_matches_the_code() -> Result<(), String> {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../release/migrations.txt");
        PgStore::check_migration_manifest(
            &path,
            &PgStore::migration_lists(),
            "cargo test -p enterplace-server the_migration_fingerprints_file_matches_the_code",
        )
    }

    #[test]
    fn a_migration_added_or_edited_changes_its_namespaces_fingerprint_alone() {
        let lines = |lists: &[(&str, &[&str])]| -> Vec<String> {
            PgStore::migration_manifest(lists)
                .lines()
                .filter(|l| !l.starts_with('#'))
                .map(str::to_string)
                .collect()
        };
        let before = lines(&[("core", &["a", "b"]), ("mcp", &["c"])]);
        let added = lines(&[("core", &["a", "b", "x"]), ("mcp", &["c"])]);
        let edited = lines(&[("core", &["a", "B"]), ("mcp", &["c"])]);
        assert!(before[0].starts_with("core 2 ") && added[0].starts_with("core 3 "));
        assert!(before[0] != added[0] && before[0] != edited[0] && added[0] != edited[0]);
        assert_eq!((&before[1], &before[1]), (&added[1], &edited[1]));
        // Where one entry ends and the next starts is part of the fingerprint.
        assert!(lines(&[("n", &["ab", "c"])]) != lines(&[("n", &["a", "bc"])]));
    }

    #[test]
    fn an_older_enterplace_runs_beside_a_newer_one_only_one_minor_version_apart() {
        for (own, writer, allowed) in [
            ("0.2.0", "0.3.0", true),
            ("0.2.4", "0.3.1", true),
            ("0.2.0", "0.2.1", true),
            ("0.2.0", "0.4.0", false),
            ("0.9.0", "1.0.0", true),
            ("0.2.0", "1.1.0", false),
            ("1.9.2", "2.0.0", true),
            ("1.9.2", "2.1.0", false),
            ("0.2.0", "0.2.0", false),
            ("0.3.0", "0.2.0", false),
            ("0.2.0", "0.3.0-rc.1", true),
            ("0.2.0", "garbage", false),
        ] {
            assert_eq!(newer_allowed(own, writer), allowed, "{own} beside {writer}");
        }
    }

    #[test]
    fn sslmode_and_sslrootcert_are_read_in_either_form() {
        let (rest, mode, root) = split_tls(
            "postgres://u:p@db.example.com:5432/g?sslmode=verify-ca&application_name=x&sslrootcert=%2Fetc%2Fca.pem",
        );
        assert_eq!(
            rest,
            "postgres://u:p@db.example.com:5432/g?application_name=x"
        );
        assert_eq!(mode.as_deref(), Some("verify-ca"));
        assert_eq!(root.as_deref(), Some("/etc/ca.pem"));
        let (rest, mode, root) = split_tls(
            "host=db user='u' password='a \\' b' sslmode = require sslrootcert='/a b/ca.pem' dbname=g",
        );
        assert_eq!(mode.as_deref(), Some("require"));
        assert_eq!(root.as_deref(), Some("/a b/ca.pem"));
        assert!(
            rest.contains("password='a \\' b'") && rest.ends_with("dbname=g"),
            "{rest}"
        );
        assert!(!rest.contains("ssl"), "{rest}");
    }

    #[test]
    fn every_libpq_mode_but_the_fallbacks_is_taken() -> Result<(), String> {
        for mode in ["require", "verify-ca", "verify-full"] {
            let (config, tls) = connection(
                "DATABASE_URL",
                &format!("postgres://u:p@db.example.com/g?sslmode={mode}"),
            )?;
            assert!(tls.is_some(), "{mode}");
            assert_eq!(config.get_ssl_mode(), SslMode::Require, "{mode}");
        }
        // verify-full is the default; disable is taken for any host, when asked for by name.
        assert!(
            connection("DATABASE_URL", "postgres://u:p@db.example.com/g")?
                .1
                .is_some()
        );
        let (config, tls) =
            connection("DATABASE_URL", "postgres://u:p@10.0.0.7/g?sslmode=disable")?;
        assert!(tls.is_none());
        assert_eq!(config.get_ssl_mode(), SslMode::Disable);
        for mode in ["prefer", "allow", "sometimes"] {
            let err = connection(
                "DATABASE_URL",
                &format!("postgres://u:p@h/g?sslmode={mode}"),
            )
            .err()
            .unwrap_or_default();
            assert!(err.contains("verify-full") && err.contains(mode), "{err}");
        }
        let err = connection(
            "DATABASE_URL",
            "postgres://u:p@h/g?sslrootcert=/no/such/ca.pem",
        )
        .err()
        .unwrap_or_default();
        assert!(
            err.contains("/no/such/ca.pem") && err.contains("PEM"),
            "{err}"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_unix_socket_is_local_and_never_tries_tls() -> Result<(), String> {
        for url in [
            "host=/cloudsql/project:europe-west1:enterplace user=u dbname=g",
            "host=/cloudsql/project:europe-west1:enterplace user=u dbname=g sslmode=verify-full",
            "postgresql://u:p@/g?host=/cloudsql/project:europe-west1:enterplace",
        ] {
            let (config, tls) = connection("DATABASE_URL", url)?;
            assert!(tls.is_none(), "{url}");
            assert!(socket(&config), "{url}: no plain text warning");
            assert_eq!(config.get_ssl_mode(), SslMode::Disable, "{url}");
        }
        let (config, _) = connection("DATABASE_URL", "postgres://u:p@10.0.0.7/g?sslmode=disable")?;
        assert!(!socket(&config), "a network host is warned about");
        Ok(())
    }

    #[test]
    fn pgsslmode_is_the_mode_when_the_string_names_none() -> Result<(), String> {
        let (config, tls) =
            connection_with("DATABASE_URL", "postgres://u:p@10.0.0.7/g", Some("disable"))?;
        assert!(tls.is_none());
        assert_eq!(config.get_ssl_mode(), SslMode::Disable);
        assert!(
            connection_with("DATABASE_URL", "postgres://u:p@h/g", Some("require"))?
                .1
                .is_some()
        );
        // The string's own sslmode wins.
        let (_, tls) = connection_with(
            "DATABASE_URL",
            "postgres://u:p@h/g?sslmode=disable",
            Some("verify-full"),
        )?;
        assert!(tls.is_none());
        let err = connection_with("DATABASE_URL", "postgres://u:p@h/g", Some("prefer"))
            .err()
            .unwrap_or_default();
        assert!(err.contains("PGSSLMODE says sslmode=prefer"), "{err}");
        Ok(())
    }

    #[test]
    fn a_bad_connection_string_is_not_repeated() {
        let err = connection("DATABASE_URL", "postgres://u:secret-pw@h:notaport/g")
            .err()
            .unwrap_or_default();
        assert!(err.contains("DATABASE_URL"), "{err}");
        assert!(!err.contains("secret-pw"), "{err}");
    }
}
