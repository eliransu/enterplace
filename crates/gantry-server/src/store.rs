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

use gantry_core::{
    config::KeyEntry,
    id,
    keyfile::{self, Revoked},
    kill::Kill,
    policy::{Budget, Period},
    store::{
        self as core_store, Bucket, Change, Credential, LEASE, Lease, NewVersion, Pending,
        PolicyVersion, Reserve, Store, VersionError,
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
const POLL: Duration = Duration::from_millis(500);

/// The longest a call waits for the database before it counts as down.
const WAIT: Duration = Duration::from_secs(5);

/// How long a settlement is retried while the database is away. A hold never given back keeps counting against
/// its budget until the period ends, which errs on the side of the budget.
const SETTLE_FOR: Duration = Duration::from_secs(600);

/// The schema, one migration per entry, applied in order. `gantry_schema` holds the number of each one applied.
/// Never edit an entry that has shipped: add one.
const MIGRATIONS: &[&str] = &[
    "
CREATE TABLE gantry_keys (
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
CREATE TABLE gantry_kills (
    scope text NOT NULL,
    value text NOT NULL,
    reason text NOT NULL,
    set_by text NOT NULL,
    set_at text NOT NULL,
    PRIMARY KEY (scope, value)
);
CREATE TABLE gantry_spend (
    scope text NOT NULL,
    per text NOT NULL,
    period text NOT NULL,
    spent double precision NOT NULL DEFAULT 0,
    reserved double precision NOT NULL DEFAULT 0,
    PRIMARY KEY (scope, per, period)
);
CREATE TABLE gantry_versions (name text PRIMARY KEY, version bigint NOT NULL);
INSERT INTO gantry_versions VALUES ('keys', 0), ('kills', 0);
", "
CREATE TABLE gantry_rate_grants (
    id bigserial PRIMARY KEY,
    scope text NOT NULL,
    until timestamptz NOT NULL,
    n bigint NOT NULL
);
CREATE INDEX gantry_rate_grants_scope ON gantry_rate_grants (scope, until);
CREATE TABLE gantry_cooldowns (deployment text PRIMARY KEY, until timestamptz NOT NULL);
CREATE TABLE gantry_sessions (sha256 text PRIMARY KEY, who text NOT NULL, expires timestamptz NOT NULL);
INSERT INTO gantry_versions VALUES ('cooldowns', 0);
",
    "
CREATE TABLE gantry_credentials (
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
CREATE TABLE gantry_master (id integer PRIMARY KEY CHECK (id = 1), sealed bytea NOT NULL);
INSERT INTO gantry_versions VALUES ('credentials', 0);
",
];

/// The policy versions' table, in a namespace of its own (`gantry_migrations`), so it never competes with the
/// numbering of the core schema above. Never edit an entry that has shipped: add one.
const POLICY_MIGRATIONS: &[&str] = &["
CREATE TABLE gantry_policy_versions (
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
INSERT INTO gantry_versions VALUES ('policy', 0) ON CONFLICT (name) DO NOTHING;
"];

/// The columns of a policy version, in the order `version_of` reads them.
const VERSION_COLUMNS: &str =
    "id, text, sha256, base, note, created_by, created_at, state, decided_by, decided_at";

/// Serializes changes to the policy versions across every gateway on the database.
const POLICY_LOCK: i64 = 7_349_127_342;

/// What the master key seals once per database, so a gateway with another master key is refused at start rather
/// than at the first credential it cannot open.
const MASTER_CHECK: (&str, &[u8]) = ("gantry master key check", b"gantry");

/// The columns of a credential anyone may see, in the order `credential_of` reads them.
const SHOWN: &str =
    "name, provider, fingerprint, created_by, created_at, rotated_by, rotated_at, generation";

/// How much longer than its [`LEASE`] the store counts a grant in the minute, in milliseconds: a gateway's clock
/// and the database's may drift apart a little within one second, and a lease is spent by the gateway's.
const LEASE_MARGIN_MS: u64 = 500;

/// The store, with the runtime its connection and poller run on. Its own runtime, so the command line (which
/// blocks) and the server (which awaits) can both call it, and a busy server does not delay the poll.
pub struct PgStore {
    runtime: Option<tokio::runtime::Runtime>,
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
        // Dropping a runtime waits for its tasks, which is refused inside another runtime (a test, the server).
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
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
    /// Set while the database cannot be reached, so the outage is reported once and its end once.
    down: AtomicBool,
}

/// A credential and its value as sealed.
type Sealed = (Credential, Vec<u8>);

fn read<T: Clone>(lock: &RwLock<T>) -> T {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

fn write<T>(lock: &RwLock<T>, value: T) {
    *lock
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = value;
}

/// Connects to the database named by the connection string in `env` (as read by the caller), creates or updates
/// its tables, and reads the keys and kill switches. Fails, naming the fix, if any of that cannot be done.
pub fn open(env: &str, url: &str) -> Result<Arc<PgStore>, String> {
    let (config, tls) = connection(env, url)?;
    if tls.is_none() && !socket(&config) {
        eprintln!(
            "warning: {env} says sslmode=disable, so the connection to the store is not encrypted: key hashes, kill switches and spend cross the network in plain text. Use it only on a network you trust, such as a cluster's own Postgres; remove sslmode=disable to encrypt it."
        );
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("gantry-store")
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
        keys: RwLock::new(String::new()),
        kills: RwLock::new(Arc::new(Vec::new())),
        cooling: RwLock::default(),
        returns: Mutex::default(),
        credentials: RwLock::new(Arc::new(Vec::new())),
        master: std::sync::OnceLock::new(),
        policies: RwLock::default(),
        policies_seen: Mutex::new(None),
        down: AtomicBool::new(false),
    });
    let store = PgStore {
        handle: runtime.handle().clone(),
        runtime: Some(runtime),
        inner: inner.clone(),
    };
    let first = inner.clone();
    store.wait(async move {
        let mut client = first
            .connect()
            .await
            .map_err(|err| unreachable(&first.env, &err))?;
        migrate(&mut client).await?;
        migrate_namespace(&mut client, "gantry_policy", POLICY_MIGRATIONS).await?;
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
            inner.poll().await;
            inner.flush_returns().await;
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
            "The server's certificate is not signed by a certificate Gantry trusts (the Mozilla roots built in, and sslrootcert if set). Add sslrootcert=/path/to/ca.pem to {env}, naming the CA that signed it: for Amazon RDS, the bundle at https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem."
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
    format!("the store cannot be reached: {text}. Gantry does not start without it. {fix}")
}

/// The connection string, and the TLS it asks for. `sslmode` and `sslrootcert` are read here as libpq reads them
/// (tokio-postgres knows neither verify mode nor root files): `verify-full`, the default, checks the server's
/// certificate and name; `verify-ca` its signer only; `require` encrypts without checking, unless `sslrootcert`
/// is given, which makes it `verify-ca`; `disable` sends plain text. `sslrootcert` names a PEM file whose
/// certificates are trusted besides the Mozilla roots built in, or, for `verify-ca`, instead of them.
fn connection(env: &str, url: &str) -> Result<(tokio_postgres::Config, Option<Rustls>), String> {
    let (rest, mode, rootcert) = split_tls(url.trim());
    let mut config = rest.parse::<tokio_postgres::Config>().map_err(|err| {
        // The error never repeats the string: it holds a password.
        format!(
            "{env} does not hold a Postgres connection string Gantry can read ({err}). Write it as postgres://user:password@host:5432/database?sslmode=verify-full."
        )
    })?;
    let mode = mode.as_deref().unwrap_or("verify-full");
    if !matches!(mode, "disable" | "require" | "verify-ca" | "verify-full") {
        return Err(format!(
            "{env} says sslmode={mode}, which Gantry does not take: it never falls back to plain text unasked. Use verify-full (the default), verify-ca, require or disable."
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

/// Creates or updates the tables, one Gantry at a time, and refuses a database a newer Gantry has written.
async fn migrate(client: &mut Client) -> Result<(), String> {
    let failed = |err: tokio_postgres::Error| {
        format!(
            "the store's tables could not be created or updated: {err}. The connection string's user needs CREATE on the database. Fix that and start again."
        )
    };
    let tx = client.transaction().await.map_err(failed)?;
    // Two replicas starting together would both create the tables: the second waits here for the first.
    tx.batch_execute(
        "SELECT pg_advisory_xact_lock(7349127341); CREATE TABLE IF NOT EXISTS gantry_schema (version integer NOT NULL);",
    )
    .await
    .map_err(failed)?;
    let row = tx
        .query_one("SELECT coalesce(max(version), 0) FROM gantry_schema", &[])
        .await
        .map_err(failed)?;
    let applied: i32 = row.try_get(0).map_err(failed)?;
    let known = i32::try_from(MIGRATIONS.len()).unwrap_or(i32::MAX);
    if applied > known {
        return Err(format!(
            "the store was written by a newer Gantry (schema version {applied}; this one knows up to {known}). Run the same Gantry version as the other gateways on this database, or point this one at another database."
        ));
    }
    for (number, sql) in MIGRATIONS.iter().enumerate().skip(applied as usize) {
        tx.batch_execute(sql).await.map_err(failed)?;
        let version = i32::try_from(number + 1).unwrap_or(i32::MAX);
        tx.execute("INSERT INTO gantry_schema VALUES ($1)", &[&version])
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

    /// One poll: reloads what changed, and reports the database going away or coming back.
    async fn poll(&self) {
        match tokio::time::timeout(WAIT, self.refresh()).await {
            Ok(Ok(())) => {
                if self.down.swap(false, Ordering::Relaxed) {
                    eprintln!(
                        "gantry: the store is reachable again. Budgeted requests are served again."
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
                        "gantry: the store cannot be reached: {err}. Known keys and kill switches stay as they were, and requests under a budget are refused (store_unavailable) until it is back. Check Postgres and {}.",
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
            .query("SELECT name, version FROM gantry_versions", &[])
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
                    &format!("SELECT {SHOWN}, sealed FROM gantry_credentials ORDER BY name"),
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
                        "SELECT {VERSION_COLUMNS} FROM gantry_policy_versions ORDER BY id DESC"
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
        Ok(())
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
            "UPDATE gantry_versions SET version = version + 1 WHERE name = 'policy'",
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
                "SELECT name, team, sha256, admin, expires, budget_usd, budget_per, models, tpm FROM gantry_keys ORDER BY id",
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
            keys.push(KeyEntry {
                name: row.try_get(0).map_err(field)?,
                team: row.try_get(1).map_err(field)?,
                sha256: row.try_get(2).map_err(field)?,
                admin: row.try_get(3).map_err(field)?,
                expires: row.try_get(4).map_err(field)?,
                budget: usd.map(|usd| Budget {
                    usd,
                    // Only Gantry writes this column. Anything but a month is read as a day, the tighter of the two.
                    per: if per.as_deref() == Some("month") {
                        Period::Month
                    } else {
                        Period::Day
                    },
                }),
                models: row.try_get(7).map_err(field)?,
                // A value out of range becomes 0, which the loader refuses: the change is then not used at all.
                tpm: tpm.map(|t| u32::try_from(t).unwrap_or(0)),
            });
        }
        Ok(keys)
    }

    async fn read_kills(&self, client: &Client) -> Result<Vec<Kill>, String> {
        let rows = client
            .query(
                "SELECT scope, value, reason, set_by, set_at FROM gantry_kills ORDER BY set_at, scope, value",
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
                "SELECT deployment, extract(epoch FROM until - clock_timestamp())::float8 FROM gantry_cooldowns \
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
             DELETE FROM gantry_rate_grants WHERE scope = {scope} AND until < clock_timestamp() - interval '61 seconds'; \
             WITH used AS (SELECT coalesce(sum(n), 0) AS n, min(until) AS first FROM gantry_rate_grants \
               WHERE scope = {scope} AND until >= clock_timestamp() - interval '60 seconds'), \
             got AS (INSERT INTO gantry_rate_grants (scope, until, n) \
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
                "UPDATE gantry_rate_grants AS g SET n = greatest(g.n - r.given, 0) \
                 FROM unnest($1::int8[], $2::int8[]) AS r(id, given) WHERE g.id = r.id",
                &[(&grants, Type::INT8_ARRAY), (&given, Type::INT8_ARRAY)],
            ),
        )
        .await;
    }

    async fn reserve(&self, bucket: &Bucket, usd: f64, limit: f64) -> Result<Reserve, String> {
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
                "INSERT INTO gantry_spend AS s (scope, per, period, reserved) SELECT $1, $2, $3, $4 WHERE $4 <= $5 \
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
                "SELECT spent, reserved FROM gantry_spend WHERE scope = $1 AND per = $2 AND period = $3",
                &params[..3],
            )
            .await
            .map_err(|err| err.to_string())?;
        let (spent, reserved) = row.first().map_or((0.0, 0.0), |row| {
            (row.try_get(0).unwrap_or(0.0), row.try_get(1).unwrap_or(0.0))
        });
        Ok(Reserve::Over { spent, reserved })
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
        let per: Vec<&str> = merged.keys().map(|b| b.per.word()).collect();
        let period: Vec<&str> = merged.keys().map(|b| b.period.as_str()).collect();
        let spent: Vec<f64> = merged.values().map(|v| v.0).collect();
        let reserved: Vec<f64> = merged.values().map(|v| v.1).collect();
        // A hold is given back to the row its reservation made, and rows are never deleted, so a negative
        // `reserved` never inserts a row.
        self.client()?
            .query_typed(
                "INSERT INTO gantry_spend AS s (scope, per, period, spent, reserved) \
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
            "SELECT id FROM gantry_policy_versions WHERE state = 'live'",
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

/// Applies `migrations` in order under `namespace`, one Gantry at a time, and refuses a database a newer binary has
/// written. The version of each namespace is its row in `gantry_migrations`, apart from the gateway's own tables.
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
    let tx = client.transaction().await.map_err(failed)?;
    tx.batch_execute(
        "SELECT pg_advisory_xact_lock(7349127341); CREATE TABLE IF NOT EXISTS gantry_migrations (namespace text PRIMARY KEY, version integer NOT NULL);",
    )
    .await
    .map_err(failed)?;
    let row = tx
        .query_opt(
            "SELECT version FROM gantry_migrations WHERE namespace = $1",
            &[&namespace],
        )
        .await
        .map_err(failed)?;
    let applied: i32 = row
        .map(|r| r.try_get(0))
        .transpose()
        .map_err(failed)?
        .unwrap_or(0);
    let known = i32::try_from(migrations.len()).unwrap_or(i32::MAX);
    if applied > known {
        return Err(format!(
            "the {namespace} tables were written by a newer version (schema version {applied}; this one knows up to {known}). Run the same version as the other gateways on this database, or point this one at another database."
        ));
    }
    for (number, sql) in migrations
        .iter()
        .enumerate()
        .skip(usize::try_from(applied).unwrap_or(0))
    {
        tx.batch_execute(sql).await.map_err(failed)?;
        let version = i32::try_from(number + 1).unwrap_or(i32::MAX);
        tx.execute(
            "INSERT INTO gantry_migrations VALUES ($1, $2) ON CONFLICT (namespace) DO UPDATE SET version = excluded.version",
            &[&namespace, &version],
        )
        .await
        .map_err(failed)?;
    }
    tx.commit().await.map_err(failed)
}

/// For a binary that embeds the gateway and keeps tables of its own in the store's database.
impl PgStore {
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
                        "INSERT INTO gantry_master (id, sealed) VALUES (1, $1) ON CONFLICT (id) DO NOTHING",
                        &[&check],
                    )
                    .await
                    .map_err(|err| err.to_string())?;
                let row = client
                    .query_one("SELECT sealed FROM gantry_master WHERE id = 1", &[])
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
                "{} is not the key the provider credentials in this store were sealed with: it does not open the store's check value. Set the master key the other gateways on this database use, and start again. A master key that is lost cannot be recovered: then remove the credentials (DELETE FROM gantry_credentials; DELETE FROM gantry_master;) and add them again under a new one.",
                crate::credentials::MASTER_ENV
            ));
        }
        let _ = self.inner.master.set(master);
        Ok(())
    }

    fn master(&self) -> Result<&MasterKey, String> {
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
                             bumped AS (UPDATE gantry_versions SET version = version + 1 \
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
                        "gantry: {what} could not be written to the store for {} minutes ({err}). It is dropped.",
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

impl Store for PgStore {
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
                // The name is looked up in the snapshot before the insert: whether it already had a key.
                let row = client
                    .query_one(
                        "WITH added AS (\
                           INSERT INTO gantry_keys (sha256, name, team, admin, expires, budget_usd, budget_per, models, tpm) \
                           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (sha256) DO NOTHING RETURNING 1), \
                         bumped AS (UPDATE gantry_versions SET version = version + 1 \
                           WHERE name = 'keys' AND EXISTS (SELECT 1 FROM added)) \
                         SELECT EXISTS (SELECT 1 FROM added), EXISTS (SELECT 1 FROM gantry_keys WHERE name = $2)",
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

    fn revoke(&self, prefix: &str) -> Result<Option<Revoked>, String> {
        let prefix = prefix.to_string();
        let ambiguous = format!(
            "more than one key hash starts with {prefix}. Give more of the hash. Nothing was changed."
        );
        let found = self.change("revocation", move |client| {
            Box::pin(async move {
                let row = client
                    .query_one(
                        "WITH matching AS (SELECT sha256 FROM gantry_keys WHERE left(sha256, length($1)) = $1), \
                         gone AS (DELETE FROM gantry_keys WHERE sha256 IN (SELECT sha256 FROM matching) \
                           AND (SELECT count(*) FROM matching) = 1 RETURNING name, team, sha256), \
                         bumped AS (UPDATE gantry_versions SET version = version + 1 \
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
                        "WITH old AS (SELECT scope, value, reason, set_by, set_at FROM gantry_kills \
                           WHERE scope = $1 AND value = $2), \
                         up AS (INSERT INTO gantry_kills VALUES ($1, $2, $3, $4, $5) ON CONFLICT (scope, value) \
                           DO UPDATE SET reason = excluded.reason, set_by = excluded.set_by, set_at = excluded.set_at), \
                         bumped AS (UPDATE gantry_versions SET version = version + 1 WHERE name = 'kills') \
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
                        "WITH gone AS (DELETE FROM gantry_kills WHERE scope = $1 AND value = $2 \
                           RETURNING scope, value, reason, set_by, set_at), \
                         bumped AS (UPDATE gantry_versions SET version = version + 1 \
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
            "INSERT INTO gantry_credentials (name, provider, sealed, fingerprint, created_by, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (name) DO NOTHING"
                .into(),
            vec![
                Box::new(name.to_string()),
                Box::new(provider.to_string()),
                Box::new(sealed),
                Box::new(gantry_core::store::fingerprint(value.trim())),
                Box::new(by.to_string()),
                Box::new(gantry_core::audit::timestamp()),
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
            "UPDATE gantry_credentials SET sealed = $2, fingerprint = $3, rotated_by = $4, rotated_at = $5, \
             generation = generation + 1 WHERE name = $1"
                .into(),
            vec![
                Box::new(name.to_string()),
                Box::new(sealed),
                Box::new(gantry_core::store::fingerprint(value.trim())),
                Box::new(by.to_string()),
                Box::new(gantry_core::audit::timestamp()),
            ],
        )
    }

    fn remove_credential(&self, name: &str) -> Result<Option<Credential>, String> {
        self.master()?;
        self.credential_change(
            "DELETE FROM gantry_credentials WHERE name = $1".into(),
            vec![Box::new(name.to_string())],
        )
    }

    fn refresh_policy(&self) -> Result<(), String> {
        let inner = self.inner.clone();
        self.wait(async move { inner.refresh().await })
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
                                "UPDATE gantry_policy_versions SET state = 'retired' WHERE state = 'live'",
                                &[],
                            )
                            .await
                            .map_err(sql)?;
                        }
                        let state = if new.pending { core_store::PENDING } else { core_store::LIVE };
                        let row = tx
                            .query_one(
                                &format!(
                                    "INSERT INTO gantry_policy_versions (text, sha256, base, note, created_by, created_at, state) \
                                     VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING {VERSION_COLUMNS}"
                                ),
                                &[
                                    &new.text,
                                    &id::sha256_hex(new.text.as_bytes()),
                                    &new.base,
                                    &new.note,
                                    &new.by,
                                    &gantry_core::audit::timestamp(),
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
                                "SELECT state, base FROM gantry_policy_versions WHERE id = $1",
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
                                "UPDATE gantry_policy_versions SET state = 'retired' WHERE state = 'live'",
                                &[],
                            )
                            .await
                            .map_err(sql)?;
                        }
                        let state = if approve { core_store::LIVE } else { core_store::REJECTED };
                        let row = tx
                            .query_one(
                                &format!(
                                    "UPDATE gantry_policy_versions SET state = $2, decided_by = $3, decided_at = $4 \
                                     WHERE id = $1 RETURNING {VERSION_COLUMNS}"
                                ),
                                &[&version, &state, &by, &gantry_core::audit::timestamp()],
                            )
                            .await
                            .map_err(sql)?;
                        version_of(&row).map_err(VersionError::Store)
                    })
                })
                .await
        })
    }

    fn update_key(&self, entry: &KeyEntry) -> Result<bool, String> {
        let entry = entry.clone();
        self.change("key", move |client| {
            Box::pin(async move {
                let per = entry.budget.map(|b| b.per.word());
                let tpm = entry.tpm.map(|t| i32::try_from(t).unwrap_or(i32::MAX));
                let n = client
                    .execute(
                        "WITH changed AS (UPDATE gantry_keys SET admin = $2, expires = $3, budget_usd = $4, \
                           budget_per = $5, models = $6, tpm = $7 WHERE sha256 = $1 RETURNING 1), \
                         bumped AS (UPDATE gantry_versions SET version = version + 1 \
                           WHERE name = 'keys' AND EXISTS (SELECT 1 FROM changed)) \
                         SELECT 1 FROM changed",
                        &[
                            &entry.sha256,
                            &entry.admin,
                            &entry.expires,
                            &entry.budget.map(|b| b.usd),
                            &per,
                            &entry.models,
                            &tpm,
                        ],
                    )
                    .await
                    .map_err(|err| err.to_string())?;
                Ok(n > 0)
            })
        })
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
                    "WITH up AS (INSERT INTO gantry_cooldowns AS c VALUES ($1, clock_timestamp() + $2 * interval '1 millisecond') \
                       ON CONFLICT (deployment) DO UPDATE SET until = greatest(c.until, excluded.until)) \
                     UPDATE gantry_versions SET version = version + 1 WHERE name = 'cooldowns'",
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
                    "WITH gone AS (DELETE FROM gantry_cooldowns WHERE deployment = $1 RETURNING 1) \
                     UPDATE gantry_versions SET version = version + 1 WHERE name = 'cooldowns' AND EXISTS (SELECT 1 FROM gone)",
                    &[&deployment],
                ),
            )
            .await;
        });
    }

    fn open_session(&self, id_sha256: String, who: String, ttl: Duration) -> Pending<()> {
        let inner = self.inner.clone();
        let seconds = ttl.as_secs_f64();
        self.ask(async move {
            inner
                .client()?
                .execute(
                    "WITH old AS (DELETE FROM gantry_sessions WHERE expires < now()) \
                     INSERT INTO gantry_sessions VALUES ($1, $2, now() + $3 * interval '1 second')",
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
                    "SELECT who FROM gantry_sessions WHERE sha256 = $1 AND expires > now()",
                    &[&id_sha256],
                )
                .await
                .map_err(|err| err.to_string())?;
            row.map(|row| row.try_get(0).map_err(|err| err.to_string()))
                .transpose()
        })
    }

    fn end_session(&self, id_sha256: String) {
        self.retried("a console sign-out", move |inner| {
            let id_sha256 = id_sha256.clone();
            async move {
                inner
                    .client()?
                    .execute(
                        "DELETE FROM gantry_sessions WHERE sha256 = $1",
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

#[cfg(test)]
mod tests {
    use super::*;

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
            "host=/cloudsql/project:europe-west1:gantry user=u dbname=g",
            "host=/cloudsql/project:europe-west1:gantry user=u dbname=g sslmode=verify-full",
            "postgresql://u:p@/g?host=/cloudsql/project:europe-west1:gantry",
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
    fn a_bad_connection_string_is_not_repeated() {
        let err = connection("DATABASE_URL", "postgres://u:secret-pw@h:notaport/g")
            .err()
            .unwrap_or_default();
        assert!(err.contains("DATABASE_URL"), "{err}");
        assert!(!err.contains("secret-pw"), "{err}");
    }
}
