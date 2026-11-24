//! Audit export and retention (license features `siem` and `retention`), ported from the Cloudflare app
//! (cloud/control-plane/src/app/siem.ts) onto each replica's hash-chained audit log.
//!
//! Export: every replica reads its own chain as it is written (from the file, after a durable cursor) into
//! `enterprise_audit`, and sends its records to every destination in batches. Each batch carries the part of the
//! chain it holds (replica, first and last number and hash, and the hash it follows), so the SIEM can prove its copy
//! is the chain, whole and in order. Delivery is at least once: a destination's cursor per replica moves only after
//! the destination took the batch, and failures back off up to five minutes. Nothing here is on the request path.
//! A pull API with one hashed token, a backfill of the last N days and an NDJSON archive read the same table.
//!
//! Retention: once a day each replica seals its log into a segment; segments older than the retention period (and
//! the start of this month, so spend is replayed whole) are retired with an `audit_retired` record that names them,
//! so `enterplace audit verify` still proves the rest. Never under legal hold, and never before every destination has
//! the records. Legal hold is set by an owner with a reason, and recorded.

#[cfg(test)]
pub(crate) mod tests;

pub mod sinks;

use std::path::{Path as FilePath, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use axum::{
    Extension as Ext, Router,
    body::Body,
    extract::State,
    http::{HeaderMap, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::get,
};
use enterplace_console::{
    Admin, Console, Form, Via, bare_page, foreign,
    html::{self, Field, esc},
    redirect, same_origin,
};
use enterplace_core::audit::{self, AuditLog};
use enterplace_server::sql::Sql;
use enterplace_server::store::tokio_postgres::types::ToSql;
use serde_json::{Value, json};

use super::{Db, alerts, capture};
use crate::license::Status;
use sinks::{Batch, Dest, Env, KINDS, Kind, Sinks};

pub const SIEM: &str = "siem";
pub const RETENTION: &str = "retention";

pub const MIGRATION: &str = "
CREATE TABLE enterprise_audit (
    seq bigserial UNIQUE,
    replica text NOT NULL,
    n bigint NOT NULL,
    hash text NOT NULL,
    prev text NOT NULL,
    time timestamptz NOT NULL,
    line text NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (replica, n)
);
CREATE INDEX enterprise_audit_time ON enterprise_audit (time);
CREATE TABLE enterprise_replicas (
    id text PRIMARY KEY,
    ingested_n bigint NOT NULL DEFAULT 0,
    seen_at timestamptz NOT NULL DEFAULT now(),
    retention_at timestamptz,
    retention_note text
);
CREATE TABLE enterprise_export_destinations (
    id bigserial PRIMARY KEY,
    kind text NOT NULL,
    url text NOT NULL,
    secret text NOT NULL DEFAULT '',
    options text NOT NULL DEFAULT '{}',
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_success_at timestamptz,
    last_error text,
    last_error_at timestamptz,
    delivered bigint NOT NULL DEFAULT 0
);
CREATE TABLE enterprise_export_cursors (
    destination bigint NOT NULL REFERENCES enterprise_export_destinations (id) ON DELETE CASCADE,
    replica text NOT NULL,
    n bigint NOT NULL,
    hash text NOT NULL,
    PRIMARY KEY (destination, replica)
);
CREATE TABLE enterprise_export_settings (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    retention_days integer NOT NULL DEFAULT 365,
    legal_hold boolean NOT NULL DEFAULT false,
    legal_hold_reason text,
    legal_hold_by text,
    legal_hold_at timestamptz,
    pull_sha256 text
);
INSERT INTO enterprise_export_settings DEFAULT VALUES;
";

/// `MIGRATION` on the Cloudflare store: SQLite numbers only a primary key by itself, and the pull API pages by `seq`,
/// so `seq` is the key (never reused, as a bigserial) and (replica, n) a unique pair.
pub const LITE_MIGRATION: &str = "
CREATE TABLE enterprise_audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    replica text NOT NULL,
    n bigint NOT NULL,
    hash text NOT NULL,
    prev text NOT NULL,
    time TEXT NOT NULL,
    line text NOT NULL,
    received_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE (replica, n)
);
CREATE INDEX enterprise_audit_time ON enterprise_audit (time);
CREATE TABLE enterprise_replicas (
    id text PRIMARY KEY,
    ingested_n bigint NOT NULL DEFAULT 0,
    seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    retention_at TEXT,
    retention_note text
);
CREATE TABLE enterprise_export_destinations (
    id INTEGER PRIMARY KEY,
    kind text NOT NULL,
    url text NOT NULL,
    secret text NOT NULL DEFAULT '',
    options text NOT NULL DEFAULT '{}',
    created_by text NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_success_at TEXT,
    last_error text,
    last_error_at TEXT,
    delivered bigint NOT NULL DEFAULT 0
);
CREATE TABLE enterprise_export_cursors (
    destination bigint NOT NULL REFERENCES enterprise_export_destinations (id) ON DELETE CASCADE,
    replica text NOT NULL,
    n bigint NOT NULL,
    hash text NOT NULL,
    PRIMARY KEY (destination, replica)
);
CREATE TABLE enterprise_export_settings (
    id boolean PRIMARY KEY DEFAULT 1 CHECK (id),
    retention_days integer NOT NULL DEFAULT 365,
    legal_hold boolean NOT NULL DEFAULT 0,
    legal_hold_reason text,
    legal_hold_by text,
    legal_hold_at TEXT,
    pull_sha256 text
);
INSERT INTO enterprise_export_settings DEFAULT VALUES;
";

const NAV: &str = "Audit export";
const BATCH: usize = 500;
const READ: usize = 1000;
const BACKFILL_MAX: i64 = 5000;
const PULL_MAX: i64 = 1000;
const BACKOFF_MAX: Duration = Duration::from_secs(300);
const RETENTION_EVERY: Duration = Duration::from_secs(3600);
/// How often each replica reads legal hold for the gateway's kept bodies, which it may delete every 2 seconds.
const HOLD_EVERY: Duration = Duration::from_secs(2);
/// The environment variable with the key that encrypts destination secrets in the database.
const KEY_ENV: &str = "ENTERPLACE_EXPORT_KEY";
const NO_KEY: &str = "Destination secrets are kept encrypted in the database, and ENTERPLACE_EXPORT_KEY is not set. Set it on every replica to the same 64 hex characters (openssl rand -hex 32) and restart.";

/// What the export runs on.
pub struct Setup {
    pub db: Arc<Db>,
    pub log: Arc<AuditLog>,
    pub audit_path: PathBuf,
    pub env: Env,
    pub siem: bool,
    pub retention: bool,
    /// Read the chain into the table even without `siem`: alerting reads it there.
    pub alerts: bool,
    /// The gateway's capture hook, when `siem` is on: destinations may opt in to prompt and answer text.
    pub captures: Option<Arc<capture::Captures>>,
    /// Set to the last record read into the table, so segments that leave the disk have been read first.
    pub read_through: Arc<std::sync::atomic::AtomicU64>,
}

/// One replica's exporter: reads its chain into the table, sends it on, and applies retention to it.
pub(crate) struct Exporter {
    pub(crate) db: Arc<Db>,
    pub(crate) log: Arc<AuditLog>,
    path: PathBuf,
    pub(crate) replica: String,
    siem: bool,
    retention: bool,
    read_through: Arc<std::sync::atomic::AtomicU64>,
    pub(crate) key: Option<[u8; 32]>,
    pub(crate) sinks: Arc<Sinks>,
    captures: Option<Arc<capture::Captures>>,
    /// Alerting reads what each tick read in, then evaluates it. Set once, after both are made.
    pub(crate) alerts: std::sync::OnceLock<Arc<alerts::Engine>>,
    alerts_on: bool,
    /// Where the last read stopped, so the next one does not read the file from the start.
    hint: Mutex<Option<Hint>>,
    /// Failures in a row and when to try again, by destination.
    backoff: Mutex<std::collections::HashMap<i64, (u32, Instant)>>,
    /// The last error printed, so a destination that is down prints once, not every second.
    said: Mutex<String>,
}

#[derive(Clone)]
struct Hint {
    file: PathBuf,
    first: u64,
    offset: u64,
    next: u64,
}

#[derive(Clone)]
struct Export {
    exporter: Arc<Exporter>,
}

/// Adds the audit export page, the pull API and the exporter that runs beside the gateway.
pub fn register(
    extension: &mut enterplace_server::Extension,
    setup: Setup,
) -> Result<Arc<Exporter>, String> {
    let exporter = chain(setup)?;
    let export = Export {
        exporter: exporter.clone(),
    };
    // Alerting alone reads the chain and adds no export page.
    if !(export.exporter.siem || export.exporter.retention) {
        return Ok(exporter);
    }
    let console = &mut extension.console;
    console.nav.push(("/console/siem".into(), NAV.into()));
    console.routes = std::mem::take(&mut console.routes)
        .route("/siem", get(page).post(act))
        .route("/siem/archive", get(archive))
        .layer(Ext(export.clone()));
    if export.exporter.siem {
        extension.routes = std::mem::take(&mut extension.routes).merge(
            Router::new()
                .route("/export/records", get(pull))
                .layer(Ext(export)),
        );
    }
    Ok(exporter)
}

/// The exporter of one chain, running: the install's, or an organization's (`audit: { per_org: true }`), which is a
/// replica of its own in the table, so its records are read, sent, retained and held as the install's are.
pub fn chain(setup: Setup) -> Result<Arc<Exporter>, String> {
    let replica = replica_id(&setup.audit_path, &setup.env)?;
    let key = match (setup.env)(KEY_ENV).filter(|k| !k.trim().is_empty()) {
        None => None,
        Some(text) => Some(parse_key(text.trim()).ok_or_else(|| {
            format!("{KEY_ENV} is set but is not 64 hex characters. Make one with `openssl rand -hex 32`, set the same value on every replica, and restart.")
        })?),
    };
    let tick = (setup.env)("ENTERPLACE_EXPORT_TICK_MS")
        .and_then(|ms| ms.parse().ok())
        .map_or(Duration::from_secs(1), Duration::from_millis);
    let exporter = Arc::new(Exporter {
        db: setup.db,
        log: setup.log,
        path: setup.audit_path,
        replica,
        siem: setup.siem,
        retention: setup.retention,
        read_through: setup.read_through,
        key,
        sinks: Arc::new(Sinks::new(setup.env)),
        captures: setup.captures,
        alerts: std::sync::OnceLock::new(),
        alerts_on: setup.alerts,
        hint: Mutex::new(None),
        backoff: Mutex::new(std::collections::HashMap::new()),
        said: Mutex::new(String::new()),
    });
    #[cfg(test)]
    tests::registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(exporter.path.clone(), exporter.clone());
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        runtime.spawn(exporter.clone().run(tick));
    }
    Ok(exporter)
}

/// Without either feature the page and the pull API say why, and there is no nav entry.
pub fn locked(extension: &mut enterplace_server::Extension, status: &Status) {
    let Err(refused) = status.require(SIEM) else {
        return;
    };
    let (code, message) = (refused.code, refused.message);
    let page = {
        let message = message.clone();
        move || {
            let message = message.clone();
            async move {
                bare_page(
                    StatusCode::FORBIDDEN,
                    "Audit export needs a license",
                    &format!(
                        r#"<h1 class="t-lg" style="margin: 0">Audit export needs a license</h1><p class="t-lead g-muted" style="margin: 0">{}</p><p class="t-small g-muted" style="margin: 0">Code: {code}</p>"#,
                        esc(&message)
                    ),
                )
            }
        }
    };
    let api = move || {
        let message = message.clone();
        async move { api_error(StatusCode::FORBIDDEN, code, &message) }
    };
    let console = &mut extension.console;
    console.routes = std::mem::take(&mut console.routes)
        .route("/siem", get(page.clone()))
        .route("/siem/archive", get(page));
    extension.routes = std::mem::take(&mut extension.routes).route("/export/records", get(api));
}

// ---------------------------------------------------------------- the replica

/// This replica's name in the table: the host name, and the first hash of its chain, so a new chain on the same host
/// (the log moved aside) is a new replica rather than a repeat of the old numbers. Kept beside the log, since the
/// first record may later be retired.
fn replica_id(path: &FilePath, env: &Env) -> Result<String, String> {
    let mut name = path.as_os_str().to_owned();
    name.push(".replica");
    let file = PathBuf::from(name);
    let host: String = env("HOSTNAME")
        .unwrap_or_else(|| "enterplace".into())
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
        .take(48)
        .collect();
    let host = if host.is_empty() {
        "enterplace".into()
    } else {
        host
    };
    let kept = std::fs::read_to_string(&file)
        .ok()
        .map(|t| t.trim().to_string());
    let first = audit::chain_reader(path).ok().and_then(|mut r| {
        let mut line = String::new();
        std::io::BufRead::read_line(&mut r, &mut line).ok()?;
        let v: Value = serde_json::from_str(&line).ok()?;
        (v["n"] == 1).then(|| v["hash"].as_str().map(str::to_string))?
    });
    let id = match (kept, first) {
        // Record 1 is still there and says which chain this is.
        (Some(kept), Some(hash)) if kept.ends_with(&hash[..12]) => kept,
        (_, Some(hash)) => format!("{host}-{}", &hash[..12]),
        (Some(kept), None) if !kept.is_empty() => kept,
        (_, None) => {
            return Err(format!(
                "the audit log at {} does not start with record 1 and {} is missing, so this replica's records cannot be told from another's. Put back the .replica file kept with the log, or start a new chain.",
                path.display(),
                file.display()
            ));
        }
    };
    std::fs::write(&file, format!("{id}\n")).map_err(|err| {
        format!("{} cannot be written: {err}. Enterplace keeps the replica's name beside its audit log; check that it may write there.", file.display())
    })?;
    Ok(id)
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

pub(crate) fn parse_key(text: &str) -> Option<[u8; 32]> {
    let bytes = unhex(text)?;
    bytes.try_into().ok()
}

// ---------------------------------------------------------------- secrets at rest

pub(crate) fn seal_secret(key: &[u8; 32], plain: &str) -> Result<String, String> {
    use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
    use ring::rand::SecureRandom;
    let mut nonce = [0u8; 12];
    ring::rand::SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| "The system gave no randomness. Try again in a moment.".to_string())?;
    let sealing = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| "the export key is not an AES key")?,
    );
    let mut data = plain.as_bytes().to_vec();
    sealing
        .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut data)
        .map_err(|_| "the secret could not be encrypted".to_string())?;
    Ok(format!(
        "v1:{}{}",
        enterplace_core::id::hex(&nonce),
        enterplace_core::id::hex(&data)
    ))
}

pub(crate) fn open_secret(key: Option<&[u8; 32]>, sealed: &str) -> Result<String, String> {
    use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
    if sealed.is_empty() {
        return Ok(String::new());
    }
    let key = key.ok_or(NO_KEY)?;
    let wrong = "the destination's secret does not open with ENTERPLACE_EXPORT_KEY: the key changed since it was saved. Set the old key back, or save the destination again.";
    let bytes = sealed
        .strip_prefix("v1:")
        .and_then(unhex)
        .filter(|b| b.len() > 12)
        .ok_or(wrong)?;
    let (nonce, data) = bytes.split_at(12);
    let opening = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).map_err(|_| wrong)?);
    let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| wrong)?;
    let mut data = data.to_vec();
    let plain = opening
        .open_in_place(nonce, Aad::empty(), &mut data)
        .map_err(|_| wrong)?;
    String::from_utf8(plain.to_vec()).map_err(|_| wrong.to_string())
}

pub(crate) fn db_error(err: impl std::fmt::Display) -> String {
    format!(
        "The audit export tables could not be read or written: {err}. Check that Postgres is up and the store's connection string is right, then try again."
    )
}

// ---------------------------------------------------------------- reading the chain

/// A record read from the chain: number, hash, prev, time and the line as written.
type Read = (u64, String, String, String, String);

/// Up to `max` records after record `after`, as (number, hash, prev, time, line), from the one file of the chain
/// that holds record `after + 1`. A line still being written is left for the next read.
fn read_after(
    path: &FilePath,
    after: u64,
    max: usize,
    hint: &mut Option<Hint>,
) -> Result<Vec<Read>, String> {
    use std::io::{BufRead, BufReader, Seek, SeekFrom};
    let io_err =
        |err: std::io::Error| format!("the audit log at {} cannot be read: {err}.", path.display());
    let mut files: Vec<(u64, PathBuf)> = audit::segments(path)
        .map_err(io_err)?
        .into_iter()
        .map(|s| (s.first, s.path))
        .collect();
    if let Ok(mut live) = std::fs::File::open(path) {
        let mut start = [0u8; 32];
        let read = std::io::Read::read(&mut live, &mut start).map_err(io_err)?;
        let first = String::from_utf8_lossy(&start[..read])
            .strip_prefix("{\"n\":")
            .and_then(|r| r.split(',').next().map(str::to_string))
            .and_then(|n| n.parse().ok());
        if let Some(first) = first {
            files.push((first, path.to_path_buf()));
        }
    }
    let want = after + 1;
    let Some((first, file)) = files
        .iter()
        .rev()
        .find(|(first, _)| *first <= want)
        .or_else(|| files.first())
        .cloned()
    else {
        return Ok(Vec::new());
    };
    let mut reader = BufReader::new(std::fs::File::open(&file).map_err(io_err)?);
    let mut offset = 0;
    if let Some(h) = hint
        .as_ref()
        .filter(|h| h.file == file && h.first == first && h.next == want)
    {
        offset = h.offset;
        reader.seek(SeekFrom::Start(offset)).map_err(io_err)?;
    }
    let mut out = Vec::new();
    let mut line = Vec::new();
    let mut next = want;
    while out.len() < max {
        line.clear();
        let read = reader.read_until(b'\n', &mut line).map_err(io_err)?;
        if read == 0 || !line.ends_with(b"\n") {
            break;
        }
        offset += read as u64;
        let text = String::from_utf8_lossy(&line[..line.len() - 1]).into_owned();
        let value: Value = serde_json::from_str(&text).map_err(|_| {
            format!(
                "a line of {} is not a record. Run enterplace audit verify {}.",
                file.display(),
                path.display()
            )
        })?;
        let n = value["n"].as_u64().unwrap_or_default();
        if n < want {
            continue;
        }
        let field = |name: &str| value[name].as_str().unwrap_or_default().to_string();
        out.push((n, field("hash"), field("prev"), field("time"), text));
        next = n + 1;
    }
    *hint = Some(Hint {
        file,
        first,
        offset,
        next,
    });
    Ok(out)
}

// ---------------------------------------------------------------- the exporter

struct Settings {
    days: i32,
    hold: bool,
    reason: String,
    by: String,
    at: String,
    pull: bool,
    capture_hours: i32,
}

impl Exporter {
    async fn settings(&self) -> Result<Settings, String> {
        let client = self.db.client().await?;
        let row = client
            .query_one(
                "SELECT retention_days, legal_hold, coalesce(legal_hold_reason, ''), coalesce(legal_hold_by, ''), \
                 coalesce(to_char(legal_hold_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI \"UTC\"'), ''), pull_sha256 IS NOT NULL, \
                 capture_hours FROM enterprise_export_settings",
                &[],
            )
            .await
            .map_err(db_error)?;
        Ok(Settings {
            days: row.try_get(0).map_err(db_error)?,
            hold: row.try_get(1).map_err(db_error)?,
            reason: row.try_get(2).map_err(db_error)?,
            by: row.try_get(3).map_err(db_error)?,
            at: row.try_get(4).map_err(db_error)?,
            pull: row.try_get(5).map_err(db_error)?,
            capture_hours: row.try_get(6).map_err(db_error)?,
        })
    }

    async fn ingested(&self) -> Result<u64, String> {
        let client = self.db.client().await?;
        client
            .execute(
                "INSERT INTO enterprise_replicas (id) VALUES ($1) ON CONFLICT (id) DO UPDATE SET seen_at = now()",
                &[&self.replica],
            )
            .await
            .map_err(db_error)?;
        let n: i64 = client
            .query_one(
                "SELECT ingested_n FROM enterprise_replicas WHERE id = $1",
                &[&self.replica],
            )
            .await
            .map_err(db_error)?
            .try_get(0)
            .map_err(db_error)?;
        Ok(u64::try_from(n).unwrap_or_default())
    }

    /// Copies the records written since the last call into the table. Returns how many.
    pub(crate) async fn ingest(&self) -> Result<usize, String> {
        let after = self.ingested().await?;
        self.read_through
            .fetch_max(after, std::sync::atomic::Ordering::SeqCst);
        let path = self.path.clone();
        let mut hint = self
            .hint
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let (rows, hint) = tokio::task::spawn_blocking(move || {
            read_after(&path, after, READ, &mut hint).map(|rows| (rows, hint))
        })
        .await
        .map_err(|err| format!("the audit reader stopped: {err}"))??;
        *self
            .hint
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = hint;
        let Some(last) = rows.last().map(|r| r.0) else {
            return Ok(0);
        };
        // The records and the cursor past them land together: on the Cloudflare store a transaction cannot roll back.
        let numbers: Vec<i64> = rows
            .iter()
            .map(|r| i64::try_from(r.0).unwrap_or(i64::MAX))
            .collect();
        let last_n = i64::try_from(last).unwrap_or(i64::MAX);
        let mut writes: Vec<(Sql, Vec<&(dyn ToSql + Sync)>, Option<u64>)> = rows
            .iter()
            .zip(&numbers)
            .map(|((_, hash, prev, time, line), n)| {
                (
                    Sql::from(
                        "INSERT INTO enterprise_audit (replica, n, hash, prev, time, line) \
                         VALUES ($1, $2, $3, $4, coalesce(CAST(nullif($5, '') AS timestamptz), now()), $6) ON CONFLICT DO NOTHING",
                    ),
                    vec![
                        &self.replica as &(dyn ToSql + Sync),
                        n,
                        hash,
                        prev,
                        time,
                        line,
                    ],
                    None,
                )
            })
            .collect();
        writes.push((
            Sql::from("UPDATE enterprise_replicas SET ingested_n = $2 WHERE id = $1"),
            vec![&self.replica, &last_n],
            None,
        ));
        self.db
            .client()
            .await?
            .atomic(writes)
            .await
            .map_err(db_error)?;
        self.read_through
            .fetch_max(last, std::sync::atomic::Ordering::SeqCst);
        Ok(rows.len())
    }

    /// Each destination and when it was added, to the microsecond the database keeps: records are timed to the
    /// millisecond, and the record of adding it is written in the same millisecond as the row, just before it.
    async fn destinations(&self) -> Result<Vec<(Dest, String)>, String> {
        let client = self.db.client().await?;
        let rows = client
            .query(
                // SQLite keeps the time as this text already, to the millisecond it was written with.
                Sql::both(
                    "SELECT id, kind, url, secret, options, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') \
                     FROM enterprise_export_destinations ORDER BY id",
                    "SELECT id, kind, url, secret, options, created_at FROM enterprise_export_destinations ORDER BY id",
                ),
                &[],
            )
            .await
            .map_err(db_error)?;
        let mut out = Vec::new();
        for row in rows {
            let get = |i| row.try_get::<_, String>(i).map_err(db_error);
            let Some(kind) = Kind::parse(&get(1)?) else {
                continue;
            };
            out.push((
                Dest {
                    id: row.try_get(0).map_err(db_error)?,
                    kind,
                    url: get(2)?,
                    // Opened when sent, so a key that changed fails that destination and says why.
                    secret: get(3)?,
                    options: serde_json::from_str(&get(4)?).unwrap_or(Value::Null),
                },
                get(5)?,
            ));
        }
        Ok(out)
    }

    /// Records of this replica after `n`, oldest first, at most `limit`.
    async fn after(&self, replica: &str, n: i64, limit: i64) -> Result<Vec<(i64, String)>, String> {
        let client = self.db.client().await?;
        let rows = client
            .query(
                "SELECT n, line FROM enterprise_audit WHERE replica = $1 AND n > $2 ORDER BY n LIMIT $3",
                &[&replica, &n, &limit],
            )
            .await
            .map_err(db_error)?;
        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get(0).map_err(db_error)?,
                    r.try_get(1).map_err(db_error)?,
                ))
            })
            .collect()
    }

    async fn send(&self, dest: &Dest, mut batch: Batch) -> Result<(), String> {
        if dest.kind.per_request() {
            self.join(dest, &mut batch).await?;
        }
        let mut dest = dest.clone();
        dest.secret = open_secret(self.key.as_ref(), &dest.secret)?;
        let sinks = self.sinks.clone();
        tokio::task::spawn_blocking(move || sinks.deliver(&dest, &batch))
            .await
            .map_err(|err| format!("the sender stopped: {err}"))?
    }

    /// For a per-request destination: each usage record's decision record, and its stored text when the
    /// destination opted in for that request's team.
    async fn join(&self, dest: &Dest, batch: &mut Batch) -> Result<(), String> {
        let ids: Vec<String> = batch
            .usage()
            .filter_map(|u| u["id"].as_str().map(str::to_string))
            .collect();
        if ids.is_empty() {
            return Ok(());
        }
        let rows = {
            let client = self.db.client().await?;
            client
                .query(
                    Sql::both(
                        "SELECT line FROM enterprise_audit WHERE replica = $1 AND (line::jsonb)->>'id' = ANY($2) \
                         AND (line::jsonb)->>'event' IS NULL",
                        "SELECT line FROM enterprise_audit WHERE replica = ?1 \
                         AND json_extract(line, '$.id') IN (SELECT value FROM json_each(?2)) \
                         AND json_extract(line, '$.event') IS NULL",
                    ),
                    &[&batch.replica, &ids],
                )
                .await
                .map_err(db_error)?
        };
        for row in rows {
            let line: String = row.try_get(0).map_err(db_error)?;
            let decision: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
            if let Some(id) = decision["id"].as_str() {
                batch.joined.entry(id.to_string()).or_default().decision = decision.clone();
            }
        }
        if capture::opted_in(dest).is_some() {
            for (id, (team, text)) in capture::texts(&self.db, self.key.as_ref(), &ids).await? {
                if capture::for_dest(dest, &team) {
                    batch.joined.entry(id).or_default().text = Some(text);
                }
            }
        }
        Ok(())
    }

    /// Stores the text captured since the last tick for the destinations that opted in, and deletes expired text.
    async fn captured(&self, dests: &[Dest]) -> Result<(), String> {
        let Some(captures) = &self.captures else {
            return Ok(());
        };
        captures.set(dests);
        let hours = self.settings().await?.capture_hours;
        captures
            .flush(&self.db, &self.replica, self.key.as_ref(), hours)
            .await?;
        capture::prune(&self.db).await?;
        Ok(())
    }

    /// Records the outcome of a delivery on the destination.
    async fn outcome(&self, id: i64, result: &Result<usize, String>) -> Result<(), String> {
        let client = self.db.client().await?;
        match result {
            Ok(count) => client
                .execute(
                    "UPDATE enterprise_export_destinations SET last_success_at = now(), delivered = delivered + $2 WHERE id = $1",
                    &[&id, &i64::try_from(*count).unwrap_or_default()],
                )
                .await,
            Err(err) => client
                .execute(
                    "UPDATE enterprise_export_destinations SET last_error = $2, last_error_at = now() WHERE id = $1",
                    &[&id, err],
                )
                .await,
        }
        .map_err(db_error)?;
        Ok(())
    }

    /// Sends each destination this replica's next batch, past its cursor. A destination that failed waits, doubling
    /// up to five minutes.
    pub(crate) async fn ship(&self) -> Result<(), String> {
        let dests = self.destinations().await?;
        self.captured(&dests.iter().map(|d| d.0.clone()).collect::<Vec<_>>())
            .await?;
        for (dest, created) in dests {
            let waiting = self
                .backoff
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&dest.id)
                .is_some_and(|(_, until)| Instant::now() < *until);
            if waiting {
                continue;
            }
            let cursor = {
                let client = self.db.client().await?;
                // A new destination starts with the records written after it was added; backfill sends older ones.
                // One stamped in the very millisecond it was added was written before (the record of adding it).
                client
                    .execute(
                        "INSERT INTO enterprise_export_cursors (destination, replica, n, hash) \
                         SELECT $1, $2, coalesce(max(n), 0), '' FROM enterprise_audit \
                         WHERE replica = $2 AND time <= CAST($3::text AS timestamptz) ON CONFLICT DO NOTHING",
                        &[&dest.id, &self.replica, &created],
                    )
                    .await
                    .map_err(db_error)?;
                let n: i64 = client
                    .query_one(
                        "SELECT n FROM enterprise_export_cursors WHERE destination = $1 AND replica = $2",
                        &[&dest.id, &self.replica],
                    )
                    .await
                    .map_err(db_error)?
                    .try_get(0)
                    .map_err(db_error)?;
                n
            };
            let rows = self.after(&self.replica, cursor, BATCH as i64).await?;
            let Some((last, _)) = rows.last().cloned() else {
                continue;
            };
            let batch = Batch::new(
                self.replica.clone(),
                rows.into_iter().map(|r| r.1).collect(),
            );
            let count = batch.lines.len();
            let last_hash = batch
                .records
                .last()
                .and_then(|r| r["hash"].as_str())
                .unwrap_or_default()
                .to_string();
            let result = self.send(&dest, batch).await.map(|()| count);
            if result.is_ok() {
                let client = self.db.client().await?;
                client
                    .execute(
                        "UPDATE enterprise_export_cursors SET n = $3, hash = $4 WHERE destination = $1 AND replica = $2",
                        &[&dest.id, &self.replica, &last, &last_hash],
                    )
                    .await
                    .map_err(db_error)?;
            }
            self.outcome(dest.id, &result).await?;
            let mut backoff = self
                .backoff
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match &result {
                Ok(_) => {
                    backoff.remove(&dest.id);
                }
                Err(err) => {
                    let fails = backoff.get(&dest.id).map_or(0, |(f, _)| *f) + 1;
                    let wait = Duration::from_secs(1u64 << fails.min(9)).min(BACKOFF_MAX);
                    backoff.insert(dest.id, (fails, Instant::now() + wait));
                    drop(backoff);
                    self.say(&format!(
                        "audit export to destination {} ({}) failed: {err} Trying again in {}s.",
                        dest.id,
                        dest.kind.word(),
                        wait.as_secs()
                    ));
                }
            }
        }
        Ok(())
    }

    /// Lets a failing destination be tried at once (a test record, a fixed destination).
    fn retry_now(&self, id: i64) {
        self.backoff
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&id);
    }

    fn say(&self, line: &str) {
        let mut said = self
            .said
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *said != line {
            eprintln!("enterplace: {line}");
            *said = line.to_string();
        }
    }

    /// Seals yesterday's records, retires segments past the retention period, and prunes the table. Returns what it
    /// did, as the page shows it.
    pub(crate) async fn retain(&self) -> Result<String, String> {
        let settings = self.settings().await?;
        let note = if settings.hold {
            "Legal hold is on: nothing was sealed or deleted.".to_string()
        } else {
            self.retire(settings.days).await?
        };
        let client = self.db.client().await?;
        client
            .execute(
                "INSERT INTO enterprise_replicas (id, retention_at, retention_note) VALUES ($1, now(), $2) \
                 ON CONFLICT (id) DO UPDATE SET retention_at = now(), retention_note = $2",
                &[&self.replica, &note],
            )
            .await
            .map_err(db_error)?;
        Ok(note)
    }

    async fn retire(&self, days: i32) -> Result<String, String> {
        let now = SystemTime::now();
        let today = audit::timestamp().get(..10).unwrap_or_default().to_string();
        let midnight = sinks::parse_time(&format!("{today}T00:00:00.000Z")).unwrap_or(now);
        let month = sinks::parse_time(&format!(
            "{}-01T00:00:00.000Z",
            &today[..7.min(today.len())]
        ))
        .unwrap_or(now);
        // Never this month: spend is replayed from the log at start.
        let cutoff =
            (now - Duration::from_secs(u64::try_from(days).unwrap_or(365) * 86_400)).min(month);
        let safe = if self.siem {
            let client = self.db.client().await?;
            let row = client
                .query_one(
                    "SELECT coalesce((SELECT min(n) FROM enterprise_export_cursors WHERE replica = $1), $2::bigint)",
                    &[&self.replica, &i64::MAX],
                )
                .await
                .map_err(db_error)?;
            let sent: i64 = row.try_get(0).map_err(db_error)?;
            // The one connection is free again before `ingested` asks for it.
            drop(client);
            let ingested = i64::try_from(self.ingested().await?).unwrap_or_default();
            u64::try_from(sent.min(ingested)).unwrap_or_default()
        } else {
            u64::MAX
        };
        let (log, path) = (self.log.clone(), self.path.clone());
        let done = tokio::task::spawn_blocking(move || -> Result<String, String> {
            // Sealed once a day, so whole days are retired.
            let live_old = std::fs::File::open(&path).ok().and_then(|f| {
                let mut line = String::new();
                std::io::BufRead::read_line(&mut std::io::BufReader::new(f), &mut line).ok()?;
                let v: Value = serde_json::from_str(&line).ok()?;
                sinks::parse_time(v["time"].as_str()?)
            });
            let mut notes = Vec::new();
            if live_old.is_some_and(|t| t < midnight) {
                match log.seal() {
                    Ok(Some(sealed)) => notes.push(format!("sealed {}", sealed.display())),
                    Ok(None) => {}
                    Err(err) => notes.push(format!("could not seal the log ({err})")),
                }
            }
            let mut through = None;
            for segment in audit::segments(&path).map_err(|e| e.to_string())? {
                let old = std::fs::metadata(&segment.path)
                    .and_then(|m| m.modified())
                    .is_ok_and(|t| t < cutoff);
                if !old || segment.last > safe {
                    break;
                }
                through = Some(segment.last);
            }
            let retired = match through {
                Some(through) => audit::retire(&log, &path, through)?,
                None => None,
            };
            notes.push(match retired {
                Some(r) => format!(
                    "retired records {} to {} ({} segments)",
                    r.from,
                    r.through,
                    r.files.len()
                ),
                None => "no sealed segment is past the retention period".into(),
            });
            Ok(notes.join("; "))
        })
        .await
        .map_err(|err| format!("retention stopped: {err}"))??;
        if self.siem {
            let client = self.db.client().await?;
            let cutoff = audit::rfc3339(cutoff);
            let gone = client
                .execute(
                    "DELETE FROM enterprise_audit WHERE time < CAST($1::text AS timestamptz)",
                    &[&cutoff],
                )
                .await
                .map_err(db_error)?;
            if gone > 0 {
                return Ok(format!(
                    "{done}; deleted {gone} exported copies before {cutoff}"
                ));
            }
        }
        Ok(done)
    }

    async fn run(self: Arc<Self>, tick: Duration) {
        let mut retained: Option<Instant> = None;
        let mut held: Option<Instant> = None;
        loop {
            // Legal hold covers the request log's kept bodies too: the gateway deletes none while it is on. Read
            // before the first wait, so a replica that just started never deletes one before it knows.
            if self.retention && held.is_none_or(|at| at.elapsed() >= HOLD_EVERY) {
                held = Some(Instant::now());
                match self.settings().await {
                    Ok(settings) => enterplace_core::insights::hold(&self.path, settings.hold),
                    Err(err) => self.say(&format!("legal hold: {err}")),
                }
            }
            tokio::time::sleep(tick).await;
            if self.siem || self.alerts_on {
                let read = async {
                    while self.ingest().await? == READ {}
                    Ok::<(), String>(())
                }
                .await;
                if let Some(engine) = self.alerts.get() {
                    engine.tick(read.as_ref().err()).await;
                }
                let worked = match read {
                    Ok(()) if self.siem => self.ship().await,
                    other => other,
                };
                if let Err(err) = worked {
                    self.say(&format!("audit export: {err}"));
                }
            }
            if self.retention && retained.is_none_or(|at| at.elapsed() >= RETENTION_EVERY) {
                retained = Some(Instant::now());
                if let Err(err) = self.retain().await {
                    self.say(&format!("audit retention: {err}"));
                }
            }
        }
    }
}

// ---------------------------------------------------------------- who may do what

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Owner,
    Admin,
    Viewer,
}

/// As the members feature maps it: an admin key acts as owner, single sign-on as admin (viewer when read only).
pub(crate) fn role_of(admin: &Admin) -> Role {
    match &admin.via {
        _ if admin.read_only => Role::Viewer,
        Via::Key => Role::Owner,
        Via::Account(_) if admin.role == "owner" => Role::Owner,
        _ => Role::Admin,
    }
}

pub(crate) fn banner(text: &str, error: bool) -> String {
    let edge = if error {
        r#" style="border-color: var(--flame)""#
    } else {
        ""
    };
    format!(
        r#"<div class="g-banner" role="alert"{edge}><span class="t-body">{}</span></div>"#,
        esc(text)
    )
}

pub(crate) fn hidden(name: &str, value: &str) -> String {
    format!(
        r#"<input type="hidden" name="{name}" value="{}">"#,
        esc(value)
    )
}

pub(crate) fn small_button(label: &str) -> String {
    format!(
        r#"<button class="g-btn g-btn--quiet g-btn--sm t-small" type="submit">{label}</button>"#
    )
}

pub(crate) fn input(id: &str, label: &str, value: &str, extra: &str, hint: &str) -> String {
    html::field(&Field {
        id,
        name: id,
        label,
        value,
        mono: false,
        extra,
        hint,
        error: "",
    })
}

pub(crate) fn section(title: &str, inner: &str) -> String {
    format!(
        r#"<section class="g-section g-stack"><h2 class="t-md" style="margin: 0">{title}</h2>{inner}</section>"#
    )
}

fn form(action: &str, inner: &str) -> String {
    format!(
        r#"<form method="post" action="/console/siem" class="g-stack">{}{inner}</form>"#,
        hidden("action", action)
    )
}

// ---------------------------------------------------------------- the page

async fn page(
    State(console): State<Console>,
    Ext(export): Ext<Export>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let Some(admin) = console.signed_in(&headers).await else {
        return redirect("/console/sign-in");
    };
    show(&console, &export, &admin, &uri, "", false, "").await
}

async fn show(
    console: &Console,
    export: &Export,
    admin: &Admin,
    uri: &Uri,
    notice: &str,
    error: bool,
    once: &str,
) -> Response {
    match main(export, admin, notice, error, once).await {
        Ok(main) => console.page(StatusCode::OK, admin, NAV, uri, &main),
        Err(err) => console.page(
            StatusCode::SERVICE_UNAVAILABLE,
            admin,
            NAV,
            uri,
            &format!("{}{}", html::head(NAV, "", ""), banner(&err, true)),
        ),
    }
}

async fn main(
    export: &Export,
    admin: &Admin,
    notice: &str,
    error: bool,
    once: &str,
) -> Result<String, String> {
    let ex = &export.exporter;
    let role = role_of(admin);
    let edit = role != Role::Viewer;
    let owner = role == Role::Owner;
    let settings = ex.settings().await?;
    let mut out = html::head(
        NAV,
        "Send every replica's audit records to your SIEM or storage as they are written, and decide how long the log is kept. Prompts and answers are never in the log, so never exported.",
        "",
    );
    if !notice.is_empty() {
        out += &banner(notice, error);
    }
    out += once;
    if ex.siem {
        out += &destinations_section(export, edit).await?;
        out += &pull_section(&settings, owner);
        let hours = settings.capture_hours;
        out += &section(
            "Captured text",
            &format!(
                r#"<p class="t-body" style="margin: 0">Prompt and answer text is captured only while a destination opts in, redacted before it is stored, and deleted <span class="t-mono-sm" id="capture-hours">{hours}</span> hours after its request, sent or not. It is never in the audit log.</p>{}"#,
                if edit {
                    form(
                        "capture_hours",
                        &format!(
                            r#"<div class="g-toolbar">{}{}</div>"#,
                            input(
                                "hours",
                                "Hours",
                                &hours.to_string(),
                                r#" type="number" min="1" max="168" required"#,
                                "1 to 168."
                            ),
                            html::button("Save", "", "submit", "")
                        ),
                    )
                } else {
                    String::new()
                }
            ),
        );
        if edit {
            let today = audit::timestamp().get(..10).unwrap_or_default().to_string();
            out += &section(
                "Archive",
                &format!(
                    r#"<form method="get" action="/console/siem/archive" class="g-toolbar">{}{}{}</form><p class="t-small g-muted" style="margin: 0">Newline-delimited JSON of every replica's records in those days (UTC, inclusive), each line as the log wrote it, in chain order per replica.</p>"#,
                    input("from", "From", &today, r#" type="date" required"#, ""),
                    input("to", "To", &today, r#" type="date" required"#, ""),
                    html::button("Download archive", "quiet", "submit", "")
                ),
            );
        }
    }
    if ex.retention {
        out += &retention_section(export, &settings, edit, owner).await?;
    }
    Ok(out)
}

async fn destinations_section(export: &Export, edit: bool) -> Result<String, String> {
    let ex = &export.exporter;
    let client = ex.db.client().await?;
    let rows = client
        .query(
            "SELECT d.id, d.kind, d.url, d.delivered, \
             coalesce(to_char(d.last_success_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS \"UTC\"'), 'never'), \
             coalesce(d.last_error, ''), coalesce(to_char(d.last_error_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS \"UTC\"'), ''), \
             (SELECT count(*) FROM enterprise_audit a LEFT JOIN enterprise_export_cursors c ON c.destination = d.id AND c.replica = a.replica \
              WHERE a.n > coalesce(c.n, 0) AND a.time > d.created_at), d.options \
             FROM enterprise_export_destinations d ORDER BY d.id",
            &[],
        )
        .await
        .map_err(db_error)?;
    let replicas = client
        .query(
            "SELECT r.id, r.ingested_n, coalesce(string_agg(d.id || ': ' || c.n, ', ' ORDER BY d.id), '') \
             FROM enterprise_replicas r LEFT JOIN enterprise_export_cursors c ON c.replica = r.id \
             LEFT JOIN enterprise_export_destinations d ON d.id = c.destination GROUP BY r.id, r.ingested_n ORDER BY r.id",
            &[],
        )
        .await
        .map_err(db_error)?;
    drop(client);
    let mut list = String::new();
    let mut options = String::new();
    for row in &rows {
        let id: i64 = row.try_get(0).map_err(db_error)?;
        let text = |i| row.try_get::<_, String>(i).map_err(db_error);
        let kind = Kind::parse(&text(1)?).map_or("unknown", Kind::label);
        let delivered: i64 = row.try_get(3).map_err(db_error)?;
        let pending: i64 = row.try_get(7).map_err(db_error)?;
        let last_error = match text(5)? {
            e if e.is_empty() => "none".to_string(),
            e => format!("{} at {}", e, text(6)?),
        };
        let facts = html::facts(&[
            (
                "Delivered",
                format!(r#"<span id="delivered-{id}">{delivered}</span>"#),
            ),
            (
                "Waiting",
                format!(r#"<span id="pending-{id}">{pending}</span>"#),
            ),
            ("Last success", esc(&text(4)?)),
            (
                "Prompt text",
                format!(r#"<span id="text-{id}">{}</span>"#, {
                    let options: Value = serde_json::from_str(&text(8)?).unwrap_or(Value::Null);
                    match (
                        options["text"] == true,
                        options["text_teams"].as_str().unwrap_or_default(),
                    ) {
                        (false, _) => "never sent".to_string(),
                        (true, "") => "sent redacted, every team".to_string(),
                        (true, teams) => format!("sent redacted, teams {}", esc(teams)),
                    }
                }),
            ),
            (
                "Last error",
                format!(r#"<span id="error-{id}">{}</span>"#, esc(&last_error)),
            ),
        ]);
        let end = if edit {
            format!(
                r#"<form method="post" action="/console/siem">{}{}{}</form><form method="post" action="/console/siem">{}{}{}</form>"#,
                hidden("action", "test"),
                hidden("id", &id.to_string()),
                small_button("Send a test record"),
                hidden("action", "remove"),
                hidden("id", &id.to_string()),
                small_button("Remove")
            )
        } else {
            String::new()
        };
        list += &html::row(
            &format!("{id}. {}", esc(kind)),
            &format!("{}{facts}", esc(&text(2)?)),
            &end,
            false,
        );
        options += &format!(r#"<option value="{id}">{id}. {}</option>"#, esc(kind));
    }
    if rows.is_empty() {
        list = r#"<p class="t-body g-muted">No destination. Audit records stay in each replica's log and in this database only.</p>"#.into();
    }
    let mut replica_rows = String::new();
    for r in &replicas {
        let id: String = r.try_get(0).map_err(db_error)?;
        let n: i64 = r.try_get(1).map_err(db_error)?;
        let cursors: String = r.try_get(2).map_err(db_error)?;
        replica_rows += &html::row(
            &esc(&id),
            &format!(
                "read up to record {n}; sent up to (destination: record) {}",
                esc(if cursors.is_empty() {
                    "none yet"
                } else {
                    &cursors
                })
            ),
            "",
            true,
        );
    }
    let kinds: String = KINDS
        .iter()
        .map(|k| format!(r#"<option value="{}">{}</option>"#, k.word(), k.label()))
        .collect();
    let add = if edit {
        section(
            "Add a destination",
            &form(
                "save",
                &format!(
                    r#"<div class="g-select-wrap"><select class="g-input g-select t-body" name="kind" aria-label="Kind">{kinds}</select>{}</div>{}{}{}{}{}{}{}{}{}<div class="g-head__actions">{}</div>"#,
                    html::icon("down"),
                    input(
                        "url",
                        "URL",
                        "",
                        " required",
                        "https only. Splunk: https://splunk:8088/services/collector/event. Datadog: https://http-intake.logs.datadoghq.com/api/v2/logs. Elasticsearch: the index, https://es:9200/enterplace-audit. OTLP: https://collector:4318/v1/logs. Sentinel: the data collection endpoint's stream URL. S3: https://s3.eu-west-1.amazonaws.com/bucket/prefix. GCS: https://storage.googleapis.com/bucket/prefix. Azure: https://account.blob.core.windows.net/container/prefix. LLM traces: https://phoenix:6006/v1/traces, or http://localhost:4318/v1/traces for a Datadog Agent. Langfuse: https://cloud.langfuse.com. Callback: your HTTPS endpoint."
                    ),
                    input(
                        "token",
                        "Secret",
                        "",
                        r#" type="password" autocomplete="off""#,
                        "Splunk HEC token, Datadog API key, Elasticsearch API key, OTLP header value, Sentinel client secret, S3 secret access key, GCS service account JSON key, or an Azure SAS token. Leave empty for a webhook (Enterplace makes its signing secret) or to use the replica's cloud identity."
                    ),
                    input(
                        "header",
                        "OTLP header",
                        "",
                        "",
                        "The header the OTLP secret goes in. Empty: Authorization: Bearer."
                    ),
                    input(
                        "region",
                        "Region",
                        "",
                        "",
                        "S3 only. us-east-1 when empty; auto for Cloudflare R2."
                    ),
                    input(
                        "access_key_id",
                        "Access key ID",
                        "",
                        r#" autocomplete="off""#,
                        "S3 only. Empty: the AWS default credential chain (IAM role)."
                    ),
                    input(
                        "public_key",
                        "Public key",
                        "",
                        r#" autocomplete="off""#,
                        "Langfuse only: the project's public key, pk-lf-..."
                    ),
                    input(
                        "tenant",
                        "Tenant ID",
                        "",
                        "",
                        "Sentinel, or Azure workload identity."
                    ),
                    input(
                        "client_id",
                        "Client ID",
                        "",
                        "",
                        "Sentinel app registration, or a user-assigned managed identity."
                    ),
                    String::from(
                        r#"<label class="t-body"><input type="checkbox" name="text"> Send prompt and answer text, redacted</label><p class="t-small g-muted" style="margin: 0">Trace and callback destinations only. Off by default. Text is captured at request time from then on, redacted by Enterplace's secrets and PII detectors, kept encrypted and apart from the audit log for the hours set below, and sent only here. The choice is recorded in the audit log.</p>"#
                    ) + &input(
                        "text_teams",
                        "Text for teams",
                        "",
                        "",
                        "Comma-separated teams whose text is sent. Empty: every team."
                    ),
                    html::button("Save destination", "", "submit", "")
                ),
            ),
        ) + &if rows.is_empty() {
            String::new()
        } else {
            section(
                "Backfill",
                &form(
                    "backfill",
                    &format!(
                        r#"<div class="g-toolbar"><div class="g-select-wrap"><select class="g-input g-select t-body" name="id" aria-label="Destination">{options}</select>{}</div>{}{}</div><p class="t-small g-muted" style="margin: 0">Sends up to {BACKFILL_MAX} of the newest records of those days, per replica in chain order, in batches of {BATCH}. Cursors do not move: records may arrive twice.</p>"#,
                        html::icon("down"),
                        input(
                            "days",
                            "Days",
                            "7",
                            r#" type="number" min="1" max="90" required"#,
                            "1 to 90."
                        ),
                        html::button("Send past records", "quiet", "submit", "")
                    ),
                ),
            )
        }
    } else {
        String::new()
    };
    Ok(section(
        "Destinations",
        &format!(r#"<section class="g-list">{list}</section>"#),
    ) + &add
        + &section(
            "Replicas",
            &if replica_rows.is_empty() {
                r#"<p class="t-body g-muted">No replica has read its log yet.</p>"#.into()
            } else {
                format!(r#"<section class="g-list">{replica_rows}</section>"#)
            },
        ))
}

fn pull_section(settings: &Settings, owner: bool) -> String {
    let state = if settings.pull {
        "A pull token is active."
    } else {
        "No pull token."
    };
    let buttons = if owner {
        let mut b = form(
            "pull_new",
            &small_button(if settings.pull {
                "Replace pull token"
            } else {
                "Create pull token"
            }),
        );
        if settings.pull {
            b += &form("pull_off", &small_button("Revoke pull token"));
        }
        format!(r#"<div class="g-toolbar">{b}</div>"#)
    } else {
        r#"<p class="t-small g-muted" style="margin: 0">Only an owner can create or revoke the pull token.</p>"#.into()
    };
    section(
        "Pull API",
        &format!(
            r#"<p class="t-body" style="margin: 0">A SIEM that cannot receive a POST fetches records itself: <span class="t-mono-sm">GET /export/records?after=0&amp;limit=500</span> with <span class="t-mono-sm">Authorization: Bearer gpull_...</span> on any replica. Pass each answer's <span class="t-mono-sm">next</span> as the following call's <span class="t-mono-sm">after</span>.</p><p class="t-body" style="margin: 0">{state}</p>{buttons}"#
        ),
    )
}

async fn retention_section(
    export: &Export,
    settings: &Settings,
    edit: bool,
    owner: bool,
) -> Result<String, String> {
    let client = export.exporter.db.client().await?;
    let notes = client
        .query(
            "SELECT id, coalesce(to_char(retention_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI \"UTC\"'), 'not yet'), coalesce(retention_note, '') \
             FROM enterprise_replicas ORDER BY id",
            &[],
        )
        .await
        .map_err(db_error)?;
    drop(client);
    let mut runs = String::new();
    for r in &notes {
        let text = |i| r.try_get::<_, String>(i).map_err(db_error);
        runs += &html::row(
            &esc(&text(0)?),
            &format!("{}: {}", esc(&text(1)?), esc(&text(2)?)),
            "",
            true,
        );
    }
    let days = settings.days;
    let mut retention = format!(
        r#"<p class="t-body" style="margin: 0">Each replica seals its log once a day. Sealed segments older than <span class="t-mono-sm" id="retention-days">{days}</span> days (and older than this month) are deleted every hour{}, after every destination has them. Each deletion is a record in the chain naming what went, so <span class="t-mono-sm">enterplace audit verify</span> still proves the rest.</p>"#,
        if settings.hold {
            ", but not while legal hold is on"
        } else {
            ""
        }
    );
    if edit {
        retention += &form(
            "retention",
            &format!(
                r#"<div class="g-toolbar">{}{}</div>"#,
                input(
                    "retention_days",
                    "Retention in days",
                    &days.to_string(),
                    r#" type="number" min="30" max="3650" required"#,
                    "30 to 3650."
                ),
                html::button("Save retention", "", "submit", "")
            ),
        );
    }
    if !runs.is_empty() {
        retention += &format!(r#"<section class="g-list">{runs}</section>"#);
    }
    let hold = if settings.hold {
        format!(
            "Legal hold is <strong>on</strong> since {}, set by {}: {}. Nothing is deleted.",
            esc(&settings.at),
            esc(&settings.by),
            esc(&settings.reason)
        )
    } else {
        "Legal hold is off.".into()
    };
    let hold_form = if owner {
        form(
            if settings.hold { "hold_off" } else { "hold_on" },
            &format!(
                "{}{}",
                input(
                    "reason",
                    "Reason",
                    "",
                    " required",
                    "Recorded in the audit log."
                ),
                html::button(
                    if settings.hold {
                        "Turn off legal hold"
                    } else {
                        "Turn on legal hold"
                    },
                    "",
                    "submit",
                    ""
                )
            ),
        )
    } else {
        r#"<p class="t-small g-muted" style="margin: 0">Only an owner can change legal hold.</p>"#
            .into()
    };
    Ok(section("Retention", &retention)
        + &section(
            "Legal hold",
            &format!(r#"<p class="t-body" style="margin: 0">{hold}</p>{hold_form}"#),
        ))
}

// ---------------------------------------------------------------- changes

async fn act(
    State(console): State<Console>,
    Ext(export): Ext<Export>,
    headers: HeaderMap,
    uri: Uri,
    body: String,
) -> Response {
    if !same_origin(&headers) {
        return foreign();
    }
    let Some(admin) = console.signed_in(&headers).await else {
        return redirect("/console/sign-in");
    };
    let form = Form::parse(&body);
    let action = form.get("action").to_string();
    let (notice, error, once) = match change(&console, &export, &admin, &form, &action).await {
        Ok((notice, once)) => (notice, false, once),
        Err(err) => (err, true, String::new()),
    };
    show(&console, &export, &admin, &uri, &notice, error, &once).await
}

/// Does one change, recorded first. `Ok` is the notice and anything shown once; `Err` the message to show.
async fn change(
    console: &Console,
    export: &Export,
    admin: &Admin,
    form: &Form,
    action: &str,
) -> Result<(String, String), String> {
    let ex = &export.exporter;
    let action: &'static str = match action {
        "save" => "export_destination_saved",
        "test" => "export_test_sent",
        "remove" => "export_destination_removed",
        "backfill" => "export_backfill",
        "pull_new" => "export_pull_token_created",
        "pull_off" => "export_pull_token_revoked",
        "retention" => "retention_set",
        "hold_on" => "legal_hold_on",
        "hold_off" => "legal_hold_off",
        "capture_hours" => "export_capture_hours_set",
        _ => return Err("Unknown action. Use the buttons on this page.".into()),
    };
    let refuse = |code: &'static str, details: Value, message: String| async move {
        let _ = console
            .audit(Some(admin), action, details, Some(code))
            .await;
        Err::<(String, String), String>(message)
    };
    let role = role_of(admin);
    if role == Role::Viewer {
        return refuse(
            "read_only",
            json!({}),
            "Your role is viewer. An owner or admin can make this change.".into(),
        )
        .await;
    }
    let needs = match action {
        "retention_set" | "legal_hold_on" | "legal_hold_off" => (RETENTION, ex.retention),
        _ => (SIEM, ex.siem),
    };
    if !needs.1 {
        return refuse(
            crate::license::LICENSE_REQUIRED,
            json!({ "feature": needs.0 }),
            format!(
                "This install's license does not include {}. Ask Enterplace to add it.",
                needs.0
            ),
        )
        .await;
    }
    let owner_only = matches!(
        action,
        "legal_hold_on"
            | "legal_hold_off"
            | "export_pull_token_created"
            | "export_pull_token_revoked"
    );
    if owner_only && role != Role::Owner {
        return refuse(
            "owner_only",
            json!({}),
            "Only an owner can change this. Ask an owner of this install.".into(),
        )
        .await;
    }
    let record = |details: Value| async move {
        console
            .audit(Some(admin), action, details, None)
            .await
            .map_err(str::to_string)
    };
    let id: i64 = form.get("id").trim().parse().unwrap_or(-1);
    match action {
        "export_destination_saved" => {
            let Some(kind) = Kind::parse(form.get("kind")) else {
                return Err("Choose a destination kind from the list.".into());
            };
            let url = form.get("url").trim().to_string();
            if !sinks::url_ok(&url) {
                return refuse(
                    "invalid_url",
                    json!({ "kind": kind.word() }),
                    "The destination URL must use https:// (plain http only to this machine)."
                        .into(),
                )
                .await;
            }
            let token = form.get("token").trim().to_string();
            if kind.needs_secret() && !kind.signs() && token.is_empty() {
                return Err(format!(
                    "Enter the {} in Secret.",
                    match kind {
                        Kind::Datadog => "Datadog API key",
                        Kind::Elastic => "Elasticsearch API key",
                        Kind::Langfuse => "Langfuse secret key (sk-lf-...)",
                        _ => "HEC token",
                    }
                ));
            }
            if kind == Kind::Langfuse && form.get("public_key").trim().is_empty() {
                return Err("Enter the Langfuse public key (pk-lf-...) in Public key.".into());
            }
            let text = form.get("text") == "on";
            if text && !kind.per_request() {
                return refuse(
                    "text_not_supported",
                    json!({ "kind": kind.word() }),
                    "Prompt and answer text can only go to a trace or callback destination (LLM traces, Langfuse, HTTP callback). Audit destinations get the records, which hold no text.".into(),
                )
                .await;
            }
            if text && ex.key.is_none() {
                return Err(format!("Captured text is kept encrypted. {NO_KEY}"));
            }
            if kind == Kind::S3 && !form.get("access_key_id").trim().is_empty() && token.is_empty()
            {
                return Err("With an access key ID, enter its secret access key in Secret.".into());
            }
            let secret = if kind.signs() {
                format!("gsig_{}", random_hex(32)?)
            } else {
                token
            };
            let sealed = match (&ex.key, secret.is_empty()) {
                (_, true) => String::new(),
                (Some(key), false) => seal_secret(key, &secret)?,
                (None, false) => return Err(NO_KEY.into()),
            };
            let mut options: serde_json::Map<String, Value> = [
                "header",
                "region",
                "access_key_id",
                "tenant",
                "client_id",
                "public_key",
            ]
            .into_iter()
            .filter(|k| !form.get(k).trim().is_empty())
            .map(|k| (k.to_string(), Value::from(form.get(k).trim())))
            .collect();
            let text_teams = capture::teams(form.get("text_teams")).join(",");
            if text {
                options.insert("text".into(), Value::from(true));
                options.insert("text_teams".into(), Value::from(text_teams.clone()));
            }
            // The opt-in is in the record, so who turned text on, for which teams, is in the chain.
            record(
                json!({ "kind": kind.word(), "url": url, "text": text, "text_teams": text_teams }),
            )
            .await?;
            // Added as of now on this process's clock, the one records are stamped with: Postgres's now() runs on
            // another machine's clock, and a few milliseconds behind would ship the record above as a new one.
            let created = enterplace_core::audit::timestamp();
            let client = ex.db.client().await?;
            let row = client
                .query_one(
                    "INSERT INTO enterprise_export_destinations (kind, url, secret, options, created_by, created_at) VALUES ($1, $2, $3, $4, $5, CAST($6::text AS timestamptz)) RETURNING id",
                    &[&kind.word(), &url, &sealed, &Value::Object(options).to_string(), &admin.name, &created],
                )
                .await
                .map_err(db_error)?;
            let id: i64 = row.try_get(0).map_err(db_error)?;
            let once = if kind.signs() {
                section(
                    "Signing secret",
                    &format!(
                        r#"<p class="t-body" style="margin: 0">Verify each POST with an HMAC-SHA256 of the raw body under this secret, sent as <span class="t-mono-sm">x-enterplace-signature: sha256=&lt;hex&gt;</span>. It is shown once.</p><span class="g-command g-command--value"><span class="g-command__text t-mono" id="signing-secret">{}</span></span>"#,
                        esc(&secret)
                    ),
                )
            } else {
                String::new()
            };
            Ok((
                format!(
                    "Saved destination {id}. New audit records are sent to it as they are written."
                ),
                once,
            ))
        }
        "export_test_sent" => {
            let dest = ex
                .destinations()
                .await?
                .into_iter()
                .find(|(d, _)| d.id == id)
                .ok_or("There is no such destination.")?
                .0;
            let line = format!(
                r#"{{"n":0,"event":"test","time":"{}","prev":"{}","hash":"test-{}"}}"#,
                audit::timestamp(),
                "0".repeat(64),
                random_hex(16)?
            );
            record(json!({ "destination": id })).await?;
            let result = ex
                .send(&dest, Batch::new(ex.replica.clone(), vec![line]))
                .await;
            ex.outcome(id, &result.clone().map(|()| 1)).await?;
            ex.retry_now(id);
            match result {
                Ok(()) => Ok(("The test record was delivered.".into(), String::new())),
                Err(err) => Err(format!("The test record failed: {err}")),
            }
        }
        "export_destination_removed" => {
            record(json!({ "destination": id })).await?;
            let client = ex.db.client().await?;
            client
                .execute(
                    "DELETE FROM enterprise_export_destinations WHERE id = $1",
                    &[&id],
                )
                .await
                .map_err(db_error)?;
            Ok((format!("Removed destination {id}."), String::new()))
        }
        "export_backfill" => {
            let days: i32 = form.get("days").trim().parse().unwrap_or(0);
            if !(1..=90).contains(&days) {
                return Err("Days is a whole number from 1 to 90.".into());
            }
            let dest = ex
                .destinations()
                .await?
                .into_iter()
                .find(|(d, _)| d.id == id)
                .ok_or("There is no such destination.")?
                .0;
            record(json!({ "destination": id, "days": days })).await?;
            let sent = backfill(ex, &dest, days).await;
            let (count, failed) = match sent {
                Ok(count) => (count, None),
                Err((count, err)) => (count, Some(err)),
            };
            ex.outcome(
                id,
                &match &failed {
                    Some(err) => Err(err.clone()),
                    None => Ok(count),
                },
            )
            .await?;
            match failed {
                Some(err) => Err(format!(
                    "Sent {count} records, then the destination failed: {err} Fix it and send again; your SIEM may see some records twice."
                )),
                None if count as i64 == BACKFILL_MAX => Ok((
                    format!(
                        "Sent the newest {count} records of the last {days} days. Use the archive or the pull API for older ones."
                    ),
                    String::new(),
                )),
                None => Ok((
                    format!("Sent {count} records from the last {days} days."),
                    String::new(),
                )),
            }
        }
        "export_pull_token_created" => {
            let token = format!("gpull_{}", random_hex(32)?);
            record(json!({})).await?;
            let client = ex.db.client().await?;
            client
                .execute(
                    "UPDATE enterprise_export_settings SET pull_sha256 = $1",
                    &[&enterplace_core::id::sha256_hex(token.as_bytes())],
                )
                .await
                .map_err(db_error)?;
            Ok((
                "Created a pull token. Any earlier one stops working.".into(),
                section(
                    "Pull token",
                    &format!(
                        r#"<p class="t-body" style="margin: 0">It is shown once.</p><span class="g-command g-command--value"><span class="g-command__text t-mono" id="pull-token">{token}</span></span>"#
                    ),
                ),
            ))
        }
        "export_pull_token_revoked" => {
            record(json!({})).await?;
            let client = ex.db.client().await?;
            client
                .execute(
                    "UPDATE enterprise_export_settings SET pull_sha256 = NULL",
                    &[],
                )
                .await
                .map_err(db_error)?;
            Ok(("Revoked the pull token.".into(), String::new()))
        }
        "export_capture_hours_set" => {
            let hours: i32 = form.get("hours").trim().parse().unwrap_or(0);
            if !(1..=capture::HOURS_MAX).contains(&hours) {
                return refuse(
                    "invalid_hours",
                    json!({ "hours": form.get("hours") }),
                    format!(
                        "Keep captured text for a whole number of hours from 1 to {}.",
                        capture::HOURS_MAX
                    ),
                )
                .await;
            }
            record(json!({ "hours": hours })).await?;
            let client = ex.db.client().await?;
            client
                .execute(
                    "UPDATE enterprise_export_settings SET capture_hours = $1",
                    &[&hours],
                )
                .await
                .map_err(db_error)?;
            Ok((
                format!("Captured text is now deleted {hours} hours after its request."),
                String::new(),
            ))
        }
        "retention_set" => {
            let days: i32 = form.get("retention_days").trim().parse().unwrap_or(0);
            if !(30..=3650).contains(&days) {
                return refuse(
                    "invalid_days",
                    json!({ "days": form.get("retention_days") }),
                    "Retention is a whole number of days from 30 to 3650.".into(),
                )
                .await;
            }
            record(json!({ "days": days })).await?;
            let client = ex.db.client().await?;
            client
                .execute(
                    "UPDATE enterprise_export_settings SET retention_days = $1",
                    &[&days],
                )
                .await
                .map_err(db_error)?;
            Ok((format!("Retention is now {days} days."), String::new()))
        }
        _ => {
            let on = action == "legal_hold_on";
            let reason: String = form.get("reason").trim().chars().take(500).collect();
            if reason.is_empty() {
                return Err("Enter a reason. It is recorded in the audit log.".into());
            }
            record(json!({ "reason": reason })).await?;
            let client = ex.db.client().await?;
            client
                .execute(
                    "UPDATE enterprise_export_settings SET legal_hold = $1, legal_hold_reason = $2, legal_hold_by = $3, legal_hold_at = now()",
                    &[&on, &reason, &admin.name],
                )
                .await
                .map_err(db_error)?;
            // At once on this replica; the others read it within HOLD_EVERY.
            enterplace_core::insights::hold(&ex.path, on);
            Ok((
                if on {
                    "Legal hold is on. Retention deletes nothing until it is turned off.".into()
                } else {
                    "Legal hold is off. Retention applies again.".into()
                },
                String::new(),
            ))
        }
    }
}

pub(crate) fn random_hex(bytes: usize) -> Result<String, String> {
    use ring::rand::SecureRandom;
    let mut out = vec![0u8; bytes];
    ring::rand::SystemRandom::new()
        .fill(&mut out)
        .map_err(|_| "The system gave no randomness. Try again in a moment.".to_string())?;
    Ok(enterplace_core::id::hex(&out))
}

/// Sends the newest records of the last `days` days, every replica's, each replica's in runs of consecutive records
/// so every batch is a whole piece of its chain. Returns how many were sent, or how many before it failed and why.
async fn backfill(ex: &Exporter, dest: &Dest, days: i32) -> Result<usize, (usize, String)> {
    let rows = async {
        let client = ex.db.client().await?;
        let rows = client
            .query(
                Sql::both(
                    "SELECT replica, n, line FROM (SELECT replica, n, line, seq FROM enterprise_audit \
                     WHERE time >= now() - make_interval(days => $1) ORDER BY seq DESC LIMIT $2) newest ORDER BY replica, n",
                    "SELECT replica, n, line FROM (SELECT replica, n, line, seq FROM enterprise_audit \
                     WHERE time >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-' || ?1 || ' days') ORDER BY seq DESC LIMIT ?2) newest \
                     ORDER BY replica, n",
                ),
                &[&days, &BACKFILL_MAX],
            )
            .await
            .map_err(db_error)?;
        rows.iter()
            .map(|r| Ok((r.try_get::<_, String>(0)?, r.try_get::<_, i64>(1)?, r.try_get::<_, String>(2)?)))
            .collect::<Result<Vec<_>, enterplace_server::sql::Error>>()
            .map_err(db_error)
    }
    .await
    .map_err(|err| (0, err))?;
    let mut sent = 0;
    let mut runs: Vec<(String, Vec<String>)> = Vec::new();
    let mut last: Option<(String, i64)> = None;
    for (replica, n, line) in rows {
        let follows = last
            .as_ref()
            .is_some_and(|(r, m)| *r == replica && *m + 1 == n);
        match runs.last_mut() {
            Some((_, lines)) if follows && lines.len() < BATCH => lines.push(line),
            _ => runs.push((replica.clone(), vec![line])),
        }
        last = Some((replica, n));
    }
    for (replica, lines) in runs {
        let count = lines.len();
        ex.send(dest, Batch::new(replica, lines))
            .await
            .map_err(|err| (sent, err))?;
        sent += count;
    }
    Ok(sent)
}

// ---------------------------------------------------------------- the pull API and the archive

fn json_response(status: StatusCode, body: &Value) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

fn api_error(status: StatusCode, code: &str, message: &str) -> Response {
    json_response(
        status,
        &json!({ "error": { "code": code, "message": message } }),
    )
}

/// GET /export/records?after=<cursor>&limit=<n>, Bearer gpull_...: every replica's records in the order they were
/// read. The answer's `next` is the following call's `after`; an empty `records` means the caller is up to date.
async fn pull(Ext(export): Ext<Export>, headers: HeaderMap, uri: Uri) -> Response {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
        .trim();
    let ex = &export.exporter;
    let wanted = async {
        let client = ex.db.client().await?;
        let row = client
            .query_one(
                "SELECT coalesce(pull_sha256, '') FROM enterprise_export_settings",
                &[],
            )
            .await
            .map_err(db_error)?;
        row.try_get::<_, String>(0).map_err(db_error)
    };
    let wanted = match wanted.await {
        Ok(wanted) => wanted,
        Err(err) => return api_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", &err),
    };
    // Hashes are compared, so timing says nothing about the token.
    let matches = !wanted.is_empty()
        && token.starts_with("gpull_")
        && enterplace_core::id::sha256_hex(token.as_bytes()) == wanted;
    if !matches {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "Send the install's pull token as Authorization: Bearer gpull_... An owner creates one in the console under Audit export.",
        );
    }
    let query = Form::of(&uri);
    let number = |name: &str, default: i64| match query.get(name) {
        "" => Some(default),
        text => text.parse::<i64>().ok(),
    };
    let (Some(after), Some(limit)) = (number("after", 0), number("limit", 500)) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "bad_query",
            &format!(
                "after is the last call's next (0 to start) and limit a whole number from 1 to {PULL_MAX}."
            ),
        );
    };
    if after < 0 || !(1..=PULL_MAX).contains(&limit) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "bad_query",
            &format!(
                "after is the last call's next (0 to start) and limit a whole number from 1 to {PULL_MAX}."
            ),
        );
    }
    let rows = async {
        let client = ex.db.client().await?;
        client
            .query(
                "SELECT seq, replica, line, to_char(received_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') \
                 FROM enterprise_audit WHERE seq > $1 ORDER BY seq LIMIT $2",
                &[&after, &limit],
            )
            .await
            .map_err(db_error)
    };
    let rows = match rows.await {
        Ok(rows) => rows,
        Err(err) => return api_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", &err),
    };
    let mut next = after;
    let mut records = Vec::new();
    for row in &rows {
        let (Ok(seq), Ok(replica), Ok(line), Ok(received)) = (
            row.try_get::<_, i64>(0),
            row.try_get::<_, String>(1),
            row.try_get::<_, String>(2),
            row.try_get::<_, String>(3),
        ) else {
            continue;
        };
        next = seq;
        records.push(json!({ "replica": replica, "received_at": received, "line": line, "record": serde_json::from_str::<Value>(&line).unwrap_or(Value::Null) }));
    }
    json_response(StatusCode::OK, &json!({ "records": records, "next": next }))
}

/// GET /console/siem/archive?from=YYYY-MM-DD&to=YYYY-MM-DD: NDJSON, per replica in chain order, each line as written.
async fn archive(
    State(console): State<Console>,
    Ext(export): Ext<Export>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let Some(admin) = console.signed_in(&headers).await else {
        return redirect("/console/sign-in");
    };
    let ex = export.exporter.clone();
    let refuse = |msg: &str| {
        let msg = msg.to_string();
        let (console, export, admin, uri) =
            (console.clone(), export.clone(), admin.clone(), uri.clone());
        async move { show(&console, &export, &admin, &uri, &msg, true, "").await }
    };
    if role_of(&admin) == Role::Viewer {
        let _ = console
            .audit(Some(&admin), "audit_exported", json!({}), Some("read_only"))
            .await;
        return refuse("Your role is viewer. An owner or admin can download the archive.").await;
    }
    if !ex.siem {
        return refuse("This install's license does not include siem.").await;
    }
    let query = Form::of(&uri);
    let (from, to) = (query.get("from").to_string(), query.get("to").to_string());
    let day = |d: &str| d.len() == 10 && sinks::parse_time(&format!("{d}T00:00:00.000Z")).is_some();
    if !day(&from) || !day(&to) || from > to {
        return refuse("Give from and to as dates, YYYY-MM-DD, with from on or before to.").await;
    }
    if console
        .audit(
            Some(&admin),
            "audit_exported",
            json!({ "from": from, "to": to }),
            None,
        )
        .await
        .is_err()
    {
        return refuse("The download could not be recorded in the audit log, so it was not made.")
            .await;
    }
    let file = format!("enterplace-audit-{from}-{to}.ndjson");
    // Pages of 1000 rows, so a long range is streamed rather than held.
    let state = (ex, from, to, String::new(), 0i64, false);
    let stream = futures_util::stream::unfold(
        state,
        |(ex, from, to, replica, n, done)| async move {
            if done {
                return None;
            }
            let page = async {
                let client = ex.db.client().await?;
                client
                .query(
                    // SQLite's times are UTC text, which a date sorts before any time of that day.
                    Sql::both(
                        "SELECT replica, n, line FROM enterprise_audit WHERE time >= CAST($1::text AS date) AND time < CAST($2::text AS date) + 1 \
                         AND (replica, n) > ($3, $4) ORDER BY replica, n LIMIT 1000",
                        "SELECT replica, n, line FROM enterprise_audit WHERE time >= ?1 AND time < date(?2, '+1 day') \
                         AND (replica, n) > (?3, ?4) ORDER BY replica, n LIMIT 1000",
                    ),
                    &[&from, &to, &replica, &n],
                )
                .await
                .map_err(db_error)
            };
            match page.await {
                Err(err) => Some((
                    Err(std::io::Error::other(err)),
                    (ex, from, to, replica, n, true),
                )),
                Ok(rows) => {
                    let mut text = String::new();
                    let mut at = (replica, n);
                    for row in &rows {
                        if let (Ok(r), Ok(m), Ok(line)) = (
                            row.try_get::<_, String>(0),
                            row.try_get::<_, i64>(1),
                            row.try_get::<_, String>(2),
                        ) {
                            text += &line;
                            text.push('\n');
                            at = (r, m);
                        }
                    }
                    let last = rows.len() < 1000;
                    if rows.is_empty() {
                        return None;
                    }
                    Some((
                        Ok::<_, std::io::Error>(text),
                        (ex, from, to, at.0, at.1, last),
                    ))
                }
            }
        },
    );
    Response::builder()
        .header(header::CONTENT_TYPE, "application/x-ndjson")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{file}\""),
        )
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
