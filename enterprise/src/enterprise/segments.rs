//! The audit chain kept in S3-compatible object storage, for a gateway whose disk does
//! not survive a restart, such as one in Cloudflare Containers.
//!
//! The log is sealed often: every `GANTRY_AUDIT_SEAL_SECONDS` (default 60) once it holds a new record, or as soon as
//! the open file reaches `GANTRY_AUDIT_SEAL_BYTES` (default 1 MiB). Each sealed segment is written to the bucket under
//! the name the log gave it (`<prefix>/<first>-<last>.jsonl`, numbers padded to 20 digits) and only then retired on
//! disk with an `audit_retired` record, so the chain itself names every segment that left the disk. A restart loses
//! at most the records not yet sealed, and none on a graceful stop, which seals and writes the rest.
//!
//! On a start with an empty disk, the newest segments are fetched back into the folder beside the log until the
//! local chain verifies: it then starts right after records that an `audit_retired` record in it names. The gateway
//! opens the log as it always does and continues the chain from the last hash. The bucket's segments in name order,
//! followed by the open file, are one chain that `gantry audit verify` proves from record 1.

use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    Extension as Ext, Router,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use gantry_core::audit::{self, AuditLog};
use gantry_core::{id::sha256_hex, sigv4};

use super::siem::sinks::Env;

/// Where the segments go: `https://<host>/<bucket>[/<prefix>]`, path style.
pub const URL_ENV: &str = "GANTRY_AUDIT_SEGMENTS_URL";
/// A token that may read the unsealed tail at `GET /audit/tail`. Unset, that route does not exist.
pub const READ_TOKEN_ENV: &str = "GANTRY_AUDIT_READ_TOKEN";
/// The object beside the segments that keeps the replica name the audit export uses (`<log>.replica`).
const REPLICA: &str = "replica";

/// An S3-compatible bucket and the prefix this replica's segments live under.
pub struct Store {
    origin: String,
    bucket: String,
    prefix: String,
    region: String,
    credentials: Option<sigv4::Credentials>,
    agent: ureq::Agent,
}

impl Store {
    /// The store `GANTRY_AUDIT_SEGMENTS_URL` names, `None` when it is unset. Requests are signed with
    /// `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` (region `AWS_REGION`, default `auto` as R2 wants) when both are
    /// set, and sent unsigned otherwise, for an endpoint that needs none (the Cloudflare Worker's own handler).
    pub fn from_env(env: &Env) -> Result<Option<Self>, String> {
        let set = |name: &str| {
            env(name)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let Some(url) = set(URL_ENV) else {
            return Ok(None);
        };
        let bad = || {
            format!(
                "{URL_ENV} is {url}, which is not http(s)://<host>/<bucket>[/<prefix>]. For R2: https://<account id>.r2.cloudflarestorage.com/<bucket>/<prefix>."
            )
        };
        let (scheme, rest) = url.split_once("://").ok_or_else(bad)?;
        let (host, path) = rest.split_once('/').ok_or_else(bad)?;
        let path = path.trim_matches('/');
        let (bucket, prefix) = path.split_once('/').unwrap_or((path, ""));
        // Names are signed as they are sent, so only characters that need no encoding are taken.
        let plain = |s: &str| {
            s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
        };
        if !matches!(scheme, "http" | "https")
            || host.is_empty()
            || bucket.is_empty()
            || !plain(bucket)
            || !plain(prefix)
        {
            return Err(bad());
        }
        let credentials = match (set("AWS_ACCESS_KEY_ID"), set("AWS_SECRET_ACCESS_KEY")) {
            (Some(access_key_id), Some(secret_access_key)) => Some(sigv4::Credentials {
                access_key_id,
                secret_access_key,
                session_token: set("AWS_SESSION_TOKEN"),
            }),
            _ => None,
        };
        Ok(Some(Self {
            origin: format!("{scheme}://{host}"),
            bucket: bucket.to_string(),
            prefix: prefix.trim_end_matches('/').to_string(),
            region: set("AWS_REGION").unwrap_or_else(|| "auto".into()),
            credentials,
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(30))
                .redirects(0)
                .build(),
        }))
    }

    /// The same bucket under `<prefix>/<sub>`: an organization's chain (`audit: { per_org: true }`) keeps its
    /// segments under `orgs/<org>`, apart from the install's.
    pub fn within(&self, sub: &str) -> Store {
        Store {
            origin: self.origin.clone(),
            bucket: self.bucket.clone(),
            prefix: self.key(sub),
            region: self.region.clone(),
            credentials: self.credentials.clone(),
            agent: self.agent.clone(),
        }
    }

    fn key(&self, name: &str) -> String {
        if self.prefix.is_empty() {
            name.to_string()
        } else {
            format!("{}/{name}", self.prefix)
        }
    }

    /// Where the segments are, for messages: `s3://bucket/prefix`.
    pub fn describe(&self) -> String {
        format!("{}/{}/{}", self.origin, self.bucket, self.prefix)
    }

    /// One request. `query` is already canonical (encoded, sorted). Returns the status and the body.
    fn send(
        &self,
        method: &str,
        key: &str,
        query: &str,
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), String> {
        let path = if key.is_empty() {
            format!("/{}", self.bucket)
        } else {
            format!("/{}/{key}", self.bucket)
        };
        let url = if query.is_empty() {
            format!("{}{path}", self.origin)
        } else {
            format!("{}{path}?{query}", self.origin)
        };
        let mut request = self.agent.request(method, &url);
        if let Some(credentials) = &self.credentials {
            let host = self.origin.split("://").nth(1).unwrap_or_default();
            let payload = sha256_hex(body);
            let signed = sigv4::sign(
                credentials,
                &self.region,
                "s3",
                &sigv4::Request {
                    method,
                    path: &path,
                    query,
                    headers: &[("host", host), ("x-amz-content-sha256", &payload)],
                    payload: body,
                },
                &sigv4::amz_date_now(),
            );
            request = request.set("x-amz-content-sha256", &payload);
            for (name, value) in signed {
                request = request.set(name, &value);
            }
        }
        let response = match request.send_bytes(body) {
            Ok(response) => response,
            Err(ureq::Error::Status(_, response)) => response,
            Err(ureq::Error::Transport(err)) => {
                return Err(format!(
                    "the audit segment store at {} could not be reached: {err}. Check {URL_ENV} and that this gateway can reach it.",
                    self.origin
                ));
            }
        };
        let status = response.status();
        let mut out = Vec::new();
        response
            .into_reader()
            .take(256 * 1024 * 1024)
            .read_to_end(&mut out)
            .map_err(|err| format!("the answer from {} was cut short: {err}.", self.origin))?;
        Ok((status, out))
    }

    fn refused(&self, what: &str, status: u16) -> String {
        match status {
            401 | 403 => format!(
                "the audit segment store refused to {what} (HTTP {status}). Check the access key's rights on bucket {}.",
                self.bucket
            ),
            _ => format!("the audit segment store answered HTTP {status} to {what}."),
        }
    }

    pub fn put(&self, name: &str, body: &[u8]) -> Result<(), String> {
        let (status, _) = self.send("PUT", &self.key(name), "", body)?;
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(self.refused(&format!("write {name}"), status))
        }
    }

    pub fn get(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
        match self.send("GET", &self.key(name), "", &[])? {
            (status, body) if (200..300).contains(&status) => Ok(Some(body)),
            (404, _) => Ok(None),
            (status, _) => Err(self.refused(&format!("read {name}"), status)),
        }
    }

    /// The names under the prefix, in name order, which is segment order.
    // ponytail: lists every key at each start (1000 a page). A pointer to the newest segment when starts get slow.
    pub fn list(&self) -> Result<Vec<String>, String> {
        let prefix = self.key("");
        let mut names = Vec::new();
        let mut token: Option<String> = None;
        loop {
            // Canonical order: names sorted.
            let mut query = Vec::new();
            if let Some(token) = &token {
                query.push(format!(
                    "continuation-token={}",
                    sigv4::uri_encode(token, false)
                ));
            }
            query.push("list-type=2".to_string());
            query.push(format!("prefix={}", sigv4::uri_encode(&prefix, false)));
            let (status, body) = self.send("GET", "", &query.join("&"), &[])?;
            if !(200..300).contains(&status) {
                return Err(self.refused("list the segments", status));
            }
            let text = String::from_utf8_lossy(&body);
            names.extend(
                tags(&text, "Key")
                    .into_iter()
                    .filter_map(|k| k.strip_prefix(&prefix).map(str::to_string)),
            );
            let truncated = tags(&text, "IsTruncated").first() == Some(&"true");
            token = tags(&text, "NextContinuationToken")
                .first()
                .map(|t| t.to_string());
            if !truncated || token.is_none() {
                break;
            }
        }
        names.sort();
        Ok(names)
    }
}

/// The text of every `<tag>...</tag>` in an S3 XML answer, unescaped. Keys here are plain names, so the five XML
/// escapes are all there is to undo.
fn tags<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find(&open) {
        rest = &rest[start + open.len()..];
        let Some(end) = rest.find(&close) else { break };
        out.push(&rest[..end]);
        rest = &rest[end + close.len()..];
    }
    out
}

/// `first` and `last` of a segment's name, as `audit::segment_path` writes it.
fn parse(name: &str) -> Option<(u64, u64)> {
    let (a, b) = name.strip_suffix(".jsonl")?.split_once('-')?;
    (a.len() == 20 && b.len() == 20).then_some(())?;
    Some((a.parse().ok()?, b.parse().ok()?))
}

fn replica_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".replica");
    PathBuf::from(name)
}

/// Before the log is opened on an empty disk: fetches the newest segments from `store` until the chain on disk
/// verifies, so the gateway continues it. A log that is already on disk is kept as it is. Fails, naming what does
/// not hold, when the segments in the bucket are not one chain: a gateway does not continue a chain it cannot vouch for.
pub fn restore(store: &Store, path: &Path) -> Result<String, String> {
    if audit::has_records(path) {
        return Ok(format!(
            "the audit log at {} is on disk; nothing fetched.",
            path.display()
        ));
    }
    let names = store.list()?;
    // An organization's chain lives in a folder beside the install's log, which an empty disk does not have yet.
    if let Some(folder) = path.parent().filter(|f| !f.as_os_str().is_empty()) {
        std::fs::create_dir_all(folder)
            .map_err(|err| format!("{} cannot be made: {err}.", folder.display()))?;
    }
    if names.iter().any(|n| n == REPLICA)
        && let Some(replica) = store.get(REPLICA)?
    {
        std::fs::write(replica_path(path), replica)
            .map_err(|err| format!("{} cannot be written: {err}.", replica_path(path).display()))?;
    }
    let segments: Vec<(u64, u64, &String)> = names
        .iter()
        .filter_map(|n| parse(n).map(|(first, last)| (first, last, n)))
        .collect();
    if segments.is_empty() {
        return Ok(format!(
            "no audit segments at {}; a new chain starts.",
            store.describe()
        ));
    }
    let dir = audit::sealed_dir(path);
    std::fs::create_dir_all(&dir)
        .map_err(|err| format!("{} cannot be made: {err}.", dir.display()))?;
    let mut fetched = 0;
    for (first, last, name) in segments.iter().rev() {
        let body = store.get(name)?.ok_or_else(|| {
            format!(
                "{name} was listed in {} and then could not be read.",
                store.describe()
            )
        })?;
        let local = audit::segment_path(path, *first, *last);
        std::fs::write(&local, body)
            .map_err(|err| format!("{} cannot be written: {err}.", local.display()))?;
        fetched += 1;
        match audit::verify_full(path, None) {
            Ok(summary) => {
                return Ok(format!(
                    "fetched {fetched} audit segment(s) from {}; the chain goes on after record {} ({}).",
                    store.describe(),
                    summary.records,
                    summary.last_hash
                ));
            }
            // Its start is explained further back: an older segment holds the record that retired what came before.
            Err(_) if *first > 1 => continue,
            Err(err) => {
                return Err(format!(
                    "the audit segments at {} are not one chain: {err} Gantry does not continue a chain that does not hold. Keep the bucket as evidence, and point {URL_ENV} at a new prefix to start a new chain.",
                    store.describe()
                ));
            }
        }
    }
    Ok(format!("fetched {fetched} audit segment(s)."))
}

/// Seals the log, writes each sealed segment to the store, and retires the written ones on disk.
pub struct Shipper {
    store: Store,
    log: Arc<AuditLog>,
    path: PathBuf,
    every: Duration,
    bytes: u64,
    /// Segments are retired only through this record: the audit export lowers it to what it has read.
    limit: Arc<AtomicU64>,
    /// With a store, the last record the request index has copied: the console's request log reads the chain from
    /// the disk, so a segment is retired only once that has passed it too.
    index: Option<Arc<AtomicU64>>,
    state: Mutex<State>,
}

struct State {
    sealed_at: Instant,
    /// Segment names already in the store.
    written: HashSet<String>,
    replica_written: bool,
    /// The open file's size after the last retirement record: a file that size holds nothing new.
    quiet_len: u64,
    said: String,
}

impl Shipper {
    pub fn new(
        store: Store,
        log: Arc<AuditLog>,
        path: PathBuf,
        env: &Env,
        limit: Arc<AtomicU64>,
        index: Option<Arc<AtomicU64>>,
    ) -> Self {
        let number = |name: &str, default: u64| {
            env(name)
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(default)
        };
        Self {
            store,
            log,
            path,
            every: Duration::from_secs(number("GANTRY_AUDIT_SEAL_SECONDS", 60)),
            bytes: number("GANTRY_AUDIT_SEAL_BYTES", 1024 * 1024),
            limit,
            index,
            state: Mutex::new(State {
                sealed_at: Instant::now(),
                written: HashSet::new(),
                replica_written: false,
                quiet_len: 0,
                said: String::new(),
            }),
        }
    }

    /// One pass. Seals when the open file holds new records and the interval has passed, it is large enough, or
    /// `now` is set (a graceful stop). Then writes every segment not yet in the store, and retires the written ones.
    /// Blocking. Returns how many segments it wrote.
    pub fn pass(&self, now: bool) -> Result<usize, String> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let len = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        let fresh = len > 0 && len != state.quiet_len;
        if fresh && (now || len >= self.bytes || state.sealed_at.elapsed() >= self.every) {
            self.log
                .seal()
                .map_err(|err| format!("the audit log could not be sealed: {err}."))?;
            state.sealed_at = Instant::now();
        }
        let replica = replica_path(&self.path);
        if !state.replica_written
            && let Ok(text) = std::fs::read(&replica)
        {
            self.store.put(REPLICA, &text)?;
            state.replica_written = true;
        }
        let segments = audit::segments(&self.path).map_err(|err| err.to_string())?;
        let mut wrote = 0;
        let mut through = None;
        let limit = self.limit.load(Ordering::SeqCst).min(
            self.index
                .as_ref()
                .map_or(u64::MAX, |copied| copied.load(Ordering::SeqCst)),
        );
        for segment in &segments {
            let name = segment
                .path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if !state.written.contains(&name) {
                let body = std::fs::read(&segment.path)
                    .map_err(|err| format!("{} cannot be read: {err}.", segment.path.display()))?;
                self.store.put(&name, &body)?;
                state.written.insert(name);
                wrote += 1;
            }
            if segment.last <= limit {
                through = Some(segment.last);
            }
        }
        if let Some(through) = through {
            // Written to the store first, then named in the chain, then removed: a removal the chain does not name
            // is a gap `verify` reports, and a segment is never removed before the store has it.
            // Kept in the store, not deleted: the record says where, and the request log keeps its rows for them.
            audit::retire_kept(&self.log, &self.path, through, &self.store.describe())?;
            state
                .written
                .retain(|n| parse(n).is_some_and(|(_, last)| last > through));
            state.quiet_len = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        }
        Ok(wrote)
    }

    /// Runs `pass` every second until the process ends. An error is printed once until it changes.
    pub async fn run(self: Arc<Self>) {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let me = self.clone();
            let result = tokio::task::spawn_blocking(move || me.pass(false))
                .await
                .unwrap_or_else(|err| Err(format!("the audit shipper stopped: {err}")));
            let line = result.err().unwrap_or_default();
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if line != state.said {
                if !line.is_empty() {
                    eprintln!(
                        "warning: audit segments: {line} Segments stay on disk until the store takes them."
                    );
                }
                state.said = line;
            }
        }
    }

    /// The records after the last seal, whole lines only.
    fn tail(&self) -> Result<Vec<u8>, String> {
        let mut text = match std::fs::read(&self.path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(err) => return Err(format!("the audit log cannot be read: {err}.")),
        };
        let whole = text.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        text.truncate(whole);
        Ok(text)
    }
}

/// `GET /audit/tail` with `Authorization: Bearer <GANTRY_AUDIT_READ_TOKEN>`: the records not yet sealed, as written.
/// Appended to the store's segments, they complete the chain for `gantry audit verify`.
pub fn routes(shipper: Arc<Shipper>, token: String) -> Router {
    let wanted = sha256_hex(token.as_bytes());
    Router::new().route(
        "/audit/tail",
        get(move |Ext(shipper): Ext<Arc<Shipper>>, headers: HeaderMap| {
            let wanted = wanted.clone();
            async move {
                let sent = headers
                    .get(header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("Bearer "))
                    .unwrap_or("")
                    .trim()
                    .to_string();
                // Hashes are compared, so timing says nothing about the token.
                if sent.is_empty() || sha256_hex(sent.as_bytes()) != wanted {
                    return (
                        StatusCode::UNAUTHORIZED,
                        format!("Send the token in {READ_TOKEN_ENV} as Authorization: Bearer <token>.\n"),
                    )
                        .into_response();
                }
                match tokio::task::spawn_blocking(move || shipper.tail()).await {
                    Ok(Ok(tail)) => Response::builder()
                        .header(header::CONTENT_TYPE, "application/x-ndjson")
                        .body(axum::body::Body::from(tail))
                        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
                    Ok(Err(err)) => (StatusCode::INTERNAL_SERVER_ERROR, err).into_response(),
                    Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
                }
            }
        }),
    )
    .layer(Ext(shipper))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use axum::{
        body::Bytes,
        extract::State,
        http::{Method, Uri},
    };
    use serde_json::{Map, Value};

    use super::*;

    type Error = Box<dyn std::error::Error>;
    type Bucket = Arc<Mutex<BTreeMap<String, Vec<u8>>>>;

    /// PUT, GET and ListObjectsV2 (two keys a page, so paging is exercised), path style, as R2 and the Worker's
    /// handler answer them.
    async fn fake_s3(
        State(bucket): State<Bucket>,
        method: Method,
        uri: Uri,
        body: Bytes,
    ) -> Response {
        let path = uri.path().trim_start_matches('/');
        let (_bucket, key) = path.split_once('/').unwrap_or((path, ""));
        let mut objects = bucket
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match method {
            Method::PUT => {
                objects.insert(key.to_string(), body.to_vec());
                StatusCode::OK.into_response()
            }
            Method::GET if key.is_empty() => {
                let query: BTreeMap<String, String> = uri
                    .query()
                    .unwrap_or("")
                    .split('&')
                    .filter_map(|p| p.split_once('='))
                    .map(|(k, v)| (k.to_string(), v.replace("%2F", "/")))
                    .collect();
                let prefix = query.get("prefix").cloned().unwrap_or_default();
                let after = query.get("continuation-token").cloned().unwrap_or_default();
                let keys: Vec<&String> = objects
                    .keys()
                    .filter(|k| k.starts_with(&prefix) && k.as_str() > after.as_str())
                    .collect();
                let page: Vec<&&String> = keys.iter().take(2).collect();
                let mut xml = String::from("<ListBucketResult>");
                for key in &page {
                    xml.push_str(&format!("<Contents><Key>{key}</Key></Contents>"));
                }
                if keys.len() > 2 {
                    let last = page.last().map(|k| k.as_str()).unwrap_or_default();
                    xml.push_str(&format!(
                        "<IsTruncated>true</IsTruncated><NextContinuationToken>{last}</NextContinuationToken>"
                    ));
                } else {
                    xml.push_str("<IsTruncated>false</IsTruncated>");
                }
                xml.push_str("</ListBucketResult>");
                xml.into_response()
            }
            Method::GET => match objects.get(key) {
                Some(body) => body.clone().into_response(),
                None => StatusCode::NOT_FOUND.into_response(),
            },
            _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
        }
    }

    async fn bucket() -> Result<(Bucket, String), Error> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}/segments/gw/one", listener.local_addr()?);
        let bucket = Bucket::default();
        let app = Router::new().fallback(fake_s3).with_state(bucket.clone());
        tokio::spawn(async move { axum::serve(listener, app).await });
        Ok((bucket, url))
    }

    fn env(url: &str) -> Env {
        let url = url.to_string();
        Arc::new(move |name| (name == URL_ENV).then(|| url.clone()))
    }

    fn store(url: &str) -> Result<Store, Error> {
        Ok(Store::from_env(&env(url))?.ok_or("no store")?)
    }

    fn disk(test: &str) -> Result<PathBuf, Error> {
        let dir =
            std::env::temp_dir().join(format!("gantry-segments-{}-{test}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        Ok(dir.join("gantry-audit.jsonl"))
    }

    fn write(log: &AuditLog, count: usize) -> Result<(), Error> {
        for i in 0..count {
            let mut record = Map::new();
            record.insert("event".into(), "admin".into());
            record.insert("note".into(), Value::from(i));
            log.append_record(&record)?;
        }
        Ok(())
    }

    fn shipper(url: &str, path: &Path, log: &Arc<AuditLog>) -> Result<Shipper, Error> {
        Ok(Shipper::new(
            store(url)?,
            log.clone(),
            path.to_path_buf(),
            &env(url),
            Arc::new(AtomicU64::new(u64::MAX)),
            None,
        ))
    }

    /// The bucket's segments then `tail` as one log on a fresh disk, verified from record 1.
    fn whole(bucket: &Bucket, tail: &Path, test: &str) -> Result<audit::Summary, Error> {
        let path = disk(test)?;
        std::fs::create_dir_all(audit::sealed_dir(&path))?;
        for (key, body) in bucket.lock().map_err(|_| "lock")?.iter() {
            let name = key.rsplit('/').next().unwrap_or_default();
            if let Some((first, last)) = parse(name) {
                std::fs::write(audit::segment_path(&path, first, last), body)?;
            }
        }
        std::fs::copy(tail, &path)?;
        Ok(audit::verify_full(&path, None)?)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_restart_on_an_empty_disk_continues_the_chain_from_the_bucket() -> Result<(), Error> {
        let (bucket, url) = bucket().await?;
        let first = disk("before")?;
        let log = Arc::new(AuditLog::open(&first)?);
        let ship = shipper(&url, &first, &log)?;
        write(&log, 3)?;
        assert_eq!(ship.pass(true)?, 1);
        assert!(
            audit::segments(&first)?.is_empty(),
            "a written segment is retired on disk"
        );
        audit::verify_full(&first, None)?;
        write(&log, 2)?;
        assert_eq!(ship.pass(true)?, 1);
        assert_eq!(
            bucket
                .lock()
                .map_err(|_| "lock")?
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            vec![
                "gw/one/00000000000000000001-00000000000000000003.jsonl".to_string(),
                "gw/one/00000000000000000004-00000000000000000006.jsonl".to_string(),
            ],
            "segments are named as the log names them, under the prefix"
        );
        // Not sealed, and lost with the disk.
        write(&log, 1)?;
        drop(ship);
        drop(log);

        let second = disk("after")?;
        let note = restore(&store(&url)?, &second)?;
        assert!(note.contains("fetched 1"), "{note}");
        let log = Arc::new(AuditLog::open(&second)?);
        // The check `gantry serve` runs before serving.
        audit::verify_full(&second, None)?;
        write(&log, 2)?;
        let local = audit::verify_full(&second, None)?;
        assert!(local.first > 1 && local.retired.is_some());

        let chain = whole(&bucket, &second, "whole")?;
        assert_eq!(
            chain.first, 1,
            "the bucket and the local tail are one chain from record 1"
        );
        assert_eq!(chain.records, local.records);
        assert_eq!(chain.last_hash, local.last_hash);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_organizations_chain_ships_under_its_own_prefix_and_comes_back_on_an_empty_disk()
    -> Result<(), Error> {
        let (bucket, url) = bucket().await?;
        let first = disk("org-before")?;
        let log = Arc::new(AuditLog::open(&first)?.per_org(&["acme".to_string()])?);
        let (org, acme) = log.org_logs().into_iter().next().ok_or("no org chain")?;
        let at = audit::org_path(&first, &org);
        let ship = Shipper::new(
            store(&url)?.within(&super::super::org_prefix(&org)),
            acme.clone(),
            at.clone(),
            &env(&url),
            Arc::new(AtomicU64::new(u64::MAX)),
            None,
        );
        write(&acme, 3)?;
        assert_eq!(ship.pass(true)?, 1);
        assert!(
            bucket
                .lock()
                .map_err(|_| "lock")?
                .keys()
                .any(|k| k == "gw/one/orgs/acme/00000000000000000001-00000000000000000003.jsonl"),
            "under the install's prefix, in orgs/acme"
        );
        // The install's chain is not mixed with it: its restore finds nothing of acme's.
        drop(ship);
        drop(acme);
        drop(log);
        let second = disk("org-after")?;
        let note = restore(&store(&url)?, &second)?;
        assert!(note.contains("no audit segments"), "{note}");
        let back = audit::org_path(&second, "acme");
        let note = restore(
            &store(&url)?.within(&super::super::org_prefix("acme")),
            &back,
        )?;
        assert!(note.contains("fetched 1"), "{note}");
        let log = AuditLog::open(&second)?.per_org(&[])?;
        assert_eq!(
            log.org_logs().len(),
            1,
            "the restored chain is opened, checked whole"
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn nothing_new_is_not_sealed_and_a_graceful_stop_loses_nothing() -> Result<(), Error> {
        let (bucket, url) = bucket().await?;
        let path = disk("quiet")?;
        let log = Arc::new(AuditLog::open(&path)?);
        let ship = shipper(&url, &path, &log)?;
        write(&log, 2)?;
        ship.pass(true)?;
        // The file now holds only the retirement record the pass wrote.
        assert_eq!(ship.pass(true)?, 0);
        assert_eq!(ship.pass(true)?, 0);
        write(&log, 1)?;
        assert_eq!(ship.pass(true)?, 1, "a stop seals and writes the tail");
        let records = audit::verify_full(&path, None)?.records;
        drop(ship);
        drop(log);
        let fresh = disk("quiet-after")?;
        restore(&store(&url)?, &fresh)?;
        let _log = AuditLog::open(&fresh)?;
        // Everything but the last retirement record (written after the last seal) is in the bucket.
        assert_eq!(audit::verify_full(&fresh, None)?.records, records - 1);
        assert_eq!(bucket.lock().map_err(|_| "lock")?.len(), 2);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn restore_reaches_back_until_the_chain_holds() -> Result<(), Error> {
        let (_bucket, url) = bucket().await?;
        let path = disk("back")?;
        let log = Arc::new(AuditLog::open(&path)?);
        let ship = shipper(&url, &path, &log)?;
        write(&log, 2)?;
        ship.pass(true)?;
        // Another seal (the daily retention seal) before the next pass: the newest segment's start is then named
        // only in the segment before it.
        log.seal()?;
        write(&log, 1)?;
        ship.pass(true)?;
        drop(ship);
        drop(log);
        let fresh = disk("back-after")?;
        let note = restore(&store(&url)?, &fresh)?;
        assert!(note.contains("fetched 2"), "{note}");
        let _log = AuditLog::open(&fresh)?;
        audit::verify_full(&fresh, None)?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_changed_segment_in_the_bucket_stops_the_start() -> Result<(), Error> {
        let (bucket, url) = bucket().await?;
        let path = disk("changed")?;
        let log = Arc::new(AuditLog::open(&path)?);
        let ship = shipper(&url, &path, &log)?;
        write(&log, 2)?;
        ship.pass(true)?;
        drop(ship);
        drop(log);
        for body in bucket.lock().map_err(|_| "lock")?.values_mut() {
            *body = String::from_utf8_lossy(body)
                .replacen("\"note\":1", "\"note\":7", 1)
                .into_bytes();
        }
        let err = restore(&store(&url)?, &disk("changed-after")?)
            .err()
            .ok_or("a changed segment was continued")?;
        assert!(
            err.contains("not one chain") && err.contains("record 2"),
            "{err}"
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn segments_stay_on_disk_until_the_audit_export_has_read_them() -> Result<(), Error> {
        let (bucket, url) = bucket().await?;
        let path = disk("limit")?;
        let log = Arc::new(AuditLog::open(&path)?);
        let limit = Arc::new(AtomicU64::new(0));
        let ship = Shipper::new(
            store(&url)?,
            log.clone(),
            path.clone(),
            &env(&url),
            limit.clone(),
            None,
        );
        write(&log, 2)?;
        assert_eq!(ship.pass(true)?, 1);
        assert_eq!(
            bucket.lock().map_err(|_| "lock")?.len(),
            1,
            "written to the store"
        );
        assert_eq!(audit::segments(&path)?.len(), 1, "but kept on disk");
        assert_eq!(ship.pass(false)?, 0, "and not written twice");
        limit.store(2, Ordering::SeqCst);
        ship.pass(false)?;
        assert!(audit::segments(&path)?.is_empty());
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn segments_stay_on_disk_until_the_request_index_has_copied_them() -> Result<(), Error> {
        // The console's request log copies the chain from the disk every two seconds: a segment retired before it
        // got there would never have its rows, though the export (here: none) has nothing left to read.
        let (bucket, url) = bucket().await?;
        let path = disk("index")?;
        let log = Arc::new(AuditLog::open(&path)?);
        let copied = Arc::new(AtomicU64::new(0));
        let ship = Shipper::new(
            store(&url)?,
            log.clone(),
            path.clone(),
            &env(&url),
            Arc::new(AtomicU64::new(u64::MAX)),
            Some(copied.clone()),
        );
        write(&log, 2)?;
        assert_eq!(ship.pass(true)?, 1);
        assert_eq!(bucket.lock().map_err(|_| "lock")?.len(), 1);
        let last = audit::segments(&path)?
            .first()
            .map(|s| s.last)
            .ok_or("no segment on disk")?;
        copied.store(last - 1, Ordering::SeqCst);
        ship.pass(false)?;
        assert_eq!(
            audit::segments(&path)?.len(),
            1,
            "kept while its last record is not copied"
        );
        copied.store(last, Ordering::SeqCst);
        ship.pass(false)?;
        assert!(audit::segments(&path)?.is_empty(), "retired once it is");
        Ok(())
    }

    #[test]
    fn the_url_names_a_bucket_and_a_prefix() -> Result<(), Error> {
        let s = store("https://acct.r2.cloudflarestorage.com/gantry-audit/prod/gw-0/")?;
        assert_eq!(
            (s.bucket.as_str(), s.prefix.as_str()),
            ("gantry-audit", "prod/gw-0")
        );
        assert!(s.credentials.is_none());
        let s = store("http://audit.internal/b")?;
        assert_eq!((s.bucket.as_str(), s.prefix.as_str()), ("b", ""));
        for bad in [
            "s3://b/p",
            "https://host",
            "https://host/",
            "https://host/b/a b",
        ] {
            let err = Store::from_env(&env(bad)).err().ok_or(bad)?;
            assert!(err.contains(URL_ENV), "{err}");
        }
        assert!(Store::from_env(&env(""))?.is_none());
        Ok(())
    }
}
