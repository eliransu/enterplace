//! The audit log: one JSON record per line, each carrying the hash of the one before it,
//! so a record cannot be changed, removed or inserted without `verify` noticing.

use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::{Map, Value};

use crate::id::sha256_hex;

/// `prev` of the first record: there is nothing before it.
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// Length of the `,"hash":"<64 hex>"}` that ends every line.
const TAIL: usize = 9 + 64 + 2;
/// Strings that come from the caller are cut to this length, so a caller cannot choose the size of a record.
const MAX_TEXT: usize = 200;
/// The longest last line `open` looks for. A policy file larger than this does not belong in one record.
const MAX_LINE: u64 = 16 * 1024 * 1024;

/// What is known about one request when it is decided. Never prompt text, never a key.
#[derive(Clone, Debug, Default)]
pub struct Entry<'a> {
    pub id: &'a str,
    pub person: Option<&'a str>,
    pub team: Option<&'a str>,
    pub client: Option<&'a str>,
    /// First 8 hex characters of the hash of the key the request came with, issued or not.
    pub key: Option<&'a str>,
    pub method: &'a str,
    pub path: &'a str,
    pub model: Option<&'a str>,
    pub allowed: bool,
    pub code: Option<&'a str>,
    pub rule: Option<&'a str>,
    pub rule_line: Option<usize>,
    pub provider: &'a str,
    pub policy_sha256: &'a str,
    pub keys_sha256: &'a str,
    /// The request came in one API's format and was translated to the provider's.
    pub translated: bool,
    /// `hit` when the answer came from Gantry's cache, `miss` when it could have and did not. Absent otherwise.
    pub cache: Option<&'a str>,
}

struct Chain {
    file: File,
    n: u64,
    prev: String,
    /// Where the file was opened, to notice when that name no longer leads to this file.
    path: Option<PathBuf>,
    /// Bytes the log held after the last write, to notice when it is cut.
    len: u64,
}

impl Chain {
    /// Whether the open file is still the audit log: at its path, and not shorter than it was left.
    /// A log that was deleted, moved, replaced or truncated must stop requests, not swallow their records.
    fn intact(&self) -> Result<(), &'static str> {
        let Ok(open) = self.file.metadata() else {
            return Err("it can no longer be read");
        };
        if open.len() < self.len {
            return Err("it was truncated");
        }
        #[cfg(unix)]
        if let Some(path) = &self.path {
            use std::os::unix::fs::MetadataExt;
            match std::fs::metadata(path) {
                Ok(named) if named.ino() == open.ino() && named.dev() == open.dev() => {}
                Ok(_) => return Err("it was replaced by another file"),
                Err(_) => return Err("it was deleted or moved"),
            }
        }
        Ok(())
    }
}

/// A record waiting to be written, and who to tell when it is on file.
type Job = (Fields, Box<dyn FnOnce(io::Result<()>) + Send>);

/// A record's fields as JSON without the braces, or the work that makes them, done on the writer's thread so the
/// caller does not wait for it. `None` from that work writes nothing.
enum Fields {
    Ready(String),
    Later(Box<dyn FnOnce() -> Option<Map<String, Value>> + Send>),
}

/// A record's fields as the writer takes them.
fn fields_of(record: &Map<String, Value>) -> io::Result<String> {
    match serde_json::to_string(record) {
        // Without the braces: the writer adds the record number in front and the chain fields behind.
        Ok(json) if json.len() > 2 => Ok(json[1..json.len() - 1].to_string()),
        Ok(_) => Err(io::Error::other("an empty record")),
        Err(err) => Err(err.into()),
    }
}

pub struct AuditLog {
    // Records go to one thread that does nothing but write them. A write from a thread that just woke up costs
    // ten times one from a thread that is already writing, and under load the writer takes many records per write.
    writer: mpsc::Sender<Job>,
    // A second handle to the same file, so syncing to disk does not hold up the writer.
    syncer: Option<File>,
    // Set by the writer once a write has failed or the file is gone. It stays set until Gantry is started again.
    broken: Arc<AtomicBool>,
    path: Option<PathBuf>,
    records_at_open: u64,
    // Bytes the log should hold, kept by the writer, so a health check can see a log cut short in place.
    len: Arc<AtomicU64>,
    stats: Arc<Stats>,
    /// The lock file this log wrote beside the file it holds, removed when it closes.
    lock: Option<PathBuf>,
}

impl Drop for AuditLog {
    fn drop(&mut self) {
        let Some(lock) = &self.lock else { return };
        locked_paths().remove(lock);
        // Only a lock that still names this process: another Gantry may have taken over one it found stale.
        if std::fs::read_to_string(lock)
            .is_ok_and(|pid| pid.trim() == std::process::id().to_string())
        {
            let _ = std::fs::remove_file(lock);
        }
    }
}

/// Lock files held by logs open in this process, so a second open in the same process is refused too.
fn locked_paths() -> std::sync::MutexGuard<'static, std::collections::HashSet<PathBuf>> {
    static HELD: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<PathBuf>>> =
        std::sync::OnceLock::new();
    HELD.get_or_init(Default::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Writes the lock file beside a log, or refuses when a live process holds it (QA12-2). Returns None when the lock
/// cannot be written (a read-only folder): the log is still served, as before.
fn take_lock(path: &Path) -> Result<Option<PathBuf>, String> {
    let lock = lock_path(path);
    let mut held = locked_paths();
    let holder = std::fs::read_to_string(&lock)
        .ok()
        .and_then(|pid| pid.trim().parse::<u32>().ok());
    // A lock naming this process's ID and no log open here is stale: in a container every Gantry is process 1.
    let refused = held.contains(&lock)
        || holder.is_some_and(|pid| pid != std::process::id() && process_alive(pid));
    if refused {
        return Err(format!(
            "another Gantry ({}) holds the audit log at {}: it wrote {}. Two writers would break the chain. Stop the other one or give this one its own `audit: {{ path: ... }}`; if no Gantry is running, delete {} and start again.",
            holder.map_or("process ID unknown".to_string(), |pid| format!(
                "process {pid}"
            )),
            path.display(),
            lock.display(),
            lock.display()
        ));
    }
    if std::fs::write(&lock, format!("{}\n", std::process::id())).is_err() {
        return Ok(None);
    }
    held.insert(lock.clone());
    Ok(Some(lock))
}

/// FILE_SHARE_READ | FILE_SHARE_WRITE, without FILE_SHARE_DELETE.
#[cfg(windows)]
const FILE_SHARE_READ_WRITE: u32 = 0x1 | 0x2;

/// Whether Windows marks the file as a device (FILE_ATTRIBUTE_DEVICE). Unix devices are already not `is_file`.
#[cfg(windows)]
fn is_device(meta: &std::fs::Metadata) -> bool {
    std::os::windows::fs::MetadataExt::file_attributes(meta) & 0x40 != 0
}

#[cfg(not(windows))]
fn is_device(_: &std::fs::Metadata) -> bool {
    false
}

/// Whether a process with this ID runs. Without unsafe code: /proc on Linux, `ps` elsewhere. When neither can
/// tell, it is taken as running, so a second writer is refused and the message names the file to delete.
// ponytail: two containers sharing one log folder both run as process 1 and cannot see each other; give each
// container its own audit path.
#[cfg(not(windows))]
fn process_alive(pid: u32) -> bool {
    if Path::new("/proc/self").exists() {
        return Path::new("/proc").join(pid.to_string()).exists();
    }
    std::process::Command::new("ps")
        .args(["-p", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_or(true, |status| status.success())
}

/// Windows has neither /proc nor a `ps` that knows Windows process IDs, so it asks `tasklist`, which ships with
/// Windows. When that cannot run, the process is taken as running, as above.
#[cfg(windows)]
fn process_alive(pid: u32) -> bool {
    std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
        .stderr(std::process::Stdio::null())
        .output()
        // A match is a CSV row whose second field is the ID; no match prints an INFO line and still exits 0.
        .map_or(true, |out| {
            String::from_utf8_lossy(&out.stdout).contains(&format!(",\"{pid}\","))
        })
}

/// The file beside an audit log that says a Gantry process holds it: `gantry audit repair` refuses while it exists.
// ponytail: a lock file, not an OS lock (File::lock needs Rust 1.89). A Gantry killed without closing its log leaves
// it behind: the next `serve` takes it over when the process it names is gone, and repair says to delete it.
pub fn lock_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

/// Something that sees each record's fields (the JSON object without its braces) as the writer chains it.
pub type Observer = Box<dyn Fn(&str) + Send + Sync>;

/// How the writer keeps up, for `/metrics`, and who else reads the records as they are written.
#[derive(Default)]
pub struct Stats {
    /// Records handed to the writer and not yet taken by it.
    pub queued: AtomicU64,
    /// Time of each write call, one per batch of records.
    pub write: crate::metrics::Histogram,
    /// Set once, by the trace exporter. It runs on the writer thread, so it must only queue work, never wait.
    pub observer: std::sync::OnceLock<Observer>,
}

impl std::fmt::Debug for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stats")
            .field("queued", &self.queued)
            .field("observed", &self.observer.get().is_some())
            .finish()
    }
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuditLog")
    }
}

/// The writer thread: takes every record that is waiting, chains them, and writes them with one call.
fn write_records(
    mut chain: Chain,
    jobs: &mpsc::Receiver<Job>,
    broken: &AtomicBool,
    len: &AtomicU64,
    stats: &Stats,
) {
    let mut failed = false;
    while let Ok(first) = jobs.recv() {
        let mut batch = Vec::with_capacity(8);
        let (mut n, mut prev) = (chain.n, chain.prev.clone());
        let mut lines = String::new();
        let mut quiet: Vec<Box<dyn FnOnce(io::Result<()>) + Send>> = Vec::new();
        for (fields, done) in std::iter::once(first).chain(jobs.try_iter().take(255)) {
            stats.queued.fetch_sub(1, Ordering::Relaxed);
            let fields = match fields {
                Fields::Ready(fields) => fields,
                Fields::Later(make) => match make().map(|record| fields_of(&record)) {
                    Some(Ok(fields)) => fields,
                    Some(Err(err)) => {
                        done(Err(err));
                        continue;
                    }
                    None => {
                        // Told once the records before it are written, so an empty job is a way to wait for them.
                        quiet.push(done);
                        continue;
                    }
                },
            };
            if let Some(see) = stats.observer.get() {
                see(&fields);
            }
            batch.push(done);
            n += 1;
            let body = format!("{{\"n\":{n},{fields},\"prev\":\"{prev}\"");
            prev = hash_of(&body);
            lines.push_str(&body);
            lines.push_str(",\"hash\":\"");
            lines.push_str(&prev);
            lines.push_str("\"}\n");
        }
        if batch.is_empty() {
            quiet.into_iter().for_each(|done| done(Ok(())));
            continue;
        }
        // After a failed write the file may end in half a record, so nothing more is written to it.
        // Every later request is refused until an admin has looked and Gantry is started again.
        let result = if failed {
            Err(io::ErrorKind::BrokenPipe)
        } else if let Err(what) = chain.intact() {
            eprintln!(
                "gantry: the audit log is gone: {what} while Gantry was running. Every request is refused until Gantry is started again. If the file is gone for good, a restart begins a new chain at record 1 in a new file: keep whatever copy of the old one you have."
            );
            Err(io::ErrorKind::NotFound)
        } else {
            let started = std::time::Instant::now();
            let written = chain
                .file
                .write_all(lines.as_bytes())
                .map_err(|err| err.kind());
            stats.write.observe(started.elapsed());
            written
        };
        match result {
            Ok(()) => {
                (chain.n, chain.prev) = (n, prev);
                chain.len += lines.len() as u64;
                len.store(chain.len, Ordering::Relaxed);
            }
            Err(_) => {
                failed = true;
                broken.store(true, Ordering::Relaxed);
            }
        }
        for done in batch {
            done(result.map_err(io::Error::from));
        }
        quiet.into_iter().for_each(|done| done(Ok(())));
    }
}

/// The time now, as records write it.
pub fn timestamp() -> String {
    rfc3339(SystemTime::now())
}

fn cut(text: &str) -> &str {
    match text.char_indices().nth(MAX_TEXT) {
        Some((end, _)) => &text[..end],
        None => text,
    }
}

/// UTC time as `2026-11-12T14:02:11.482Z`. Days to a calendar date by Howard Hinnant's civil-from-days.
/// A time as audit records write it, for example `2026-11-13T09:14:02.120Z`.
pub fn rfc3339(now: SystemTime) -> String {
    let millis = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis());
    let (secs, ms) = (millis / 1000, millis % 1000);
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let z = days + 719_468;
    let (era, doe) = (z / 146_097, z % 146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u128::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{ms:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn broken(path: &Path, what: &str) -> String {
    format!(
        "the audit log at {} is broken at its end: {what}. Run `gantry audit verify {}` to see how far the chain holds. \
         If only the last line is cut short (a write failed part way, for example on a full disk), free the space, run \
         `gantry audit repair {}` to see that line, then `gantry audit repair {} --yes` to remove it and record the \
         repair, and start again.",
        path.display(),
        path.display(),
        path.display(),
        path.display()
    )
}

/// Splits a line into the text its hash covers and the hash, or `None` if it does not end as a record must.
fn split(line: &str) -> Option<(&str, &str)> {
    let at = line.len().checked_sub(TAIL)?;
    let (body, tail) = (line.get(..at)?, line.get(at..)?);
    let hash = tail.strip_prefix(",\"hash\":\"")?.strip_suffix("\"}")?;
    Some((body, hash))
}

fn hash_of(body: &str) -> String {
    sha256_hex(format!("{body}}}").as_bytes())
}

impl AuditLog {
    /// Opens the log for appending and picks the chain up where the last record left it.
    pub fn open(path: &Path) -> Result<Self, String> {
        let mut options = OpenOptions::new();
        options.create(true).read(true).append(true);
        // A new log is readable by its owner only: it names every caller and what each asked for.
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        // Windows has no inode to compare, so it cannot tell a replaced log from the one it opened. Without
        // FILE_SHARE_DELETE nobody can delete, rename or replace the log while this handle is open; writers and readers
        // are still let in, and a log cut short is caught by its length as on Unix.
        #[cfg(windows)]
        std::os::windows::fs::OpenOptionsExt::share_mode(&mut options, FILE_SHARE_READ_WRITE);
        let mut file = options
            .open(path)
            .map_err(|err| {
                format!(
                    "the audit log at {} cannot be opened for writing: {err}. Check that the folder exists and that Gantry may write to it, or set `audit: {{ path: ... }}` in the policy file.",
                    path.display()
                )
            })?;
        let io_err =
            |err: io::Error| format!("the audit log at {} cannot be read: {err}.", path.display());
        // A device or a pipe would swallow records and still report success. Windows can fail to describe a device
        // such as NUL at all, so there that failure counts as not a regular file.
        let meta = match file.metadata() {
            Ok(meta) if meta.is_file() && !is_device(&meta) => meta,
            Err(err) if !cfg!(windows) => return Err(io_err(err)),
            _ => {
                return Err(format!(
                    "the audit log at {} is not a regular file, so records written to it would not be kept. Point `audit: {{ path: ... }}` at a file.",
                    path.display()
                ));
            }
        };
        let len = meta.len();
        let (mut n, mut prev) = (0, GENESIS.to_string());
        // A configuration record holds the whole policy file, so the last line can be long. The window grows to fit it.
        let mut window = 64 * 1024;
        // Ends at the first whole last line, or returns why there is none.
        while len > 0 && n == 0 {
            // The last record is enough to continue the chain. `gantry audit verify` checks all of it.
            let from = len.saturating_sub(window);
            file.seek(SeekFrom::Start(from)).map_err(io_err)?;
            // Read as bytes: the window can start in the middle of a character, and only the last line has to be text.
            let mut tail = Vec::new();
            file.read_to_end(&mut tail).map_err(io_err)?;
            let Some(complete) = tail.strip_suffix(b"\n") else {
                return Err(broken(path, "the last line is cut short"));
            };
            let start = complete
                .iter()
                .rposition(|b| *b == b'\n')
                .map_or(0, |i| i + 1);
            if start == 0 && from > 0 {
                if window < MAX_LINE {
                    window *= 4;
                    continue;
                }
                return Err(broken(
                    path,
                    "the last line is longer than any record Gantry writes",
                ));
            }
            let Ok(last) = std::str::from_utf8(&complete[start..]) else {
                return Err(broken(path, "the last line is not text"));
            };
            let record = split(last)
                .filter(|(body, hash)| hash_of(body) == *hash)
                .and_then(|(_, hash)| {
                    let value: Value = serde_json::from_str(last).ok()?;
                    Some((value.get("n")?.as_u64()?, hash.to_string()))
                });
            let Some(found) = record else {
                return Err(broken(path, "the last line is not a whole record"));
            };
            (n, prev) = found;
            break;
        }
        let mut log = Self::start(Chain {
            file,
            n,
            prev,
            path: Some(path.to_path_buf()),
            len,
        })
        .map_err(|err| format!("the audit log writer could not be started: {err}."))?;
        log.lock = take_lock(path)?;
        Ok(log)
    }

    fn start(chain: Chain) -> io::Result<Self> {
        let syncer = chain.file.try_clone().ok();
        let (path, records_at_open) = (chain.path.clone(), chain.n);
        let len = Arc::new(AtomicU64::new(chain.len));
        let (writer, jobs) = mpsc::channel();
        let broken = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(Stats::default());
        std::thread::Builder::new()
            .name("gantry-audit".into())
            .spawn({
                let (broken, len, stats) = (broken.clone(), len.clone(), stats.clone());
                move || write_records(chain, &jobs, &broken, &len, &stats)
            })?;
        Ok(Self {
            writer,
            syncer,
            broken,
            path,
            records_at_open,
            len,
            stats,
            lock: None,
        })
    }

    /// Starts an empty chain on a file that is already open.
    pub fn from_file(file: File) -> io::Result<Self> {
        let len = file.metadata().map_or(0, |m| m.len());
        Self::start(Chain {
            file,
            n: 0,
            prev: GENESIS.to_string(),
            path: None,
            len,
        })
    }

    /// Hands one record to the writer. `done` is called with the outcome: on `Ok`, the operating system has the record.
    pub fn append_then(
        &self,
        entry: &Entry<'_>,
        done: impl FnOnce(io::Result<()>) + Send + 'static,
    ) {
        self.append_record_then(&record(entry), done);
    }
}

/// The fields of a request record, for a caller that adds fields of its own before writing it.
pub fn record(entry: &Entry<'_>) -> Map<String, Value> {
    let text = |value: Option<&str>| value.map_or(Value::Null, |v| Value::from(cut(v)));
    let mut record = Map::new();
    record.insert("id".into(), entry.id.into());
    record.insert("time".into(), rfc3339(SystemTime::now()).into());
    record.insert("person".into(), text(entry.person.or(Some("unknown"))));
    record.insert("team".into(), text(entry.team));
    record.insert("client".into(), text(entry.client));
    record.insert("key".into(), text(entry.key));
    record.insert("method".into(), text(Some(entry.method)));
    record.insert("path".into(), text(Some(entry.path)));
    record.insert("model".into(), text(entry.model));
    let verdict = if entry.allowed { "allow" } else { "refused" };
    record.insert("verdict".into(), verdict.into());
    record.insert("code".into(), text(entry.code));
    record.insert("rule".into(), text(entry.rule));
    record.insert(
        "rule_line".into(),
        entry.rule_line.map_or(Value::Null, Value::from),
    );
    // A request refused before a provider was chosen has none.
    let provider = Some(entry.provider).filter(|p| !p.is_empty());
    record.insert("provider".into(), provider.map_or(Value::Null, Value::from));
    record.insert("policy_sha256".into(), entry.policy_sha256.into());
    record.insert("keys_sha256".into(), entry.keys_sha256.into());
    // Only when true, so records of requests that were not translated keep their shape.
    if entry.translated {
        record.insert("translated".into(), true.into());
    }
    if let Some(cache) = entry.cache {
        record.insert("cache".into(), cache.into());
    }
    record
}

impl AuditLog {
    /// Hands any record to the writer, for records that are not requests: configuration changes and admin calls.
    /// Their fields are written as given, after the record number.
    pub fn append_record_then(
        &self,
        record: &Map<String, Value>,
        done: impl FnOnce(io::Result<()>) + Send + 'static,
    ) {
        match fields_of(record) {
            Ok(fields) => self.send(Fields::Ready(fields), Box::new(done)),
            Err(err) => done(Err(err)),
        }
    }

    /// Hands the writer the work that makes a record, run on its thread in turn with the other records. For a record
    /// that follows an answer (usage), so the answer is not held up by building it. `make` returning `None` writes
    /// nothing; `done` is told either way.
    pub fn append_later(
        &self,
        make: impl FnOnce() -> Option<Map<String, Value>> + Send + 'static,
        done: impl FnOnce(io::Result<()>) + Send + 'static,
    ) {
        self.send(Fields::Later(Box::new(make)), Box::new(done));
    }

    fn send(&self, fields: Fields, done: Box<dyn FnOnce(io::Result<()>) + Send>) {
        self.stats.queued.fetch_add(1, Ordering::Relaxed);
        if let Err(mpsc::SendError((_, done))) = self.writer.send((fields, done)) {
            self.stats.queued.fetch_sub(1, Ordering::Relaxed);
            done(Err(io::Error::other("the audit log writer has stopped")));
        }
    }

    /// Queue depth and write times of the writer.
    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Writes any record and waits for it. Not for a worker thread of the server.
    pub fn append_record(&self, record: &Map<String, Value>) -> io::Result<()> {
        let (tell, outcome) = mpsc::channel();
        self.append_record_then(record, move |result| {
            let _ = tell.send(result);
        });
        outcome
            .recv()
            .unwrap_or_else(|_| Err(io::Error::other("the audit log writer has stopped")))
    }

    /// Writes one record and waits for it. For tools and tests: a server must not block a worker thread on this.
    pub fn append(&self, entry: &Entry<'_>) -> io::Result<()> {
        let (tell, outcome) = mpsc::channel();
        self.append_then(entry, move |result| {
            let _ = tell.send(result);
        });
        outcome
            .recv()
            .unwrap_or_else(|_| Err(io::Error::other("the audit log writer has stopped")))
    }

    /// Whether a write has failed or the file has gone. Once true, every record is refused until a restart.
    /// It also looks at the file itself, so a health check sees a deleted or replaced log before any request does.
    pub fn is_broken(&self) -> bool {
        if self.broken.load(Ordering::Relaxed) {
            return true;
        }
        #[cfg(unix)]
        if let (Some(path), Some(open)) = (&self.path, &self.syncer) {
            use std::os::unix::fs::MetadataExt;
            return !matches!(
                (std::fs::metadata(path), open.metadata()),
                (Ok(named), Ok(open)) if named.ino() == open.ino() && named.dev() == open.dev() && open.len() >= self.len.load(Ordering::Relaxed)
            );
        }
        // Elsewhere the log is opened so it cannot be deleted or replaced (see `open`): only its length can change.
        #[cfg(not(unix))]
        if let (Some(_), Some(open)) = (&self.path, &self.syncer) {
            return !open
                .metadata()
                .is_ok_and(|open| open.len() >= self.len.load(Ordering::Relaxed));
        }
        false
    }

    /// How many records the log held when it was opened. Zero means a new chain starts at record 1.
    pub fn records_at_open(&self) -> u64 {
        self.records_at_open
    }

    /// Waits until every record handed to the writer before this call is written, then puts the log on disk.
    /// For a server that is stopping: a usage record is handed over when an answer ends, and would be lost if the
    /// process ended before the writer got to it. Blocks the calling thread.
    pub fn flush(&self) {
        let (tell, told) = mpsc::channel();
        self.append_later(
            || None,
            move |_| {
                let _ = tell.send(());
            },
        );
        let _ = told.recv();
        self.sync();
    }

    /// Asks the operating system to put what was written on disk. Called once a second by the server.
    pub fn sync(&self) {
        if let Some(file) = &self.syncer {
            let _ = file.sync_data();
        }
    }
}

/// The configuration in use after the last `config_loaded` record of a log.
#[derive(Clone, Debug, Default)]
pub struct LastConfig {
    pub policy_sha256: String,
    pub keys_sha256: String,
    /// Name, team and first 8 hex characters of the hash of each key, replayed from the records.
    pub keys: BTreeSet<(String, String, String)>,
}

/// What a walk of the whole chain found.
#[derive(Clone, Debug, Default)]
pub struct Summary {
    pub records: u64,
    pub requests: u64,
    pub configuration: u64,
    pub admin: u64,
    /// Follow-ups to a request record that list each provider tried when one failed before answering.
    pub attempts: u64,
    /// Records of what a forwarded request used and cost, or how an MCP tool call ended, written when its answer ends.
    pub usage: u64,
    pub last_hash: String,
    /// The number of the record with the hash that was asked for.
    pub found: Option<u64>,
    pub last_config: Option<LastConfig>,
}

fn key_refs(value: &Value) -> impl Iterator<Item = (String, String, String)> + '_ {
    value.as_array().into_iter().flatten().map(|key| {
        let text = |field: &str| key[field].as_str().unwrap_or_default().to_string();
        (text("name"), text("team"), text("sha256_prefix"))
    })
}

/// Walks the whole chain. Returns the number of records, or what is wrong with the first record that does not hold.
/// Records removed from the end leave an unbroken chain, so the last hash is returned for comparing with a copy kept elsewhere.
pub fn verify(path: &Path) -> Result<(u64, String), String> {
    verify_full(path, None).map(|summary| (summary.records, summary.last_hash))
}

/// Walks the whole chain and counts each kind of record. With `expect`, it also passes only if a record with
/// that hash is in the chain and nothing before it was changed: the check against a hash kept elsewhere.
pub fn verify_full(path: &Path, expect: Option<&str>) -> Result<Summary, String> {
    // A hash copied short would otherwise read as records removed, which is a claim of tampering.
    if let Some(expect) = expect.filter(|e| e.len() != 64) {
        return Err(format!(
            "{expect} is {} characters; a record hash is 64. Copy the whole hash, as `gantry audit verify` or the console prints it.",
            expect.chars().count()
        ));
    }
    let file = File::open(path).map_err(|err| {
        format!(
            "the audit log at {} cannot be opened: {err}.",
            path.display()
        )
    })?;
    walk(BufReader::new(file), path, expect)
}

/// A last line cut short by a write that failed part way: where the whole records end, and the bytes after them.
pub struct Cut {
    pub keep: u64,
    pub removed: Vec<u8>,
}

/// Finds a last line cut short after a chain that holds, for `gantry audit repair`. `None` when the log ends with a
/// whole line. Anything else wrong (a changed record, a missing one, a whole last line that is not a record) is an
/// error, as `gantry audit verify` reports it: only a cut last line is ever offered for removal.
pub fn find_cut(path: &Path) -> Result<Option<Cut>, String> {
    let io_err =
        |err: io::Error| format!("the audit log at {} cannot be read: {err}.", path.display());
    let mut file = File::open(path).map_err(io_err)?;
    let len = file.metadata().map_err(io_err)?.len();
    // A record is at most MAX_LINE bytes, so a cut one is too.
    let from = len.saturating_sub(MAX_LINE);
    file.seek(SeekFrom::Start(from)).map_err(io_err)?;
    let mut tail = Vec::new();
    file.read_to_end(&mut tail).map_err(io_err)?;
    if tail.is_empty() || tail.ends_with(b"\n") {
        return Ok(None);
    }
    let whole_line = |line: &[u8]| serde_json::from_slice::<Value>(line).is_ok();
    let keep = match tail.iter().rposition(|b| *b == b'\n') {
        Some(at) => from + at as u64 + 1,
        None if from == 0 => 0,
        None => {
            return Err(broken(
                path,
                "the last line is longer than any record Gantry writes, so it is not a cut record",
            ));
        }
    };
    file.seek(SeekFrom::Start(0)).map_err(io_err)?;
    let records = walk(BufReader::new(file.take(keep)), path, None)?.records;
    let removed = tail[usize::try_from(keep - from).unwrap_or(0)..].to_vec();
    // Only the start of the record the writer was writing is a cut line. Whole JSON (a record that lost its newline,
    // or a changed one) and anything else is evidence, never removed.
    if whole_line(&removed) {
        return Err(format!(
            "the last line of {} is whole JSON without its newline, not a line cut short. It may be a record that lost its newline, or a changed one: check it, and if it is Gantry's record, add the newline at the end of the file and run gantry audit verify.",
            path.display()
        ));
    }
    let next = format!("{{\"n\":{},", records + 1);
    let starts_right = if removed.len() < next.len() {
        next.as_bytes().starts_with(&removed)
    } else {
        removed.starts_with(next.as_bytes())
    };
    if !starts_right {
        return Err(format!(
            "the last line of {} does not start as record {} must ({next}...), so it is not a record cut short. Nothing was removed: keep the file as it is, as evidence, and to start a new chain move it aside while Gantry is stopped.",
            path.display(),
            records + 1
        ));
    }
    Ok(Some(Cut { keep, removed }))
}

/// Removes the cut last line `find_cut` found and appends an `audit_repaired` record that holds it, so the chain
/// shows what was removed. Returns the number of records after the repair.
pub fn repair(path: &Path, cut: &Cut) -> Result<u64, String> {
    let io_err = |err: io::Error| {
        format!(
            "the audit log at {} could not be repaired: {err}. Nothing was removed if the file still ends with the cut line; check the disk has space and try again.",
            path.display()
        )
    };
    let lock = lock_path(path);
    if lock.exists() {
        let pid = std::fs::read_to_string(&lock).unwrap_or_default();
        return Err(format!(
            "a Gantry process ({}) holds the audit log at {}: it wrote {}. Stop it and run the repair again; a repair while it writes would break the chain. If no Gantry is running (it was killed), delete {} and run the repair again.",
            match pid.trim() {
                "" => "process ID unknown".to_string(),
                pid => format!("process {pid}"),
            },
            path.display(),
            lock.display(),
            lock.display()
        ));
    }
    let file = OpenOptions::new().write(true).open(path).map_err(io_err)?;
    // The cut line is still at the end: nothing wrote to the file since it was found.
    if file.metadata().map_err(io_err)?.len() != cut.keep + cut.removed.len() as u64 {
        return Err(format!(
            "the audit log at {} changed while it was being repaired. Stop whatever writes to it and run the repair again.",
            path.display()
        ));
    }
    file.set_len(cut.keep).map_err(io_err)?;
    file.sync_all().map_err(io_err)?;
    drop(file);
    let log = AuditLog::open(path)?;
    let mut record = Map::new();
    record.insert("event".into(), "audit_repaired".into());
    record.insert("time".into(), timestamp().into());
    record.insert("removed_bytes".into(), cut.removed.len().into());
    record.insert("removed_sha256".into(), sha256_hex(&cut.removed).into());
    record.insert(
        "removed_text".into(),
        String::from_utf8_lossy(&cut.removed).into_owned().into(),
    );
    log.append_record(&record).map_err(io_err)?;
    log.flush();
    Ok(log.records_at_open() + 1)
}

/// Walks a chain read from `reader`, `path` naming it in messages.
fn walk(reader: impl BufRead, path: &Path, expect: Option<&str>) -> Result<Summary, String> {
    let mut summary = Summary {
        last_hash: GENESIS.to_string(),
        ..Summary::default()
    };
    let not_here = |expect: &str| {
        format!(
            "not in this file: no record in {} has the hash {expect}. Either the records up to it were removed, or this is not the log that hash was taken from.",
            path.display()
        )
    };
    let mut lines = reader.lines();
    while let Some(line) = lines.next() {
        let n = summary.records + 1;
        let count = summary.records;
        let before = match count {
            0 => "No record before it is intact.".to_string(),
            1 => "Record 1 is intact.".to_string(),
            _ => format!("Records 1 to {count} are intact."),
        };
        let fail = |what: &str| {
            format!(
                "record {n} in {} does not hold: {what}. {before} Record {n} and everything after it cannot be trusted.",
                path.display()
            )
        };
        let checked = (|| {
            let line = line.map_err(|_| fail("it is not text"))?;
            let (body, hash) =
                split(&line).ok_or_else(|| fail("it is cut short or has no hash"))?;
            if hash_of(body) != hash {
                return Err(fail(
                    "its content does not match its hash, so it was changed after it was written",
                ));
            }
            let value: Value =
                serde_json::from_str(&line).map_err(|_| fail("it is not a JSON record"))?;
            if value.get("prev").and_then(Value::as_str) != Some(summary.last_hash.as_str()) {
                return Err(fail(
                    "it does not follow the record before it, so a record was removed, inserted or reordered",
                ));
            }
            if value.get("n").and_then(Value::as_u64) != Some(n) {
                return Err(fail("its number is out of sequence"));
            }
            Ok((value, hash.to_string()))
        })();
        let (value, hash) = match checked {
            Ok(found) => found,
            Err(err) => {
                let Some(expect) = expect else {
                    return Err(err);
                };
                if summary.found.is_some() {
                    return Err(format!(
                        "{expect} is record {} and the chain holds up to it, but {err}",
                        summary.found.unwrap_or_default()
                    ));
                }
                // The kept hash may still be further on, past the damage.
                let tail = format!(",\"hash\":\"{expect}\"}}");
                let later = lines
                    .map_while(Result::ok)
                    .position(|line| line.ends_with(&tail));
                return Err(match later {
                    Some(_) => format!(
                        "chain broken before it: a record with the hash {expect} is further on in this file, but {err}"
                    ),
                    None => format!("{} Also: {err}", not_here(expect)),
                });
            }
        };
        match value.get("event").and_then(Value::as_str) {
            None => summary.requests += 1,
            Some("admin" | "audit_repaired") => summary.admin += 1,
            Some("attempts") => summary.attempts += 1,
            // An MCP tool call's outcome follows its decision as a usage record follows a model request's.
            Some("usage" | "mcp_result") => summary.usage += 1,
            Some(event) => {
                summary.configuration += 1;
                if event == "config_loaded" {
                    let mut keys = summary
                        .last_config
                        .take()
                        .map(|last| last.keys)
                        .unwrap_or_default();
                    for removed in key_refs(&value["keys_removed"]) {
                        keys.remove(&removed);
                    }
                    keys.extend(key_refs(&value["keys_added"]));
                    let text = |field: &str| value[field].as_str().unwrap_or_default().to_string();
                    summary.last_config = Some(LastConfig {
                        policy_sha256: text("policy_sha256"),
                        keys_sha256: text("keys_sha256"),
                        keys,
                    });
                }
            }
        }
        if expect == Some(hash.as_str()) {
            summary.found = Some(n);
        }
        summary.records = n;
        summary.last_hash = hash;
    }
    match expect {
        Some(expect) if summary.found.is_none() => Err(not_here(expect)),
        _ => Ok(summary),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn temp(name: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("gantry-audit-{}-{name}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn repair_removes_only_the_cut_start_of_the_next_record_and_never_while_held() -> TestResult {
        // QA11-8.
        let path = temp("repair-only-cut");
        let log = AuditLog::open(&path)?;
        for id in ["A", "B"] {
            log.append(&Entry {
                id,
                ..Default::default()
            })?;
        }
        log.flush();
        assert!(lock_path(&path).exists(), "an open log holds its lock");
        drop(log);
        assert!(
            !lock_path(&path).exists(),
            "closing the log removes its lock"
        );
        let whole = std::fs::read(&path)?;
        let with = |tail: &[u8]| -> Result<(), std::io::Error> {
            let mut bytes = whole.clone();
            bytes.extend_from_slice(tail);
            std::fs::write(&path, bytes)
        };
        let last = whole[..whole.len() - 1]
            .rsplit(|b| *b == b'\n')
            .next()
            .ok_or("no last line")?
            .to_vec();
        // (a) A whole record without its newline, (b) a tail that is not a record, (c) a changed record without its
        // newline, and a cut line with the wrong number: all refused.
        let unchanged = whole[..whole.len() - 1].to_vec();
        let changed = String::from_utf8(unchanged.clone())?.replacen("\"B\"", "\"Z\"", 1);
        for (what, bytes) in [
            ("whole record", unchanged),
            ("changed record", changed.into_bytes()),
        ] {
            std::fs::write(&path, &bytes)?;
            let err = find_cut(&path).err().ok_or(what)?;
            assert!(err.contains("whole JSON"), "{what}: {err}");
        }
        assert!(!last.is_empty());
        for tail in [&b"not a record at all"[..], b"{\"n\":7,\"id\":\"C"] {
            with(tail)?;
            let err = find_cut(&path).err().ok_or("refused")?;
            assert!(err.contains("does not start as record 3"), "{err}");
        }
        // The cut start of record 3, however short, is a cut line.
        for tail in [&b"{\"n"[..], b"{\"n\":3,\"id\":\"C"] {
            with(tail)?;
            let cut = find_cut(&path)?.ok_or("no cut found")?;
            assert_eq!(cut.removed, tail);
        }
        // (f) A writer that appends between finding the cut and removing it: refused, nothing removed.
        let cut = find_cut(&path)?.ok_or("no cut found")?;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)?
            .write_all(b"more")?;
        let before = std::fs::read(&path)?;
        let err = repair(&path, &cut)
            .err()
            .ok_or("repaired a changing file")?;
        assert!(err.contains("changed while"), "{err}");
        assert_eq!(std::fs::read(&path)?, before);
        // (d) While a Gantry holds the log, repair is refused; once it is gone, it goes ahead.
        with(b"{\"n\":3,\"id\":\"C")?;
        let cut = find_cut(&path)?.ok_or("no cut found")?;
        std::fs::write(lock_path(&path), "4242\n")?;
        let err = repair(&path, &cut).err().ok_or("repaired a held log")?;
        assert!(
            err.contains("process 4242") && err.contains(".lock"),
            "{err}"
        );
        std::fs::remove_file(lock_path(&path))?;
        assert_eq!(repair(&path, &cut)?, 3);
        assert!(!lock_path(&path).exists());
        assert_eq!(verify(&path)?.0, 3);
        Ok(())
    }

    #[test]
    fn a_second_open_of_a_held_log_is_refused_and_never_removes_the_holders_lock() -> TestResult {
        // QA12-2.
        let path = temp("held-twice");
        let first = AuditLog::open(&path)?;
        let err = AuditLog::open(&path)
            .err()
            .ok_or("a second log opened a held file")?;
        assert!(err.contains(".lock") && err.contains("holds"), "{err}");
        assert!(
            lock_path(&path).exists(),
            "the refusal kept the holder's lock"
        );
        drop(first);
        assert!(!lock_path(&path).exists());
        // A live process that is not a Gantry of this process: refused, the file named.
        let other = std::process::Command::new("sleep").arg("30").spawn()?;
        std::fs::write(lock_path(&path), format!("{}\n", other.id()))?;
        let err = AuditLog::open(&path)
            .err()
            .ok_or("opened a log held by a live process")?;
        assert!(err.contains(&format!("process {}", other.id())), "{err}");
        let mut other = other;
        other.kill()?;
        other.wait()?;
        // A lock left by a process that is gone is taken over, and a lock that is not this log's is never removed.
        let log = AuditLog::open(&path)?;
        std::fs::write(lock_path(&path), "4242\n")?;
        drop(log);
        assert!(lock_path(&path).exists(), "removed another process's lock");
        std::fs::remove_file(lock_path(&path))?;
        Ok(())
    }

    #[test]
    fn a_kept_hash_cut_short_is_named_as_cut_short_not_as_removed_records() -> TestResult {
        let path = temp("short-expect");
        drop(AuditLog::open(&path)?);
        let err = verify_full(&path, Some("fa69f55ddad9"))
            .err()
            .unwrap_or_default();
        assert!(
            err.contains("12 characters") && err.contains("64") && !err.contains("removed"),
            "{err}"
        );
        Ok(())
    }

    /// What a stopping server relies on: once an empty job is told, every record handed over before it is in the
    /// file, even one still being made and one in the same batch as the empty job.
    #[cfg(unix)]
    #[test]
    fn a_new_log_is_readable_by_its_owner_only() -> TestResult {
        use std::os::unix::fs::PermissionsExt;
        let path = temp("mode");
        drop(AuditLog::open(&path)?);
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            0o600
        );
        Ok(())
    }

    #[test]
    fn flush_waits_for_records_handed_over_before_it() -> TestResult {
        let path = temp("flush");
        let log = AuditLog::open(&path)?;
        let slow = |event: &'static str| {
            move || {
                std::thread::sleep(std::time::Duration::from_millis(200));
                let mut record = Map::new();
                record.insert("event".into(), event.into());
                Some(record)
            }
        };
        log.append_later(slow("first"), |_| {});
        let (tell, told) = mpsc::channel();
        log.append_later(
            || None,
            move |_| {
                let _ = tell.send(());
            },
        );
        // Made after the empty job in the same batch: the empty job must still wait for "first" to be written.
        log.append_later(slow("second"), |_| {});
        told.recv()?;
        assert!(std::fs::read_to_string(&path)?.contains("\"event\":\"first\""));
        log.flush();
        let text = std::fs::read_to_string(&path)?;
        assert!(text.contains("\"event\":\"second\""), "{text}");
        assert_eq!(verify_full(&path, None)?.records, 2);
        Ok(())
    }

    #[test]
    fn a_record_made_later_is_chained_in_turn_and_none_writes_nothing() -> TestResult {
        let path = temp("later");
        let log = AuditLog::open(&path)?;
        let (tell, told) = mpsc::channel();
        let tell_none = tell.clone();
        log.append_later(
            || {
                let mut record = Map::new();
                record.insert("event".into(), "usage".into());
                Some(record)
            },
            move |result| {
                let _ = tell.send(result.is_ok());
            },
        );
        log.append_later(
            || None,
            move |result| {
                let _ = tell_none.send(result.is_ok());
            },
        );
        log.append(&entry("01B"))?;
        assert_eq!((told.recv()?, told.recv()?), (true, true));
        let text = std::fs::read_to_string(&path)?;
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert!(
            lines[0].starts_with("{\"n\":1,\"event\":\"usage\""),
            "{text}"
        );
        assert!(lines[1].starts_with("{\"n\":2,"), "{text}");
        verify(&path)?;
        Ok(())
    }

    fn entry(id: &str) -> Entry<'_> {
        Entry {
            id,
            person: Some("maya.cohen"),
            team: Some("payments"),
            method: "POST",
            path: "/v1/chat/completions",
            model: Some("gpt-4o-mini"),
            allowed: true,
            provider: "openai",
            ..Entry::default()
        }
    }

    #[test]
    fn time_is_written_as_utc() {
        let at = |secs| rfc3339(UNIX_EPOCH + std::time::Duration::from_millis(secs));
        assert_eq!(at(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(at(951_782_400_000), "2000-02-29T00:00:00.000Z");
        assert_eq!(at(1_794_492_131_482), "2026-11-12T14:02:11.482Z");
    }

    #[test]
    fn the_chain_holds_and_continues_after_a_restart() -> TestResult {
        let path = temp("chain");
        let log = AuditLog::open(&path)?;
        log.append(&entry("A"))?;
        log.append(&entry("B"))?;
        drop(log);
        let log = AuditLog::open(&path)?;
        log.append(&entry("C"))?;
        assert_eq!(verify(&path)?.0, 3);
        Ok(())
    }

    #[test]
    fn a_changed_removed_or_cut_record_is_found() -> TestResult {
        let path = temp("tamper");
        let log = AuditLog::open(&path)?;
        for id in ["A", "B", "C"] {
            log.append(&entry(id))?;
        }
        let original = std::fs::read_to_string(&path)?;

        std::fs::write(
            &path,
            original
                .replacen("maya.cohen", "mallory.x", 2)
                .replacen("mallory.x", "maya.cohen", 1),
        )?;
        let err = verify(&path).err().ok_or("a changed record passed")?;
        assert!(err.contains("record 2") && err.contains("changed"), "{err}");

        let without_second: String = original
            .lines()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, l)| format!("{l}\n"))
            .collect();
        std::fs::write(&path, without_second)?;
        let err = verify(&path).err().ok_or("a removed record passed")?;
        assert!(err.contains("record 2") && err.contains("removed"), "{err}");

        std::fs::write(&path, &original[..original.len() - 20])?;
        let err = AuditLog::open(&path).err().ok_or("a cut log opened")?;
        assert!(
            err.contains("gantry audit verify") && err.contains("gantry audit repair"),
            "{err}"
        );
        Ok(())
    }

    #[test]
    fn a_last_record_that_does_not_match_its_hash_stops_the_log_from_opening() -> TestResult {
        let path = temp("lasthash");
        let log = AuditLog::open(&path)?;
        log.append(&entry("A"))?;
        log.append(&entry("B"))?;
        drop(log);
        let text = std::fs::read_to_string(&path)?;
        let at = text
            .rfind("maya.cohen")
            .ok_or("no person in the last record")?;
        std::fs::write(
            &path,
            format!("{}mala.cohen{}", &text[..at], &text[at + 10..]),
        )?;
        let err = AuditLog::open(&path)
            .err()
            .ok_or("a changed last record was trusted")?;
        assert!(err.contains("not a whole record"), "{err}");
        Ok(())
    }

    #[test]
    fn the_health_of_the_log_shows_a_truncation_before_any_record_is_written() -> TestResult {
        let path = temp("cut-health");
        let log = AuditLog::open(&path)?;
        log.append(&entry("A"))?;
        assert!(!log.is_broken());
        std::fs::write(&path, "")?;
        assert!(log.is_broken(), "a log cut short in place looked healthy");
        Ok(())
    }

    #[test]
    fn a_last_record_longer_than_the_first_window_reopens() -> TestResult {
        // A configuration record holds the whole policy file.
        let path = temp("long-last");
        let log = AuditLog::open(&path)?;
        let mut record = Map::new();
        record.insert("event".into(), "config_loaded".into());
        record.insert("policy".into(), "x".repeat(300 * 1024).into());
        log.append_record(&record)?;
        drop(log);
        AuditLog::open(&path)?.append(&entry("A"))?;
        let summary = verify_full(&path, None)?;
        assert_eq!(
            (summary.records, summary.configuration, summary.requests),
            (2, 1, 1)
        );
        Ok(())
    }

    #[test]
    fn a_device_is_not_accepted_as_an_audit_log() {
        // NUL is Windows' /dev/null.
        let device = if cfg!(windows) { "NUL" } else { "/dev/null" };
        let err = AuditLog::open(Path::new(device)).err();
        assert!(err.is_some_and(|e| e.contains("not a regular file")));
    }

    #[test]
    fn a_long_log_with_wide_characters_reopens() -> TestResult {
        // The tail window used to be read as text and could start in the middle of a character.
        let path = temp("wide");
        let log = AuditLog::open(&path)?;
        let model = "é".repeat(150);
        for i in 0..400 {
            let shifted = format!("{}{model}", "x".repeat(i % 3));
            log.append(&Entry {
                model: Some(&shifted),
                ..entry("A")
            })?;
        }
        drop(log);
        assert!(std::fs::metadata(&path)?.len() > 64 * 1024);
        AuditLog::open(&path)?.append(&entry("B"))?;
        assert_eq!(verify(&path)?.0, 401);
        Ok(())
    }

    #[test]
    fn a_log_that_is_deleted_replaced_or_truncated_stops_taking_records() -> TestResult {
        for (name, damage) in [("deleted", 0), ("replaced", 1), ("truncated", 2)] {
            let path = temp(name);
            let log = AuditLog::open(&path)?;
            log.append(&entry("A"))?;
            if cfg!(windows) && damage < 2 {
                // Windows: the log cannot be deleted or replaced while it is held, so no record can go to a lost file.
                let other = path.with_extension("other");
                std::fs::write(&other, "")?;
                assert!(
                    std::fs::remove_file(&path).is_err()
                        && std::fs::rename(&path, path.with_extension("moved")).is_err()
                        && std::fs::rename(&other, &path).is_err(),
                    "{name}: a held log was deleted, moved or replaced"
                );
                std::fs::remove_file(&other)?;
                assert!(!log.is_broken(), "{name}: the refused delete broke the log");
                log.append(&entry("B"))?;
                drop(log);
                assert_eq!(verify(&path)?.0, 2, "{name}: a record was lost");
                continue;
            }
            match damage {
                0 => std::fs::remove_file(&path)?,
                1 => {
                    std::fs::remove_file(&path)?;
                    std::fs::write(&path, "")?;
                }
                _ => std::fs::write(&path, "")?,
            }
            assert!(
                log.append(&entry("B")).is_err(),
                "{name}: a record was accepted"
            );
            assert!(log.is_broken());
            if damage == 2 {
                // The file grows back past its old length. The writer must still not trust it.
                std::fs::write(&path, "x".repeat(4096))?;
            }
            assert!(
                log.append(&entry("C")).is_err(),
                "{name}: the log recovered by itself"
            );
        }
        Ok(())
    }

    #[test]
    fn text_from_the_caller_is_cut_and_escaped() -> TestResult {
        let path = temp("cut");
        let log = AuditLog::open(&path)?;
        let long = "x\"\n".repeat(500);
        log.append(&Entry {
            path: &long,
            ..entry("A")
        })?;
        let text = std::fs::read_to_string(&path)?;
        assert_eq!(text.lines().count(), 1);
        assert!(text.len() < 2000, "{}", text.len());
        assert_eq!(verify(&path)?.0, 1);
        Ok(())
    }
}
