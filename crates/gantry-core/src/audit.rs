//! The audit log: one JSON record per line, each carrying the hash of the one before it,
//! so a record cannot be changed, removed or inserted without `verify` noticing.

use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
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
    /// The caller's `user-agent`, which names the coding tool and is what the coverage report counts by.
    pub user_agent: Option<&'a str>,
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
    /// The number of the first record in the open file: `n + 1` while it holds none. Sealed segments hold the ones
    /// before it.
    first: u64,
    /// Where the file was opened, to notice when that name no longer leads to this file.
    path: Option<PathBuf>,
    /// Bytes the log held after the last write, to notice when it is cut.
    len: u64,
    /// Whether this log still holds its lock, when it took one.
    fence: Option<Arc<Fence>>,
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
    /// Seal the file once the records before it are written: see [`AuditLog::seal`].
    Seal(mpsc::Sender<io::Result<Option<PathBuf>>>),
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
    // A second handle to the same file, so syncing to disk does not hold up the writer. The writer replaces it when
    // it seals the file.
    syncer: Arc<std::sync::Mutex<Option<File>>>,
    // Set by the writer once a write has failed or the file is gone. It stays set until Gantry is started again.
    broken: Arc<AtomicBool>,
    path: Option<PathBuf>,
    records_at_open: u64,
    // Bytes the log should hold, kept by the writer, so a health check can see a log cut short in place.
    len: Arc<AtomicU64>,
    stats: Arc<Stats>,
    /// The lock file this log wrote beside the file it holds, removed when it closes.
    lock: Option<Lock>,
    /// With `audit: { per_org: true }`: each organization's chain, where its records go instead of this one.
    orgs: Option<Arc<Orgs>>,
}

/// Decisions remembered to route the records that follow them (attempts, upstream errors, answer guardrails), which
/// do not name their organization, to the chain their decision went to.
const ORG_IDS: usize = 100_000;

/// Each organization's own chain, opened on its first record, beside the install's.
struct Orgs {
    path: PathBuf,
    logs: std::sync::Mutex<HashMap<String, Arc<AuditLog>>>,
    ids: std::sync::Mutex<(HashMap<String, String>, VecDeque<String>)>,
}

impl Orgs {
    fn log(&self, org: &str) -> Result<Arc<AuditLog>, String> {
        let mut logs = self
            .logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(log) = logs.get(org) {
            return Ok(log.clone());
        }
        let path = org_path(&self.path, org);
        let dir = orgs_dir(&self.path);
        std::fs::create_dir_all(&dir).map_err(|err| {
            format!(
                "the folder of the organizations' audit chains, {}, cannot be made: {err}.",
                dir.display()
            )
        })?;
        let log = Arc::new(AuditLog::open(&path)?);
        logs.insert(org.to_string(), log.clone());
        Ok(log)
    }

    fn all(&self) -> Vec<Arc<AuditLog>> {
        self.logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .collect()
    }

    /// The organization a record goes to: its own `org`, else that of the decision it follows.
    fn of(&self, record: &Map<String, Value>) -> Option<String> {
        let id = record.get("id").and_then(Value::as_str);
        let mut ids = self
            .ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match record
            .get("org")
            .and_then(Value::as_str)
            .filter(|o| !o.is_empty())
        {
            Some(org) => {
                if let Some(id) = id
                    && !ids.0.contains_key(id)
                {
                    let (map, order) = &mut *ids;
                    map.insert(id.to_string(), org.to_string());
                    order.push_back(id.to_string());
                    while order.len() > ORG_IDS {
                        if let Some(old) = order.pop_front() {
                            map.remove(&old);
                        }
                    }
                }
                Some(org.to_string())
            }
            None => ids.0.get(id?).cloned(),
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

/// How often a holder rewrites its lock. A lock that has not changed for six beats belongs to a Gantry that is gone;
/// one that cannot rewrite its own for three beats stops writing records first, so the two never overlap.
const BEAT: Duration = Duration::from_secs(5);

/// Who writes a lock: a process, the machine it runs on, and the process space it sees. Two containers can both
/// be process 1 on one share, so a process ID alone says nothing about a lock another container wrote.
#[derive(Clone, Debug)]
struct Me {
    pid: u32,
    host: Option<String>,
    /// Equal only for processes that can see each other's process IDs. None when it cannot be told.
    space: Option<String>,
}

impl Me {
    fn this_process() -> Me {
        static ME: std::sync::OnceLock<Me> = std::sync::OnceLock::new();
        ME.get_or_init(|| {
            let host = host_name();
            Me {
                pid: std::process::id(),
                space: pid_space(host.as_deref()),
                host,
            }
        })
        .clone()
    }
}

#[cfg(target_os = "linux")]
fn host_name() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
}

#[cfg(windows)]
fn host_name() -> Option<String> {
    std::env::var("COMPUTERNAME")
        .ok()
        .filter(|name| !name.is_empty())
}

#[cfg(not(any(target_os = "linux", windows)))]
fn host_name() -> Option<String> {
    let out = std::process::Command::new("hostname")
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !name.is_empty()).then_some(name)
}

/// On Linux a host name is no proof: Cloud Run and others can give every instance the same one. The boot ID tells
/// machines apart and the PID namespace tells containers on one machine apart.
#[cfg(target_os = "linux")]
fn pid_space(_: Option<&str>) -> Option<String> {
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let ns = std::fs::read_link("/proc/self/ns/pid").ok()?;
    Some(format!("{}/{}", boot.trim(), ns.display()))
}

/// Elsewhere containers do not share a machine's host name, and machines on one network do not either.
#[cfg(not(target_os = "linux"))]
fn pid_space(host: Option<&str>) -> Option<String> {
    host.map(str::to_string)
}

fn lock_text(me: &Me, instance: &str, beat: u64) -> String {
    format!(
        "holder {instance}\npid {}\nhost {}\nspace {}\nbeat {beat}\n",
        me.pid,
        me.host.as_deref().unwrap_or("unknown"),
        me.space.as_deref().unwrap_or("unknown")
    )
}

/// What a lock file says about its holder. A lock from before the holder line holds only a process ID.
struct Holder {
    pid: Option<u32>,
    host: Option<String>,
    space: Option<String>,
    bare: bool,
}

impl Holder {
    fn parse(text: &str) -> Holder {
        if let Ok(pid) = text.trim().parse::<u32>() {
            return Holder {
                pid: Some(pid),
                host: None,
                space: None,
                bare: true,
            };
        }
        let field = |name: &str| {
            text.lines()
                .filter_map(|line| line.split_once(' '))
                .find(|(key, value)| *key == name && *value != "unknown")
                .map(|(_, value)| value.to_string())
        };
        Holder {
            pid: field("pid").and_then(|pid| pid.parse().ok()),
            host: field("host"),
            space: field("space"),
            bare: false,
        }
    }

    fn describe(&self) -> String {
        match (self.pid, &self.host) {
            (Some(pid), Some(host)) => format!("process {pid} on {host}"),
            (Some(pid), None) => format!("process {pid}"),
            (None, _) => "process ID unknown".to_string(),
        }
    }
}

/// Whole seconds, rounded up, for messages.
fn secs(time: Duration) -> String {
    format!("{:.0}", time.as_secs_f64().ceil())
}

/// The holder's own say on whether it still holds its lock, which the writer asks before each write.
struct Fence {
    lock: PathBuf,
    start: Instant,
    /// When the holder last rewrote its lock, in milliseconds after `start`.
    beat_ms: AtomicU64,
    limit: Duration,
    /// Why records stopped. Kept once set: a lock that came back does not undo records another Gantry wrote meanwhile.
    lost: std::sync::OnceLock<String>,
}

impl Fence {
    fn beat(&self) {
        let ms = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.beat_ms.store(ms, Ordering::Relaxed);
    }

    /// Why records may no longer be written, or None while the lock is this log's.
    fn lost(&self) -> Option<String> {
        let since = Duration::from_millis(self.beat_ms.load(Ordering::Relaxed));
        if self.lost.get().is_none() && self.start.elapsed().saturating_sub(since) >= self.limit {
            let _ = self.lost.set(format!(
                "the audit log lock {} could not be updated for {} seconds, so another Gantry may take the log over. Every request is refused until Gantry is started again. Check that the folder is reachable and writable.",
                self.lock.display(),
                secs(self.limit)
            ));
        }
        self.lost.get().cloned()
    }
}

/// A lock this log holds: a thread rewrites it every beat, and closing the log removes it.
struct Lock {
    path: PathBuf,
    instance: String,
    fence: Arc<Fence>,
    stop: Option<mpsc::Sender<()>>,
    beats: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Lock {
    fn drop(&mut self) {
        // Stopped first, so a beat cannot write the lock again after it is removed.
        drop(self.stop.take());
        if let Some(beats) = self.beats.take() {
            let _ = beats.join();
        }
        locked_paths().remove(&self.path);
        // Only a lock that still names this log: another Gantry may have taken over one it found stale.
        if is_mine(&self.path, &self.instance) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn is_mine(lock: &Path, instance: &str) -> bool {
    std::fs::read_to_string(lock)
        .is_ok_and(|text| text.starts_with(&format!("holder {instance}\n")))
}

/// The lock's text written whole beside it, for a rename or link into place: a Gantry elsewhere reading the lock
/// while it is written in place can read it cut short, and then names a wrong holder.
fn staged(lock: &Path, text: &str) -> io::Result<PathBuf> {
    let mut name = lock.as_os_str().to_owned();
    name.push(format!(".{}.tmp", crate::id::random_hex(4)));
    let staged = PathBuf::from(name);
    std::fs::write(&staged, text)?;
    Ok(staged)
}

/// Creates the lock, whole, unless it exists: a hard link fails on an existing name, as create_new does.
fn create_lock(lock: &Path, text: &str) -> io::Result<()> {
    let staged = staged(lock, text)?;
    let linked = std::fs::hard_link(&staged, lock);
    let _ = std::fs::remove_file(&staged);
    linked
}

/// Replaces the lock, whole.
fn write_lock(lock: &Path, text: &str) -> io::Result<()> {
    let staged = staged(lock, text)?;
    std::fs::rename(&staged, lock).inspect_err(|_| {
        let _ = std::fs::remove_file(&staged);
    })
}

/// Rewrites the lock every beat, and stops once it names another Gantry.
fn keep_lock(
    lock: &Path,
    me: &Me,
    instance: &str,
    fence: &Fence,
    stop: &mpsc::Receiver<()>,
    beat: Duration,
) {
    let mut n = 0;
    while let Err(mpsc::RecvTimeoutError::Timeout) = stop.recv_timeout(beat) {
        n += 1;
        let text = lock_text(me, instance, n);
        let wrote = match std::fs::read_to_string(lock) {
            Ok(_) if is_mine(lock, instance) => write_lock(lock, &text),
            // Removed by hand while this log holds it: nobody else holds it either.
            Err(err) if err.kind() == io::ErrorKind::NotFound => create_lock(lock, &text),
            Ok(_) => {
                let _ = fence.lost.set(format!(
                    "the audit log lock {} now names another Gantry, which took the log over after this one could not update the lock. Every request is refused until Gantry is started again: two writers would break the chain.",
                    lock.display()
                ));
                return;
            }
            Err(err) => Err(err),
        };
        // A beat that fails is tried again; after three the fence stops the writer.
        if wrote.is_ok() {
            fence.beat();
        }
    }
}

enum Verdict {
    Take,
    /// A holder this process can see running.
    Live,
    /// A holder it cannot see: alive while its lock keeps changing.
    Watch,
}

fn judge(holder: &Holder, me: &Me, held_here: bool) -> Verdict {
    // A bare process ID comes from a Gantry that could only see its own machine, as this check did.
    let near = holder.bare || (holder.space.is_some() && holder.space == me.space);
    match holder.pid {
        Some(pid) if near && pid != me.pid => {
            if process_alive(pid) {
                Verdict::Live
            } else {
                Verdict::Take
            }
        }
        // This very process: held by a log open here, or left by one that was dropped without closing.
        Some(_) if near && !holder.bare => {
            if held_here {
                Verdict::Live
            } else {
                Verdict::Take
            }
        }
        _ => Verdict::Watch,
    }
}

/// Writes the lock file beside a log, or refuses when another Gantry holds it (QA12-2). A holder on this machine is
/// checked by its process ID. One in another container or on another machine cannot be seen, so it counts as
/// alive while its lock keeps changing: this waits up to eight beats for it to stop, which is what the new Gantry
/// of a rollout needs. Returns None when the lock cannot be written (a read-only folder): the log is still served.
// The lock is judged by its content changing, timed on this machine's own clock. NFS and SMB set modification
// times from the server's clock, which can be far from this one, and a reader cannot tell how far; a change in
// content needs no clock in common. The price is that a lock left by a holder elsewhere is taken over only after
// six beats of watching it, never at once.
// ponytail: two Gantrys that both find the same lock stale at the same moment race between reading it and removing
// it, a window of microseconds after thirty seconds of watching; create_new settles who creates the new one, and a
// loser that removed the winner's lock is caught by the winner's next beat, which stops the winner's writer. An OS
// lock does not help: NFS and SMB locks do not survive a client that is gone.
fn take_lock(path: &Path, beat: Duration, me: &Me) -> Result<Option<Lock>, String> {
    let lock = lock_path(path);
    let (stale, wait) = (beat * 6, beat * 8);
    let deadline = Instant::now() + wait;
    let instance = crate::id::random_hex(8);
    let mine = lock_text(me, &instance, 0);
    let mut seen: Option<(String, Instant)> = None;
    let mut told = false;
    loop {
        let text = match std::fs::read_to_string(&lock) {
            Ok(text) => Some(text),
            Err(err) if err.kind() == io::ErrorKind::NotFound => None,
            Err(err) => {
                return Err(format!(
                    "the audit log lock {} cannot be read: {err}. Gantry cannot tell whether another Gantry writes to {}. Check that Gantry may read the folder, or delete the lock file if no Gantry is running.",
                    lock.display(),
                    path.display()
                ));
            }
        };
        let take = if let Some(text) = &text {
            let holder = Holder::parse(text);
            match judge(&holder, me, locked_paths().contains(&lock)) {
                Verdict::Take => true,
                Verdict::Live => {
                    return Err(format!(
                        "another Gantry ({}) holds the audit log at {}: it wrote {}. Two writers would break the chain. Stop the other one or give this one its own `audit: {{ path: ... }}`; if no Gantry is running, delete {} and start again.",
                        holder.describe(),
                        path.display(),
                        lock.display(),
                        lock.display()
                    ));
                }
                Verdict::Watch => {
                    let now = Instant::now();
                    let changed = match &seen {
                        Some((before, at)) if before == text => *at,
                        _ => {
                            seen = Some((text.clone(), now));
                            now
                        }
                    };
                    let quiet = now - changed;
                    if quiet >= stale {
                        true
                    } else if now >= deadline {
                        return Err(format!(
                            "another Gantry ({}) holds the audit log at {}: its lock {} last changed {} seconds ago, and Gantry waited {} seconds for it to stop. Two writers would break the chain. Stop the other one or give this one its own `audit: {{ path: ... }}`. A Gantry that is gone is taken over once its lock has not changed for {} seconds; if no Gantry is running anywhere, delete {} and start again.",
                            holder.describe(),
                            path.display(),
                            lock.display(),
                            secs(quiet),
                            secs(wait),
                            secs(stale),
                            lock.display()
                        ));
                    } else {
                        if !told {
                            told = true;
                            eprintln!(
                                "gantry: the audit log at {} is held by another Gantry ({}), which may be the one this one replaces. Waiting up to {} seconds for it to stop; its lock is taken over once it has not changed for {} seconds.",
                                path.display(),
                                holder.describe(),
                                secs(wait),
                                secs(stale)
                            );
                        }
                        std::thread::sleep(beat / 5);
                        false
                    }
                }
            }
        } else {
            true
        };
        if !take {
            continue;
        }
        // Removed only while it still says what was judged, so a lock someone just wrote is not.
        if let Some(text) = &text {
            if std::fs::read_to_string(&lock).is_ok_and(|now| now == *text) {
                let _ = std::fs::remove_file(&lock);
            } else {
                continue;
            }
        }
        match create_lock(&lock, &mine) {
            Ok(()) => break,
            // Another Gantry created it first: judge its lock instead.
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Ok(None),
        }
    }
    let fence = Arc::new(Fence {
        lock: lock.clone(),
        start: Instant::now(),
        beat_ms: AtomicU64::new(0),
        limit: beat * 3,
        lost: std::sync::OnceLock::new(),
    });
    let (stop, stopped) = mpsc::channel();
    locked_paths().insert(lock.clone());
    let mut held = Lock {
        path: lock.clone(),
        instance: instance.clone(),
        fence: fence.clone(),
        stop: Some(stop),
        beats: None,
    };
    let me = me.clone();
    held.beats = Some(
        std::thread::Builder::new()
            .name("gantry-audit-lock".into())
            .spawn(move || keep_lock(&lock, &me, &instance, &fence, &stopped, beat))
            .map_err(|err| {
                format!(
                    "the audit log lock could not be kept: {err}. Without it another Gantry could take the log over while this one writes. Check the process and thread limits and start again."
                )
            })?,
    );
    Ok(Some(held))
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
// ponytail: a lock file, not an OS lock (File::lock needs Rust 1.89, and NFS and SMB locks do not outlive a client
// that is gone). A Gantry killed without closing its log leaves it behind: the next `serve` takes it over once the
// process it names is gone or its lock stops changing (see `take_lock`), and repair says to delete it.
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
    syncer: &std::sync::Mutex<Option<File>>,
) {
    let mut failed = false;
    while let Ok(first) = jobs.recv() {
        let mut batch = Vec::with_capacity(8);
        let (mut n, mut prev) = (chain.n, chain.prev.clone());
        let mut lines = String::new();
        let mut quiet: Vec<Box<dyn FnOnce(io::Result<()>) + Send>> = Vec::new();
        let mut seal = None;
        for (fields, done) in std::iter::once(first).chain(jobs.try_iter().take(255)) {
            stats.queued.fetch_sub(1, Ordering::Relaxed);
            let fields = match fields {
                Fields::Ready(fields) => fields,
                // Later records wait for the next round, so they go to the new file.
                Fields::Seal(reply) => {
                    quiet.push(done);
                    seal = Some(reply);
                    break;
                }
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
        if !batch.is_empty() {
            write_batch(
                &mut chain,
                &lines,
                (n, prev),
                batch,
                &mut failed,
                broken,
                len,
                stats,
            );
        }
        if let Some(reply) = seal {
            let sealed = if failed {
                Err(io::Error::other(
                    "the audit log is broken, so it is not sealed",
                ))
            } else {
                seal_file(&mut chain, len, syncer)
            };
            if sealed.is_err() && chain.intact().is_err() {
                failed = true;
                broken.store(true, Ordering::Relaxed);
            }
            let _ = reply.send(sealed);
        }
        quiet.into_iter().for_each(|done| done(Ok(())));
    }
}

/// Writes one round of chained lines and tells each record's caller how it went.
#[allow(clippy::too_many_arguments)]
fn write_batch(
    chain: &mut Chain,
    lines: &str,
    (n, prev): (u64, String),
    batch: Vec<Box<dyn FnOnce(io::Result<()>) + Send>>,
    failed: &mut bool,
    broken: &AtomicBool,
    len: &AtomicU64,
    stats: &Stats,
) {
    {
        // After a failed write the file may end in half a record, so nothing more is written to it.
        // Every later request is refused until an admin has looked and Gantry is started again.
        let result = if *failed {
            Err(io::ErrorKind::BrokenPipe)
        } else if let Some(why) = chain.fence.as_ref().and_then(|fence| fence.lost()) {
            eprintln!("gantry: {why}");
            Err(io::ErrorKind::PermissionDenied)
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
                *failed = true;
                broken.store(true, Ordering::Relaxed);
            }
        }
        for done in batch {
            done(result.map_err(io::Error::from));
        }
    }
}

/// Moves the open file aside as a sealed segment and goes on in a new, empty file at the same path. The chain goes
/// on unchanged: the new file's first record follows the segment's last.
fn seal_file(
    chain: &mut Chain,
    len: &AtomicU64,
    syncer: &std::sync::Mutex<Option<File>>,
) -> io::Result<Option<PathBuf>> {
    let Some(path) = chain.path.clone() else {
        return Err(io::Error::other(
            "this audit log was opened without a path, so it has nothing to seal",
        ));
    };
    if !cfg!(unix) {
        // The log is opened so that no one may rename it while it is open (see `open`), Gantry included.
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "sealing a log that is being written works on Linux and macOS only",
        ));
    }
    if chain.first > chain.n {
        return Ok(None);
    }
    chain.file.sync_all()?;
    let sealed = segment_path(&path, chain.first, chain.n);
    if sealed.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} already exists", sealed.display()),
        ));
    }
    let mut folder = std::fs::DirBuilder::new();
    folder.recursive(true);
    // Readable by the log's owner only, as the log is.
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut folder, 0o700);
    folder.create(sealed_dir(&path))?;
    std::fs::rename(&path, &sealed)?;
    // From here the old file is a segment. If the new one cannot be made, the log is gone and requests stop.
    let file = log_options().open(&path)?;
    *syncer
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = file.try_clone().ok();
    chain.file = file;
    chain.len = 0;
    len.store(0, Ordering::Relaxed);
    chain.first = chain.n + 1;
    Ok(Some(sealed))
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

/// Whether a record's line hashes to the hash it carries: the record is as it was written.
pub fn line_holds(line: &str) -> bool {
    split(line).is_some_and(|(body, hash)| hash_of(body) == hash)
}

impl AuditLog {
    /// Opens the log for appending and picks the chain up where the last record left it.
    pub fn open(path: &Path) -> Result<Self, String> {
        Self::open_as(path, BEAT, &Me::this_process())
    }

    /// `open` with the beat of the lock and the holder it names, so a test can be another Gantry, sooner.
    fn open_as(path: &Path, beat: Duration, me: &Me) -> Result<Self, String> {
        // Taken before the chain is read: a Gantry waited for may still be adding records until it stops.
        let lock = take_lock(path, beat, me)?;
        let mut file = log_options()
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
        let (n, prev) = match last_record(&mut file, len, path)? {
            Some(last) => last,
            // An empty file after a seal: the chain goes on from the newest sealed segment.
            None => match segments(path).map_err(io_err)?.last() {
                Some(segment) => {
                    let mut sealed = File::open(&segment.path).map_err(io_err)?;
                    let size = sealed.metadata().map_err(io_err)?.len();
                    last_record(&mut sealed, size, &segment.path)?.ok_or_else(|| {
                        broken(&segment.path, "this sealed segment holds no record")
                    })?
                }
                None => (0, GENESIS.to_string()),
            },
        };
        let first = if len == 0 {
            n + 1
        } else {
            first_number(&mut file).map_err(io_err)?
        };
        let mut log = Self::start(Chain {
            file,
            n,
            prev,
            first,
            path: Some(path.to_path_buf()),
            len,
            fence: lock.as_ref().map(|lock| lock.fence.clone()),
        })
        .map_err(|err| format!("the audit log writer could not be started: {err}."))?;
        log.lock = lock;
        Ok(log)
    }
}

/// How the log file is opened, at start and when a seal makes a new one.
fn log_options() -> OpenOptions {
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
    options
}

/// The number of the first record in a file that holds one.
fn first_number(file: &mut File) -> io::Result<u64> {
    file.seek(SeekFrom::Start(0))?;
    let mut start = Vec::new();
    // `{"n":<number>,` is all that is needed; a configuration record's line can be megabytes long.
    file.take(32).read_to_end(&mut start)?;
    let text = String::from_utf8_lossy(&start);
    text.strip_prefix("{\"n\":")
        .and_then(|rest| rest.split(',').next())
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| io::Error::other("its first line does not start as a record does"))
}

/// The number and hash of the last record of a file, `None` when it is empty, or why its end is not a record.
fn last_record(file: &mut File, len: u64, path: &Path) -> Result<Option<(u64, String)>, String> {
    let io_err =
        |err: io::Error| format!("the audit log at {} cannot be read: {err}.", path.display());
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
    Ok((n > 0).then_some((n, prev)))
}

impl AuditLog {
    fn start(chain: Chain) -> io::Result<Self> {
        let syncer = Arc::new(std::sync::Mutex::new(chain.file.try_clone().ok()));
        let (path, records_at_open) = (chain.path.clone(), chain.n);
        let len = Arc::new(AtomicU64::new(chain.len));
        let (writer, jobs) = mpsc::channel();
        let broken = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(Stats::default());
        std::thread::Builder::new()
            .name("gantry-audit".into())
            .spawn({
                let (broken, len, stats, syncer) =
                    (broken.clone(), len.clone(), stats.clone(), syncer.clone());
                move || write_records(chain, &jobs, &broken, &len, &stats, &syncer)
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
            orgs: None,
        })
    }

    /// Starts an empty chain on a file that is already open.
    pub fn from_file(file: File) -> io::Result<Self> {
        let len = file.metadata().map_or(0, |m| m.len());
        Self::start(Chain {
            file,
            n: 0,
            prev: GENESIS.to_string(),
            first: 1,
            path: None,
            len,
            fence: None,
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
    // Only when sent, so records of callers that send none keep their shape.
    if let Some(user_agent) = entry.user_agent {
        record.insert("user_agent".into(), cut(user_agent).into());
    }
    record
}

/// The coding tool a `user-agent` names: a known tool by its short name, otherwise the product the agent names
/// first (an SDK such as `OpenAI/JS` when a tool sends its SDK's default), and `unknown` when there is none.
/// ponytail: substring list of tools whose user agent is known; a tool missing here shows up as its product token.
pub fn tool_of(user_agent: Option<&str>) -> String {
    const KNOWN: [(&str, &str); 13] = [
        ("claude-cli", "claude-code"),
        ("claude-code", "claude-code"),
        ("codex", "codex"),
        ("geminicli", "gemini-cli"),
        ("qwen", "qwen-code"),
        ("githubcopilot", "github-copilot"),
        ("copilot", "github-copilot"),
        ("cursor", "cursor"),
        ("kilo", "kilo-code"),
        ("roo-code", "roo-code"),
        ("roocode", "roo-code"),
        ("cline", "cline"),
        ("opencode", "opencode"),
    ];
    let Some(agent) = user_agent.map(str::trim).filter(|a| !a.is_empty()) else {
        return "unknown".into();
    };
    let lower = agent.to_ascii_lowercase();
    if let Some((_, tool)) = KNOWN.iter().find(|(needle, _)| lower.contains(needle)) {
        return (*tool).into();
    }
    // The first word, without a version after its last slash: `OpenAI/JS 5.20.0` is `OpenAI/JS`,
    // `python-requests/2.31` is `python-requests`.
    let first = agent.split_whitespace().next().unwrap_or(agent);
    match first.rsplit_once('/') {
        Some((product, version)) if version.starts_with(|c: char| c.is_ascii_digit()) => {
            product.into()
        }
        _ => first.into(),
    }
}

impl AuditLog {
    /// Hands any record to the writer, for records that are not requests: configuration changes and admin calls.
    /// Their fields are written as given, after the record number.
    pub fn append_record_then(
        &self,
        record: &Map<String, Value>,
        done: impl FnOnce(io::Result<()>) + Send + 'static,
    ) {
        if let Some(orgs) = &self.orgs
            && let Some(org) = orgs.of(record)
        {
            return match orgs.log(&org) {
                Ok(log) => log.append_record_then(record, done),
                Err(err) => done(Err(io::Error::other(err))),
            };
        }
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
        let Some(orgs) = self.orgs.clone() else {
            return self.send(Fields::Later(Box::new(make)), Box::new(done));
        };
        // The record is made on this log's writer: one of an organization goes on to its chain from there, and
        // `done` goes with it, so it hears from the writer that wrote it.
        type Done = Box<dyn FnOnce(io::Result<()>) + Send>;
        let slot: Arc<std::sync::Mutex<Option<Done>>> =
            Arc::new(std::sync::Mutex::new(Some(Box::new(done))));
        let take = |slot: &std::sync::Mutex<Option<Done>>| {
            slot.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
        };
        let routed = slot.clone();
        let make = move || {
            let record = make()?;
            let Some(org) = orgs.of(&record) else {
                return Some(record);
            };
            if let Some(done) = take(&routed) {
                match orgs.log(&org) {
                    Ok(log) => log.append_record_then(&record, done),
                    Err(err) => done(Err(io::Error::other(err))),
                }
            }
            None
        };
        self.send(
            Fields::Later(Box::new(make)),
            Box::new(move |result| {
                if let Some(done) = take(&slot) {
                    done(result);
                }
            }),
        );
    }

    /// Sends each organization's records to its own chain (`audit: { per_org: true }`), records without one
    /// staying here. The chains already on disk beside this one, and those of `orgs`, are opened now, each checked
    /// whole first: Gantry does not add records to a chain it cannot vouch for.
    pub fn per_org(mut self, orgs: &[String]) -> Result<Self, String> {
        let Some(path) = self.path.clone() else {
            return Ok(self);
        };
        let chains = Orgs {
            path: path.clone(),
            logs: std::sync::Mutex::new(HashMap::new()),
            ids: std::sync::Mutex::new((HashMap::new(), VecDeque::new())),
        };
        let found = org_chains(&path).map_err(|err| {
            format!(
                "the organizations' audit chains in {} cannot be listed: {err}.",
                orgs_dir(&path).display()
            )
        })?;
        let mut names: Vec<String> = found.into_iter().map(|(org, _)| org).collect();
        names.extend(orgs.iter().cloned());
        names.sort();
        names.dedup();
        for org in names {
            let at = org_path(&path, &org);
            let checked = chains.log(&org).and_then(|_| {
                if has_records(&at) {
                    verify_full(&at, None)?;
                }
                Ok(())
            });
            checked.map_err(|err| {
                format!("{err} This is the audit chain of organization \"{org}\". Gantry does not start on an audit chain that does not hold. Move the file aside to keep it, and start again to begin a new chain for it.")
            })?;
        }
        self.orgs = Some(Arc::new(chains));
        Ok(self)
    }

    /// Each organization's open chain, with `audit: { per_org: true }`: for what reads, seals or ships them.
    pub fn org_logs(&self) -> Vec<(String, Arc<AuditLog>)> {
        let Some(orgs) = &self.orgs else {
            return Vec::new();
        };
        let mut logs: Vec<(String, Arc<AuditLog>)> = orgs
            .logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|(org, log)| (org.clone(), log.clone()))
            .collect();
        logs.sort_by(|a, b| a.0.cmp(&b.0));
        logs
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
        // An organization's chain that cannot be written stops requests as this one does.
        if self
            .orgs
            .as_ref()
            .is_some_and(|orgs| orgs.all().iter().any(|log| log.is_broken()))
        {
            return true;
        }
        if self.broken.load(Ordering::Relaxed)
            || self
                .lock
                .as_ref()
                .is_some_and(|lock| lock.fence.lost().is_some())
        {
            return true;
        }
        let syncer = self
            .syncer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(unix)]
        if let (Some(path), Some(open)) = (&self.path, syncer.as_ref()) {
            use std::os::unix::fs::MetadataExt;
            return !matches!(
                (std::fs::metadata(path), open.metadata()),
                (Ok(named), Ok(open)) if named.ino() == open.ino() && named.dev() == open.dev() && open.len() >= self.len.load(Ordering::Relaxed)
            );
        }
        // Elsewhere the log is opened so it cannot be deleted or replaced (see `open`): only its length can change.
        #[cfg(not(unix))]
        if let (Some(_), Some(open)) = (&self.path, syncer.as_ref()) {
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
        // Records handed over before this call may have gone on to an organization's chain meanwhile.
        if let Some(orgs) = &self.orgs {
            for log in orgs.all() {
                log.flush();
            }
        }
    }

    /// Moves the records written so far into a sealed segment in the folder beside the log, named for the first and
    /// last record it holds (`gantry-audit.jsonl.sealed/<first>-<last>.jsonl`, numbers padded to 20 digits), and goes on in a new, empty
    /// file at the log's path. The chain is not changed: the next record follows the segment's last, and `verify`
    /// walks the segments and the log as one chain. `None` when the log holds no record since the last seal. Waits
    /// for the records handed over before it. Linux and macOS only: on Windows the open log cannot be renamed.
    pub fn seal(&self) -> io::Result<Option<PathBuf>> {
        let (tell, told) = mpsc::channel();
        self.send(Fields::Seal(tell), Box::new(|_| {}));
        told.recv()
            .unwrap_or_else(|_| Err(io::Error::other("the audit log writer has stopped")))
    }

    /// Asks the operating system to put what was written on disk. Called once a second by the server.
    pub fn sync(&self) {
        // Cloned out of the lock, so a seal waits for no disk.
        let file = self
            .syncer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .and_then(|f| f.try_clone().ok());
        if let Some(file) = file {
            let _ = file.sync_data();
        }
        if let Some(orgs) = &self.orgs {
            for log in orgs.all() {
                log.sync();
            }
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

/// A sealed segment of a log: a file of whole records, `first` to `last`, that the log went on from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub first: u64,
    pub last: u64,
    pub path: PathBuf,
}

/// The folder beside the log at `path` that holds its sealed segments: `<log>.sealed`.
pub fn sealed_dir(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".sealed");
    PathBuf::from(name)
}

/// Where the segment holding `first` to `last` of the log at `path` is kept.
pub fn segment_path(path: &Path, first: u64, last: u64) -> PathBuf {
    sealed_dir(path).join(format!("{first:020}-{last:020}.jsonl"))
}

/// The sealed segments of the log at `path`, oldest first.
pub fn segments(path: &Path) -> io::Result<Vec<Segment>> {
    let dir = sealed_dir(path);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    let mut found = Vec::new();
    for entry in entries {
        let file = entry?.file_name();
        let parsed = file
            .to_str()
            .and_then(|f| f.strip_suffix(".jsonl"))
            .and_then(|f| f.split_once('-'))
            .filter(|(a, b)| a.len() == 20 && b.len() == 20)
            .and_then(|(a, b)| Some((a.parse().ok()?, b.parse().ok()?)));
        if let Some((first, last)) = parsed {
            found.push(Segment {
                first,
                last,
                path: dir.join(&file),
            });
        }
    }
    found.sort_by_key(|s| s.first);
    Ok(found)
}

/// The folder beside the install's log at `path` that holds each organization's chain: `<log>.orgs`.
pub fn orgs_dir(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".orgs");
    PathBuf::from(name)
}

/// Where organization `org` keeps its chain: `<log>.orgs/<org>.jsonl`, any byte outside letters, digits, `-`, `_`
/// and an inner `.` written as `%XX`, so no name leaves the folder.
pub fn org_path(path: &Path, org: &str) -> PathBuf {
    let mut name = String::new();
    for (i, b) in org.bytes().enumerate() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || (b == b'.' && i > 0) {
            name.push(char::from(b));
        } else {
            name.push_str(&format!("%{b:02X}"));
        }
    }
    orgs_dir(path).join(format!("{name}.jsonl"))
}

/// The organizations' chains beside the install's log at `path`, by organization, in name order.
pub fn org_chains(path: &Path) -> io::Result<Vec<(String, PathBuf)>> {
    let dir = orgs_dir(path);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let kind = entry.file_type()?;
        // The open file, or only its sealed segments (all of them fetched back, before the log is opened).
        let stem = match name.to_str() {
            Some(f) if kind.is_file() => f.strip_suffix(".jsonl"),
            Some(f) if kind.is_dir() => f.strip_suffix(".jsonl.sealed"),
            _ => None,
        };
        let Some(stem) = stem.map(str::to_string) else {
            continue;
        };
        let bytes = stem.as_bytes();
        let mut org = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            match (bytes[i], stem.get(i + 1..i + 3)) {
                (b'%', Some(hex)) => {
                    org.push(u8::from_str_radix(hex, 16).map_err(io::Error::other)?);
                    i += 3;
                }
                (b, _) => {
                    org.push(b);
                    i += 1;
                }
            }
        }
        let org = String::from_utf8(org).map_err(io::Error::other)?;
        let at = org_path(path, &org);
        found.push((org, at));
    }
    found.sort();
    found.dedup();
    Ok(found)
}

/// Every chain of an install: its own (`None`), then each organization's, by name.
pub fn chains(path: &Path) -> io::Result<Vec<(Option<String>, PathBuf)>> {
    let mut all = vec![(None, path.to_path_buf())];
    all.extend(
        org_chains(path)?
            .into_iter()
            .map(|(org, at)| (Some(org), at)),
    );
    Ok(all)
}

/// [`chain_reader`] of every chain of an install, one after another: for what counts records whatever chain they
/// are in (spend, batches, coverage). Each chain is whole; their lines are not one hash chain.
pub fn chains_reader(path: &Path) -> io::Result<Box<dyn BufRead + Send>> {
    let mut reader: Box<dyn Read + Send> = Box::new(io::empty());
    for (_, at) in chains(path)? {
        reader = Box::new(reader.chain(chain_reader(&at)?));
    }
    Ok(Box::new(BufReader::new(reader)))
}

/// Whether the log at `path` holds any record, in its sealed segments or in the file itself.
pub fn has_records(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.len() > 0)
        || segments(path).is_ok_and(|s| !s.is_empty())
}

/// The whole chain of the log at `path` as one reader: its sealed segments oldest first, then the file itself.
/// For whatever reads the records back (spend, an exporter).
pub fn chain_reader(path: &Path) -> io::Result<Box<dyn BufRead + Send>> {
    let mut reader: Box<dyn Read + Send> = Box::new(io::empty());
    for segment in segments(path)? {
        reader = Box::new(reader.chain(File::open(&segment.path)?));
    }
    match File::open(path) {
        Ok(file) => reader = Box::new(reader.chain(file)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    Ok(Box::new(BufReader::new(reader)))
}

/// What `retire` removed.
#[derive(Clone, Debug)]
pub struct Retired {
    pub from: u64,
    pub through: u64,
    pub files: Vec<PathBuf>,
}

/// Removes the oldest sealed segments, those whose records all come at or before record `through`, after writing
/// an `audit_retired` record to the chain that names them: the numbers and hashes they ran between (`from_n`,
/// `from_prev`, the hash they chained from, `through_n`, `through_hash`) and each file's SHA-256. `verify` then
/// accepts a chain that starts after them, because that record says what went and the first record kept still
/// follows `through_hash`. The whole chain is verified first, so a log that does not hold keeps its evidence.
/// `None` when no segment is that old. `log` must be the log open at `path`. Blocks while it reads the chain.
pub fn retire(log: &AuditLog, path: &Path, through: u64) -> Result<Option<Retired>, String> {
    retire_with(log, path, through, None)
}

/// `retire`, for segments that leave the disk because they are kept elsewhere (`kept`, such as an object storage
/// bucket), not deleted: the `audit_retired` record names where, so readers that follow retention (the request log)
/// keep what they copied of those records.
pub fn retire_kept(
    log: &AuditLog,
    path: &Path,
    through: u64,
    kept: &str,
) -> Result<Option<Retired>, String> {
    retire_with(log, path, through, Some(kept))
}

fn retire_with(
    log: &AuditLog,
    path: &Path,
    through: u64,
    kept: Option<&str>,
) -> Result<Option<Retired>, String> {
    let io_err =
        |err: io::Error| format!("the audit log at {} cannot be read: {err}.", path.display());
    let old: Vec<Segment> = segments(path)
        .map_err(io_err)?
        .into_iter()
        .take_while(|s| s.last <= through)
        .collect();
    let (Some(oldest), Some(newest)) = (old.first(), old.last()) else {
        return Ok(None);
    };
    verify_full(path, None).map_err(|err| {
        format!("{err} Nothing was retired: a log that does not hold is kept whole, as evidence.")
    })?;
    let line_of = |segment: &Segment, last: bool| -> Result<Value, String> {
        let file = File::open(&segment.path).map_err(io_err)?;
        let mut lines = BufReader::new(file).lines();
        let line = if last {
            lines.map_while(Result::ok).last()
        } else {
            lines.next().and_then(Result::ok)
        };
        line.and_then(|l| serde_json::from_str(&l).ok())
            .ok_or_else(|| broken(&segment.path, "this sealed segment holds no record"))
    };
    let (first, last) = (line_of(oldest, false)?, line_of(newest, true)?);
    let mut files = Vec::new();
    for segment in &old {
        let mut file = File::open(&segment.path).map_err(io_err)?;
        let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
        let mut bytes = 0u64;
        let mut chunk = vec![0u8; 1 << 16];
        loop {
            let read = file.read(&mut chunk).map_err(io_err)?;
            if read == 0 {
                break;
            }
            bytes += read as u64;
            sha2::Digest::update(&mut hasher, &chunk[..read]);
        }
        let name = segment
            .path
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        files.push(serde_json::json!({
            "file": name,
            "first_n": segment.first,
            "last_n": segment.last,
            "bytes": bytes,
            "sha256": crate::id::hex(&sha2::Digest::finalize(hasher)),
        }));
    }
    let mut record = Map::new();
    record.insert("event".into(), "audit_retired".into());
    record.insert("time".into(), timestamp().into());
    record.insert("from_n".into(), oldest.first.into());
    record.insert("from_prev".into(), first["prev"].clone());
    record.insert("through_n".into(), newest.last.into());
    record.insert("through_hash".into(), last["hash"].clone());
    record.insert("records".into(), (newest.last - oldest.first + 1).into());
    record.insert("segments".into(), files.into());
    if let Some(kept) = kept {
        record.insert("kept".into(), kept.into());
    }
    // Written before anything is removed: a removal the chain does not name is a gap `verify` reports.
    log.append_record(&record).map_err(|err| {
        format!(
            "the audit log at {} could not record the retirement: {err}. Nothing was removed.",
            path.display()
        )
    })?;
    let mut removed = Vec::new();
    for segment in &old {
        std::fs::remove_file(&segment.path).map_err(|err| {
            format!(
                "{} could not be removed: {err}. The chain already names it as retired; remove it by hand or retire again.",
                segment.path.display()
            )
        })?;
        removed.push(segment.path.clone());
    }
    Ok(Some(Retired {
        from: oldest.first,
        through: newest.last,
        files: removed,
    }))
}

/// Records at the start of a chain that an `audit_retired` record says were removed on purpose.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Retirement {
    /// The last record retired: the chain now starts at `through + 1`.
    pub through: u64,
    pub through_hash: String,
    /// The number and time of the `audit_retired` record that names them.
    pub by: u64,
    pub time: String,
}

/// What a walk of the whole chain found.
#[derive(Clone, Debug, Default)]
pub struct Summary {
    /// The number of the last record: how many the chain has held, retired ones included.
    pub records: u64,
    /// The number of the first record still kept: 1 unless older records were retired.
    pub first: u64,
    /// Set when the chain starts after record 1, by the record that retired the ones before.
    pub retired: Option<Retirement>,
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
    // Sealed segments with no file beside them are still a chain; a log with neither cannot be opened.
    if !path.exists() && segments(path).is_ok_and(|s| s.is_empty()) {
        return Err(format!(
            "the audit log at {} cannot be opened: it does not exist.",
            path.display()
        ));
    }
    let reader = chain_reader(path).map_err(|err| {
        format!(
            "the audit log at {} cannot be opened: {err}.",
            path.display()
        )
    })?;
    walk(reader, path, expect)
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
    let mut sealed: Box<dyn Read> = Box::new(io::empty());
    for segment in segments(path).map_err(io_err)? {
        sealed = Box::new(sealed.chain(File::open(&segment.path).map_err(io_err)?));
    }
    let records = walk(BufReader::new(sealed.chain(file.take(keep))), path, None)?.records;
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
        let holder = Holder::parse(&std::fs::read_to_string(&lock).unwrap_or_default());
        return Err(format!(
            "a Gantry process ({}) holds the audit log at {}: it wrote {}. Stop it and run the repair again; a repair while it writes would break the chain. If no Gantry is running (it was killed), delete {} and run the repair again.",
            holder.describe(),
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
    let mut lines = reader.lines().peekable();
    // A chain whose oldest records were retired starts after record 1. It is taken from where it starts, and holds
    // only if an `audit_retired` record further on names exactly what came before.
    let mut start = None;
    if let Some(Ok(line)) = lines.peek() {
        let head = serde_json::from_str::<Value>(line).ok();
        let at = head
            .as_ref()
            .and_then(|v| Some((v.get("n")?.as_u64()?, v.get("prev")?.as_str()?.to_string())));
        if let Some((n, prev)) = at.filter(|(n, _)| *n > 1) {
            summary.records = n - 1;
            summary.last_hash = prev.clone();
            start = Some((n, prev));
        }
    }
    summary.first = summary.records + 1;
    while let Some(line) = lines.next() {
        let n = summary.records + 1;
        let count = summary.records;
        let first = summary.first;
        let before = match count + 1 - first {
            0 => "No record before it is intact.".to_string(),
            1 => format!("Record {first} is intact."),
            _ => format!("Records {first} to {count} are intact."),
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
            Some("audit_retired") => {
                summary.admin += 1;
                let through = value["through_n"].as_u64();
                let through_hash = value["through_hash"].as_str().unwrap_or_default();
                if let Some((first, prev)) = &start
                    && through.is_some_and(|t| t + 1 == *first)
                    && through_hash == prev
                {
                    summary.retired = Some(Retirement {
                        through: first - 1,
                        through_hash: through_hash.to_string(),
                        by: n,
                        time: value["time"].as_str().unwrap_or_default().to_string(),
                    });
                }
            }
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
    let unexplained = start.filter(|_| summary.retired.is_none()).map(|(first, prev)| {
        let missing = match first - 1 {
            1 => "record 1 is".to_string(),
            last => format!("records 1 to {last} are"),
        };
        format!(
            "{} starts at record {first}: {missing} missing, and no audit_retired record in the chain says they were retired after {prev}. They were removed or moved aside without being retired; the records from {first} on hold only if that was on purpose.",
            path.display()
        )
    });
    if summary.records == 0 {
        summary.first = 0;
    }
    match (expect, unexplained) {
        (Some(expect), Some(gap)) if summary.found.is_none() => {
            Err(format!("{} Also: {gap}", not_here(expect)))
        }
        (Some(expect), None) if summary.found.is_none() => Err(not_here(expect)),
        (_, Some(gap)) => Err(gap),
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

    fn object(value: Value) -> Map<String, Value> {
        match value {
            Value::Object(map) => map,
            _ => Map::new(),
        }
    }

    #[test]
    fn per_org_each_organization_keeps_its_own_chain_and_the_rest_stays_in_the_install()
    -> TestResult {
        let path = temp("per-org");
        let _ = std::fs::remove_dir_all(orgs_dir(&path));
        let write = |log: &AuditLog| -> io::Result<()> {
            log.append_record(&object(
                serde_json::json!({"event": "config_loaded", "id": "C"}),
            ))?;
            log.append_record(&object(
                serde_json::json!({"id": "D1", "verdict": "allow", "org": "acme"}),
            ))?;
            // Follows decision D1 and names no organization: it goes where D1 went.
            log.append_record(&object(
                serde_json::json!({"event": "attempts", "id": "D1"}),
            ))?;
            log.append_record(&object(serde_json::json!({"id": "D2", "verdict": "allow"})))?;
            let (tell, told) = mpsc::channel();
            log.append_later(
                || {
                    Some(object(
                        serde_json::json!({"event": "usage", "id": "D3", "org": "a/b"}),
                    ))
                },
                move |result| {
                    let _ = tell.send(result);
                },
            );
            told.recv().map_err(io::Error::other)?
        };
        let log = AuditLog::open(&path)?.per_org(&["globex".to_string()])?;
        write(&log)?;
        log.flush();
        assert_eq!(
            log.org_logs()
                .iter()
                .map(|(o, _)| o.as_str())
                .collect::<Vec<_>>(),
            ["a/b", "acme", "globex"]
        );
        drop(log);
        let acme = org_path(&path, "acme");
        assert_eq!(verify(&path)?.0, 2, "the configuration and D2");
        assert_eq!(verify(&acme)?.0, 2, "D1 and its attempts");
        assert_eq!(verify(&org_path(&path, "a/b"))?.0, 1);
        assert!(
            org_path(&path, "a/b").ends_with("a%2Fb.jsonl"),
            "no name leaves the folder"
        );
        assert!(org_path(&path, "../x").ends_with("%2E.%2Fx.jsonl"));
        // Reopened, each chain goes on from its own last record.
        let log = AuditLog::open(&path)?.per_org(&[])?;
        write(&log)?;
        log.flush();
        drop(log);
        assert_eq!(verify(&acme)?.0, 4);
        assert_eq!(verify(&path)?.0, 4);
        let listed: Vec<String> = org_chains(&path)?.into_iter().map(|(o, _)| o).collect();
        assert_eq!(listed, ["a/b", "acme", "globex"]);
        assert_eq!(chains_reader(&path)?.lines().count(), 10);
        // A broken organization's chain stops the start, as the install's does.
        let text = std::fs::read_to_string(&acme)?.replace("\"D1\"", "\"DX\"");
        std::fs::write(&acme, text)?;
        let refused = AuditLog::open(&path)?
            .per_org(&[])
            .err()
            .unwrap_or_default();
        assert!(refused.contains("organization \"acme\""), "{refused}");
        Ok(())
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

    /// A short beat, so a test sees a lock go stale in a second instead of thirty.
    const TEST_BEAT: Duration = Duration::from_millis(200);

    /// A Gantry in another container or on another machine: a process space this one cannot see into.
    fn elsewhere(space: &str) -> Me {
        Me {
            pid: 1,
            host: Some(format!("host-{space}")),
            space: Some(space.to_string()),
        }
    }

    /// The beat of the test below. Off Linux, telling whether a process runs means starting `ps`, which a loaded
    /// machine can take more than a second to do. "At once" means without watching the lock, which takes at least
    /// six beats; a beat long enough that `ps` cannot cross five of them keeps that distinction and lets a slow `ps`
    /// pass. A Live or Take verdict never sleeps, so the test takes only as long as `ps` does.
    const LIVE_BEAT: Duration = Duration::from_secs(2);

    #[test]
    fn a_lock_from_this_host_names_a_live_process_and_is_refused_at_once() -> TestResult {
        let path = temp("live-here");
        let other = std::process::Command::new("sleep").arg("60").spawn()?;
        let here = Me {
            pid: other.id(),
            ..Me::this_process()
        };
        std::fs::write(lock_path(&path), lock_text(&here, "abc", 0))?;
        let started = Instant::now();
        let err = AuditLog::open_as(&path, LIVE_BEAT, &Me::this_process())
            .err()
            .ok_or("opened a log held by a live process on this host")?;
        let refused_after = started.elapsed();
        let mut other = other;
        other.kill()?;
        other.wait()?;
        // Refused as a live holder, not after watching its lock go quiet: that refusal says how long it waited.
        assert!(err.contains("it wrote") && !err.contains("waited"), "{err}");
        assert!(
            refused_after < LIVE_BEAT * 5,
            "waited for a holder it can see: {refused_after:?}"
        );
        assert!(err.contains(&format!("process {}", other.id())), "{err}");
        // Once that process is gone, its lock is taken over at once.
        let started = Instant::now();
        drop(AuditLog::open_as(&path, LIVE_BEAT, &Me::this_process())?);
        let taken_after = started.elapsed();
        assert!(
            taken_after < LIVE_BEAT * 5,
            "waited for a dead holder: {taken_after:?}"
        );
        assert!(!lock_path(&path).exists());
        Ok(())
    }

    #[test]
    fn a_holder_elsewhere_that_still_beats_is_waited_for_then_refused() -> TestResult {
        let path = temp("remote-live");
        let remote = elsewhere("a");
        std::fs::write(lock_path(&path), lock_text(&remote, "abc", 0))?;
        let stop = Arc::new(AtomicBool::new(false));
        let beating = std::thread::spawn({
            let (stop, lock, remote) = (stop.clone(), lock_path(&path), remote.clone());
            move || {
                let mut n = 0;
                while !stop.load(Ordering::Relaxed) {
                    n += 1;
                    let _ = write_lock(&lock, &lock_text(&remote, "abc", n));
                    std::thread::sleep(TEST_BEAT / 4);
                }
            }
        });
        let started = Instant::now();
        let refused = AuditLog::open_as(&path, TEST_BEAT, &Me::this_process()).err();
        let waited = started.elapsed();
        stop.store(true, Ordering::Relaxed);
        let _ = beating.join();
        let err = refused.ok_or("opened a log a live Gantry elsewhere holds")?;
        // Waited out the bound, and not much longer.
        assert!(waited >= TEST_BEAT * 8, "gave up after {waited:?}");
        assert!(
            waited < TEST_BEAT * 8 + Duration::from_secs(5),
            "{waited:?}"
        );
        assert!(
            err.contains("process 1 on host-a") && err.contains(".lock") && err.contains("gone"),
            "{err}"
        );
        assert!(
            std::fs::read_to_string(lock_path(&path))?.contains("host host-a"),
            "the refusal kept the holder's lock"
        );
        std::fs::remove_file(lock_path(&path))?;
        Ok(())
    }

    #[test]
    fn a_holder_elsewhere_whose_lock_stopped_changing_is_taken_over() -> TestResult {
        let path = temp("remote-gone");
        std::fs::write(lock_path(&path), lock_text(&elsewhere("a"), "abc", 7))?;
        let started = Instant::now();
        let log = AuditLog::open_as(&path, TEST_BEAT, &Me::this_process())?;
        assert!(
            started.elapsed() >= TEST_BEAT * 6,
            "took over a lock it had not watched"
        );
        assert!(
            !std::fs::read_to_string(lock_path(&path))?.contains("host-a"),
            "the lock still names the holder that is gone"
        );
        drop(log);
        assert!(!lock_path(&path).exists());
        Ok(())
    }

    #[test]
    fn a_new_gantry_waits_for_the_old_one_and_continues_its_chain() -> TestResult {
        // The old Gantry must stop between six beats (a stale lock) and eight (the new one's deadline) after the
        // new one starts waiting. With TEST_BEAT that window is 200 ms, and on a loaded machine a sleeping thread
        // wakes later than that: about one run in five failed under load. A beat of 600 ms gives 600 ms; every
        // check is the same.
        let beat = TEST_BEAT * 3;
        let path = temp("rollout");
        let old = AuditLog::open_as(&path, beat, &elsewhere("old"))?;
        old.append(&entry("A"))?;
        let started = Instant::now();
        let new = std::thread::spawn({
            let path = path.clone();
            move || AuditLog::open_as(&path, beat, &elsewhere("new"))
        });
        // Written and flushed while the new one waits, well before its deadline.
        std::thread::sleep(beat * 3);
        old.append(&entry("B"))?;
        old.flush();
        // Longer than a stale lock takes, counted from the start of the wait: the old one beats, so the new one
        // keeps waiting.
        std::thread::sleep((beat * 7).saturating_sub(started.elapsed()));
        assert!(!new.is_finished(), "the new Gantry did not wait");
        assert!(!old.is_broken(), "the old Gantry lost its lock");
        drop(old);
        let new = new.join().map_err(|_| "the new Gantry panicked")??;
        assert_eq!(
            new.records_at_open(),
            2,
            "the new Gantry read the chain before the old one stopped"
        );
        new.append(&entry("C"))?;
        new.flush();
        drop(new);
        assert_eq!(verify(&path)?.0, 3);
        Ok(())
    }

    #[test]
    fn a_log_whose_lock_another_gantry_took_refuses_records() -> TestResult {
        let path = temp("lost");
        let log = AuditLog::open_as(&path, TEST_BEAT, &Me::this_process())?;
        log.append(&entry("A"))?;
        std::fs::write(lock_path(&path), lock_text(&elsewhere("a"), "abc", 0))?;
        std::thread::sleep(TEST_BEAT * 3);
        assert!(log.is_broken());
        assert!(log.append(&entry("B")).is_err());
        drop(log);
        assert!(
            lock_path(&path).exists(),
            "removed the lock of the Gantry that took over"
        );
        std::fs::remove_file(lock_path(&path))?;
        assert_eq!(verify(&path)?.0, 1);
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
        // Closed, so the open below meets the cut log and not this log's lock.
        drop(log);
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

    /// Appends requests `ids` and waits for them.
    fn requests(log: &AuditLog, ids: &[&str]) -> TestResult {
        for id in ids {
            log.append(&Entry {
                id,
                ..Default::default()
            })?;
        }
        Ok(())
    }

    fn clear(path: &Path) -> TestResult {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(sealed_dir(path));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_sealed_segment_keeps_the_chain_going_across_files_and_restarts() -> TestResult {
        let path = temp("seal");
        clear(&path)?;
        let log = AuditLog::open(&path)?;
        requests(&log, &["A", "B", "C"])?;
        let sealed = log.seal()?.ok_or("nothing sealed")?;
        assert_eq!(sealed, segment_path(&path, 1, 3));
        assert!(
            sealed
                .to_string_lossy()
                .ends_with(".jsonl.sealed/00000000000000000001-00000000000000000003.jsonl")
        );
        assert_eq!(
            std::fs::metadata(&path)?.len(),
            0,
            "the log goes on in a new file"
        );
        assert!(log.seal()?.is_none(), "an empty file is not sealed");
        assert!(!log.is_broken(), "a seal is not a replaced log");
        requests(&log, &["D"])?;
        let summary = verify_full(&path, None)?;
        assert_eq!(
            (summary.first, summary.records, summary.requests),
            (1, 4, 4)
        );
        // The chain crosses the file boundary: record 4 follows record 3's hash.
        let segment = std::fs::read_to_string(&sealed)?;
        let three: Value = serde_json::from_str(segment.lines().last().ok_or("empty")?)?;
        let four: Value = serde_json::from_str(std::fs::read_to_string(&path)?.trim())?;
        assert_eq!(four["prev"], three["hash"]);
        assert_eq!(four["n"], 4);
        // Sealed again and restarted on the empty file: the next record still follows.
        assert_eq!(log.seal()?, Some(segment_path(&path, 4, 4)));
        drop(log);
        let log = AuditLog::open(&path)?;
        assert_eq!(log.records_at_open(), 4);
        requests(&log, &["E"])?;
        log.flush();
        let summary = verify_full(&path, None)?;
        assert_eq!((summary.records, summary.requests), (5, 5));
        assert_eq!(chain_reader(&path)?.lines().count(), 5);
        // A segment changed after it was sealed breaks the chain where it was changed.
        std::fs::write(&sealed, segment.replacen("\"B\"", "\"Z\"", 1))?;
        let err = verify(&path).err().ok_or("a changed segment passed")?;
        assert!(err.contains("record 2"), "{err}");
        drop(log);
        clear(&path)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn retiring_old_segments_is_recorded_and_verify_proves_what_went() -> TestResult {
        let path = temp("retire");
        clear(&path)?;
        let log = AuditLog::open(&path)?;
        requests(&log, &["A", "B"])?;
        log.seal()?;
        requests(&log, &["C", "D"])?;
        log.seal()?;
        requests(&log, &["E"])?;
        let before = std::fs::read_to_string(segment_path(&path, 3, 4))?;
        let four: Value = serde_json::from_str(before.lines().last().ok_or("empty")?)?;
        let one: Value = serde_json::from_str(
            std::fs::read_to_string(segment_path(&path, 1, 2))?
                .lines()
                .next()
                .ok_or("empty")?,
        )?;

        assert!(
            retire(&log, &path, 1)?.is_none(),
            "no segment ends by record 1"
        );
        let retired = retire(&log, &path, 4)?.ok_or("nothing retired")?;
        assert_eq!((retired.from, retired.through), (1, 4));
        assert_eq!(retired.files.len(), 2);
        assert!(segments(&path)?.is_empty());

        // The chain starts at 5 now, and the record at 6 says why.
        let summary = verify_full(&path, None)?;
        assert_eq!((summary.first, summary.records), (5, 6));
        let why = summary.retired.ok_or("no retirement found")?;
        assert_eq!((why.through, why.by), (4, 6));
        assert_eq!(Value::from(why.through_hash.clone()), four["hash"]);
        let text = std::fs::read_to_string(&path)?;
        let record: Value = serde_json::from_str(text.lines().last().ok_or("empty")?)?;
        assert_eq!(record["event"], "audit_retired");
        assert_eq!(record["from_n"], 1);
        assert_eq!(record["from_prev"], one["prev"]);
        assert_eq!(record["through_n"], 4);
        assert_eq!(record["records"], 4);
        assert_eq!(
            record["segments"][1]["sha256"],
            Value::from(sha256_hex(before.as_bytes()))
        );

        // The kept hash of a retired record is not in the chain any more, and verify says so.
        let gone = four["hash"].as_str().ok_or("hash")?;
        assert!(verify_full(&path, Some(gone)).is_err());
        drop(log);
        clear(&path)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn records_removed_from_the_start_without_a_retire_record_fail_verify() -> TestResult {
        let path = temp("retire-forged");
        clear(&path)?;
        let log = AuditLog::open(&path)?;
        requests(&log, &["A", "B"])?;
        log.seal()?;
        requests(&log, &["C"])?;
        log.flush();
        std::fs::remove_file(segment_path(&path, 1, 2))?;
        let err = verify(&path).err().ok_or("a removed segment passed")?;
        assert!(
            err.contains("starts at record 3") && err.contains("records 1 to 2 are missing"),
            "{err}"
        );

        // A retire record that names another range does not cover the gap either.
        let mut record = Map::new();
        record.insert("event".into(), "audit_retired".into());
        record.insert("through_n".into(), 1.into());
        record.insert("through_hash".into(), "f".repeat(64).into());
        log.append_record(&record)?;
        assert!(verify(&path).is_err());
        drop(log);
        clear(&path)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_log_that_does_not_hold_is_never_retired() -> TestResult {
        let path = temp("retire-broken");
        clear(&path)?;
        let log = AuditLog::open(&path)?;
        requests(&log, &["A", "B"])?;
        log.seal()?;
        let segment = segment_path(&path, 1, 2);
        let text = std::fs::read_to_string(&segment)?;
        std::fs::write(&segment, text.replacen("\"A\"", "\"Z\"", 1))?;
        let err = retire(&log, &path, 2).err().ok_or("retired a broken log")?;
        assert!(err.contains("Nothing was retired"), "{err}");
        assert!(segment.exists());
        drop(log);
        clear(&path)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_cut_last_line_is_found_after_a_seal() -> TestResult {
        let path = temp("seal-cut");
        clear(&path)?;
        let log = AuditLog::open(&path)?;
        requests(&log, &["A", "B"])?;
        log.seal()?;
        requests(&log, &["C"])?;
        drop(log);
        let mut file = OpenOptions::new().append(true).open(&path)?;
        file.write_all(b"{\"n\":4,\"id\"")?;
        drop(file);
        let cut = find_cut(&path)?.ok_or("no cut found")?;
        assert_eq!(repair(&path, &cut)?, 4);
        assert_eq!(verify(&path)?.0, 4);
        clear(&path)?;
        Ok(())
    }
}
