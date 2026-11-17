//! Kill switches: stop traffic for a person, a team, a key, a model or everyone at once, with a reason.
//!
//! The switches are kept in memory and in a file beside the keys file (`enterplace.kills.json`), so a restart keeps them,
//! and every node that serves the same files reads a change within a second. Only the admin API writes the file.

use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant, SystemTime},
};

use serde::{Deserialize, Serialize};

use crate::{config, id};

/// What a switch can stop, as `enterplace kill` names it.
pub const SCOPES: [&str; 5] = ["person", "team", "key_prefix", "model", "all"];

/// How often the file is looked at again, so a switch set on another node takes effect here within a second.
const RECHECK: Duration = Duration::from_millis(250);

/// One switch that is on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Kill {
    pub scope: String,
    /// Empty for `all`.
    #[serde(default)]
    pub value: String,
    pub reason: String,
    /// The admin who set it.
    pub by: String,
    /// UTC time it was set, as audit records write it.
    pub at: String,
}

impl Kill {
    /// "person maya.cohen", "everyone".
    pub fn label(&self) -> String {
        match self.scope.as_str() {
            "all" => "everyone".into(),
            "key_prefix" => format!("key {}", self.value),
            scope => format!("{scope} {}", self.value),
        }
    }

    /// Whether this switch stops a request of `person` in `team`, whose key hashes to `key_sha256`, for `model`
    /// (`None` before the model is known).
    pub fn stops(&self, person: &str, team: &str, key_sha256: &str, model: Option<&str>) -> bool {
        match self.scope.as_str() {
            "person" => self.value == person,
            "team" => self.value == team,
            "key_prefix" => key_sha256.starts_with(&self.value),
            "model" => model == Some(self.value.as_str()),
            // `all`, and a scope this version does not know, which can only come from a hand edit: fail closed.
            _ => true,
        }
    }
}

/// Where the switches of a keys file are kept.
pub fn path_beside(keys: &Path) -> PathBuf {
    keys.with_file_name("enterplace.kills.json")
}

/// Checks a switch before it is set: a known scope, a value that can match, a reason. Returns the value as stored.
pub fn checked(scope: &str, value: &str, reason: &str) -> Result<String, String> {
    if !SCOPES.contains(&scope) {
        return Err(format!(
            "scope is \"{scope}\". Use one of person, team, key_prefix, model or all."
        ));
    }
    if reason.trim().is_empty() || reason.len() > 500 {
        return Err("a kill switch needs a reason of 1 to 500 characters: the people stopped see it in their tool, and the audit log keeps it.".into());
    }
    let value = value.trim();
    match scope {
        "all" if value.is_empty() => Ok(String::new()),
        "all" => Err("--all stops everyone and takes no value.".into()),
        "key_prefix" => {
            let value = value.to_ascii_lowercase();
            if (8..=64).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_hexdigit()) {
                Ok(value)
            } else {
                Err("a key is named by at least the first 8 hex characters of its hash, as `enterplace key list` shows it.".into())
            }
        }
        "model" if !value.is_empty() && value.len() <= 200 => Ok(value.to_string()),
        "model" => Err("name the model as clients send it, for example gpt-4o-mini.".into()),
        _ if config::valid_name(value) => Ok(value.to_string()),
        _ => Err(format!(
            "a {scope} is named with letters, digits, dots, dashes, underscores and @ only, as the keys file names it."
        )),
    }
}

#[derive(Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct File {
    kills: Vec<Kill>,
}

/// The switches in the file. No file is no switch.
pub fn read(path: &Path) -> Result<Vec<Kill>, String> {
    // With a store, the switches are in the database, and every reader of this file gets them from there.
    if let Some(store) = crate::store::attached_kills(path) {
        return Ok(store.kills().to_vec());
    }
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(format!(
                "{} cannot be read: {err}. Fix its permissions.",
                path.display()
            ));
        }
    };
    serde_json::from_str::<File>(&text)
        .map(|f| f.kills)
        .map_err(|err| {
            format!(
                "{} is not a kill switch list ({err}). Only `enterplace kill` and the admin API should write it: put back a copy, or delete it to turn every switch off.",
                path.display()
            )
        })
}

/// Writes the whole list beside the file and moves it into place, so a reader never sees half of it.
fn write(path: &Path, kills: &[Kill]) -> Result<(), String> {
    let text = serde_json::to_string_pretty(&File {
        kills: kills.to_vec(),
    })
    .map_err(|err| format!("the switches could not be written out: {err}"))?;
    let temporary = path.with_extension(format!("{}.tmp", &id::decision_id()[10..]));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let written = options
        .open(&temporary)
        .and_then(|mut file| {
            file.write_all(text.as_bytes())
                .and_then(|()| file.sync_all())
        })
        .and_then(|()| std::fs::rename(&temporary, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written.map_err(|err| {
        format!(
            "{} cannot be written: {err}. Nothing was changed. Fix the folder's permissions.",
            path.display()
        )
    })
}

type Stamp = Option<(u64, Option<SystemTime>, i64)>;

/// The change time counts too: a chmod that locks the gateway out changes neither size nor modified time, and must
/// still be noticed so every request is refused.
fn stamp(path: &Path) -> Stamp {
    std::fs::metadata(path)
        .ok()
        .map(|m| (m.len(), m.modified().ok(), changed(&m)))
}

#[cfg(unix)]
fn changed(m: &std::fs::Metadata) -> i64 {
    use std::os::unix::fs::MetadataExt;
    m.ctime()
        .saturating_mul(1_000_000_000)
        .saturating_add(m.ctime_nsec())
}

#[cfg(not(unix))]
fn changed(_: &std::fs::Metadata) -> i64 {
    0
}

struct Cached {
    checked: Instant,
    stamp: Stamp,
    kills: Result<Arc<Vec<Kill>>, String>,
}

/// The switches in force on this node.
pub struct Switches {
    path: PathBuf,
    cache: RwLock<Cached>,
    /// One change at a time on this node, so two changes made together both stay.
    // ponytail: two nodes changing switches in the same instant can lose one change; admins set switches by hand.
    changing: Mutex<()>,
    /// Serves the switches in place of the file when the policy has `store:`.
    store: Option<Arc<dyn crate::store::Store>>,
}

impl Switches {
    pub fn open(path: PathBuf) -> Self {
        let cache = RwLock::new(Cached {
            checked: Instant::now(),
            stamp: stamp(&path),
            kills: read(&path).map(Arc::new),
        });
        Self {
            store: crate::store::attached_kills(&path),
            path,
            cache,
            changing: Mutex::new(()),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The switches on now. `Err` when the file cannot be read: no request can then be told it is not stopped.
    pub fn current(&self) -> Result<Arc<Vec<Kill>>, String> {
        if let Some(store) = &self.store {
            return Ok(store.kills());
        }
        {
            let cache = self
                .cache
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if cache.checked.elapsed() < RECHECK {
                return cache.kills.clone();
            }
        }
        let mut cache = self
            .cache
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cache.checked.elapsed() >= RECHECK {
            let now = stamp(&self.path);
            if now != cache.stamp || cache.kills.is_err() {
                cache.kills = read(&self.path).map(Arc::new);
                cache.stamp = now;
            }
            cache.checked = Instant::now();
        }
        cache.kills.clone()
    }

    /// Changes the list as `change` says, writes it, and puts it in force here at once. Returns what `change` returned.
    fn change<T>(&self, change: impl FnOnce(&mut Vec<Kill>) -> T) -> Result<T, String> {
        let _one = self
            .changing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut kills = read(&self.path)?;
        let out = change(&mut kills);
        write(&self.path, &kills)?;
        *self
            .cache
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Cached {
            checked: Instant::now(),
            stamp: stamp(&self.path),
            kills: Ok(Arc::new(kills)),
        };
        Ok(out)
    }

    /// Turns a switch on, or replaces the reason of the same switch. Returns the switch it replaced.
    pub fn set(&self, kill: Kill) -> Result<Option<Kill>, String> {
        if let Some(store) = &self.store {
            return store.set_kill(&kill);
        }
        self.change(|kills| {
            let old = kills
                .iter()
                .position(|k| k.scope == kill.scope && k.value == kill.value)
                .map(|at| kills.remove(at));
            kills.push(kill);
            old
        })
    }

    /// Turns a switch off. Returns it, or `None` when it was not on.
    pub fn clear(&self, scope: &str, value: &str) -> Result<Option<Kill>, String> {
        if let Some(store) = &self.store {
            return store.clear_kill(scope, value);
        }
        self.change(|kills| {
            kills
                .iter()
                .position(|k| k.scope == scope && k.value == value)
                .map(|at| kills.remove(at))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn kill(scope: &str, value: &str) -> Kill {
        Kill {
            scope: scope.into(),
            value: value.into(),
            reason: "looping".into(),
            by: "noa".into(),
            at: "2026-11-13T10:00:00.000Z".into(),
        }
    }

    #[test]
    fn each_scope_stops_only_what_it_names() {
        let hash = "abcdef0123456789";
        assert!(kill("person", "maya").stops("maya", "t", hash, None));
        assert!(!kill("person", "maya").stops("omer", "t", hash, None));
        assert!(kill("team", "t").stops("omer", "t", hash, None));
        assert!(kill("key_prefix", "abcdef01").stops("x", "y", hash, None));
        assert!(!kill("key_prefix", "abcdef02").stops("x", "y", hash, None));
        assert!(!kill("model", "m").stops("x", "y", hash, None));
        assert!(kill("model", "m").stops("x", "y", hash, Some("m")));
        assert!(kill("all", "").stops("x", "y", hash, None));
        assert!(
            kill("someday", "").stops("x", "y", hash, None),
            "an unknown scope must fail closed"
        );
    }

    #[test]
    fn a_switch_needs_a_scope_a_value_and_a_reason() {
        assert!(checked("person", "maya", "").is_err());
        assert!(checked("person", "maya", "  ").is_err());
        assert!(checked("person", "ma ya", "r").is_err());
        assert!(checked("all", "x", "r").is_err());
        assert!(checked("key_prefix", "abc", "r").is_err());
        assert!(checked("planet", "x", "r").is_err());
        assert_eq!(
            checked("key_prefix", "ABCDEF01", "r").ok().as_deref(),
            Some("abcdef01")
        );
        assert_eq!(checked("all", "", "r").ok().as_deref(), Some(""));
    }

    #[test]
    fn switches_persist_and_another_node_sees_a_change_within_a_second() -> TestResult {
        let dir = std::env::temp_dir().join(format!("enterplace-kills-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        let path = path_beside(&dir.join("enterplace.keys.yaml"));
        let (one, two) = (Switches::open(path.clone()), Switches::open(path.clone()));
        assert!(two.current()?.is_empty());
        assert_eq!(one.set(kill("person", "maya"))?, None);
        assert_eq!(
            one.current()?.len(),
            1,
            "the node that set it applies it at once"
        );
        let start = Instant::now();
        while two.current()?.is_empty() {
            assert!(
                start.elapsed() < Duration::from_secs(1),
                "not seen within a second"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        // A restart reads the file.
        assert_eq!(Switches::open(path.clone()).current()?[0].value, "maya");
        assert!(one.clear("person", "omer")?.is_none());
        assert!(one.clear("person", "maya")?.is_some());
        assert!(one.current()?.is_empty());
        std::fs::write(&path, "not json")?;
        let broken = Switches::open(path);
        assert!(
            broken.current().is_err(),
            "an unreadable list must not read as no switch"
        );
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}
