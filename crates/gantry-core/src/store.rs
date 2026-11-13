//! The store: what several gateways share while they run (keys, kill switches, spend), so two or more processes
//! act as one gateway. The policy stays a file, reviewed in git. Postgres is the one backend today; the interface
//! names no database, so another (D1 or Durable Objects on Cloudflare) can be added behind it.

use std::{
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex, Weak},
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

/// Shared state. Reads come from memory, refreshed in the background, so a request never waits on the database
/// for a key or a kill switch, and a database that is down leaves the last state in force.
pub trait Store: Send + Sync + std::fmt::Debug {
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
