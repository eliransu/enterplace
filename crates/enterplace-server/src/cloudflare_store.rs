//! The Cloudflare store (`store: { cloudflare: true }`): what the Postgres store keeps, kept instead in the SQLite of
//! one Durable Object (`EnterplaceStore` in `deploy/cloudflare/src/store.ts`), so Enterplace on Cloudflare runs with
//! nothing outside Cloudflare.
//!
//! The gateway sends each call as `POST <url>/v1/<call>` with a JSON body. In a Cloudflare Container the URL is
//! `http://store.enterplace.internal` (set by the Worker as ENTERPLACE_CLOUDFLARE_STORE_URL): a name that exists only
//! inside the container, answered by the Worker, which forwards the call to the object. The object runs one call at
//! a time, so a reservation, a lease, a probe lease and a policy change are each atomic across every gateway.
//!
//! It behaves as [`PgStore`](crate::store::PgStore) does: keys, kill switches, cooldowns, credentials, policy
//! versions and everything routing shares are read from memory, refreshed by one poll call every 500 ms that also
//! writes what this gateway gathered since the last one. Only a budgeted or rate-limited request waits on the store,
//! and one is refused while the store cannot be reached.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    future::Future,
    sync::{
        Arc, Mutex, OnceLock, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use axum::body::Bytes;
use enterplace_core::{
    config::KeyEntry,
    id,
    keyfile::{self, Revoked},
    kill::Kill,
    policy::{Budget, Period},
    store::{
        self as core_store, Bucket, CachedAnswer, Change, Credential, DeploymentLoad, LEASE, Lease,
        NewVersion, Pending, PolicyVersion, Raise, Replica, Reserve, Store, VersionError,
    },
    x509::{base64_decode, base64_encode},
};
use http_body_util::{BodyExt, Full};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use serde_json::{Value, json};

use crate::credentials::{MasterKey, NO_MASTER};
use crate::store::{
    CLEAN_EVERY, HEALTHY_FOR_SECS, HEARTBEAT_EVERY, LATENCY_FOR_SECS, LEASE_MARGIN_MS,
    LOAD_FOR_SECS, MASTER_CHECK, PIN_OVERLAP_SECS, PIN_TOUCH, POLL, SETTLE_FOR, WAIT, read, write,
};

/// The variable that names the store's address. The Worker sets it; a test points it at the store on node:sqlite.
pub const URL_ENV: &str = "ENTERPLACE_CLOUDFLARE_STORE_URL";

/// Where the store is inside a Cloudflare Container, when the variable is not set.
pub const DEFAULT_URL: &str = "http://store.enterplace.internal";

pub struct CfStore {
    runtime: Mutex<Option<tokio::runtime::Runtime>>,
    handle: tokio::runtime::Handle,
    inner: Arc<Inner>,
}

impl std::fmt::Debug for CfStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CfStore")
    }
}

impl Drop for CfStore {
    fn drop(&mut self) {
        let runtime = self
            .runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(runtime) = runtime {
            runtime.shutdown_background();
        }
    }
}

type Sealed = (Credential, Vec<u8>);
type Pinned = (String, Instant, Instant);

struct Inner {
    url: String,
    http: Client<HttpConnector, Full<Bytes>>,
    /// The version of each watched part last read, as the store numbers them.
    seen: Mutex<serde_json::Map<String, Value>>,
    polling: tokio::sync::Mutex<()>,
    keys: RwLock<String>,
    kills: RwLock<Arc<Vec<Kill>>>,
    cooling: RwLock<Arc<HashMap<String, Instant>>>,
    returns: Mutex<HashMap<i64, i64>>,
    credentials: RwLock<Arc<Vec<Sealed>>>,
    master: OnceLock<MasterKey>,
    policies: RwLock<Arc<Vec<PolicyVersion>>>,
    ended: RwLock<Arc<HashMap<String, (Instant, String)>>>,
    raises: RwLock<Arc<Vec<Raise>>>,
    down: AtomicBool,
    gateway: String,
    pins: RwLock<HashMap<String, Pinned>>,
    pins_out: Mutex<HashMap<String, String>>,
    /// The store's clock at the last read of the pins, in seconds since 1970.
    pins_read: Mutex<f64>,
    samples: Mutex<HashMap<String, (VecDeque<u32>, bool)>>,
    latency: RwLock<Arc<HashMap<String, u32>>>,
    load_out: Mutex<HashMap<String, DeploymentLoad>>,
    load: RwLock<Arc<HashMap<String, DeploymentLoad>>>,
    health_out: Mutex<Option<String>>,
    health: RwLock<Arc<Vec<String>>>,
    polls: AtomicU64,
    shares_cache: AtomicBool,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Opens the store at `url`, reads what it keeps, and starts the poll. Fails, naming the fix, when it cannot be
/// reached.
pub fn open(url: &str) -> Result<Arc<CfStore>, String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("enterplace-store")
        .enable_all()
        .build()
        .map_err(|err| {
            format!("the store's thread could not be started: {err}. Report this as a bug.")
        })?;
    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(WAIT));
    let inner = Arc::new(Inner {
        url: url.trim_end_matches('/').to_string(),
        http: Client::builder(TokioExecutor::new()).build(connector),
        seen: Mutex::default(),
        polling: tokio::sync::Mutex::new(()),
        keys: RwLock::default(),
        kills: RwLock::default(),
        cooling: RwLock::default(),
        returns: Mutex::default(),
        credentials: RwLock::default(),
        master: OnceLock::new(),
        policies: RwLock::default(),
        ended: RwLock::default(),
        raises: RwLock::default(),
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
        polls: AtomicU64::new(0),
        shares_cache: AtomicBool::new(false),
    });
    let store = CfStore {
        handle: runtime.handle().clone(),
        runtime: Mutex::new(Some(runtime)),
        inner: inner.clone(),
    };
    let first = inner.clone();
    store.wait(async move { first.refresh().await }).map_err(|err| {
        format!(
            "the store cannot be reached: {err}. Enterplace does not start without it. On Cloudflare, deploy the Worker of deploy/cloudflare (it answers {DEFAULT_URL}) and run `npx wrangler tail` to see why it refused; elsewhere, set {URL_ENV} to the store's address."
        )
    })?;
    let weak = Arc::downgrade(&inner);
    store.handle.spawn(async move {
        loop {
            tokio::time::sleep(POLL).await;
            let Some(inner) = weak.upgrade() else {
                return;
            };
            inner.round().await;
        }
    });
    Ok(Arc::new(store))
}

impl Inner {
    /// One call to the store, given up after [`WAIT`].
    async fn call(&self, name: &str, body: Value) -> Result<Value, String> {
        send(&self.http, &self.url, name, body).await
    }

    /// A call on the request path: refused at once while the store is down, as the Postgres store refuses without
    /// its connection, rather than waiting.
    async fn ask_up(&self, name: &str, body: Value) -> Result<Value, String> {
        if self.down.load(Ordering::Relaxed) {
            return Err("the store cannot be reached".into());
        }
        self.call(name, body).await
    }

    /// One poll round, reporting the store going away or coming back.
    async fn round(&self) {
        match self.refresh().await {
            Ok(()) => {
                if self.down.swap(false, Ordering::Relaxed) {
                    eprintln!(
                        "enterplace: the store is reachable again. Budgeted requests are served again."
                    );
                }
            }
            Err(err) => {
                if !self.down.swap(true, Ordering::Relaxed) {
                    eprintln!(
                        "enterplace: the store cannot be reached: {err}. Known keys and kill switches stay as they were, and requests under a budget are refused (store_unavailable) until it is back. Run `npx wrangler tail` to see why the Worker or its EnterplaceStore object refused."
                    );
                }
            }
        }
    }

    /// Writes what this gateway gathered, and reads what changed: one call.
    async fn refresh(&self) -> Result<(), String> {
        let _one = self.polling.lock().await;
        let polls = self.polls.fetch_add(1, Ordering::Relaxed);
        let returns: Vec<(i64, i64)> = std::mem::take(&mut *lock(&self.returns))
            .into_iter()
            .collect();
        let pins: Vec<(String, String)> = std::mem::take(&mut *lock(&self.pins_out))
            .into_iter()
            .collect();
        let samples: Vec<(String, Vec<u32>)> = lock(&self.samples)
            .iter_mut()
            .filter(|(_, (_, dirty))| *dirty)
            .map(|(d, (samples, dirty))| {
                *dirty = false;
                (d.clone(), samples.iter().copied().collect())
            })
            .collect();
        let load: Vec<Value> = std::mem::take(&mut *lock(&self.load_out))
            .into_iter()
            .map(|(d, l)| json!([d, l.in_flight, l.minute, l.requests, l.tokens]))
            .collect();
        let heartbeat = (polls % HEARTBEAT_EVERY == 0).then(|| {
            json!({
                "host": std::env::var("HOSTNAME").unwrap_or_default(),
                "version": enterplace_core::VERSION,
                "schema": "cloudflare",
            })
        });
        let body = json!({
            "gateway": self.gateway,
            "seen": *lock(&self.seen),
            "pins_since": *lock(&self.pins_read),
            "pin_overlap": PIN_OVERLAP_SECS,
            "idle": crate::alias::SESSION_IDLE.as_secs_f64(),
            "latency_for": LATENCY_FOR_SECS,
            "load_for": LOAD_FOR_SECS,
            "minute": crate::alias::minute_now(),
            "returns": returns,
            "pins": pins,
            "samples": samples,
            "load": load,
            "health": lock(&self.health_out).take(),
            "heartbeat": heartbeat,
            "clean": polls % CLEAN_EVERY == 0,
        });
        let answer = self.call("poll", body).await?;
        self.apply(&answer)?;
        if polls % CLEAN_EVERY == 0 {
            let now = Instant::now();
            self.pins
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .retain(|_, (_, at, _)| now.duration_since(*at) < crate::alias::SESSION_IDLE);
        }
        Ok(())
    }

    /// Puts what a poll read in memory. A part that does not read leaves everything as it was, never a key with
    /// fewer limits.
    fn apply(&self, answer: &Value) -> Result<(), String> {
        let now = Instant::now();
        let later = |left: &Value| now + secs(left);
        let keys = match answer.get("keys") {
            Some(list) => Some(keyfile::keys_text(
                &array(list)
                    .iter()
                    .map(key_of)
                    .collect::<Result<Vec<_>, _>>()?,
            )),
            None => None,
        };
        let kills = answer
            .get("kills")
            .map(|list| array(list).iter().map(kill_of).collect::<Vec<_>>());
        let credentials = match answer.get("credentials") {
            Some(list) => Some(
                array(list)
                    .iter()
                    .map(|c| {
                        let sealed = base64_decode(text(&c["sealed"]))
                            .ok_or("a sealed credential is not base64")?;
                        Ok((credential_of(c), sealed))
                    })
                    .collect::<Result<Vec<_>, String>>()?,
            ),
            None => None,
        };
        let policies = answer
            .get("policies")
            .map(|list| array(list).iter().map(version_of).collect::<Vec<_>>());
        if let Some(keys) = keys {
            write(&self.keys, keys);
        }
        if let Some(kills) = kills {
            write(&self.kills, Arc::new(kills));
        }
        if let Some(list) = answer.get("cooling") {
            let cooling = array(list)
                .iter()
                .map(|c| (text(&c[0]).to_string(), later(&c[1])))
                .collect();
            write(&self.cooling, Arc::new(cooling));
        }
        if let Some(credentials) = credentials {
            write(&self.credentials, Arc::new(credentials));
        }
        if let Some(policies) = policies {
            write(&self.policies, Arc::new(policies));
        }
        if let Some(list) = answer.get("ended") {
            let ended = array(list)
                .iter()
                .map(|e| {
                    (
                        text(&e[0]).to_string(),
                        (later(&e[2]), text(&e[1]).to_string()),
                    )
                })
                .collect();
            write(&self.ended, Arc::new(ended));
        }
        if let Some(list) = answer.get("raises") {
            let raises = array(list)
                .iter()
                .filter_map(|r| serde_json::from_value(r.clone()).ok())
                .collect();
            write(&self.raises, Arc::new(raises));
        }
        if let Some(versions) = answer["versions"].as_object() {
            *lock(&self.seen) = versions.clone();
        }
        self.apply_routing(answer, now);
        Ok(())
    }

    /// Pins written since the last read (another gateway's sessions), every gateway's latency, the others' load
    /// and their health reports.
    fn apply_routing(&self, answer: &Value, now: Instant) {
        let pending = lock(&self.pins_out).clone();
        {
            let mut pins = self
                .pins
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for pin in array(&answer["pins"]) {
                let session = text(&pin[0]).to_string();
                if pending.contains_key(&session) {
                    continue;
                }
                let deployment = text(&pin[1]).to_string();
                let at = now.checked_sub(secs(&pin[2])).unwrap_or(now);
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
        if let Some(clock) = answer["now"].as_f64() {
            *lock(&self.pins_read) = clock;
        }
        let mut all: HashMap<String, VecDeque<u32>> = HashMap::new();
        for row in array(&answer["latency"]) {
            all.entry(text(&row[0]).to_string()).or_default().extend(
                array(&row[1])
                    .iter()
                    .map(|ms| u32::try_from(ms.as_u64().unwrap_or(0)).unwrap_or(0)),
            );
        }
        let p90 = all
            .iter()
            .filter_map(|(d, samples)| Some((d.clone(), crate::alias::percentile(samples, 90)?)))
            .collect();
        write(&self.latency, Arc::new(p90));
        let minute = crate::alias::minute_now();
        let count = |v: &Value| v.as_u64().unwrap_or(0);
        let load = array(&answer["load"])
            .iter()
            .map(|row| {
                (
                    text(&row[0]).to_string(),
                    DeploymentLoad {
                        in_flight: u32::try_from(count(&row[1])).unwrap_or(0),
                        minute,
                        requests: u32::try_from(count(&row[2])).unwrap_or(0),
                        tokens: count(&row[3]),
                    },
                )
            })
            .collect();
        write(&self.load, Arc::new(load));
        let reports = array(&answer["health"])
            .iter()
            .filter_map(|r| r.as_str().map(str::to_string))
            .collect();
        write(&self.health, Arc::new(reports));
    }

    async fn reserve(&self, bucket: &Bucket, usd: f64, limit: f64) -> Result<Reserve, String> {
        if !usd.is_finite() || !limit.is_finite() {
            return Err(format!(
                "a reservation of {usd} against a limit of {limit} is not a number of dollars"
            ));
        }
        let answer = self
            .ask_up(
                "reserve",
                json!({
                    "scope": bucket.scope,
                    "per": bucket.per.word(),
                    "period": bucket.period,
                    "usd": usd,
                    "limit": limit,
                    "sliding": bucket.per.sliding,
                    "from": bucket.per.window_start_label(&bucket.period),
                }),
            )
            .await?;
        Ok(if answer["done"].as_bool() == Some(true) {
            Reserve::Done
        } else {
            Reserve::Over {
                spent: answer["spent"].as_f64().unwrap_or(0.0),
                reserved: answer["reserved"].as_f64().unwrap_or(0.0),
            }
        })
    }

    async fn lease(&self, scope: &str, need: u64, want: u64, limit: u64) -> Result<Lease, String> {
        let hold = u64::try_from(LEASE.as_millis()).unwrap_or(1000) + LEASE_MARGIN_MS;
        let answer = self
            .ask_up(
                "lease",
                json!({ "scope": scope, "need": need, "want": want, "limit": limit, "hold_ms": hold }),
            )
            .await?;
        Ok(match (answer["grant"].as_i64(), answer["n"].as_u64()) {
            (Some(grant), Some(n)) => Lease::Granted { grant, n },
            _ => Lease::Over {
                wait: answer["wait"].as_u64().unwrap_or(1).max(1),
            },
        })
    }
}

/// `POST <url>/v1/<name>` with `body`, and the store's JSON answer.
async fn send(
    http: &Client<HttpConnector, Full<Bytes>>,
    url: &str,
    name: &str,
    body: Value,
) -> Result<Value, String> {
    let request = axum::http::Request::post(format!("{url}/v1/{name}"))
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .map_err(|err| err.to_string())?;
    let answer = async {
        let response = http.request(request).await.map_err(|err| {
            let cause = std::error::Error::source(&err).map(ToString::to_string);
            format!(
                "{err}{}",
                cause.map(|c| format!(": {c}")).unwrap_or_default()
            )
        })?;
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|err| err.to_string())?
            .to_bytes();
        if !status.is_success() {
            return Err(format!(
                "the store answered {status}: {}",
                String::from_utf8_lossy(&bytes).trim()
            ));
        }
        serde_json::from_slice(&bytes).map_err(|err| format!("the store's answer: {err}"))
    };
    tokio::time::timeout(WAIT, answer)
        .await
        .unwrap_or_else(|_| Err(format!("no answer within {} seconds", WAIT.as_secs())))
}

/// One call to the store at `url`, for a test that sets up or reads the store's rows as a database test would
/// with SQL.
#[doc(hidden)]
pub async fn call(url: &str, name: &str, body: Value) -> Result<Value, String> {
    send(
        &Client::builder(TokioExecutor::new()).build(HttpConnector::new()),
        url,
        name,
        body,
    )
    .await
}

fn array(v: &Value) -> &[Value] {
    v.as_array().map_or(&[], Vec::as_slice)
}

fn text(v: &Value) -> &str {
    v.as_str().unwrap_or_default()
}

fn opt(v: &Value) -> Option<String> {
    v.as_str().map(str::to_string)
}

fn secs(v: &Value) -> Duration {
    Duration::try_from_secs_f64(v.as_f64().unwrap_or(0.0)).unwrap_or_default()
}

/// A key as the store keeps it: the columns of the Postgres store's `enterplace_keys`, as one JSON object.
fn key_json(entry: &KeyEntry) -> Value {
    json!({
        "sha256": entry.sha256,
        "name": entry.name,
        "team": entry.team,
        "admin": entry.admin,
        "expires": entry.expires,
        "budget_usd": entry.budget.map(|b| b.usd),
        "budget_per": entry.budget.map(|b| b.per.word()),
        "models": entry.models,
        "tpm": entry.tpm,
        "org": (!entry.org.is_empty()).then_some(&entry.org),
        "customer": entry.customer,
        "tags": entry.tags,
        "parallel": entry.parallel,
        "role": entry.role,
        "options": keyfile::options_json(&entry.options),
    })
}

fn key_of(v: &Value) -> Result<KeyEntry, String> {
    let strings = |v: &Value| -> Vec<String> {
        array(v)
            .iter()
            .filter_map(|s| s.as_str().map(str::to_string))
            .collect()
    };
    // A value out of range becomes 0, which the loader refuses: the change is then not used at all.
    let small = |v: &Value| v.as_u64().map(|n| u32::try_from(n).unwrap_or(0));
    Ok(KeyEntry {
        name: text(&v["name"]).to_string(),
        team: text(&v["team"]).to_string(),
        sha256: text(&v["sha256"]).to_string(),
        admin: v["admin"].as_bool().unwrap_or(false),
        expires: opt(&v["expires"]),
        budget: v["budget_usd"].as_f64().map(|usd| Budget {
            usd,
            // A word no version writes is read as a day, the tightest common period.
            per: v["budget_per"]
                .as_str()
                .and_then(Period::from_word)
                .unwrap_or(Period::Day),
        }),
        models: v["models"].is_array().then(|| strings(&v["models"])),
        tpm: small(&v["tpm"]),
        org: text(&v["org"]).to_string(),
        customer: opt(&v["customer"]),
        tags: strings(&v["tags"]),
        parallel: small(&v["parallel"]),
        role: opt(&v["role"]),
        // Unreadable options stop the refresh: the last keys stay in force, never one with fewer limits.
        options: v["options"]
            .as_str()
            .map(keyfile::options_from_json)
            .transpose()?
            .unwrap_or_default(),
    })
}

fn kill_of(v: &Value) -> Kill {
    Kill {
        scope: text(&v["scope"]).to_string(),
        value: text(&v["value"]).to_string(),
        reason: text(&v["reason"]).to_string(),
        by: text(&v["set_by"]).to_string(),
        at: text(&v["set_at"]).to_string(),
    }
}

fn credential_of(v: &Value) -> Credential {
    Credential {
        name: text(&v["name"]).to_string(),
        provider: text(&v["provider"]).to_string(),
        fingerprint: text(&v["fingerprint"]).to_string(),
        created_by: text(&v["created_by"]).to_string(),
        created_at: text(&v["created_at"]).to_string(),
        rotated_by: opt(&v["rotated_by"]),
        rotated_at: opt(&v["rotated_at"]),
        generation: v["generation"].as_i64().unwrap_or(1),
    }
}

fn version_of(v: &Value) -> PolicyVersion {
    PolicyVersion {
        id: v["id"].as_i64().unwrap_or(0),
        text: text(&v["text"]).to_string(),
        sha256: text(&v["sha256"]).to_string(),
        base: v["base"].as_i64(),
        note: text(&v["note"]).to_string(),
        created_by: text(&v["created_by"]).to_string(),
        created_at: text(&v["created_at"]).to_string(),
        state: text(&v["state"]).to_string(),
        decided_by: opt(&v["decided_by"]),
        decided_at: opt(&v["decided_at"]),
    }
}

fn key32(v: &Value) -> Option<[u8; 32]> {
    base64_decode(v.as_str()?)?.try_into().ok()
}

impl CfStore {
    /// Keeps cached answers in the store (`store.answer_cache`), so every gateway serves them.
    pub fn share_cache(&self, yes: bool) {
        self.inner.shares_cache.store(yes, Ordering::Relaxed);
    }

    /// Turns provider credentials on with the customer's master key. The first gateway seals a check value with it;
    /// every later one must open that value, so a wrong key is refused here, at start, with the fix.
    pub fn unlock(&self, master: MasterKey) -> Result<(), String> {
        let check = base64_encode(&master.seal(MASTER_CHECK.0, MASTER_CHECK.1)?);
        let inner = self.inner.clone();
        let stored = self
            .wait(async move { inner.call("master", json!({ "sealed": check })).await })
            .map_err(|err| {
                format!(
                    "the master key could not be checked against the store: {err}. Check the Worker with `npx wrangler tail`, then start again."
                )
            })?;
        let stored = base64_decode(text(&stored["sealed"])).unwrap_or_default();
        if master.open(MASTER_CHECK.0, &stored).ok().as_deref() != Some(MASTER_CHECK.1) {
            return Err(format!(
                "{} is not the key the provider credentials in this store were sealed with: it does not open the store's check value. Set the master key the other gateways use, and start again. A master key that is lost cannot be recovered: then delete the store's Durable Object data and add the credentials again under a new one.",
                crate::credentials::MASTER_ENV
            ));
        }
        let _ = self.inner.master.set(master);
        Ok(())
    }

    fn master(&self) -> Result<&MasterKey, String> {
        self.inner.master.get().ok_or_else(|| NO_MASTER.to_string())
    }

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

    /// Runs `work` on the store's runtime, for a caller on the request path to await.
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

    /// One call without waiting for it, tried again each second while the store is away, for up to
    /// [`SETTLE_FOR`].
    fn retried(&self, what: &'static str, name: &'static str, body: Value) {
        let inner = self.inner.clone();
        self.handle.spawn(async move {
            let started = tokio::time::Instant::now();
            loop {
                // ponytail: an answer lost after the store applied the call makes the retry apply it twice, as with
                // Postgres. An idempotency key per call fixes it if it shows.
                let err = match inner.call(name, body.clone()).await {
                    Ok(_) => return,
                    Err(err) => err,
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

    /// One call without waiting for it or trying it again: what is lost is made again by the next request.
    fn fire(&self, name: &'static str, body: Value) {
        let inner = self.inner.clone();
        self.handle.spawn(async move {
            let _ = inner.ask_up(name, body).await;
        });
    }

    /// A change: one call, then the store read again, so this gateway applies it at once.
    fn change(&self, what: &'static str, name: &'static str, body: Value) -> Result<Value, String> {
        let inner = self.inner.clone();
        self.wait(async move {
            let done = inner.call(name, body).await?;
            // The change is made. If reading it back fails, the poll picks it up within half a second.
            let _ = inner.refresh().await;
            Ok(done)
        })
        .map_err(|err| {
            format!(
                "the {what} could not be written to the store: {err}. Nothing was changed. Check the Worker with `npx wrangler tail`, then try again."
            )
        })
    }

    fn credential_change(
        &self,
        name: &'static str,
        body: Value,
    ) -> Result<Option<Credential>, String> {
        let answer = self.change("credential", name, body)?;
        Ok((!answer["credential"].is_null()).then(|| credential_of(&answer["credential"])))
    }

    /// A policy change, refused with what moved on when the versions changed since the caller read them. `id` is
    /// the version decided, `base` the one a new version was drafted on.
    fn policy_change(
        &self,
        name: &'static str,
        body: Value,
        id: i64,
        base: Option<i64>,
    ) -> Result<PolicyVersion, VersionError> {
        let inner = self.inner.clone();
        let answer = self
            .wait(async move {
                let done = inner.call(name, body).await?;
                let _ = inner.refresh().await;
                Ok(done)
            })
            .map_err(|err| {
                VersionError::Store(format!(
                    "the policy version could not be written to the store: {err}. Nothing may have been changed: reload the versions page and check."
                ))
            })?;
        let word =
            |v: Option<i64>| v.map_or_else(|| "none".to_string(), |v| format!("version {v}"));
        match answer["conflict"].as_str() {
            None => Ok(version_of(&answer["version"])),
            Some("base") => Err(VersionError::Conflict(format!(
                "the draft started from {} and {} is live now: someone saved a change meanwhile. Open the live version, make the change again on it, and save.",
                word(base),
                word(answer["live"].as_i64())
            ))),
            Some("missing") => Err(VersionError::Conflict(format!(
                "there is no policy version {id}."
            ))),
            Some("state") => Err(VersionError::Conflict(format!(
                "version {id} is {} now, not waiting for approval: someone decided it meanwhile.",
                text(&answer["state"])
            ))),
            Some(_) => Err(VersionError::Conflict(format!(
                "version {id} was drafted on a version that is no longer live. Reject it and draft the change again on the live version."
            ))),
        }
    }
}

impl core_store::Credentials for CfStore {
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
            "add_credential",
            json!({
                "name": name,
                "provider": provider,
                "sealed": base64_encode(&sealed),
                "fingerprint": core_store::fingerprint(value.trim()),
                "by": by,
                "at": enterplace_core::audit::timestamp(),
            }),
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
            "rotate_credential",
            json!({
                "name": name,
                "sealed": base64_encode(&sealed),
                "fingerprint": core_store::fingerprint(value.trim()),
                "by": by,
                "at": enterplace_core::audit::timestamp(),
            }),
        )
    }

    fn remove_credential(&self, name: &str) -> Result<Option<Credential>, String> {
        self.master()?;
        self.credential_change("remove_credential", json!({ "name": name }))
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

impl Store for CfStore {
    fn raises(&self) -> Option<Arc<Vec<Raise>>> {
        Some(read(&self.inner.raises))
    }

    fn put_raise(&self, raise: &Raise) -> Result<(), String> {
        let raise = serde_json::to_value(raise).map_err(|err| err.to_string())?;
        self.change("budget raise", "put_raise", json!({ "raise": raise }))
            .map(|_| ())
    }

    fn replicas(&self) -> Pending<Vec<Replica>> {
        let inner = self.inner.clone();
        self.ask(async move {
            let answer = inner
                .ask_up("replicas", json!({ "healthy_for": HEALTHY_FOR_SECS }))
                .await?;
            Ok(array(&answer["replicas"])
                .iter()
                .map(|r| Replica {
                    gateway: text(&r["gateway"]).to_string(),
                    host: text(&r["host"]).to_string(),
                    version: text(&r["version"]).to_string(),
                    started: text(&r["started"]).to_string(),
                    seen: text(&r["seen"]).to_string(),
                    healthy: r["healthy"].as_bool().unwrap_or(false),
                    schema: text(&r["schema"]).to_string(),
                })
                .collect())
        })
    }

    fn shares_cache(&self) -> bool {
        self.inner.shares_cache.load(Ordering::Relaxed)
    }

    fn cache_get(&self, key: [u8; 32], scope: String) -> Pending<Option<CachedAnswer>> {
        let inner = self.inner.clone();
        self.ask(async move {
            let answer = inner
                .ask_up(
                    "cache_get",
                    json!({ "key": base64_encode(&key), "scope": id::sha256_hex(scope.as_bytes()) }),
                )
                .await?;
            let a = &answer["answer"];
            if a.is_null() {
                return Ok(None);
            }
            Ok(Some(CachedAnswer {
                key,
                scope,
                status: u16::try_from(a["status"].as_u64().unwrap_or(200)).unwrap_or(200),
                content_type: opt(&a["content_type"]),
                body: base64_decode(text(&a["body"])).ok_or("a cached answer is not base64")?,
                origin: text(&a["origin"]).to_string(),
                cost: a["cost"].as_f64().unwrap_or(0.0),
                ttl: secs(&a["left"]),
                vector: None,
            }))
        })
    }

    fn cache_put(&self, answer: CachedAnswer) {
        // Not retried: an answer that is not kept is asked of the provider again, which is what no cache does.
        self.fire(
            "cache_put",
            json!({
                "key": base64_encode(&answer.key),
                "scope": id::sha256_hex(answer.scope.as_bytes()),
                "status": answer.status,
                "content_type": answer.content_type,
                "body": base64_encode(&answer.body),
                "origin": answer.origin,
                "cost": answer.cost,
                "ttl": answer.ttl.as_secs_f64(),
                "vector": answer.vector.as_ref().map(|(partition, values)| json!({
                    "partition": base64_encode(partition),
                    "values": values,
                })),
            }),
        );
    }

    fn cache_vectors(&self, partition: [u8; 32]) -> Pending<Vec<([u8; 32], Vec<f32>)>> {
        let inner = self.inner.clone();
        self.ask(async move {
            let answer = inner
                .ask_up(
                    "cache_vectors",
                    json!({ "partition": base64_encode(&partition), "limit": core_store::MAX_SHARED_VECTORS }),
                )
                .await?;
            Ok(array(&answer["vectors"])
                .iter()
                .filter_map(|row| {
                    let values = array(&row[1])
                        .iter()
                        .map(|v| v.as_f64().map(|f| f as f32))
                        .collect::<Option<Vec<f32>>>()?;
                    Some((key32(&row[0])?, values))
                })
                .collect())
        })
    }

    fn keeps_settings(&self) -> bool {
        true
    }

    fn setting(&self, name: &str) -> Result<Option<String>, String> {
        let (inner, name) = (self.inner.clone(), name.to_string());
        self.wait(async move {
            let answer = inner.call("setting", json!({ "name": name })).await?;
            Ok(opt(&answer["value"]))
        })
    }

    fn set_setting(&self, name: &str, value: &str) -> Result<(), String> {
        let (inner, body) = (self.inner.clone(), json!({ "name": name, "value": value }));
        self.wait(async move { inner.call("set_setting", body).await.map(|_| ()) })
    }

    fn keys_text(&self) -> String {
        read(&self.inner.keys)
    }

    fn kills(&self) -> Arc<Vec<Kill>> {
        read(&self.inner.kills)
    }

    fn add_key(&self, entry: &KeyEntry) -> Result<bool, String> {
        let answer = self.change("key", "add_key", json!({ "key": key_json(entry) }))?;
        if answer["added"].as_bool() != Some(true) {
            return Err("a key with this hash is already in the store".into());
        }
        Ok(answer["name_had"].as_bool().unwrap_or(false))
    }

    fn update_key(&self, entry: &KeyEntry) -> Result<bool, String> {
        let answer = self.change("key", "update_key", json!({ "key": key_json(entry) }))?;
        Ok(answer["changed"].as_bool().unwrap_or(false))
    }

    fn reachable(&self) -> Result<(), String> {
        if self.inner.down.load(Ordering::Relaxed) {
            return Err(
                "the store cannot be reached: check the Worker with `npx wrangler tail`".into(),
            );
        }
        Ok(())
    }

    fn spend(&self, scope: String) -> Pending<Vec<(String, String, f64, f64)>> {
        let inner = self.inner.clone();
        self.ask(async move {
            let answer = inner.ask_up("spend", json!({ "scope": scope })).await?;
            Ok(array(&answer["rows"])
                .iter()
                .map(|r| {
                    (
                        text(&r["per"]).to_string(),
                        text(&r["period"]).to_string(),
                        r["spent"].as_f64().unwrap_or(0.0),
                        r["reserved"].as_f64().unwrap_or(0.0),
                    )
                })
                .collect())
        })
    }

    fn revoke(&self, prefix: &str) -> Result<Option<Revoked>, String> {
        let answer = self.change("revocation", "revoke", json!({ "prefix": prefix }))?;
        if answer["matching"].as_u64().unwrap_or(0) > 1 {
            return Err(format!(
                "more than one key hash starts with {prefix}. Give more of the hash. Nothing was changed."
            ));
        }
        let gone = &answer["gone"];
        Ok((!gone.is_null()).then(|| Revoked {
            name: text(&gone["name"]).to_string(),
            team: text(&gone["team"]).to_string(),
            sha256: text(&gone["sha256"]).to_string(),
        }))
    }

    fn set_kill(&self, kill: &Kill) -> Result<Option<Kill>, String> {
        let answer = self.change(
            "kill switch",
            "set_kill",
            json!({ "kill": {
                "scope": kill.scope, "value": kill.value, "reason": kill.reason, "set_by": kill.by, "set_at": kill.at,
            }}),
        )?;
        Ok((!answer["old"].is_null()).then(|| kill_of(&answer["old"])))
    }

    fn clear_kill(&self, scope: &str, value: &str) -> Result<Option<Kill>, String> {
        let answer = self.change(
            "kill switch",
            "clear_kill",
            json!({ "scope": scope, "value": value }),
        )?;
        Ok((!answer["gone"].is_null()).then(|| kill_of(&answer["gone"])))
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
                return Err(
                    "the store cannot be reached. Check the Worker with `npx wrangler tail`."
                        .into(),
                );
            }
            Ok(())
        })
    }

    fn policy_versions(&self) -> Result<Arc<Vec<PolicyVersion>>, String> {
        Ok(read(&self.inner.policies))
    }

    fn add_policy_version(&self, new: &NewVersion) -> Result<PolicyVersion, VersionError> {
        self.policy_change(
            "add_policy_version",
            json!({
                "text": new.text,
                "sha256": id::sha256_hex(new.text.as_bytes()),
                "base": new.base,
                "note": new.note,
                "by": new.by,
                "at": enterplace_core::audit::timestamp(),
                "pending": new.pending,
            }),
            0,
            new.base,
        )
    }

    fn decide_policy_version(
        &self,
        version: i64,
        approve: bool,
        by: &str,
    ) -> Result<PolicyVersion, VersionError> {
        self.policy_change(
            "decide_policy_version",
            json!({ "id": version, "approve": approve, "by": by, "at": enterplace_core::audit::timestamp() }),
            version,
            None,
        )
    }

    fn settle(&self, changes: Vec<Change>) {
        if changes.is_empty() {
            return;
        }
        let mut merged: BTreeMap<&Bucket, (f64, f64)> = BTreeMap::new();
        for change in &changes {
            let sum = merged.entry(&change.bucket).or_default();
            sum.0 += change.spent;
            sum.1 += change.reserved;
        }
        let rows: Vec<Value> = merged
            .iter()
            .map(|(b, (spent, reserved))| json!([b.scope, b.per.word(), b.period, spent, reserved]))
            .collect();
        // A hold never given back keeps counting against its budget until the period ends.
        self.retried("spend", "settle", json!({ "changes": rows }));
    }

    fn lease(&self, scope: String, need: u64, want: u64, limit: u64) -> Pending<Lease> {
        let inner = self.inner.clone();
        self.ask(async move { inner.lease(&scope, need, want, limit).await })
    }

    fn give_back(&self, grant: i64, n: i64) {
        *lock(&self.inner.returns).entry(grant).or_default() += n;
    }

    fn cooling(&self) -> Arc<HashMap<String, Instant>> {
        read(&self.inner.cooling)
    }

    fn cooled(&self, deployment: &str, cooldown: Duration) {
        // Not retried: the deployment is passed over here at once, and a cooldown written late is worth little.
        let ms = u64::try_from(cooldown.as_millis()).unwrap_or(u64::MAX);
        self.fire("cooled", json!({ "deployment": deployment, "ms": ms }));
    }

    fn warmed(&self, deployment: &str) {
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
        self.fire("warmed", json!({ "deployment": deployment }));
    }

    fn shares_routing(&self) -> bool {
        true
    }

    fn probe_lease(&self, deployment: String, ttl: Duration) -> Pending<bool> {
        let inner = self.inner.clone();
        self.ask(async move {
            let answer = inner
                .ask_up(
                    "probe_lease",
                    json!({ "deployment": deployment, "gateway": inner.gateway, "ttl": ttl.as_secs_f64() }),
                )
                .await?;
            Ok(answer["held"].as_bool().unwrap_or(false))
        })
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
        // Sessions are kept by hash: the person and the session ID their client sent stay out of the store.
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
        lock(&self.inner.pins_out).insert(key, deployment.to_string());
    }

    fn latency(&self) -> Arc<HashMap<String, u32>> {
        read(&self.inner.latency)
    }

    fn observed(&self, deployment: &str, ms: u32) {
        let mut samples = lock(&self.inner.samples);
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
        *lock(&self.inner.health_out) = Some(report);
    }

    fn health_reports(&self) -> Arc<Vec<String>> {
        read(&self.inner.health)
    }

    fn publish_load(&self, deployment: &str, load: DeploymentLoad) {
        lock(&self.inner.load_out).insert(deployment.to_string(), load);
    }

    fn ended_sessions(&self) -> Arc<HashMap<String, (Instant, String)>> {
        read(&self.inner.ended)
    }

    fn end_events_session(&self, key: String, by: String, ttl: Duration) {
        self.retried(
            "the end of a session",
            "end_events_session",
            json!({ "key": key, "by": by, "seconds": ttl.as_secs_f64() }),
        );
    }

    fn open_session(&self, id_sha256: String, who: String, ttl: Duration) -> Pending<()> {
        let inner = self.inner.clone();
        self.ask(async move {
            inner
                .ask_up(
                    "open_session",
                    json!({ "sha256": id_sha256, "who": who, "seconds": ttl.as_secs_f64() }),
                )
                .await
                .map(|_| ())
        })
    }

    fn session(&self, id_sha256: String) -> Pending<Option<String>> {
        let inner = self.inner.clone();
        self.ask(async move {
            let answer = inner
                .ask_up("session", json!({ "sha256": id_sha256 }))
                .await?;
            Ok(opt(&answer["who"]))
        })
    }

    fn end_session(&self, id_sha256: String) {
        self.retried(
            "a console sign-out",
            "end_session",
            json!({ "sha256": id_sha256 }),
        );
    }
}
