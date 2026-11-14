//! Aliases: one model name a caller sends, served by several deployments (a provider and a model there), picked in
//! turn by weight or by the fewest requests in flight, with a deployment that failed passed over for a while.
//! Also the two body edits routing needs: the model of a JSON body, and the model field of a multipart form.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use axum::body::Bytes;
use gantry_core::config::{Alias, Balance};

/// What Gantry remembers about each deployment and alias. One per server, kept across reloads.
#[derive(Default)]
pub(crate) struct Pool {
    deployments: Mutex<HashMap<String, Deployed>>,
    turns: Mutex<HashMap<String, u64>>,
    /// Which deployment each session of each alias is pinned to, and when it last sent.
    sessions: Mutex<HashMap<String, (String, Instant)>>,
    /// With a store, a deployment that fails here is passed over by every gateway, and one that failed on another
    /// gateway is passed over here.
    store: Option<Arc<dyn gantry_core::store::Store>>,
    /// Each key of each provider's key pool, by `provider/fingerprint`.
    keys: Mutex<HashMap<String, Keyed>>,
    /// The last health probe of each probed deployment.
    probes: Mutex<HashMap<String, Probed>>,
}

/// One key of a pool: when it may be used again (after a 401, 403 or 429), and how many requests it was sent.
#[derive(Default)]
struct Keyed {
    out_until: Option<Instant>,
    uses: u64,
}

/// A health probe's last outcome.
#[derive(Clone, Debug)]
pub(crate) struct Probed {
    pub(crate) up: bool,
    /// When it was sent, for the next one's turn.
    pub(crate) at: Instant,
    /// When it was sent, as a timestamp for /readyz.
    pub(crate) time: String,
    /// The status or refusal code it got.
    pub(crate) outcome: String,
}

/// How long a key answered 429 without a Retry-After rests.
const KEY_REST: Duration = Duration::from_secs(60);

/// A deployment whose provider says less than this share of its rate limit is left goes after the others, unless
/// its alias sets `rate_limit_headroom_percent`.
const HEADROOM_PERCENT: u32 = 5;

/// The window of a deployment's `rpm` and `tpm`.
/// How long a provider's rate-limit headers are believed: its windows are about a minute.
const HEADROOM_FOR: Duration = Duration::from_secs(60);

/// A deployment's circuit: closed (no failure since the last answer), open (cooling down), or half open (the
/// cooldown is over and one request is out probing it).
#[derive(Default)]
struct Deployed {
    cool_until: Option<Instant>,
    busy: Arc<AtomicUsize>,
    /// Failures since the last answer: each doubles the next cooldown, up to `MAX_BACKOFF` times the base.
    failures: u32,
    /// When the probe of a half-open deployment was let through. Another is let through a base cooldown later, so
    /// a probe that never reports back (its request went elsewhere, or the caller left) cannot shut it out.
    probe_since: Option<Instant>,
    base: Duration,
    /// Time to first byte of its last answers here, in milliseconds, oldest first.
    latency: std::collections::VecDeque<u32>,
    /// Share of recent attempts that failed, as a moving average: each attempt moves it a fifth of the way.
    errors: f64,
    /// The smallest share of its rate limits its provider said was left, and when.
    headroom: Option<(f64, Instant)>,
    /// The current wall-clock minute (as [`minute_now`]), and the requests and tokens sent in it: each request's
    /// estimate while it runs, its answer's own count once that is known.
    minute: (i64, u32, u64),
    /// Times it was put to cool down, for `/metrics`.
    cooldowns: u64,
}

/// What a request brings to the choice of deployment besides the alias.
#[derive(Default)]
pub(crate) struct Ask<'a> {
    /// The person and the session their client names, for an alias with session affinity.
    pub(crate) session: Option<String>,
    /// Each deployment's price in dollars per million tokens in and out, by position, for lowest_cost.
    pub(crate) cost: &'a [Option<f64>],
}

/// How many answers a deployment's latency is judged on: recent enough to follow a slow region, enough that one
/// slow answer does not move the 90th percentile.
pub(crate) const LATENCY_SAMPLES: usize = 32;

/// A session with no request for this long is forgotten, and its next request is balanced afresh. With a store
/// the pins are shared, so replicas behind a balancer that is not sticky keep a session on one deployment.
// ponytail: fixed idle time; a setting when someone needs another.
pub(crate) const SESSION_IDLE: Duration = Duration::from_secs(3600);

/// Most sessions remembered at once, about 10 MB at most.
const MAX_SESSIONS: usize = 100_000;

/// The `p`th percentile of `samples`, by nearest rank. `None` without samples.
pub(crate) fn percentile(samples: &std::collections::VecDeque<u32>, p: usize) -> Option<u32> {
    let mut sorted: Vec<u32> = samples.iter().copied().collect();
    sorted.sort_unstable();
    let rank = (sorted.len() * p).div_ceil(100).max(1);
    sorted.get(rank - 1).copied()
}

/// Inserts into a session table bounded at [`MAX_SESSIONS`]: past its size, idle sessions are dropped, and if none
/// is idle the oldest goes. `seen` says when an entry's session last sent.
pub(crate) fn bounded_insert<V>(
    map: &mut HashMap<String, V>,
    key: String,
    value: V,
    now: Instant,
    seen: impl Fn(&V) -> Instant,
) {
    if map.len() >= MAX_SESSIONS && !map.contains_key(&key) {
        map.retain(|_, v| now.duration_since(seen(v)) < SESSION_IDLE);
        if map.len() >= MAX_SESSIONS {
            let oldest = map
                .iter()
                .min_by_key(|(_, v)| seen(v))
                .map(|(k, _)| k.clone());
            if let Some(oldest) = oldest {
                map.remove(&oldest);
            }
        }
    }
    map.insert(key, value);
}

/// How many times the base cooldown a deployment that keeps failing waits at most.
const MAX_BACKOFF: u32 = 16;

/// The name a deployment is remembered and recorded by.
pub(crate) fn label(provider: &str, model: &str) -> String {
    format!("{provider}/{model}")
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // Each update leaves its map whole, so a poisoned lock still holds sound state.
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Held while a request is at a deployment, so `least_busy` sees it. Dropped with the answer's body.
pub(crate) struct Busy {
    count: Arc<AtomicUsize>,
    pool: Option<Arc<Pool>>,
    deployment: String,
    /// The minute it was counted in and the tokens it was counted with, until its answer's own count replaces them.
    minute: i64,
    held: u64,
}

impl Busy {
    /// Replaces the tokens this request was counted with by what its answer used, when the provider said.
    pub(crate) fn settler(&self) -> Option<impl FnOnce(Option<u64>) + Send + Sync + 'static> {
        let pool = self.pool.clone()?;
        let (deployment, minute, held) = (self.deployment.clone(), self.minute, self.held);
        Some(move |used: Option<u64>| {
            if let Some(used) = used {
                pool.settle_tokens(&deployment, minute, held, used);
            }
        })
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::Relaxed);
        if let Some(pool) = &self.pool {
            pool.publish(&self.deployment);
        }
    }
}

/// The wall-clock minute, the window of a deployment's `rpm` and `tpm` on every gateway alike.
pub(crate) fn minute_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| (d.as_secs() / 60) as i64)
}

impl Pool {
    pub(crate) fn new(store: Option<Arc<dyn gantry_core::store::Store>>) -> Self {
        Pool {
            store,
            ..Pool::default()
        }
    }

    /// The order to try `alias`'s deployments in, and why the first was picked: `eligible` holds the positions of
    /// those that can take this request. A half-open deployment is probed first; then a session's pinned deployment,
    /// while it is not cooling down; then the balance picks. The rest follow in the alias's order, and deployments
    /// cooling down go last, so a request still goes somewhere when all have failed lately.
    pub(crate) fn order(
        &self,
        alias: &Alias,
        eligible: &[usize],
        now: Instant,
        ask: &Ask<'_>,
    ) -> (Vec<usize>, String) {
        let shared = self.store.as_ref().map(|store| store.cooling());
        // With a store that shares them, pins and latency come from it, so every gateway routes alike.
        let routing = self.store.as_ref().filter(|store| store.shares_routing());
        let mut deployments = locked(&self.deployments);
        let name_of = |i: usize| {
            alias
                .deployments
                .get(i)
                .map(|d| label(&d.provider, &d.model))
                .unwrap_or_default()
        };
        // One half-open deployment at most is probed by this request, and it is tried first.
        let mut probe = None;
        let mut cooling = |i: &usize| {
            let Some(d) = alias.deployments.get(*i) else {
                return false;
            };
            let name = label(&d.provider, &d.model);
            // Cooling down after a failure on another gateway. Its circuit here is closed, so once that is over
            // it is used as before, not probed: the gateway it failed on probes it.
            if shared
                .as_ref()
                .and_then(|shared| shared.get(&name))
                .is_some_and(|until| *until > now)
            {
                return true;
            }
            let Some(s) = deployments.get_mut(&name) else {
                return false;
            };
            match s.cool_until {
                None => false,
                Some(until) if until > now => true,
                Some(_) => {
                    let free = s.probe_since.is_none_or(|at| now >= at + s.base);
                    if free && probe.is_none() {
                        s.probe_since = Some(now);
                        probe = Some(*i);
                        false
                    } else {
                        true
                    }
                }
            }
        };
        let (warm, cold): (Vec<usize>, Vec<usize>) =
            eligible.iter().copied().partition(|i| !cooling(i));
        // A deployment nearly out of its provider's rate limit goes after those with room, before those cooling.
        let headroom = f64::from(
            alias
                .rate_limit_headroom_percent
                .unwrap_or(HEADROOM_PERCENT),
        ) / 100.0;
        let tight = |i: &usize| {
            deployments
                .get(&name_of(*i))
                .and_then(|s| s.headroom)
                .is_some_and(|(left, at)| left < headroom && now.duration_since(at) < HEADROOM_FOR)
        };
        let (mut warm, full): (Vec<usize>, Vec<usize>) = warm.into_iter().partition(|i| !tight(i));
        let cold: Vec<usize> = full.into_iter().chain(cold).collect();
        if let Some(probe) = probe {
            warm.retain(|i| *i != probe);
            warm.extend(cold);
            warm.insert(0, probe);
            return (
                warm,
                format!("probe: {} is tried again after a failure", name_of(probe)),
            );
        }
        let session = ask
            .session
            .as_ref()
            .filter(|_| alias.session_affinity)
            .map(|s| format!("{}\n{s}", alias.name));
        if let Some(key) = &session {
            let pinned = match routing {
                Some(store) => store.pinned(key, SESSION_IDLE),
                None => locked(&self.sessions)
                    .get(key)
                    .filter(|(_, at)| now.duration_since(*at) < SESSION_IDLE)
                    .map(|(name, _)| name.clone()),
            };
            if let Some(at) = pinned.and_then(|name| warm.iter().position(|i| name_of(*i) == name))
            {
                let picked = warm.remove(at);
                warm.insert(0, picked);
                warm.extend(cold);
                let name = name_of(picked);
                self.pin(key, &name, now);
                return (warm, format!("session: pinned to {name}"));
            }
        }
        let weight = |i: &usize| alias.deployments.get(*i).map_or(0, |d| u64::from(d.weight));
        let (first, why) = match alias.balance {
            Balance::RoundRobin => {
                let total: u64 = warm.iter().map(weight).sum();
                let mut turns = locked(&self.turns);
                let turn = turns.entry(alias.name.clone()).or_default();
                let mut at = *turn % total.max(1);
                *turn = turn.wrapping_add(1);
                let first = warm.iter().position(|i| {
                    if at < weight(i) {
                        return true;
                    }
                    at -= weight(i);
                    false
                });
                (first, "round_robin: its turn by weight".to_string())
            }
            Balance::LeastBusy => {
                let busy = |i: &usize| {
                    deployments
                        .get(&name_of(*i))
                        .map_or(0, |s| s.busy.load(Ordering::Relaxed))
                };
                let first = warm
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, i)| busy(i))
                    .map(|(at, _)| at);
                let n = first.and_then(|at| warm.get(at)).map_or(0, busy);
                (first, format!("least_busy: {n} in flight"))
            }
            Balance::LowestLatency => {
                // A deployment with no answer yet counts as fastest, so each is measured before it is judged.
                let latency = routing.map(|store| store.latency());
                let p90 = |i: &usize| match &latency {
                    Some(latency) => latency.get(&name_of(*i)).copied(),
                    None => deployments
                        .get(&name_of(*i))
                        .and_then(|s| percentile(&s.latency, 90)),
                };
                let first = warm
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, i)| p90(i).unwrap_or(0))
                    .map(|(at, _)| at);
                let why = match first.and_then(|at| warm.get(at)).and_then(p90) {
                    Some(ms) => format!("lowest_latency: p90 time to first byte {ms} ms"),
                    None => "lowest_latency: not measured yet, so tried to measure it".to_string(),
                };
                (first, why)
            }
            Balance::LowestCost => {
                // Unpriced deployments go after every priced one: their cost is unknown, not zero.
                let cost = |i: &usize| ask.cost.get(*i).copied().flatten();
                let first = warm
                    .iter()
                    .enumerate()
                    .min_by(|(_, a), (_, b)| {
                        cost(a)
                            .unwrap_or(f64::INFINITY)
                            .total_cmp(&cost(b).unwrap_or(f64::INFINITY))
                    })
                    .map(|(at, _)| at);
                let why = match first.and_then(|at| warm.get(at)).and_then(cost) {
                    Some(usd) => format!("lowest_cost: ${usd} per million tokens in and out"),
                    None => "lowest_cost: no deployment has a price, so the first".to_string(),
                };
                (first, why)
            }
            Balance::Adaptive => {
                let latency = routing.map(|store| store.latency());
                let p90 = |i: &usize| match &latency {
                    Some(latency) => latency.get(&name_of(*i)).copied(),
                    None => deployments
                        .get(&name_of(*i))
                        .and_then(|s| percentile(&s.latency, 90)),
                };
                let errors = |i: &usize| deployments.get(&name_of(*i)).map_or(0.0, |s| s.errors);
                let cost = |i: &usize| ask.cost.get(*i).copied().flatten();
                let parts: Vec<(f64, f64, Option<f64>)> = warm
                    .iter()
                    .map(|i| (f64::from(p90(i).unwrap_or(0)), errors(i), cost(i)))
                    .collect();
                let (first, why) = adaptive(&alias.weights, &parts);
                (first, why)
            }
        };
        let mut why = why;
        if let Some(first) = first {
            let picked = warm.remove(first);
            warm.insert(0, picked);
        } else if warm.is_empty() {
            why = "every deployment is cooling down after failures: tried in order anyway".into();
        }
        if let (Some(key), Some(first)) = (&session, warm.first()) {
            self.pin(key, &name_of(*first), now);
        }
        warm.extend(cold);
        (warm, why)
    }

    /// Keeps `session` on `deployment` from `now`, on every gateway when the store shares pins.
    fn pin(&self, session: &str, deployment: &str, now: Instant) {
        if let Some(store) = self.store.as_ref().filter(|store| store.shares_routing()) {
            store.pin(session, deployment);
            return;
        }
        bounded_insert(
            &mut locked(&self.sessions),
            session.to_string(),
            (deployment.to_string(), now),
            now,
            |(_, at)| *at,
        );
    }

    /// A deployment answered after `took` (its response headers arrived): one sample of its latency.
    pub(crate) fn observed(&self, deployment: &str, took: Duration) {
        let mut deployments = locked(&self.deployments);
        let samples = &mut deployments
            .entry(deployment.to_string())
            .or_default()
            .latency;
        if samples.len() == LATENCY_SAMPLES {
            samples.pop_front();
        }
        let ms = u32::try_from(took.as_millis()).unwrap_or(u32::MAX);
        samples.push_back(ms);
        drop(deployments);
        if let Some(store) = self.store.as_ref().filter(|store| store.shares_routing()) {
            store.observed(deployment, ms);
        }
    }

    /// Whether `d` can take one more request of about `tokens` tokens now: under its `max_parallel` in flight, and
    /// under its `rpm` and `tpm` this minute, counting what every gateway on the store has. A deployment with none
    /// of them always can.
    // ponytail: the other gateways' load is read from memory, polled every half second, so requests arriving at once
    // on several gateways can pass a limit by a few; a reservation in the store per request if a provider's limit
    // must never be crossed.
    pub(crate) fn has_room(&self, d: &gantry_core::config::Deployment, tokens: u64) -> bool {
        if d.max_parallel.is_none() && d.rpm.is_none() && d.tpm.is_none() {
            return true;
        }
        let label = label(&d.provider, &d.model);
        let now = minute_now();
        let others = self
            .store
            .as_ref()
            .filter(|store| store.shares_routing())
            .and_then(|store| store.deployment_load().get(&label).copied())
            .unwrap_or_default();
        let (mut busy, mut requests, mut used) = (others.in_flight as usize, 0, 0);
        if others.minute == now {
            (requests, used) = (others.requests, others.tokens);
        }
        if let Some(state) = locked(&self.deployments).get(&label) {
            busy += state.busy.load(Ordering::Relaxed);
            if state.minute.0 == now {
                requests += state.minute.1;
                used += state.minute.2;
            }
        }
        d.max_parallel.is_none_or(|max| busy < max as usize)
            && d.rpm.is_none_or(|rpm| requests < rpm)
            && d.tpm.is_none_or(|tpm| used + tokens <= tpm)
    }

    /// Counts a request in flight at a deployment until the returned guard is dropped.
    /// Also counts it, with its estimated `tokens`, in the deployment's minute for `rpm` and `tpm`, until its
    /// answer's count replaces the estimate ([`Busy::settler`]).
    pub(crate) fn busy(self: &Arc<Self>, deployment: &str, tokens: u64) -> Busy {
        let now = minute_now();
        let count = {
            let mut deployments = locked(&self.deployments);
            let state = deployments.entry(deployment.to_string()).or_default();
            state.minute = if state.minute.0 == now {
                (
                    now,
                    state.minute.1.saturating_add(1),
                    state.minute.2.saturating_add(tokens),
                )
            } else {
                (now, 1, tokens)
            };
            let count = state.busy.clone();
            count.fetch_add(1, Ordering::Relaxed);
            count
        };
        self.publish(deployment);
        Busy {
            count,
            pool: Some(self.clone()),
            deployment: deployment.to_string(),
            minute: now,
            held: tokens,
        }
    }

    /// An answer used `used` tokens where `held` were counted: its minute's count takes the difference.
    pub(crate) fn settle_tokens(&self, deployment: &str, minute: i64, held: u64, used: u64) {
        {
            let mut deployments = locked(&self.deployments);
            let Some(state) = deployments.get_mut(deployment) else {
                return;
            };
            if state.minute.0 != minute {
                return;
            }
            state.minute.2 = state.minute.2.saturating_sub(held).saturating_add(used);
        }
        self.publish(deployment);
    }

    /// Hands this gateway's load on `deployment` to the store, for the other gateways' limits.
    fn publish(&self, deployment: &str) {
        let Some(store) = self.store.as_ref().filter(|store| store.shares_routing()) else {
            return;
        };
        let load = locked(&self.deployments).get(deployment).map(|state| {
            gantry_core::store::DeploymentLoad {
                in_flight: u32::try_from(state.busy.load(Ordering::Relaxed)).unwrap_or(u32::MAX),
                minute: state.minute.0,
                requests: state.minute.1,
                tokens: state.minute.2,
            }
        });
        if let Some(load) = load {
            store.publish_load(deployment, load);
        }
    }

    /// A deployment failed (no answer, a 429 or a 5xx): it is passed over for `cooldown`.
    pub(crate) fn failed(&self, deployment: &str, cooldown: Duration) {
        let mut deployments = locked(&self.deployments);
        let state = deployments.entry(deployment.to_string()).or_default();
        state.errors = state.errors * (1.0 - ERROR_STEP) + ERROR_STEP;
        state.failures = state.failures.saturating_add(1);
        state.cooldowns += 1;
        let factor = 1u32
            .checked_shl(state.failures - 1)
            .unwrap_or(MAX_BACKOFF)
            .min(MAX_BACKOFF);
        state.base = cooldown;
        state.cool_until = Some(Instant::now() + cooldown * factor);
        state.probe_since = None;
        if let Some(store) = &self.store {
            store.cooled(deployment, cooldown * factor);
        }
    }

    /// Each deployment seen here (`provider/model`), whether it is cooling down now, and how often it was put to.
    pub(crate) fn health(&self) -> Vec<(String, bool, u64)> {
        let now = Instant::now();
        let mut out: Vec<_> = locked(&self.deployments)
            .iter()
            .map(|(name, d)| {
                (
                    name.clone(),
                    d.cool_until.is_some_and(|t| t > now),
                    d.cooldowns,
                )
            })
            .collect();
        out.sort();
        out
    }

    /// A deployment answered: its circuit closes and its backoff starts over.
    pub(crate) fn answered(&self, deployment: &str) {
        if let Some(state) = locked(&self.deployments).get_mut(deployment) {
            state.cool_until = None;
            state.failures = 0;
            state.probe_since = None;
            state.errors *= 1.0 - ERROR_STEP;
        }
        // Writes only when the deployment is cooling down on the store's list, so a normal answer costs nothing.
        if let Some(store) = &self.store {
            store.warmed(deployment);
        }
    }
}

impl Pool {
    /// Reads a provider's rate-limit headers off an answer of `deployment`: OpenAI's `x-ratelimit-*` and Anthropic's
    /// `anthropic-ratelimit-*`. The smallest share left of any limit it names is what counts.
    pub(crate) fn rate_limits(&self, deployment: &str, headers: &axum::http::HeaderMap) {
        let Some(left) = headroom(headers) else {
            return;
        };
        locked(&self.deployments)
            .entry(deployment.to_string())
            .or_default()
            .headroom = Some((left, Instant::now()));
    }

    /// Which key of `provider`'s pool to send with: in turn by weight, or the least used for its weight, passing over
    /// keys set aside. When every key is set aside, the one back soonest. `None` for a provider without a pool.
    pub(crate) fn key(
        &self,
        provider: &str,
        ids: &[String],
        weights: &[u32],
        least_used: bool,
    ) -> Option<usize> {
        if ids.is_empty() {
            return None;
        }
        let now = Instant::now();
        let weight = |i: usize| weights.get(i).copied().unwrap_or(1).max(1);
        let mut keys = locked(&self.keys);
        let name = |id: &String| format!("{provider}/{id}");
        let out = |k: &Keyed| k.out_until.is_some_and(|until| until > now);
        let ready: Vec<usize> = (0..ids.len())
            .filter(|i| !keys.get(&name(&ids[*i])).is_some_and(out))
            .collect();
        let picked = if ready.is_empty() {
            (0..ids.len()).min_by_key(|i| keys.get(&name(&ids[*i])).and_then(|k| k.out_until))
        } else if least_used {
            // Uses per unit of weight: a key of weight 2 takes twice the requests before it is the least used.
            ready.iter().copied().min_by(|a, b| {
                let per = |i: &usize| {
                    keys.get(&name(&ids[*i])).map_or(0, |k| k.uses) as f64 / f64::from(weight(*i))
                };
                per(a).total_cmp(&per(b))
            })
        } else {
            // In turn over the whole pool by weight (a key of weight 2 holds two turns), from where the last pick
            // left off, so a key set aside hands over to the one after it.
            let slots: Vec<usize> = (0..ids.len())
                .flat_map(|i| std::iter::repeat_n(i, weight(i) as usize))
                .collect();
            let mut turns = locked(&self.turns);
            let turn = turns.entry(format!("key\n{provider}")).or_default();
            let start = usize::try_from(*turn).unwrap_or(0) % slots.len().max(1);
            let at = (0..slots.len())
                .map(|step| (start + step) % slots.len())
                .find(|slot| ready.contains(&slots[*slot]));
            *turn = at.map_or(*turn, |at| at as u64 + 1);
            at.map(|slot| slots[slot])
        }?;
        keys.entry(name(&ids[picked])).or_default().uses += 1;
        Some(picked)
    }

    /// A key of a pool got `status`. A 401 or 403 sets it aside for `quarantine` (an hour unless the provider says),
    /// a 429 for its Retry-After or a minute.
    /// Returns whether another key can be tried now: the request then moves on to it.
    pub(crate) fn key_answered(
        &self,
        provider: &str,
        ids: &[String],
        at: usize,
        status: axum::http::StatusCode,
        retry_after: Option<u64>,
        quarantine: Duration,
    ) -> bool {
        let rest = match status.as_u16() {
            401 | 403 => quarantine,
            429 => retry_after.map_or(KEY_REST, |s| Duration::from_secs(s.min(3600))),
            _ => return false,
        };
        let Some(id) = ids.get(at) else {
            return false;
        };
        let now = Instant::now();
        let mut keys = locked(&self.keys);
        keys.entry(format!("{provider}/{id}"))
            .or_default()
            .out_until = Some(now + rest);
        ids.iter().any(|other| {
            keys.get(&format!("{provider}/{other}"))
                .is_none_or(|k| k.out_until.is_none_or(|until| until <= now))
        })
    }

    /// The store deployments' state is shared through, when there is one.
    pub(crate) fn store(&self) -> Option<&Arc<dyn gantry_core::store::Store>> {
        self.store.as_ref()
    }

    /// A health probe of `deployment` got `outcome`.
    pub(crate) fn probed(&self, deployment: &str, up: bool, outcome: String) {
        locked(&self.probes).insert(
            deployment.to_string(),
            Probed {
                up,
                at: Instant::now(),
                time: gantry_core::audit::timestamp(),
                outcome,
            },
        );
    }

    /// The last probe of each probed deployment, by name.
    pub(crate) fn probes(&self) -> Vec<(String, Probed)> {
        let mut all: Vec<(String, Probed)> = locked(&self.probes)
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        all.sort_by(|a, b| a.0.cmp(&b.0));
        all
    }

    /// Whether `deployment` is due a probe every `every`.
    pub(crate) fn probe_due(&self, deployment: &str, every: Duration) -> bool {
        locked(&self.probes)
            .get(deployment)
            .is_none_or(|p| p.at.elapsed() >= every)
    }
}

/// How far one attempt moves a deployment's error rate.
const ERROR_STEP: f64 = 0.2;

/// The smallest share left of the rate limits a provider's answer names, if it names any.
pub(crate) fn headroom(headers: &axum::http::HeaderMap) -> Option<f64> {
    let number = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<f64>().ok())
    };
    [
        (
            "x-ratelimit-remaining-requests",
            "x-ratelimit-limit-requests",
        ),
        ("x-ratelimit-remaining-tokens", "x-ratelimit-limit-tokens"),
        (
            "anthropic-ratelimit-requests-remaining",
            "anthropic-ratelimit-requests-limit",
        ),
        (
            "anthropic-ratelimit-tokens-remaining",
            "anthropic-ratelimit-tokens-limit",
        ),
        (
            "anthropic-ratelimit-input-tokens-remaining",
            "anthropic-ratelimit-input-tokens-limit",
        ),
        (
            "anthropic-ratelimit-output-tokens-remaining",
            "anthropic-ratelimit-output-tokens-limit",
        ),
    ]
    .iter()
    .filter_map(|(left, limit)| {
        let (left, limit) = (number(left)?, number(limit)?);
        (limit > 0.0).then(|| (left / limit).clamp(0.0, 1.0))
    })
    .min_by(f64::total_cmp)
}

/// The position of the lowest adaptive score among `parts` (p90 latency in ms, error rate, price per million
/// tokens), and why. Latency and cost are scaled to 0..1 against the highest of the candidates; the error rate is
/// one already. A deployment not measured yet counts as fastest, so each is measured; one with no price counts as
/// the dearest, as lowest_cost has it.
pub(crate) fn adaptive(
    weights: &gantry_core::config::Weights,
    parts: &[(f64, f64, Option<f64>)],
) -> (Option<usize>, String) {
    let most = |values: &mut dyn Iterator<Item = f64>| values.fold(0.0, f64::max);
    let slowest = most(&mut parts.iter().map(|p| p.0));
    let dearest = most(&mut parts.iter().filter_map(|p| p.2));
    let scale = |value: f64, top: f64| if top > 0.0 { value / top } else { 0.0 };
    let score = |p: &(f64, f64, Option<f64>)| {
        weights.latency * scale(p.0, slowest)
            + weights.errors * p.1
            + weights.cost * p.2.map_or(1.0, |c| scale(c, dearest))
    };
    let first = parts
        .iter()
        .enumerate()
        .min_by(|a, b| score(a.1).total_cmp(&score(b.1)))
        .map(|(at, _)| at);
    let why = match first.and_then(|at| parts.get(at)) {
        Some(p) => format!(
            "adaptive: score {:.2} (p90 {} ms, errors {:.0}%, {})",
            score(p),
            p.0,
            p.1 * 100.0,
            p.2.map_or_else(
                || "no price".to_string(),
                |c| format!("${c} per million tokens")
            )
        ),
        None => "adaptive: no deployment to score".to_string(),
    };
    (first, why)
}

/// The boundary of a `multipart/form-data` content type. A second boundary parameter is refused: parsers differ on
/// which one they use.
pub(crate) fn boundary(content_type: &str) -> Option<&str> {
    let (kind, params) = content_type.split_once(';')?;
    if !kind.trim().eq_ignore_ascii_case("multipart/form-data") {
        return None;
    }
    let mut found = params.split(';').filter_map(|param| {
        let (name, value) = param.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("boundary")
            .then(|| value.trim().trim_matches('"'))
    });
    let one = found.next().filter(|b| !b.is_empty())?;
    found.next().is_none().then_some(one)
}

/// One field of a form: its name, whether it is a file, and where its value is in the body.
pub(crate) struct Part {
    pub(crate) name: String,
    pub(crate) file: bool,
    pub(crate) value: std::ops::Range<usize>,
}

/// Why a form is refused: anything a standard parser could read differently from Gantry.
const NOT_PLAIN: &str = "a form part's Content-Disposition is not plain (only name=\"...\" and filename=\"...\" without escapes, extended name*= parameters or spaces around =)";

/// The `name` and whether there is a `filename` of a part's Content-Disposition value. QA14-4: parsed with quoted
/// strings, and anything that is not plain is refused rather than read one way of several.
fn disposition(value: &str) -> Result<(String, bool), &'static str> {
    let rest = value.trim_start_matches([' ', '\t']);
    let kind_end = rest.find(';').unwrap_or(rest.len());
    if !rest[..kind_end]
        .trim_end()
        .eq_ignore_ascii_case("form-data")
    {
        return Err("a form part's Content-Disposition is not form-data");
    }
    let mut rest = &rest[kind_end..];
    let (mut name, mut file, mut seen) = (None, false, Vec::new());
    loop {
        rest = rest.trim_start_matches([' ', '\t']);
        if rest.is_empty() {
            break;
        }
        rest = rest.strip_prefix(';').ok_or(NOT_PLAIN)?;
        rest = rest.trim_start_matches([' ', '\t']);
        let eq = rest.find('=').ok_or(NOT_PLAIN)?;
        let key = rest[..eq].to_ascii_lowercase();
        if key.is_empty()
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(NOT_PLAIN);
        }
        rest = &rest[eq + 1..];
        let value = if let Some(quoted) = rest.strip_prefix('"') {
            let end = quoted.find('"').ok_or(NOT_PLAIN)?;
            rest = &quoted[end + 1..];
            &quoted[..end]
        } else {
            let end = rest.find([';', ' ', '\t']).unwrap_or(rest.len());
            let token = &rest[..end];
            rest = &rest[end..];
            if token.is_empty() || token.contains(['\'', '"']) {
                return Err(NOT_PLAIN);
            }
            token
        };
        if value.contains('\\') || seen.contains(&key) {
            return Err(NOT_PLAIN);
        }
        match key.as_str() {
            "name" => name = Some(value.to_string()),
            "filename" => file = true,
            _ => {}
        }
        seen.push(key);
    }
    Ok((name.ok_or("a form part has no name")?, file))
}

/// Every field of a `multipart/form-data` body, parsed strictly: the body starts with its delimiter, every other
/// delimiter starts a line and is followed by a line end or the closing `--`, each part has one plain
/// Content-Disposition, and nothing follows the closing delimiter but a line end.
pub(crate) fn form_parts(content_type: &str, body: &[u8]) -> Result<Vec<Part>, &'static str> {
    let boundary =
        boundary(content_type).ok_or("the body is not multipart/form-data with one boundary")?;
    let open = format!("--{boundary}");
    let inner = format!("\r\n--{boundary}");
    let find = |from: usize, needle: &[u8]| {
        body.get(from..)?
            .windows(needle.len())
            .position(|w| w == needle)
            .map(|p| p + from)
    };
    if !body.starts_with(open.as_bytes()) {
        return Err("the form does not start with its boundary");
    }
    let mut at = open.len();
    let mut parts = Vec::new();
    loop {
        let rest = &body[at..];
        if let Some(after) = rest.strip_prefix(b"--") {
            if !matches!(after, b"" | b"\r\n") {
                return Err("the form has bytes after its closing boundary");
            }
            return Ok(parts);
        }
        if !rest.starts_with(b"\r\n") {
            return Err("a form boundary is followed by something other than a line end");
        }
        let headers_end = find(at, b"\r\n\r\n").ok_or("a form part has no end to its headers")?;
        let headers = std::str::from_utf8(body.get(at + 2..headers_end).unwrap_or_default())
            .map_err(|_| "a form part's headers are not UTF-8")?;
        let mut named = None;
        for line in headers.split("\r\n") {
            let (header, value) = line
                .split_once(':')
                .ok_or("a form part has a header line without a colon")?;
            // A folded line, or a name with spaces, is read differently by different parsers.
            if header.is_empty() || header.trim() != header {
                return Err("a form part has a folded or spaced header line");
            }
            if header.eq_ignore_ascii_case("content-disposition")
                && named.replace(disposition(value)?).is_some()
            {
                return Err("a form part has two Content-Disposition headers");
            }
        }
        let (name, file) = named.ok_or("a form part has no Content-Disposition")?;
        let value_start = headers_end + 4;
        let next = find(value_start, inner.as_bytes()).ok_or("a form part does not end")?;
        parts.push(Part {
            name,
            file,
            value: value_start..next,
        });
        at = next + inner.len();
    }
}

/// The byte range of the value of the one form field named `model`, or why there is none. Two fields named `model`
/// are refused: the policy would check one and the provider could read the other.
pub(crate) fn multipart_model(
    content_type: &str,
    body: &[u8],
) -> Result<std::ops::Range<usize>, &'static str> {
    let mut models = form_parts(content_type, body)?
        .into_iter()
        .filter(|p| p.name == "model");
    let model = models.next().ok_or("the form has no model field")?;
    if models.next().is_some() {
        return Err("the form names model twice");
    }
    if model.file {
        return Err("the model field is a file");
    }
    Ok(model.value)
}

/// The body with its model replaced by `model`: a JSON body's `model` key, or a form's `model` field. A body that
/// is neither is sent as it is.
pub(crate) fn with_model(content_type: Option<&str>, body: &Bytes, model: &str) -> Bytes {
    if let Some(range) = content_type.and_then(|ct| multipart_model(ct, body).ok()) {
        let mut out = Vec::with_capacity(body.len() + model.len());
        out.extend_from_slice(&body[..range.start]);
        out.extend_from_slice(model.as_bytes());
        out.extend_from_slice(&body[range.end..]);
        return Bytes::from(out);
    }
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(serde_json::Value::Object(mut map)) if map.contains_key("model") => {
            map.insert("model".into(), model.into());
            serde_json::to_vec(&map).map_or_else(|_| body.clone(), Bytes::from)
        }
        _ => body.clone(),
    }
}

/// Why the provider refused a request, as far as a named fallback goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    ContextWindow,
    ContentPolicy,
}

/// Reads a provider's error answer for the two refusals a named fallback can take. OpenAI and Azure name them in
/// `error.code`; Anthropic says "prompt is too long" in an invalid_request_error.
pub(crate) fn refused(body: &[u8]) -> Option<Refused> {
    let answer: serde_json::Value = serde_json::from_slice(body).ok()?;
    let error = &answer["error"];
    let code = error["code"].as_str().unwrap_or_default();
    let kind = error["type"].as_str().unwrap_or_default();
    let message = error["message"]
        .as_str()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if code == "context_length_exceeded"
        || message.contains("maximum context length")
        || message.contains("prompt is too long")
        || message.contains("context window")
    {
        return Some(Refused::ContextWindow);
    }
    if matches!(code, "content_policy_violation" | "content_filter")
        || kind == "content_policy_violation"
        || message.contains("content management policy")
    {
        return Some(Refused::ContentPolicy);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use gantry_core::config::Deployment;

    fn alias(balance: Balance, weights: &[u32]) -> Alias {
        Alias {
            name: "smart".into(),
            deployments: weights
                .iter()
                .enumerate()
                .map(|(i, w)| Deployment {
                    provider: format!("p{i}"),
                    model: "m".into(),
                    weight: *w,
                    ..Deployment::default()
                })
                .collect(),
            balance,
            cooldown_seconds: 30,
            ..Alias::default()
        }
    }

    fn order(pool: &Pool, alias: &Alias, eligible: &[usize], now: Instant) -> Vec<usize> {
        pool.order(alias, eligible, now, &Ask::default()).0
    }

    #[test]
    fn lowest_latency_measures_each_deployment_then_picks_the_fastest_by_its_p90() {
        let pool = Pool::default();
        let smart = alias(Balance::LowestLatency, &[1, 1]);
        let (first, why) = pool.order(&smart, &[0, 1], Instant::now(), &Ask::default());
        assert!(why.contains("not measured yet"), "{why}");
        assert_eq!(first[0], 0);
        for _ in 0..20 {
            pool.observed("p0/m", Duration::from_millis(300));
            pool.observed("p1/m", Duration::from_millis(120));
        }
        // One slow answer is under the 90th percentile and does not move it.
        pool.observed("p1/m", Duration::from_secs(5));
        let (first, why) = pool.order(&smart, &[0, 1], Instant::now(), &Ask::default());
        assert_eq!(first[0], 1, "{why}");
        assert!(why.contains("p90 time to first byte 120 ms"), "{why}");
        // A deployment that slows down for long enough loses its place.
        for _ in 0..LATENCY_SAMPLES {
            pool.observed("p1/m", Duration::from_millis(900));
        }
        assert_eq!(order(&pool, &smart, &[0, 1], Instant::now())[0], 0);
    }

    #[test]
    fn lowest_cost_picks_the_cheapest_priced_deployment_and_leaves_unpriced_ones_last() {
        let pool = Pool::default();
        let smart = alias(Balance::LowestCost, &[1, 1, 1]);
        let cost = [None, Some(15.0), Some(0.75)];
        let ask = Ask {
            cost: &cost,
            ..Ask::default()
        };
        let (first, why) = pool.order(&smart, &[0, 1, 2], Instant::now(), &ask);
        assert_eq!(first[0], 2);
        assert!(why.contains("$0.75"), "{why}");
        // The cheapest is cooling down: the next cheapest priced one, never the unpriced one.
        pool.failed("p2/m", Duration::from_secs(30));
        assert_eq!(pool.order(&smart, &[0, 1, 2], Instant::now(), &ask).0[0], 1);
    }

    #[test]
    fn a_session_stays_on_its_deployment_while_it_is_healthy_and_moves_when_it_fails() {
        let pool = Pool::default();
        let mut smart = alias(Balance::RoundRobin, &[1, 1, 1]);
        smart.session_affinity = true;
        let ask = |s: &str| Ask {
            session: Some(s.into()),
            ..Ask::default()
        };
        let (first, _) = pool.order(&smart, &[0, 1, 2], Instant::now(), &ask("maya\ns1"));
        let pinned = first[0];
        for _ in 0..5 {
            let (again, why) = pool.order(&smart, &[0, 1, 2], Instant::now(), &ask("maya\ns1"));
            assert_eq!(again[0], pinned, "{why}");
            assert!(why.starts_with("session: pinned"), "{why}");
        }
        // Another session is balanced as usual (round robin moves on).
        let other = pool
            .order(&smart, &[0, 1, 2], Instant::now(), &ask("maya\ns2"))
            .0[0];
        assert_ne!(other, pinned);
        // The pinned deployment fails: the session moves, and stays where it moved.
        pool.failed(&format!("p{pinned}/m"), Duration::from_secs(30));
        let moved = pool
            .order(&smart, &[0, 1, 2], Instant::now(), &ask("maya\ns1"))
            .0[0];
        assert_ne!(moved, pinned);
        assert_eq!(
            pool.order(&smart, &[0, 1, 2], Instant::now(), &ask("maya\ns1"))
                .0[0],
            moved
        );
        // Without affinity on the alias, the session header changes nothing.
        smart.session_affinity = false;
        let (_, why) = pool.order(&smart, &[0, 1, 2], Instant::now(), &ask("maya\ns1"));
        assert!(why.starts_with("round_robin"), "{why}");
    }

    #[test]
    fn round_robin_follows_the_weights_and_skips_a_cooling_deployment() {
        let pool = Pool::default();
        let smart = alias(Balance::RoundRobin, &[2, 1]);
        let now = Instant::now();
        let firsts: Vec<usize> = (0..6)
            .map(|_| order(&pool, &smart, &[0, 1], now)[0])
            .collect();
        assert_eq!(firsts, [0, 0, 1, 0, 0, 1]);
        pool.failed("p0/m", Duration::from_secs(30));
        assert_eq!(order(&pool, &smart, &[0, 1], Instant::now()), [1, 0]);
        pool.answered("p0/m");
        assert_eq!(order(&pool, &smart, &[0, 1], Instant::now()).len(), 2);
    }

    #[test]
    fn a_deployment_that_keeps_failing_waits_longer_and_comes_back_through_one_probe() {
        let pool = Pool::default();
        let smart = alias(Balance::RoundRobin, &[1, 1, 1]);
        let base = Duration::from_secs(10);
        let start = Instant::now();
        pool.failed("p0/m", base);
        let cold = |at: Instant| order(&pool, &smart, &[0, 1, 2], at).last().copied();
        assert_eq!(
            cold(start + Duration::from_secs(5)),
            Some(0),
            "open: tried last"
        );
        // Half open: once the cooldown is over, one request probes it first; the others still pass it over.
        let probe = order(&pool, &smart, &[0, 1, 2], start + Duration::from_secs(11));
        assert_eq!(
            probe[0], 0,
            "the probe goes to the recovering deployment first"
        );
        for _ in 0..3 {
            assert_eq!(
                cold(start + Duration::from_secs(11)),
                Some(0),
                "while one probe is out, others pass it over"
            );
        }
        // The probe failed: open again, for twice as long.
        pool.failed("p0/m", base);
        let again = Instant::now();
        assert_eq!(
            cold(again + Duration::from_secs(15)),
            Some(0),
            "the second cooldown is 20 seconds"
        );
        assert_eq!(
            order(&pool, &smart, &[0, 1, 2], again + Duration::from_secs(21))[0],
            0,
            "then one probe"
        );
        for _ in 0..10 {
            pool.failed("p0/m", base);
        }
        let capped = Instant::now();
        assert_eq!(
            order(&pool, &smart, &[0, 1, 2], capped + Duration::from_secs(161))[0],
            0,
            "capped at 16 times the base"
        );
        // The probe answered: closed, in turn with the others again.
        pool.answered("p0/m");
        let firsts: Vec<usize> = (0..3)
            .map(|_| order(&pool, &smart, &[0, 1, 2], Instant::now())[0])
            .collect();
        assert!(
            firsts.contains(&0) && firsts.contains(&1) && firsts.contains(&2),
            "{firsts:?}"
        );
        pool.failed("p0/m", base);
        assert_eq!(cold(Instant::now() + Duration::from_secs(5)), Some(0));
        assert!(
            order(
                &pool,
                &smart,
                &[0, 1, 2],
                Instant::now() + Duration::from_secs(11)
            )[0] == 0,
            "after a success the backoff starts over"
        );
    }

    #[test]
    fn a_probe_that_never_reports_back_does_not_shut_the_deployment_out() {
        let pool = Pool::default();
        let smart = alias(Balance::RoundRobin, &[1, 1]);
        let base = Duration::from_secs(10);
        pool.failed("p0/m", base);
        let after = Instant::now() + Duration::from_secs(11);
        assert_eq!(order(&pool, &smart, &[0, 1], after)[0], 0);
        // That request went elsewhere or was dropped: after another base cooldown a new probe is let through.
        assert_eq!(
            order(&pool, &smart, &[0, 1], after + Duration::from_secs(11))[0],
            0
        );
    }

    #[test]
    fn adaptive_weighs_latency_errors_and_cost_and_remembers_errors_after_the_circuit_closes() {
        let weights = gantry_core::config::Weights::default();
        // Fast and cheap wins; then, with cost weighed out, the fast one even when dear.
        let (first, why) = adaptive(
            &weights,
            &[(400.0, 0.0, Some(10.0)), (100.0, 0.0, Some(1.0))],
        );
        assert_eq!(first, Some(1), "{why}");
        let latency_only = gantry_core::config::Weights {
            latency: 1.0,
            errors: 0.0,
            cost: 0.0,
        };
        assert_eq!(
            adaptive(
                &latency_only,
                &[(400.0, 0.0, Some(1.0)), (100.0, 0.0, Some(10.0))]
            )
            .0,
            Some(1)
        );
        // An unpriced deployment counts as the dearest, never as free.
        assert_eq!(
            adaptive(
                &weights,
                &[
                    (100.0, 0.0, None),
                    (100.0, 0.0, Some(5.0)),
                    (100.0, 0.0, Some(1.0))
                ]
            )
            .0,
            Some(2)
        );
        let pool = Pool::default();
        let smart = alias(Balance::Adaptive, &[1, 1]);
        for _ in 0..3 {
            pool.failed("p0/m", Duration::from_secs(30));
        }
        pool.answered("p0/m");
        let (order, why) = pool.order(&smart, &[0, 1], Instant::now(), &Ask::default());
        assert_eq!(
            order[0], 1,
            "its circuit is closed, and its error rate still counts: {why}"
        );
        assert!(why.starts_with("adaptive: score"), "{why}");
    }

    #[test]
    fn key_pools_rotate_or_take_the_least_used_and_set_keys_aside() {
        use axum::http::StatusCode;
        const HOUR: Duration = Duration::from_secs(3600);
        let pool = Pool::default();
        let ids: Vec<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
        let picks: Vec<Option<usize>> = (0..4).map(|_| pool.key("p", &ids, &[], false)).collect();
        assert_eq!(picks, [Some(0), Some(1), Some(2), Some(0)]);
        // b is refused: set aside, and another key can be tried.
        assert!(pool.key_answered("p", &ids, 1, StatusCode::UNAUTHORIZED, None, HOUR));
        let picks: Vec<Option<usize>> = (0..3).map(|_| pool.key("p", &ids, &[], false)).collect();
        assert!(!picks.contains(&Some(1)), "{picks:?}");
        // A 500 is the provider's failure, not the key's.
        assert!(!pool.key_answered("p", &ids, 0, StatusCode::INTERNAL_SERVER_ERROR, None, HOUR));
        // With every key aside, the one back soonest is used rather than none.
        assert!(pool.key_answered("p", &ids, 0, StatusCode::TOO_MANY_REQUESTS, Some(5), HOUR));
        assert!(!pool.key_answered("p", &ids, 2, StatusCode::TOO_MANY_REQUESTS, Some(60), HOUR));
        assert_eq!(pool.key("p", &ids, &[], false), Some(0));
        let least = Pool::default();
        least.key("q", &ids, &[], true);
        least.key("q", &ids, &[], true);
        assert_eq!(least.key("q", &ids, &[], true), Some(2));
        assert_eq!(pool.key("p", &[], &[], false), None);
        // Weights: a key of weight 3 takes three turns to one's one, and three times the uses before least used.
        let weighted = Pool::default();
        let two = &ids[..2];
        let picks: Vec<Option<usize>> = (0..8)
            .map(|_| weighted.key("w", two, &[1, 3], false))
            .collect();
        assert_eq!(
            picks.iter().filter(|p| **p == Some(1)).count(),
            6,
            "{picks:?}"
        );
        let least = Pool::default();
        let picks: Vec<Option<usize>> =
            (0..8).map(|_| least.key("l", two, &[1, 3], true)).collect();
        assert_eq!(
            picks.iter().filter(|p| **p == Some(1)).count(),
            6,
            "{picks:?}"
        );
        // The quarantine is the provider's setting: a short one is over when it says.
        let short = Pool::default();
        short.key_answered(
            "s",
            two,
            0,
            StatusCode::UNAUTHORIZED,
            None,
            Duration::from_millis(1),
        );
        std::thread::sleep(Duration::from_millis(5));
        let picks: Vec<Option<usize>> = (0..2).map(|_| short.key("s", two, &[], false)).collect();
        assert!(picks.contains(&Some(0)), "{picks:?}");
    }

    #[test]
    fn a_deployment_at_its_max_parallel_rpm_or_tpm_has_no_room() {
        let pool = Arc::new(Pool::default());
        let d = |max_parallel, rpm, tpm| gantry_core::config::Deployment {
            provider: "p".into(),
            model: "m".into(),
            max_parallel,
            rpm,
            tpm,
            ..Default::default()
        };
        assert!(pool.has_room(&d(Some(1), None, None), 10));
        let held = pool.busy("p/m", 10);
        assert!(
            !pool.has_room(&d(Some(1), None, None), 10),
            "one in flight of one"
        );
        assert!(pool.has_room(&d(Some(2), None, None), 10));
        drop(held);
        assert!(
            pool.has_room(&d(Some(1), None, None), 10),
            "back once it answered"
        );
        // Two sent this minute, 20 tokens: an rpm of 2 is full, a tpm of 25 has no room for 10 more, of 30 has.
        drop(pool.busy("p/m", 10));
        assert!(!pool.has_room(&d(None, Some(2), None), 10));
        assert!(pool.has_room(&d(None, Some(3), None), 10));
        assert!(!pool.has_room(&d(None, None, Some(25)), 10));
        assert!(pool.has_room(&d(None, None, Some(30)), 10));
    }

    #[test]
    fn a_settled_answer_replaces_its_estimate_in_the_tpm() {
        let pool = Arc::new(Pool::default());
        let d = gantry_core::config::Deployment {
            provider: "p".into(),
            model: "m".into(),
            tpm: Some(100),
            ..Default::default()
        };
        let held = pool.busy("p/m", 90);
        assert!(!pool.has_room(&d, 20), "90 held of 100");
        if let Some(settle) = held.settler() {
            settle(Some(5));
        }
        assert!(pool.has_room(&d, 20), "5 used of 100");
        if let Some(settle) = held.settler() {
            settle(None);
        }
        assert!(
            pool.has_room(&d, 20),
            "no count from the provider keeps what was counted"
        );
    }

    #[test]
    fn rate_limit_headers_give_the_smallest_share_left() {
        let mut headers = axum::http::HeaderMap::new();
        assert_eq!(headroom(&headers), None);
        headers.insert(
            "x-ratelimit-remaining-requests",
            "50".parse()
                .unwrap_or_else(|_| axum::http::HeaderValue::from_static("0")),
        );
        headers.insert(
            "x-ratelimit-limit-requests",
            axum::http::HeaderValue::from_static("100"),
        );
        headers.insert(
            "x-ratelimit-remaining-tokens",
            axum::http::HeaderValue::from_static("1000"),
        );
        headers.insert(
            "x-ratelimit-limit-tokens",
            axum::http::HeaderValue::from_static("100000"),
        );
        assert_eq!(headroom(&headers), Some(0.01));
    }

    #[test]
    fn least_busy_picks_the_deployment_with_fewest_in_flight() {
        let pool = Arc::new(Pool::default());
        let smart = alias(Balance::LeastBusy, &[1, 1]);
        let held = pool.busy("p0/m", 0);
        assert_eq!(order(&pool, &smart, &[0, 1], Instant::now())[0], 1);
        drop(held);
        let _other = pool.busy("p1/m", 0);
        assert_eq!(order(&pool, &smart, &[0, 1], Instant::now())[0], 0);
    }

    #[test]
    fn the_model_field_of_a_form_is_found_once_and_replaced() {
        let ct = "multipart/form-data; boundary=XyZ";
        let body = b"--XyZ\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.wav\"\r\nContent-Type: audio/wav\r\n\r\nRIFF\x00\x01model\r\n--XyZ\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nwhisper\r\n--XyZ--\r\n";
        let range = multipart_model(ct, body);
        assert_eq!(range.clone().map(|r| &body[r]), Ok(&b"whisper"[..]));
        let swapped = with_model(Some(ct), &Bytes::from_static(body), "whisper-1");
        assert!(swapped.windows(14).any(|w| w == b"\r\n\r\nwhisper-1\r"));
        let twice = b"--b\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\na\r\n--b\r\nContent-Disposition: form-data; name=model\r\n\r\nb\r\n--b--\r\n";
        assert!(multipart_model("multipart/form-data; boundary=b", twice).is_err());
        assert!(multipart_model("application/json", body).is_err());
    }

    #[test]
    fn context_window_and_content_policy_refusals_are_told_apart() {
        assert_eq!(
            refused(br#"{"error":{"code":"context_length_exceeded","message":"x"}}"#),
            Some(Refused::ContextWindow)
        );
        assert_eq!(
            refused(br#"{"type":"error","error":{"type":"invalid_request_error","message":"prompt is too long: 300000 tokens > 200000 maximum"}}"#),
            Some(Refused::ContextWindow)
        );
        assert_eq!(
            refused(br#"{"error":{"code":"content_filter","message":"x"}}"#),
            Some(Refused::ContentPolicy)
        );
        assert_eq!(refused(br#"{"error":{"code":"invalid_api_key"}}"#), None);
    }
}
