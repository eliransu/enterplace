//! Spend, budgets, rate limits and the answer cache: what a rule limits besides the models.
//!
//! Budgets follow one rule: a request is admitted only if what is spent, plus what requests in flight have reserved,
//! plus the most this request could cost, fits the budget. When its answer ends its reservation is replaced by what it
//! cost, read from the provider's answer and written to the audit log as a `usage` record. At start, the usage records
//! of the current period are summed from the log, so spend survives a restart.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    io::BufRead,
    path::Path,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use axum::{
    body::{Body, Bytes},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use gantry_core::{
    audit::{self, AuditLog},
    id::sha256,
    policy::{Applied, Budget, CacheScope, Limit, Period, Policy, Principal, Rule, applied_json},
    store::{Bucket as Counter, Change, LEASE, Lease, Reserve, Store},
    usage::{Price, PriceOverrides, Usage, UsageScanner, price_for},
};
use http_body::{Body as _, Frame};
use serde_json::{Map, Value};

use crate::Refusal;

/// Output tokens assumed, for the charge only, when a request without a budget is cut off and neither it nor its
/// model's price says how many it could have had. A budgeted request in that case is refused instead.
const UNBUDGETED_OUTPUT_GUESS: u64 = 4096;

/// Most bytes of answers the cache holds, across every rule.
// ponytail: one fixed size per process. A `cache_bytes` setting comes when someone needs another size.
pub const CACHE_BYTES: usize = 64 * 1024 * 1024;

/// Most bytes of a whole (not streamed) answer kept to read its usage and to cache it. A larger answer is passed on
/// whole and its usage is recorded as not read.
const MAX_ANSWER_COPY: usize = 32 * 1024 * 1024;

/// The state behind budgets, rate limits and the cache. One per server, kept across reloads.
#[derive(Default)]
pub(crate) struct Spend {
    ledger: Mutex<HashMap<(String, Period), Bucket>>,
    // Times of each person's admitted requests within the last minute.
    rates: Mutex<HashMap<String, VecDeque<Instant>>>,
    // Tokens used within the last minute, and held by requests in flight, per team, person or key.
    tokens: Mutex<HashMap<String, Tokens>>,
    // ponytail: the cache stays per process even with a store. Answers are never written to the database (slice 7),
    // and a hit from memory takes microseconds where one from Postgres would take a round trip.
    cache: Mutex<Cache>,
    /// The semantic cache's embeddings, each pointing at an answer in `cache`. Kept in memory for the same reason.
    vectors: Mutex<Vectors>,
    /// With a store: this gateway's lease on each rate-limit scope. One lease asked for at a time per scope, so a
    /// burst waits for it instead of leasing the whole limit in pieces.
    leases: Mutex<HashMap<String, Arc<tokio::sync::Mutex<Leased>>>>,
    pub(crate) metrics: Arc<crate::metrics::Metrics>,
    /// Shared with other gateways when the policy has `store:`: budgets are then reserved and settled there, and
    /// the ledger above only counts for this process.
    pub(crate) store: Option<Arc<dyn Store>>,
    /// Requests in flight per scope with a `parallel:` limit, without a store.
    parallel: Mutex<HashMap<String, u32>>,
    /// With a store: this gateway's holds on `parallel:` limits, by ID, with the hour's counter each is in now.
    holds: Mutex<HashMap<u64, (String, String)>>,
    next_hold: std::sync::atomic::AtomicU64,
    /// Where the redacted bodies of rules with `capture:` are kept. `None` when no master key seals them.
    pub(crate) bodies: Option<Arc<dyn gantry_core::insights::Bodies>>,
    /// Takes the text of requests an embedding binary keeps (`Extension::capture`).
    pub(crate) capture: Option<Arc<dyn crate::Capture>>,
}

/// A request's place under one `parallel:` limit, given back when its answer ends.
pub(crate) struct Hold {
    scope: String,
    /// With a store: the ID of the hold in `Spend::holds`.
    id: Option<u64>,
}

/// What a limit's refusal says allows it: `rule "payments-team"`, `its key's entry`, or where the policy sets it.
fn allows(applied: &Applied, rule: &Rule) -> String {
    match applied.of {
        "rule" => format!("rule \"{}\"", rule.name),
        "key" => "its key's entry".to_string(),
        _ => applied.source.clone(),
    }
}

/// The fields a refusal by a limit adds to its decision record: `limit` as the console reads it for rpm and tpm,
/// and `applied`, naming the scope, the counter and where the limit is written.
fn limit_record(applied: &Applied, legacy: Value) -> Value {
    let mut fields = Map::new();
    if !legacy.is_null() {
        fields.insert("limit".into(), legacy);
    }
    fields.insert("applied".into(), applied_json(applied));
    Value::Object(fields)
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // Every update below leaves its map whole, so a poisoned lock still holds sound numbers.
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Tokens a scope used in the last minute, each with when its request ended, and what requests in flight hold.
#[derive(Default)]
struct Tokens {
    used: VecDeque<(Instant, u64)>,
    reserved: u64,
}

/// What is left of a lease on a rate limit, and until when it may be spent.
#[derive(Default)]
struct Leased {
    grant: i64,
    left: u64,
    until: Option<Instant>,
}

/// A lease is this part of the limit, or what the request needs if more: a gateway leases about once every three
/// seconds of traffic at the limit's pace, and holds at most a twentieth of it unused for a lease's second.
const LEASE_PARTS: u64 = 20;

/// Why a request was not given what it needs from a shared rate limit.
enum Short {
    /// Seconds until it could fit.
    Over(u64),
    /// The store cannot be reached.
    Down(String),
}

/// What one team or person has spent and reserved in the current day or month.
#[derive(Default)]
struct Bucket {
    /// `2026-11` for a month, `2026-11-13` for a day, UTC.
    period: String,
    spent: f64,
    reserved: f64,
}

/// The period a timestamp (`2026-11-13T09:14:02.120Z`) falls in.
fn period_of(time: &str, per: Period) -> String {
    per.label(time)
}

/// When a period ends, as `2026-12-01 00:00 UTC`.
fn resets(period: &str, per: Period) -> String {
    per.resets(period)
}

/// Dollars as a person reads them: cents, or four places for amounts under a dollar.
fn dollars(usd: f64) -> String {
    if usd >= 1.0 {
        format!("${usd:.2}")
    } else {
        format!("${usd:.4}")
    }
}

/// What a request set aside against its budget when it was admitted.
pub(crate) struct Reservation {
    scope: String,
    per: Period,
    period: String,
    usd: f64,
}

impl Reservation {
    fn bucket(&self) -> Counter {
        Counter {
            scope: self.scope.clone(),
            per: self.per,
            period: self.period.clone(),
        }
    }
}

/// The buckets a cost counts in: its person, team and key, for the day and the month of `time`, and every other
/// budget counter the request counted against (`counted`), each once.
fn buckets(
    person: &str,
    team: &str,
    key: &str,
    counted: &[(String, Period)],
    time: &str,
) -> Vec<Counter> {
    let mut scopes = vec![person.to_string(), team.to_string()];
    // Records written before keys were named in usage records have no key: they count for person and team only.
    if !key.is_empty() {
        scopes.push(format!("key:{key}"));
    }
    let mut pairs: Vec<(String, Period)> = Vec::with_capacity(scopes.len() * 2 + counted.len());
    for scope in scopes {
        for per in [Period::Day, Period::Month] {
            pairs.push((scope.clone(), per));
        }
    }
    for pair in counted {
        if !pairs.contains(pair) {
            pairs.push(pair.clone());
        }
    }
    pairs
        .into_iter()
        .map(|(scope, per)| Counter {
            period: period_of(time, per),
            scope,
            per,
        })
        .collect()
}

/// The store cannot be asked for a reservation: the request is refused, never let through unchecked.
fn store_unavailable(err: &str) -> Refusal {
    Refusal::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "store_unavailable",
        format!(
            "Refused: a budget applies to this request, and Gantry cannot reach its store to reserve what it could cost ({err}). Requests under a budget are refused until the store is back; requests without one still work. Tell your Gantry admin to check the Postgres database the policy's store: names."
        ),
    )
}

/// The store cannot be asked for a rate-limit lease: refused as a budget is, since the gateways could otherwise
/// admit the limit each.
fn rate_store_unavailable(err: &str) -> Refusal {
    Refusal::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "store_unavailable",
        format!(
            "Refused: a rate limit applies to this request, and Gantry cannot reach its store to count it against the limit every replica shares ({err}). Requests under rpm or tpm are refused until the store is back; requests without one still work. Tell your Gantry admin to check the Postgres database the policy's store: names."
        ),
    )
}

/// The budget would be passed: what the refusal tells the caller.
struct Over {
    spent: f64,
    reserved: f64,
    resets: String,
}

impl Spend {
    /// The bucket of `scope` for `period`, started afresh when the period has turned. None for a period already over.
    fn bucket<'a>(
        ledger: &'a mut HashMap<(String, Period), Bucket>,
        scope: &str,
        per: Period,
        period: &str,
    ) -> Option<&'a mut Bucket> {
        let bucket = ledger.entry((scope.to_string(), per)).or_default();
        if bucket.period.as_str() < period {
            *bucket = Bucket {
                period: period.to_string(),
                ..Bucket::default()
            };
        }
        (bucket.period == period).then_some(bucket)
    }

    fn reserve(
        &self,
        scope: &str,
        budget: Budget,
        usd: f64,
        now: &str,
    ) -> Result<Reservation, Over> {
        let period = period_of(now, budget.per);
        let period = period.as_str();
        let mut ledger = locked(&self.ledger);
        let Some(bucket) = Self::bucket(&mut ledger, scope, budget.per, period) else {
            // The clock went back past a period boundary. Counting nothing would let spend through unchecked.
            return Err(Over {
                spent: 0.0,
                reserved: 0.0,
                resets: resets(period, budget.per),
            });
        };
        if bucket.spent + bucket.reserved + usd > budget.usd {
            return Err(Over {
                spent: bucket.spent,
                reserved: bucket.reserved,
                resets: resets(period, budget.per),
            });
        }
        bucket.reserved += usd;
        Ok(Reservation {
            scope: scope.to_string(),
            per: budget.per,
            period: period.to_string(),
            usd,
        })
    }

    /// `reserve`, in the store when there is one. The outer `Err` is a refusal; inside it, `Err` names why the
    /// store could not be asked.
    async fn reserve_shared(
        &self,
        scope: &str,
        budget: Budget,
        usd: f64,
        now: &str,
    ) -> Result<Reservation, Result<Over, String>> {
        let Some(store) = &self.store else {
            return self.reserve(scope, budget, usd, now).map_err(Ok);
        };
        let period = period_of(now, budget.per);
        let bucket = Counter {
            scope: scope.to_string(),
            per: budget.per,
            period: period.clone(),
        };
        match store.reserve(bucket, usd, budget.usd).await {
            Ok(Reserve::Done) => Ok(Reservation {
                scope: scope.to_string(),
                per: budget.per,
                period,
                usd,
            }),
            Ok(Reserve::Over { spent, reserved }) => Err(Ok(Over {
                spent,
                reserved,
                resets: resets(&period, budget.per),
            })),
            Err(err) => Err(Err(err)),
        }
    }

    fn release(&self, reservation: &Reservation) {
        if let Some(store) = &self.store {
            store.settle(vec![Change {
                bucket: reservation.bucket(),
                spent: 0.0,
                reserved: -reservation.usd,
            }]);
            return;
        }
        let mut ledger = locked(&self.ledger);
        if let Some(bucket) = ledger.get_mut(&(reservation.scope.clone(), reservation.per)) {
            if bucket.period == reservation.period {
                bucket.reserved = (bucket.reserved - reservation.usd).max(0.0);
            }
        }
    }

    /// Counts what a request cost against its person, its team and its key, for the day and the month of `time`,
    /// and every other budget counter it counted against.
    fn add(
        &self,
        person: &str,
        team: &str,
        key: &str,
        counted: &[(String, Period)],
        usd: f64,
        time: &str,
    ) {
        if usd <= 0.0 || !usd.is_finite() {
            return;
        }
        let mut ledger = locked(&self.ledger);
        for b in buckets(person, team, key, counted, time) {
            if let Some(bucket) = Self::bucket(&mut ledger, &b.scope, b.per, &b.period) {
                bucket.spent += usd;
            }
        }
    }

    /// Sums the usage records of the current month from the audit log, so a restart does not forget spend.
    // ponytail: reads the whole log at start, as the chain check before it does. A checkpoint comes with that one.
    pub(crate) fn replay(&self, path: &Path, policy: Option<&Policy>) -> Result<(), String> {
        // Sealed segments too: the month may have begun before the last seal.
        let file = match audit::chain_reader(path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => {
                return Err(format!(
                    "the audit log at {} cannot be read to count this month's spend: {err}. Fix its permissions and start again.",
                    path.display()
                ));
            }
        };
        let now = audit::timestamp();
        // The longest budget period is a year: a record from before last year counts in none.
        let since = now
            .get(..4)
            .and_then(|y| y.parse::<u32>().ok())
            .map_or(String::new(), |y| format!("{:04}", y.saturating_sub(1)));
        for line in file.lines() {
            let line = line.map_err(|err| {
                format!(
                    "the audit log at {} cannot be read to count this month's spend: {err}.",
                    path.display()
                )
            })?;
            if !line.contains("\"event\":\"usage\"") {
                continue;
            }
            let Ok(record) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            let text = |key: &str| record[key].as_str().unwrap_or_default();
            if text("time") < since.as_str() {
                continue;
            }
            // Caller-paid spend the rule kept out of its budgets stays out after a restart too.
            if record["budget"] == "not_counted" {
                continue;
            }
            let charged = record["charged_usd"].as_f64().unwrap_or_default();
            let who = Principal {
                name: text("person").to_string(),
                team: text("team").to_string(),
                key: text("key").to_string(),
                org: text("org").to_string(),
                ..Principal::default()
            };
            // The budgets the policy in force sets for this record's caller, customer, tags and model.
            let tags: Vec<String> = record["tags"]
                .as_array()
                .map(|t| {
                    t.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let counted: Vec<(String, Period)> = policy
                .and_then(|policy| {
                    let identified = policy
                        .entries()
                        .find(|(_, p)| p.key == who.key)
                        .map_or(who.clone(), |(_, p)| p.clone());
                    let rule = policy.rule_for(&identified)?;
                    let sent = if text("alias").is_empty() {
                        text("model")
                    } else {
                        text("alias")
                    };
                    Some(counted_for(
                        policy,
                        &identified,
                        rule,
                        sent,
                        text("model"),
                        record["customer"].as_str(),
                        &tags,
                    ))
                })
                .unwrap_or_default();
            self.add(
                &who.person_scope(),
                &who.team_scope(),
                &who.key,
                &counted,
                charged,
                text("time"),
            );
        }
        Ok(())
    }

    /// Admits one request from `person` under a limit of `rpm` per sliding minute, or says how many seconds to wait.
    fn rate(&self, person: &str, rpm: u32, now: Instant) -> Result<(), u64> {
        let minute = Duration::from_secs(60);
        let mut rates = locked(&self.rates);
        let sent = rates.entry(person.to_string()).or_default();
        while sent
            .front()
            .is_some_and(|at| now.duration_since(*at) >= minute)
        {
            sent.pop_front();
        }
        if sent.len() >= rpm as usize {
            let oldest = sent.front().copied().unwrap_or(now);
            let wait = minute.saturating_sub(now.duration_since(oldest));
            return Err(wait.as_secs_f64().ceil().max(1.0) as u64);
        }
        sent.push_back(now);
        Ok(())
    }

    /// Holds `tokens` against a scope's tokens-per-minute limit, or says how many seconds until they could fit.
    /// Tokens are reserved as budgets reserve dollars: what a request could use, until its answer says what it did.
    fn hold_tokens(&self, scope: &str, tpm: u32, tokens: u64, now: Instant) -> Result<(), u64> {
        let minute = Duration::from_secs(60);
        let mut all = locked(&self.tokens);
        let window = all.entry(scope.to_string()).or_default();
        while window
            .used
            .front()
            .is_some_and(|(at, _)| now.duration_since(*at) >= minute)
        {
            window.used.pop_front();
        }
        let used: u64 = window.used.iter().map(|(_, n)| n).sum();
        if used + window.reserved + tokens > u64::from(tpm) {
            let wait = window.used.front().map_or(minute, |(at, _)| {
                minute.saturating_sub(now.duration_since(*at))
            });
            return Err(wait.as_secs_f64().ceil().max(1.0) as u64);
        }
        window.reserved += tokens;
        Ok(())
    }

    /// Takes `need` of `limit` per minute for `scope` from this gateway's lease, leasing more from the store when
    /// the lease is spent or over. Returns the grant it came from, to give back what is not used.
    async fn take(
        &self,
        store: &Arc<dyn Store>,
        scope: &str,
        need: u64,
        limit: u64,
    ) -> Result<i64, Short> {
        let slot = locked(&self.leases)
            .entry(scope.to_string())
            .or_default()
            .clone();
        let mut lease = slot.lock().await;
        if lease.until.is_some_and(|until| until > Instant::now()) && lease.left >= need {
            lease.left -= need;
            return Ok(lease.grant);
        }
        if lease.left > 0 {
            store.give_back(lease.grant, i64::try_from(lease.left).unwrap_or(i64::MAX));
        }
        *lease = Leased::default();
        let want = need.max(limit.div_ceil(LEASE_PARTS)).min(limit);
        // Timed from before the store is asked, so the lease ends before the store stops counting it.
        let until = Instant::now() + LEASE;
        match store.lease(scope.to_string(), need, want, limit).await {
            Ok(Lease::Granted { grant, n }) => {
                *lease = Leased {
                    grant,
                    left: n.saturating_sub(need),
                    until: Some(until),
                };
                if lease.left > 0 {
                    // What is not spent by the end of the lease goes back, so another gateway may have it.
                    let (slot, store) = (slot.clone(), store.clone());
                    tokio::spawn(async move {
                        tokio::time::sleep_until(tokio::time::Instant::from_std(until)).await;
                        let mut lease = slot.lock().await;
                        if lease.grant == grant && lease.left > 0 {
                            store.give_back(grant, i64::try_from(lease.left).unwrap_or(i64::MAX));
                            lease.left = 0;
                        }
                    });
                }
                Ok(grant)
            }
            Ok(Lease::Over { wait }) => Err(Short::Over(wait)),
            Err(err) => Err(Short::Down(err)),
        }
    }

    /// Counts `need` for `scope` in the store past its limit, for a request observe mode or a shadow period lets
    /// through: an observed request is counted as an enforced one is, so the numbers are real when enforcement starts.
    async fn take_past(
        &self,
        store: &Arc<dyn Store>,
        scope: &str,
        need: u64,
    ) -> Result<i64, Short> {
        // No limit to keep under, and exactly `need` granted: nothing is leased ahead for this gateway.
        match store
            .lease(scope.to_string(), need, need, i64::MAX as u64)
            .await
        {
            Ok(Lease::Granted { grant, .. }) => Ok(grant),
            Ok(Lease::Over { wait }) => Err(Short::Over(wait)),
            Err(err) => Err(Short::Down(err)),
        }
    }

    /// Gives `n` back to a grant: to this gateway's lease while it lasts, else to the store.
    fn give_back(&self, store: &Arc<dyn Store>, scope: &str, grant: i64, n: i64) {
        if let (Ok(add), Some(slot)) = (u64::try_from(n), locked(&self.leases).get(scope)) {
            if let Ok(mut lease) = slot.try_lock() {
                if lease.grant == grant && lease.until.is_some_and(|until| until > Instant::now()) {
                    lease.left += add;
                    return;
                }
            }
        }
        store.give_back(grant, n);
    }

    /// Gives back what a request held, and counts what it used, if it was sent.
    fn settle_tokens(&self, scope: &str, held: u64, used: Option<u64>, grant: Option<i64>) {
        // With a store the tokens were counted when the request was admitted: what it did not use goes back, and
        // what it used beyond its hold is added.
        if let (Some(store), Some(grant)) = (&self.store, grant) {
            let n = i64::try_from(held).unwrap_or(i64::MAX)
                - i64::try_from(used.unwrap_or(0)).unwrap_or(i64::MAX);
            if n != 0 {
                self.give_back(store, scope, grant, n);
            }
            return;
        }
        let mut all = locked(&self.tokens);
        let window = all.entry(scope.to_string()).or_default();
        window.reserved = window.reserved.saturating_sub(held);
        if let Some(used) = used.filter(|n| *n > 0) {
            window.used.push_back((Instant::now(), used));
        }
    }

    /// Takes a place under `limit` requests in flight for `scope`. With a store the count is shared by every
    /// gateway, kept in a counter of the current hour that holds still running at the turn of the hour are moved to.
    async fn hold_parallel(&self, scope: &str, limit: u32) -> Result<Hold, Short> {
        let Some(store) = &self.store else {
            let mut all = locked(&self.parallel);
            let n = all.entry(scope.to_string()).or_default();
            if *n >= limit {
                return Err(Short::Over(1));
            }
            *n += 1;
            return Ok(Hold {
                scope: scope.to_string(),
                id: None,
            });
        };
        self.move_holds();
        let scope = format!("parallel:{scope}");
        let period = period_of(&audit::timestamp(), Period::Hour);
        let bucket = Counter {
            scope: scope.clone(),
            per: Period::Hour,
            period: period.clone(),
        };
        match store.reserve(bucket, 1.0, f64::from(limit)).await {
            Ok(Reserve::Done) => {
                let id = self
                    .next_hold
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                locked(&self.holds).insert(id, (scope.clone(), period));
                Ok(Hold {
                    scope,
                    id: Some(id),
                })
            }
            Ok(Reserve::Over { .. }) => Err(Short::Over(1)),
            Err(err) => Err(Short::Down(err)),
        }
    }

    /// Gives a place under a `parallel:` limit back.
    fn release_parallel(&self, hold: &Hold) {
        match (&self.store, hold.id) {
            (Some(store), Some(id)) => {
                if let Some((scope, period)) = locked(&self.holds).remove(&id) {
                    store.settle(vec![Change {
                        bucket: Counter {
                            scope,
                            per: Period::Hour,
                            period,
                        },
                        spent: 0.0,
                        reserved: -1.0,
                    }]);
                }
            }
            _ => {
                let mut all = locked(&self.parallel);
                if let Some(n) = all.get_mut(&hold.scope) {
                    *n = n.saturating_sub(1);
                    if *n == 0 {
                        all.remove(&hold.scope);
                    }
                }
            }
        }
    }

    /// At the turn of the hour, moves this gateway's holds still in flight into the new hour's counter, so they
    /// keep counting there. A hold left by a gateway that stopped counts until its hour ends, then frees itself.
    pub(crate) fn move_holds(&self) {
        let Some(store) = &self.store else {
            return;
        };
        let now = period_of(&audit::timestamp(), Period::Hour);
        let mut changes = Vec::new();
        for (scope, period) in locked(&self.holds).values_mut() {
            if *period == now {
                continue;
            }
            let at = |period: &str| Counter {
                scope: scope.clone(),
                per: Period::Hour,
                period: period.to_string(),
            };
            changes.push(Change {
                bucket: at(period),
                spent: 0.0,
                reserved: -1.0,
            });
            changes.push(Change {
                bucket: at(&now),
                spent: 0.0,
                reserved: 1.0,
            });
            *period = now.clone();
        }
        if !changes.is_empty() {
            store.settle(changes);
        }
    }

    /// What a budget's counter has spent and holds now, for the explanation. With a store, read from it: a
    /// reservation that can never pass (a limit below zero) holds nothing and answers with the counter.
    pub(crate) async fn spent_now(&self, scope: &str, per: Period) -> Option<(f64, f64)> {
        let now = audit::timestamp();
        let period = period_of(&now, per);
        match &self.store {
            Some(store) => match store
                .reserve(
                    Counter {
                        scope: scope.to_string(),
                        per,
                        period,
                    },
                    0.0,
                    -1.0,
                )
                .await
            {
                Ok(Reserve::Over { spent, reserved }) => Some((spent, reserved)),
                _ => None,
            },
            None => Some(
                locked(&self.ledger)
                    .get(&(scope.to_string(), per))
                    .filter(|b| b.period == period)
                    .map_or((0.0, 0.0), |b| (b.spent, b.reserved)),
            ),
        }
    }

    /// What `scope` spent and holds in this process for the current day and month: `(per, period, spent, reserved)`.
    pub(crate) fn usage(&self, scope: &str) -> Vec<(String, String, f64, f64)> {
        let now = audit::timestamp();
        let ledger = locked(&self.ledger);
        [Period::Day, Period::Month]
            .into_iter()
            .map(|per| {
                let period = period_of(&now, per);
                let bucket = ledger
                    .get(&(scope.to_string(), per))
                    .filter(|b| b.period == period);
                (
                    per.word().to_string(),
                    period.to_string(),
                    bucket.map_or(0.0, |b| b.spent),
                    bucket.map_or(0.0, |b| b.reserved),
                )
            })
            .collect()
    }

    /// Spend so far in the current period, for tests and the console.
    #[cfg(test)]
    fn spent(&self, scope: &str, per: Period) -> f64 {
        let now = audit::timestamp();
        locked(&self.ledger)
            .get(&(scope.to_string(), per))
            .filter(|b| b.period == period_of(&now, per))
            .map_or(0.0, |b| b.spent)
    }
}

/// An answer kept for identical requests.
struct Cached {
    status: StatusCode,
    content_type: Option<HeaderValue>,
    body: Bytes,
    expires: Instant,
    used: u64,
    /// The rule and person or team it was made for. Checked on every read, beside the key that already holds it.
    scope: String,
    /// The decision that asked the provider for it.
    origin: String,
    /// What that decision was charged: what each hit saves.
    cost: f64,
}

/// An answer read from the cache.
struct Found {
    status: StatusCode,
    content_type: Option<HeaderValue>,
    body: Bytes,
    origin: String,
    cost: f64,
}

/// Answers by the hash of provider, model and request body, least recently used out first.
#[derive(Default)]
struct Cache {
    entries: HashMap<[u8; 32], Cached>,
    order: BTreeMap<u64, [u8; 32]>,
    bytes: usize,
    tick: u64,
}

impl Cache {
    fn remove(&mut self, key: &[u8; 32]) {
        if let Some(old) = self.entries.remove(key) {
            self.order.remove(&old.used);
            self.bytes -= old.body.len();
        }
    }

    fn get(&mut self, key: &[u8; 32], scope: &str, now: Instant) -> Option<Found> {
        if self.entries.get(key).is_some_and(|c| c.expires <= now) {
            self.remove(key);
        }
        self.tick += 1;
        let tick = self.tick;
        let entry = self.entries.get_mut(key).filter(|c| c.scope == scope)?;
        self.order.remove(&entry.used);
        entry.used = tick;
        self.order.insert(tick, *key);
        Some(Found {
            status: entry.status,
            content_type: entry.content_type.clone(),
            body: entry.body.clone(),
            origin: entry.origin.clone(),
            cost: entry.cost,
        })
    }

    fn live(&self, key: &[u8; 32], scope: &str, now: Instant) -> bool {
        self.entries
            .get(key)
            .is_some_and(|c| c.scope == scope && c.expires > now)
    }

    fn put(&mut self, key: [u8; 32], mut entry: Cached, cap: usize) {
        self.remove(&key);
        if entry.body.len() > cap {
            return;
        }
        while self.bytes + entry.body.len() > cap {
            let Some((_, oldest)) = self.order.pop_first() else {
                break;
            };
            self.remove(&oldest);
        }
        self.tick += 1;
        entry.used = self.tick;
        self.bytes += entry.body.len();
        self.order.insert(entry.used, key);
        self.entries.insert(key, entry);
    }
}

/// Most embeddings the semantic cache holds, across every rule. Each is scanned on a semantic lookup in its
/// partition, and an answer it points at lives in the answer cache, within that cache's size.
// ponytail: a linear scan of at most 4096 vectors (about 24 MiB at 1536 dimensions). An index (HNSW) when a
// deployment needs more than that.
const MAX_VECTORS: usize = 4096;

/// Most bytes of request text embedded. A longer request is not compared by meaning, only byte for byte: cutting
/// it would let two conversations that differ past the cut match.
const MAX_EMBEDDED_TEXT: usize = 32 * 1024;

struct Vector {
    /// The scope, provider, model, route and every field of the body but its text: only requests alike in all of
    /// these are compared.
    partition: [u8; 32],
    vector: Vec<f32>,
    /// The answer's key in the answer cache.
    key: [u8; 32],
}

/// The semantic cache's embeddings, oldest out first.
#[derive(Default)]
struct Vectors(VecDeque<Vector>);

impl Vectors {
    fn push(&mut self, vector: Vector) {
        self.0.retain(|v| v.key != vector.key);
        if self.0.len() >= MAX_VECTORS {
            self.0.pop_front();
        }
        self.0.push_back(vector);
    }

    /// The answer keys in `partition` at or above `threshold`, closest first.
    fn near(&self, partition: &[u8; 32], vector: &[f32], threshold: f64) -> Vec<([u8; 32], f64)> {
        let mut near: Vec<([u8; 32], f64)> = self
            .0
            .iter()
            .filter(|v| &v.partition == partition)
            .filter_map(|v| Some((v.key, cosine(&v.vector, vector)?)))
            .filter(|(_, score)| *score >= threshold)
            .collect();
        near.sort_by(|a, b| b.1.total_cmp(&a.1));
        near
    }
}

/// Cosine similarity, or None for vectors that cannot be compared (another length, or all zero).
fn cosine(a: &[f32], b: &[f32]) -> Option<f64> {
    if a.len() != b.len() || a.is_empty() {
        return None;
    }
    let (mut dot, mut na, mut nb) = (0.0f64, 0.0f64, 0.0f64);
    for (x, y) in a.iter().zip(b) {
        let (x, y) = (f64::from(*x), f64::from(*y));
        dot += x * y;
        na += x * x;
        nb += y * y;
    }
    let norms = na.sqrt() * nb.sqrt();
    (norms > 0.0 && dot.is_finite()).then(|| dot / norms)
}

/// A request's embedding, made through Gantry's embeddings route, to compare it with cached ones.
pub(crate) struct Probe {
    pub partition: [u8; 32],
    pub vector: Vec<f32>,
    pub threshold: f64,
}

/// How a cached answer was found, for the decision record.
pub(crate) struct Hit {
    pub matched: &'static str,
    pub similarity: Option<f64>,
    pub origin: String,
    pub scope: &'static str,
}

/// What a cacheable answer becomes when it is settled.
struct Keep {
    key: [u8; 32],
    ttl: Duration,
    scope: String,
    /// The semantic partition and embedding, when the rule has a semantic cache.
    vector: Option<([u8; 32], Vec<f32>)>,
    /// Set when answer guardrails must pass the answer before it is kept.
    gate: Option<Gate>,
}

type Commit = Box<dyn FnOnce() + Send>;

/// Holds a settled answer until the answer guardrails pass it, or the verdict until the answer is settled: the two
/// happen on different threads, in either order. Only an explicit pass keeps the answer: a block, a mask, an
/// unreadable answer or a check that could not be recorded drop it.
#[derive(Clone, Default)]
pub(crate) struct Gate(Arc<Mutex<(Option<bool>, Option<Commit>)>>);

impl Gate {
    pub(crate) fn passed(&self, yes: bool) {
        let commit = {
            let mut slot = locked(&self.0);
            slot.0 = Some(yes);
            slot.1.take()
        };
        if let (true, Some(commit)) = (yes, commit) {
            commit();
        }
    }

    fn settled(&self, commit: Commit) {
        let mut slot = locked(&self.0);
        match slot.0 {
            Some(true) => {
                drop(slot);
                commit();
            }
            Some(false) => {}
            None => slot.1 = Some(commit),
        }
    }
}

/// The fields of a request body that limits need. Everything else is left alone.
#[derive(Default)]
struct Hints {
    stream: Option<bool>,
    /// The largest of max_tokens, max_completion_tokens and (the Responses API's name) max_output_tokens: a
    /// provider that reads another one than Gantry would otherwise run more than was reserved.
    max_output: Option<u64>,
    /// How many answers the request asks for (chat's `n`): the provider writes, and bills, each one.
    n: Option<u64>,
    /// Responses fields that make the provider add stored context the body does not hold.
    stored: Vec<&'static str>,
}

/// Counts one request against every rpm limit in `applied` (from `Policy::applied`): the rule's, the key's and the
/// `limits:` list's. One over its limit refuses, unless it is observed: then it is counted all the same and pushed to
/// `observed`.
pub(crate) async fn count_rpm(
    spend: &Spend,
    applied_all: &[Applied],
    rule: &Rule,
    observed: &mut Vec<(Refusal, &'static str)>,
) -> Result<(), Refusal> {
    for applied in applied_all {
        let Limit::Rpm(rpm) = applied.limit else {
            continue;
        };
        let counted = match &spend.store {
            None => spend.rate(&applied.scope, rpm, Instant::now()),
            Some(store) => match spend
                .take(store, &format!("rpm:{}", applied.scope), 1, u64::from(rpm))
                .await
            {
                Ok(_) => Ok(()),
                Err(Short::Over(wait)) => Err(wait),
                Err(Short::Down(err)) => return Err(rate_store_unavailable(&err)),
            },
        };
        if let Err(wait) = counted {
            let mut refusal = Refusal::new(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                format!(
                    "Refused: {} has sent {rpm} requests in the last minute, the most {} allows. Send this one again in {wait} seconds.",
                    applied.whose,
                    allows(applied, rule)
                ),
            );
            refusal.retry_after = Some(wait);
            refusal.record = Some(Box::new(limit_record(
                applied,
                serde_json::json!({ "kind": "rpm", "of": applied.of, "value": rpm }),
            )));
            let Some(by) = applied.shadow else {
                return Err(refusal);
            };
            observed.push((refusal, by));
            // Observed: counted all the same, so the minute's count is the one enforcement will see.
            match &spend.store {
                None => {
                    let _ = spend.rate(&applied.scope, u32::MAX, Instant::now());
                }
                Some(store) => {
                    if let Err(Short::Down(err)) = spend
                        .take_past(store, &format!("rpm:{}", applied.scope), 1)
                        .await
                    {
                        return Err(rate_store_unavailable(&err));
                    }
                }
            }
        }
    }
    Ok(())
}

/// What a form (an image edit or variation, a transcription) tells the estimate: how many images its `n` asks for.
fn form_hints(body: &[u8]) -> Result<Hints, String> {
    // The form was read strictly before it got here; its boundary is its first line.
    let first = body.split(|b| *b == b'\r').next().unwrap_or_default();
    let boundary =
        String::from_utf8_lossy(first.strip_prefix(b"--").unwrap_or_default()).into_owned();
    let content_type = format!("multipart/form-data; boundary={boundary}");
    let Ok(parts) = crate::alias::form_parts(&content_type, body) else {
        return Ok(Hints::default());
    };
    let mut n = parts.iter().filter(|p| p.name == "n" && !p.file);
    let (Some(part), None) = (n.next(), n.next()) else {
        return match parts.iter().filter(|p| p.name == "n").count() {
            0 => Ok(Hints::default()),
            _ => Err("the form has more than one \"n\" field".into()),
        };
    };
    let text = String::from_utf8_lossy(&body[part.value.clone()])
        .trim()
        .to_string();
    match text.parse::<u64>() {
        Ok(count @ 1..=MAX_N) => Ok(Hints {
            n: Some(count),
            ..Hints::default()
        }),
        _ => Err(format!("\"n\" must be a whole number from 1 to {MAX_N}")),
    }
}

/// The most answers one request may ask for under a budget or a cache. OpenAI allows 128, and with it one request
/// costs 128 times its output limit: a burst of them would pass a budget by far more than one request's worth.
const MAX_N: u64 = 16;

/// Responses fields that pull in stored context: an earlier response, a conversation, a stored prompt.
const STORED: [&str; 3] = ["previous_response_id", "conversation", "prompt"];

/// Top-level fields that must appear at most once: the ones limits read, and the ones a provider acts on that a
/// guardrail or the estimate reads. Parsers differ on which copy of a duplicate wins.
const ONCE: &[&str] = &[
    "model",
    "messages",
    "system",
    "input",
    "stream",
    "max_tokens",
    "max_completion_tokens",
    "max_output_tokens",
    "n",
    "previous_response_id",
    "conversation",
    "prompt",
    "generationConfig",
    "generation_config",
];

/// Reads the fields limits need, refusing a duplicate or a value of the wrong type: either would let the provider
/// run a request larger than the one reserved for.
fn hints(body: &[u8]) -> Result<Hints, String> {
    use serde::de::{Error, IgnoredAny, MapAccess, Visitor};
    struct Fields;
    impl<'de> Visitor<'de> for Fields {
        type Value = Hints;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a JSON object")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Hints, A::Error> {
            let mut hints = Hints::default();
            let mut seen: Vec<std::borrow::Cow<'de, str>> = Vec::new();
            while let Some(key) = map.next_key::<std::borrow::Cow<'de, str>>()? {
                if ONCE.contains(&key.as_ref()) {
                    if seen.contains(&key) {
                        return Err(A::Error::custom(format!(
                            "\"{key}\" appears twice in the request body"
                        )));
                    }
                    seen.push(key.clone());
                }
                match key.as_ref() {
                    "stream" => {
                        hints.stream = map.next_value().map_err(|_| {
                            A::Error::custom("\"stream\" must be true, false or null")
                        })?;
                    }
                    "max_tokens" | "max_completion_tokens" | "max_output_tokens" => {
                        let value: Option<u64> = map.next_value().map_err(|_| {
                            A::Error::custom(format!(
                                "\"{key}\" must be a whole number of tokens, 0 or more, written as a number"
                            ))
                        })?;
                        hints.max_output = hints.max_output.max(value);
                    }
                    "n" => {
                        let value: Option<u64> = map.next_value().map_err(|_| {
                            A::Error::custom(format!(
                                "\"n\" must be a whole number from 1 to {MAX_N}"
                            ))
                        })?;
                        if value.is_some_and(|n| n == 0 || n > MAX_N) {
                            return Err(A::Error::custom(format!(
                                "\"n\" must be a whole number from 1 to {MAX_N}: each answer costs its output limit again"
                            )));
                        }
                        hints.n = value;
                    }
                    // Google's Gemini API names the output limit and the number of answers inside its config.
                    "generationConfig" | "generation_config" => {
                        let config: Option<serde_json::Map<String, Value>> =
                            map.next_value().map_err(|_| {
                                A::Error::custom(format!("\"{key}\" must be an object"))
                            })?;
                        let config = config.unwrap_or_default();
                        let number = |names: [&str; 2]| -> Result<Option<u64>, A::Error> {
                            let mut found = None;
                            for name in names {
                                match config.get(name) {
                                    None | Some(Value::Null) => {}
                                    Some(value) => {
                                        let n = value.as_u64().ok_or_else(|| {
                                            A::Error::custom(format!(
                                                "\"{key}.{name}\" must be a whole number, 0 or more, written as a number"
                                            ))
                                        })?;
                                        found = found.max(Some(n));
                                    }
                                }
                            }
                            Ok(found)
                        };
                        hints.max_output = hints
                            .max_output
                            .max(number(["maxOutputTokens", "max_output_tokens"])?);
                        if let Some(n) = number(["candidateCount", "candidate_count"])? {
                            if n == 0 || n > MAX_N {
                                return Err(A::Error::custom(format!(
                                    "\"candidateCount\" must be a whole number from 1 to {MAX_N}: each answer costs its output limit again"
                                )));
                            }
                            hints.n = Some(n);
                        }
                    }
                    field @ ("previous_response_id" | "conversation" | "prompt") => {
                        let value: Value = map.next_value()?;
                        if !value.is_null() {
                            if let Some(name) = STORED.iter().find(|s| **s == field) {
                                hints.stored.push(name);
                            }
                        }
                    }
                    _ => {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
            }
            Ok(hints)
        }
    }
    let mut de = serde_json::Deserializer::from_slice(body);
    let hints = serde::Deserializer::deserialize_map(&mut de, Fields).map_err(|e| e.to_string())?;
    de.end().map_err(|e| e.to_string())?;
    Ok(hints)
}

/// Output tokens to reserve: what the request asks for, else the most its model writes. None when neither says.
/// An embeddings request writes none.
fn output_tokens(hints: &Hints, price: Option<&Price>, route: &str) -> Option<u64> {
    // QA14-3: an image (gpt-image) or speech (gpt-4o-mini-tts) model priced by the token bills what it generates as
    // output tokens, and the body has no field that bounds them: only the model's max_output does. An image model
    // priced by the image reserves that instead.
    if route.starts_with("/v1/images") || route.starts_with("/v1/audio/speech") {
        if route.starts_with("/v1/images") && price.is_some_and(|p| p.per_image.is_some()) {
            return Some(0);
        }
        let one = price.and_then(|p| p.max_output)?;
        return Some(one.saturating_mul(hints.n.unwrap_or(1)));
    }
    // These write no text tokens, or (rerank) are not billed by them.
    // ponytail: a transcription's text is billed as output tokens on token-priced models and not reserved here; its
    // reservation is the uploaded bytes as prompt tokens, which is far more than any transcript of them.
    if [
        "/v1/embeddings",
        "/v1/audio",
        "/v1/moderations",
        "/v1/rerank",
    ]
    .iter()
    .any(|r| route.starts_with(r))
        || route.contains(":embedContent")
        || route.contains(":batchEmbedContents")
    {
        return Some(0);
    }
    let one = hints.max_output.or(price.and_then(|p| p.max_output))?;
    Some(one.saturating_mul(hints.n.unwrap_or(1)))
}

/// Input tokens to reserve beyond the body: the model's whole context for a Responses request that names stored
/// context. Err names the fields when the price does not bound it.
fn stored_tokens(hints: &Hints, price: &Price, route: &str) -> Result<u64, String> {
    if hints.stored.is_empty() || !route.starts_with("/v1/responses") {
        return Ok(0);
    }
    price.max_context.ok_or_else(|| hints.stored.join(", "))
}

/// One request that passed its limits, on its way to the provider. Its reservation is given back if it never gets
/// an answer.
pub(crate) struct Admitted {
    spend: Arc<Spend>,
    audit: Option<Arc<AuditLog>>,
    decision: String,
    person: String,
    team: String,
    /// First 8 hex characters of the key's hash, as on the decision record.
    key: String,
    model: String,
    provider: String,
    /// The version that decided the request, as on its decision record.
    version: (String, String),
    price: Option<Price>,
    /// One per budget the request counts against: its rule's and its key's.
    reservations: Vec<Reservation>,
    /// The body sent, kept (by reference) to estimate what a request without a budget could have cost if it is
    /// cut off. None for a budgeted request, whose reservation is that estimate, and for a free one.
    estimate_from: Option<(Bytes, String)>,
    /// Where to keep the answer, and for how long, if it may be cached.
    cache: Option<Keep>,
    /// For a cache hit: what the answer cost when it was made.
    saved: Option<f64>,
    /// Bytes of the body sent, for the prompt part of an estimate from streamed text.
    body_len: usize,
    /// At most the output tokens a finished stream without usage streamed, set when it ends.
    streamed: Option<u64>,
    /// The path the request was sent to: an images request may be priced by the image.
    route: String,
    /// Tokens held against each tokens-per-minute limit the request counts against, by scope, with the store's
    /// grant they came from when there is a store.
    tokens: Vec<(String, u64, Option<i64>)>,
    /// Set while the provider has the request and its answer has not been handed on: a caller who hangs up then
    /// has still made the provider run (and bill) it.
    forwarded: bool,
    /// Sent with the caller's own provider key, and whether its spend counts against budgets.
    caller_paid: Option<bool>,
    /// The counters of the person and the team, inside the key's organization.
    person_scope: String,
    team_scope: String,
    /// The organization, end customer and tags, for the usage record.
    org: String,
    customer: Option<String>,
    tags: Vec<String>,
    /// The alias the caller sent, when it is not the model, for the usage record.
    alias: Option<String>,
    /// Every budget counter the request counted against, to charge its cost to each.
    counted: Vec<(String, Period)>,
    /// Places held under `parallel:` limits until the answer ends.
    parallel: Vec<Hold>,
    /// When it was admitted, for the latency on its usage record.
    started: Instant,
    /// What its rule's `capture:` keeps, until the answer ends.
    capture: Option<Capture>,
    /// The body sent, by reference, when `Spend::capture` wants this request's text.
    captured: Option<Bytes>,
    /// A streamed answer's frames, kept only for a captured request.
    stream_copy: Option<Vec<Bytes>>,
}

/// A request body to keep with its answer, per its rule's `capture:`.
struct Capture {
    rule: String,
    days: u32,
    viewers: Vec<String>,
    request: Bytes,
    /// A streamed answer's frames, joined when the stream ends. A whole answer comes to `close` itself.
    answer: Option<Bytes>,
}

impl Drop for Admitted {
    fn drop(&mut self) {
        // QA14-1: the caller hung up after the request was forwarded and before its answer started. It is settled as
        // cut off, charged the most it could cost, so a loop of hang-ups cannot spend past a budget or a TPM limit.
        if self.forwarded {
            let decision = self.decision.clone();
            if let (Some(record), Some(log)) = (
                self.close(StatusCode::OK, Ended::CallerLeft, None, false, None),
                self.audit.clone(),
            ) {
                log.append_record_then(&record, move |result| written(&decision, result));
            }
        }
        for reservation in self.reservations.drain(..) {
            self.spend.release(&reservation);
        }
        // Never sent, or never answered: what it held goes back and nothing is counted as used.
        for (scope, held, grant) in self.tokens.drain(..) {
            self.spend.settle_tokens(&scope, held, None, grant);
        }
        for hold in self.parallel.drain(..) {
            self.spend.release_parallel(&hold);
        }
    }
}

/// The admitted request, carried in the request's extensions from the check to the send. Extensions must be
/// `Clone`, and the request must be admitted once, so the clones share one slot.
#[derive(Clone)]
pub(crate) struct Meter(Arc<Mutex<Option<Admitted>>>);

impl Meter {
    pub(crate) fn take(&self) -> Option<Admitted> {
        locked(&self.0).take()
    }

    /// Makes a cacheable answer wait for the answer guardrails' pass before it is kept.
    pub(crate) fn gate(&self) -> Option<Gate> {
        let mut slot = locked(&self.0);
        let keep = slot.as_mut()?.cache.as_mut()?;
        Some(keep.gate.get_or_insert_with(Gate::default).clone())
    }
}

/// What `admit` decided.
pub(crate) enum Admit {
    /// The cache holds the answer: it never reaches the provider.
    Hit(Response, Box<Admitted>, Hit),
    /// Sent on, with what observe mode or a shadow period let through: each refusal and why it was not enforced.
    Go(Meter, Option<&'static str>, Vec<(Refusal, &'static str)>),
}

/// The request as the limits see it.
pub(crate) struct Ask<'a> {
    pub decision: &'a str,
    pub person: &'a Principal,
    pub rule: &'a Rule,
    pub model: &'a str,
    /// The model name the caller sent: an alias's name when `model` is one of its deployments.
    pub sent: &'a str,
    pub provider: &'a str,
    /// The policy and keys hashes of the version that decided the request.
    pub version: (&'a str, &'a str),
    pub prices: &'a PriceOverrides,
    pub headers: &'a HeaderMap,
    /// The path and query the caller sent the request to: the same body means something else on another route.
    pub route: &'a str,
    pub body: &'a Bytes,
    /// Counting tokens is free, so it reserves nothing.
    pub free: bool,
    /// Sent with the caller's own provider key: `Some(true)` when its spend still counts against budgets.
    pub caller_paid: Option<bool>,
    /// The request's embedding, for a rule with a semantic cache.
    pub probe: Option<Probe>,
    /// Every limit the request counts against, from `Policy::applied`.
    pub applied: &'a [Applied],
    /// The end customer, from the key or the `x-gantry-customer` header.
    pub customer: Option<&'a str>,
    /// The tags, from the key and the `x-gantry-tags` header.
    pub tags: &'a [String],
}

/// Applies the rule's cache, rate and budget to an allowed request, in that order: a cached answer costs nothing
/// and uses no provider capacity, so it is neither rate limited nor charged.
pub(crate) async fn admit(
    spend: &Arc<Spend>,
    audit: Option<&Arc<AuditLog>>,
    mut ask: Ask<'_>,
) -> Result<Admit, Refusal> {
    let limits = &ask.rule.limits;
    // What the caller knows the model as, with the deployment as detail when an alias picked it.
    let named = if ask.sent == ask.model {
        format!("model \"{}\"", ask.model)
    } else {
        format!(
            "alias \"{}\" (deployment \"{}\" on provider \"{}\")",
            ask.sent, ask.model, ask.provider
        )
    };
    let mut admitted = Admitted {
        spend: spend.clone(),
        audit: audit.cloned(),
        decision: ask.decision.to_string(),
        person: ask.person.name.clone(),
        team: ask.person.team.clone(),
        key: ask.person.key.clone(),
        model: ask.model.to_string(),
        provider: ask.provider.to_string(),
        version: (ask.version.0.to_string(), ask.version.1.to_string()),
        price: price_for(ask.model, ask.prices),
        reservations: Vec::new(),
        estimate_from: None,
        cache: None,
        saved: None,
        body_len: ask.body.len(),
        streamed: None,
        route: ask.route.to_string(),
        tokens: Vec::new(),
        forwarded: false,
        caller_paid: ask.caller_paid,
        person_scope: ask.person.person_scope(),
        team_scope: ask.person.team_scope(),
        org: ask.person.org.clone(),
        customer: ask.customer.map(str::to_string),
        tags: ask.tags.to_vec(),
        alias: (ask.sent != ask.model).then(|| ask.sent.to_string()),
        counted: Vec::new(),
        parallel: Vec::new(),
        started: Instant::now(),
        capture: ask.rule.limits.capture.as_ref().map(|c| Capture {
            rule: ask.rule.name.clone(),
            days: c.days,
            viewers: c.viewers.clone(),
            request: ask.body.clone(),
            answer: None,
        }),
        captured: spend
            .capture
            .as_ref()
            .filter(|c| c.wanted(&ask.person.team))
            .map(|_| ask.body.clone()),
        stream_copy: None,
    };
    // The caller pays their provider: unless the rule says otherwise, budgets (what the organization pays) do not
    // reserve or count it. Rate and token limits still hold.
    let budgeted = ask
        .applied
        .iter()
        .any(|a| matches!(a.limit, Limit::Budget(_)))
        && ask.caller_paid != Some(false);
    let tpm = ask.applied.iter().any(|a| matches!(a.limit, Limit::Tpm(_)));
    if !budgeted && !ask.free {
        admitted.estimate_from = Some((ask.body.clone(), ask.route.to_string()));
    }
    // An audio upload is a form, not JSON: it carries none of the fields read here.
    let form = ask.route.starts_with("/v1/audio/transcriptions")
        || ask.route.starts_with("/v1/images/edits")
        || ask.route.starts_with("/v1/images/variations");
    let hints: Hints = if form {
        form_hints(ask.body).map_err(|err| {
            Refusal::new(
                StatusCode::BAD_REQUEST,
                "bad_limits",
                format!("Refused: {err}. Send n once, as a whole number from 1 to {MAX_N}."),
            )
        })?
    } else if budgeted || tpm || limits.cache_ttl_seconds.is_some() {
        hints(ask.body).map_err(|err| {
            Refusal::new(
                StatusCode::BAD_REQUEST,
                "bad_limits",
                format!(
                    "Refused: {err}. A budget or a cache applies to this request, and Gantry reads these fields to know what it could cost. Send each of model, messages, system, input, stream, max_tokens, max_completion_tokens, max_output_tokens and n at most once, token limits as whole numbers, n from 1 to {MAX_N}."
                ),
            )
        })?
    } else {
        Hints::default()
    };
    let mut cache_word = None;
    let mut observed: Vec<(Refusal, &'static str)> = Vec::new();
    if let Some(ttl) = limits.cache_ttl_seconds {
        if cacheable(&ask, &hints) {
            let scope = scope_of(&ask);
            let key = cache_key(&ask, &scope);
            let probe = ask.probe.take();
            let now = Instant::now();
            let found = {
                let mut cache = locked(&spend.cache);
                match cache.get(&key, &scope, now) {
                    Some(found) => Some((found, "exact", None)),
                    None => probe.as_ref().and_then(|p| {
                        let near =
                            locked(&spend.vectors).near(&p.partition, &p.vector, p.threshold);
                        near.into_iter().find_map(|(key, score)| {
                            Some((cache.get(&key, &scope, now)?, "semantic", Some(score)))
                        })
                    }),
                }
            };
            if let Some((found, matched, similarity)) = found {
                let mut response = (found.status, found.body).into_response();
                if let Some(content_type) = found.content_type {
                    response
                        .headers_mut()
                        .insert(header::CONTENT_TYPE, content_type);
                }
                response.headers_mut().insert(
                    HeaderName::from_static("x-gantry-cache"),
                    HeaderValue::from_static("hit"),
                );
                admitted.saved = Some(found.cost);
                let hit = Hit {
                    matched,
                    similarity,
                    origin: found.origin,
                    scope: limits.cache_scope.word(),
                };
                return Ok(Admit::Hit(response, Box::new(admitted), hit));
            }
            cache_word = Some("miss");
            admitted.cache = Some(Keep {
                key,
                ttl: Duration::from_secs(ttl),
                scope,
                vector: probe.map(|p| (p.partition, p.vector)),
                gate: None,
            });
        }
    }
    count_rpm(spend, ask.applied, ask.rule, &mut observed).await?;
    let tpm_applied: Vec<&Applied> = ask
        .applied
        .iter()
        .filter(|a| matches!(a.limit, Limit::Tpm(_)))
        .collect();
    let mut tpm = tpm;
    if tpm && !ask.free && output_tokens(&hints, admitted.price.as_ref(), ask.route).is_none() {
        if let Some(by) = all_shadowed(&tpm_applied) {
            // Observed: the tokens it could use are unknown, so none are held; the answer's count is not either.
            observed.push((max_tokens_for_tpm(&named), by));
            tpm = false;
        }
    }
    if tpm && !ask.free {
        // The most tokens this request could use: every three bytes of its body one, and the output it may write.
        let output = output_tokens(&hints, admitted.price.as_ref(), ask.route)
            .ok_or_else(|| max_tokens_for_tpm(&named))?;
        let most = (ask.body.len().div_ceil(3) as u64).saturating_add(output);
        for applied in ask.applied {
            let Limit::Tpm(limit) = applied.limit else {
                continue;
            };
            let scope = applied.scope.clone();
            let whose = if applied.of == "key" {
                applied.whose.clone()
            } else {
                allows(applied, ask.rule)
            };
            let held = match &spend.store {
                None => spend
                    .hold_tokens(&scope, limit, most, Instant::now())
                    .map(|()| None),
                // Never fits: refused without asking the store.
                Some(_) if most > u64::from(limit) => Err(60),
                Some(store) => match spend
                    .take(store, &format!("tpm:{scope}"), most, u64::from(limit))
                    .await
                {
                    Ok(grant) => Ok(Some(grant)),
                    Err(Short::Over(wait)) => Err(wait),
                    Err(Short::Down(err)) => return Err(rate_store_unavailable(&err)),
                },
            };
            let grant = match held {
                Ok(grant) => grant,
                Err(wait) => {
                    let mut refusal = Refusal::new(
                        StatusCode::TOO_MANY_REQUESTS,
                        "rate_limited",
                        if most > u64::from(limit) {
                            format!(
                                "Refused: this request could use up to {most} tokens, more than the {limit} per minute {whose} allows. Send a shorter request or a smaller max_tokens."
                            )
                        } else {
                            format!(
                                "Refused: the tokens used in the last minute and held by requests in flight, with up to {most} for this request, would pass the {limit} per minute {whose} allows. Send it again in {wait} seconds."
                            )
                        },
                    );
                    if most <= u64::from(limit) {
                        refusal.retry_after = Some(wait);
                    }
                    refusal.record = Some(Box::new(limit_record(
                        applied,
                        serde_json::json!({ "kind": "tpm", "of": applied.of, "value": limit, "request_could_use": most }),
                    )));
                    let Some(by) = applied.shadow else {
                        return Err(refusal);
                    };
                    observed.push((refusal, by));
                    // Observed: held all the same, so the minute's count is the one enforcement will see.
                    match &spend.store {
                        None => {
                            if spend
                                .hold_tokens(&scope, u32::MAX, most, Instant::now())
                                .is_err()
                            {
                                continue;
                            }
                            None
                        }
                        Some(store) => {
                            match spend.take_past(store, &format!("tpm:{scope}"), most).await {
                                Ok(grant) => Some(grant),
                                Err(Short::Over(_)) => continue,
                                Err(Short::Down(err)) => return Err(rate_store_unavailable(&err)),
                            }
                        }
                    }
                }
            };
            // With a store, the scope is the lease's, so what is given back finds it.
            let scope = if grant.is_some() {
                format!("tpm:{scope}")
            } else {
                scope
            };
            admitted.tokens.push((scope, most, grant));
        }
    }
    for applied in ask.applied {
        let Limit::Parallel(limit) = applied.limit else {
            continue;
        };
        match spend.hold_parallel(&applied.scope, limit).await {
            Ok(hold) => admitted.parallel.push(hold),
            Err(Short::Down(err)) => return Err(rate_store_unavailable(&err)),
            Err(Short::Over(_)) => {
                let mut refusal = Refusal::new(
                    StatusCode::TOO_MANY_REQUESTS,
                    "parallel_limited",
                    format!(
                        "Refused: {} already has {limit} requests in flight, the most {} allows at once. Send this one again when one of them has finished.",
                        applied.whose,
                        allows(applied, ask.rule)
                    ),
                );
                refusal.retry_after = Some(1);
                refusal.record = Some(Box::new(limit_record(applied, Value::Null)));
                let Some(by) = applied.shadow else {
                    return Err(refusal);
                };
                observed.push((refusal, by));
                // Observed: in flight all the same, so the count is the one enforcement will see.
                match spend.hold_parallel(&applied.scope, u32::MAX).await {
                    Ok(hold) => admitted.parallel.push(hold),
                    Err(Short::Down(err)) => return Err(rate_store_unavailable(&err)),
                    Err(Short::Over(_)) => {}
                }
            }
        }
    }
    if budgeted && !ask.free {
        let budgets: Vec<&Applied> = ask
            .applied
            .iter()
            .filter(|a| matches!(a.limit, Limit::Budget(_)))
            .collect();
        // Observed budgets (every one that applies): a request whose cost cannot be known is forwarded, and what
        // would have refused it is recorded.
        let shadow = all_shadowed(&budgets);
        let unknown = |refusal: Refusal, observed: &mut Vec<(Refusal, &'static str)>| match shadow {
            Some(by) => {
                observed.push((refusal, by));
                Ok(())
            }
            None => Err(refusal),
        };
        let Some(price) = &admitted.price else {
            // The loader refuses a rule budget over an unpriced model, so only a key budget, a scope's budget or a
            // policy built in code gets here.
            unknown(
                Refusal::new(
                    StatusCode::FORBIDDEN,
                    "no_price",
                    format!(
                        "Refused: a budget applies to this request ({}) and {named} has no price, so its spend could not be counted. Ask a Gantry admin to add its price under prices: in the policy.",
                        budgets
                            .iter()
                            .map(|a| a.source.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                ),
                &mut observed,
            )?;
            return Ok(Admit::Go(
                Meter(Arc::new(Mutex::new(Some(admitted)))),
                cache_word,
                observed,
            ));
        };
        let estimate = match output_tokens(&hints, Some(price), ask.route) {
            None => Err(None),
            Some(output) => stored_tokens(&hints, price, ask.route)
                .map(|context| (output, context))
                .map_err(Some),
        };
        let most = match estimate {
            Ok((output, context)) => match price
                .per_image
                .filter(|_| ask.route.starts_with("/v1/images"))
            {
                Some(each) => each * hints.n.unwrap_or(1) as f64,
                None => most_cost(price, ask.body.len(), context, output),
            },
            Err(None) => {
                let whose = match budgets.as_slice() {
                    [one] if one.of == "rule" => {
                        format!("the budget of rule \"{}\" applies", ask.rule.name)
                    }
                    [one] if one.of == "key" => {
                        format!("the key of \"{}\" has a budget", ask.person.name)
                    }
                    [one] => format!("the budget of {} applies", one.whose),
                    many => format!(
                        "the budgets of {} apply",
                        many.iter()
                            .map(|a| a.whose.as_str())
                            .collect::<Vec<_>>()
                            .join(" and ")
                    ),
                };
                // Each API names its output limit differently; the caller can only send its own route's.
                let images = ask.route.starts_with("/v1/images");
                if images || ask.route.starts_with("/v1/audio/speech") {
                    let per_image = if images { "per_image or " } else { "" };
                    unknown(
                        Refusal::new(
                            StatusCode::BAD_REQUEST,
                            "max_tokens_needed",
                            format!(
                                "Refused: {whose} to this request, and {named} is priced by the token with no max_output, so the most its generated output could cost is unknown. Ask a Gantry admin to set {per_image}max_output for the model under prices: in the policy."
                            ),
                        ),
                        &mut observed,
                    )?;
                } else {
                    let field = if ask.route.starts_with("/v1/responses") {
                        "max_output_tokens"
                    } else if ask.route.starts_with("/v1/messages") {
                        "max_tokens"
                    } else if crate::gemini_native(ask.route.split('?').next().unwrap_or_default())
                        .is_some()
                    {
                        "generationConfig.maxOutputTokens"
                    } else {
                        "max_tokens (or max_completion_tokens)"
                    };
                    unknown(
                        Refusal::new(
                            StatusCode::BAD_REQUEST,
                            "max_tokens_needed",
                            format!(
                                "Refused: {whose} to this request, and it does not say how many output tokens it may use, and {named} has no max_output in its price, so the most it could cost is unknown. Send {field} with the request, or ask a Gantry admin to set max_output for the model under prices: in the policy."
                            ),
                        ),
                        &mut observed,
                    )?;
                }
                // Observed: nothing is reserved, and the answer's cost still counts against the budgets.
                0.0
            }
            Err(Some(fields)) => {
                unknown(
                    Refusal::new(
                        StatusCode::BAD_REQUEST,
                        "stored_context",
                        format!(
                            "Refused: a budget applies to this request and it names stored context ({fields}), which the provider adds to the prompt and Gantry cannot see, so the most it could cost is unknown. Send the whole conversation in input instead (as Codex does, with store: false), or ask a Gantry admin to set max_context for model \"{}\" under prices: in the policy, so such a request reserves the model's whole context.",
                            ask.model
                        ),
                    ),
                    &mut observed,
                )?;
                0.0
            }
        };
        let (reservations, counted) = reserve_budgets(
            spend,
            &budgets,
            ask.rule,
            most,
            "This request",
            Some(&mut observed),
        )
        .await?;
        admitted.reservations = reservations;
        admitted.counted = counted;
    }
    Ok(Admit::Go(
        Meter(Arc::new(Mutex::new(Some(admitted)))),
        cache_word,
        observed,
    ))
}

/// The shadow every limit in `applied` is under, when each is: `None` when one of them is enforced, or none applies.
pub(crate) fn all_shadowed(applied: &[&Applied]) -> Option<&'static str> {
    let first = applied.first()?.shadow?;
    applied.iter().all(|a| a.shadow.is_some()).then_some(first)
}

fn max_tokens_for_tpm(named: &str) -> Refusal {
    Refusal::new(
        StatusCode::BAD_REQUEST,
        "max_tokens_needed",
        format!(
            "Refused: a tokens-per-minute limit applies to this request, and it does not say how many output tokens it may use, and {named} has no max_output in its price, so the tokens it could use are unknown. Send max_tokens (max_output_tokens on /v1/responses) with the request, or ask a Gantry admin to set max_output for the model under prices: in the policy."
        ),
    )
}

/// Whether a request's answer may be cached. Never a stream, a request sent with `Cache-Control: no-store`, a
/// count of tokens (cheap, and not an answer to the request), nor a Responses request naming stored context
/// (QA12-4): the conversation or stored prompt can change while the body does not.
fn cacheable(ask: &Ask<'_>, hints: &Hints) -> bool {
    let no_store = ask
        .headers
        .get_all(header::CACHE_CONTROL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.to_ascii_lowercase().contains("no-store"));
    let stored = !hints.stored.is_empty() && ask.route.starts_with("/v1/responses");
    // Google's Gemini API streams by its method, not a body field.
    let streams = ask.route.contains(":streamGenerateContent");
    hints.stream != Some(true) && !streams && !no_store && !ask.free && !stored
}

/// Who may be served an answer cached for this request: the rule, and the person, or their team under a team
/// scope. A person without a team keeps their own scope.
fn scope_of(ask: &Ask<'_>) -> String {
    let who = match ask.rule.limits.cache_scope {
        // Within the person's organization: the same team or person name in two organizations is two scopes.
        CacheScope::Team if !ask.person.team.is_empty() => ask.person.team_scope(),
        _ => ask.person.person_scope(),
    };
    format!("{}\0{who}", ask.rule.name)
}

/// The text of a request the semantic cache embeds, and the partition its embedding is compared within: the cache
/// key of the body with its text left out. None when the rule has no semantic cache or the request is not one it
/// compares (not cacheable, not a chat, messages or Responses request, no text, or too much of it), or when an
/// identical request is already cached, so no embedding is paid for an exact hit.
pub(crate) fn semantic_text(spend: &Spend, ask: &Ask<'_>) -> Option<([u8; 32], String)> {
    ask.rule.limits.semantic.as_ref()?;
    ask.rule.limits.cache_ttl_seconds?;
    let path = ask.route.split('?').next().unwrap_or_default();
    if !matches!(
        path,
        "/v1/chat/completions" | "/v1/messages" | "/v1/responses"
    ) {
        return None;
    }
    if !cacheable(ask, &hints(ask.body).ok()?) {
        return None;
    }
    let scope = scope_of(ask);
    if locked(&spend.cache).live(&cache_key(ask, &scope), &scope, Instant::now()) {
        return None;
    }
    let mut body: Value = serde_json::from_slice(ask.body).ok()?;
    let mut texts = Vec::new();
    take_texts(&mut body, &mut texts);
    let text = texts.join("\n");
    if text.trim().is_empty() || text.len() > MAX_EMBEDDED_TEXT {
        return None;
    }
    let blanked = Bytes::from(serde_json::to_vec(&body).ok()?);
    let partition = cache_key(
        &Ask {
            body: &blanked,
            probe: None,
            ..*ask
        },
        &scope,
    );
    Some((partition, text))
}

/// Moves every string under a key that holds text (content, text, system, instructions, input) out of a body, in
/// order. Roles, tools, parameters and anything that is not text (an image's data) stay, so they must match exactly.
fn take_texts(value: &mut Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, field) in map.iter_mut() {
                let text = matches!(
                    key.as_str(),
                    "content" | "text" | "system" | "instructions" | "input"
                );
                match field {
                    Value::String(s) if text => out.push(std::mem::take(s)),
                    _ => take_texts(field, out),
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|item| take_texts(item, out)),
        _ => {}
    }
}

/// Places Anthropic cache breakpoints (`cache_control: {"type": "ephemeral"}`) on the stable prefix of a messages
/// request that has none: the last tool, the end of the system prompt and the last block of the conversation, three
/// of the four a request may carry. Returns the body and where it placed them, or None to send the body as it came:
/// the caller placed their own, it names a key twice (a rewrite would pick one copy), or there is nowhere to place
/// one. A string system prompt or message becomes one text block, which the messages API reads the same; nothing
/// else changes. A prefix shorter than the model's minimum is simply not cached by the provider.
pub(crate) fn prompt_cache(body: &Bytes) -> Option<(Bytes, Vec<&'static str>)> {
    if body.windows(15).any(|w| w == b"\"cache_control\"") {
        return None;
    }
    gantry_core::chat::reject_duplicate_keys(body).ok()?;
    let mut request: Value = serde_json::from_slice(body).ok()?;
    let mark = || serde_json::json!({ "type": "ephemeral" });
    let block =
        |text: &str| serde_json::json!({ "type": "text", "text": text, "cache_control": mark() });
    // Thinking blocks take no breakpoint, nor does an empty text block (the provider refuses one).
    let markable = |b: &Value| match b["type"].as_str() {
        Some("thinking" | "redacted_thinking") | None => false,
        Some("text") => b["text"].as_str().is_some_and(|t| !t.is_empty()),
        Some(_) => true,
    };
    let mut marks = Vec::new();
    if let Some(tool) = request["tools"].as_array_mut().and_then(|t| t.last_mut()) {
        if let Some(tool) = tool.as_object_mut() {
            tool.insert("cache_control".into(), mark());
            marks.push("tools");
        }
    }
    let system = &mut request["system"];
    match system {
        Value::String(text) if !text.is_empty() => {
            *system = Value::Array(vec![block(text)]);
            marks.push("system");
        }
        Value::Array(blocks) => {
            if let Some(last) = blocks.last_mut().filter(|b| markable(b)) {
                if let Some(last) = last.as_object_mut() {
                    last.insert("cache_control".into(), mark());
                    marks.push("system");
                }
            }
        }
        _ => {}
    }
    if let Some(content) = request["messages"]
        .as_array_mut()
        .and_then(|m| m.last_mut())
        .and_then(|m| m.get_mut("content"))
    {
        match content {
            Value::String(text) if !text.is_empty() => {
                *content = Value::Array(vec![block(text)]);
                marks.push("messages");
            }
            Value::Array(blocks) => {
                if let Some(last) = blocks.last_mut().filter(|b| markable(b)) {
                    if let Some(last) = last.as_object_mut() {
                        last.insert("cache_control".into(), mark());
                        marks.push("messages");
                    }
                }
            }
            _ => {}
        }
    }
    if marks.is_empty() {
        return None;
    }
    Some((Bytes::from(serde_json::to_vec(&request).ok()?), marks))
}

/// Reserves `most` against every budget in `budgets` (from `Policy::applied`), and returns the reservations with
/// the counters the cost is then charged to. `what` names it in a refusal ("This request", "This batch"). A
/// reservation already taken is given back when a later one is refused.
pub(crate) async fn reserve_budgets(
    spend: &Arc<Spend>,
    budgets: &[&Applied],
    rule: &Rule,
    most: f64,
    what: &str,
    mut observed: Option<&mut Vec<(Refusal, &'static str)>>,
) -> Result<(Vec<Reservation>, Vec<(String, Period)>), Refusal> {
    let mut reservations = Vec::new();
    let mut counted = Vec::new();
    let now = audit::timestamp();
    for applied in budgets {
        let Limit::Budget(budget) = applied.limit else {
            continue;
        };
        let (code, under) = match applied.of {
            "rule" => ("budget_exceeded", format!(" under rule \"{}\"", rule.name)),
            "key" => ("key_budget_exceeded", String::new()),
            _ => ("budget_exceeded", format!(" set by {}", applied.source)),
        };
        match spend
            .reserve_shared(&applied.scope, budget, most, &now)
            .await
        {
            Ok(reservation) => {
                reservations.push(reservation);
                counted.push((applied.scope.clone(), budget.per));
            }
            // Observed: the request goes on and its cost still counts here, so the numbers are real when the budget
            // is enforced. A reservation of nothing makes the store settle this counter with the rest.
            Err(Ok(over)) if applied.shadow.is_some() && observed.is_some() => {
                let mut refusal =
                    over_budget(&over, code, &applied.whose, budget, &under, most, what);
                refusal.record = Some(Box::new(limit_record(applied, Value::Null)));
                if let (Some(list), Some(by)) = (observed.as_deref_mut(), applied.shadow) {
                    list.push((refusal, by));
                }
                reservations.push(Reservation {
                    scope: applied.scope.clone(),
                    per: budget.per,
                    period: period_of(&now, budget.per),
                    usd: 0.0,
                });
                counted.push((applied.scope.clone(), budget.per));
            }
            Err(over) => {
                release_all(spend, reservations);
                return Err(match over {
                    Ok(over) => {
                        let mut refusal =
                            over_budget(&over, code, &applied.whose, budget, &under, most, what);
                        refusal.record = Some(Box::new(limit_record(applied, Value::Null)));
                        refusal
                    }
                    Err(err) => store_unavailable(&err),
                });
            }
        }
    }
    Ok((reservations, counted))
}

/// Gives back reservations that will not be settled by an answer: a batch that ended, or one the provider refused.
pub(crate) fn release_all(spend: &Spend, reservations: Vec<Reservation>) {
    for reservation in &reservations {
        spend.release(reservation);
    }
}

/// The budget counters a request of `who` under `rule` counts against, for `sent` (the model or alias asked for)
/// answered by `model`, with its customer and tags: what its cost is charged to, as `Policy::applied` names them.
pub(crate) fn counted_for(
    policy: &Policy,
    who: &Principal,
    rule: &Rule,
    sent: &str,
    model: &str,
    customer: Option<&str>,
    tags: &[String],
) -> Vec<(String, Period)> {
    policy
        .applied(
            who,
            rule,
            gantry_core::policy::Context {
                sent,
                model,
                customer,
                tags,
            },
        )
        .into_iter()
        .filter_map(|a| match a.limit {
            Limit::Budget(b) => Some((a.scope, b.per)),
            _ => None,
        })
        .collect()
}

/// The cache key: the same body means the same answer only on the same route of the same provider and model, with
/// the same headers that change what the provider does, and only within the scope it was made for.
fn cache_key(ask: &Ask<'_>, scope: &str) -> [u8; 32] {
    let mut joined = Vec::with_capacity(256);
    for part in [scope, ask.provider, ask.model, ask.route] {
        joined.extend_from_slice(part.as_bytes());
        joined.push(0);
    }
    for name in ["anthropic-beta", "anthropic-version"] {
        for value in ask.headers.get_all(name) {
            joined.extend_from_slice(name.as_bytes());
            joined.push(b':');
            joined.extend_from_slice(value.as_bytes());
            joined.push(0);
        }
    }
    joined.extend_from_slice(&sha256(ask.body));
    sha256(&joined)
}

/// The refusal of a request that would pass a budget.
fn over_budget(
    over: &Over,
    code: &'static str,
    whose: &str,
    budget: Budget,
    under: &str,
    most: f64,
    what: &str,
) -> Refusal {
    let held = if over.reserved > 0.0 {
        format!(
            ", and requests in flight hold {} more",
            dollars(over.reserved)
        )
    } else {
        String::new()
    };
    // With money left, a request that asks for fewer output tokens may fit: most of the reserve is output.
    let smaller = if over.spent + over.reserved < budget.usd {
        " A request with a smaller output token limit (max_tokens, or max_output_tokens on /v1/responses) could fit in what is left."
    } else {
        ""
    };
    Refusal::new(
        StatusCode::TOO_MANY_REQUESTS,
        code,
        format!(
            "Refused: {whose} has spent {} of its {} budget for this {}{under}{held}. {what} could cost up to {}, which would pass it.{smaller} The budget starts again at {}. Ask a Gantry admin to raise it if you need more before then.",
            dollars(over.spent),
            dollars(budget.usd),
            budget.per.describe(),
            dollars(most),
            over.resets
        ),
    )
}

/// The most a request could cost: every byte of its body a token, at the dearest price a prompt token can have,
/// and `output` tokens at the output price.
// ponytail: one token per three bytes of body. Tokenizers give fewer for every text and code we know of; a body that
// is mostly base64 images is over-reserved, never under.
fn most_cost(price: &Price, body_bytes: usize, stored: u64, output: u64) -> f64 {
    let input = (body_bytes.div_ceil(3) as u64).max(stored);
    let plain = Usage {
        input,
        output,
        ..Usage::default()
    };
    let written = Usage {
        input: 0,
        cache_write_1h: input,
        ..plain
    };
    price.cost_usd(&plain).max(price.cost_usd(&written))
}

impl Admitted {
    /// Marks whether the provider holds the request now, so a caller who leaves before the answer is charged.
    pub(crate) fn forwarded(&mut self, yes: bool) {
        self.forwarded = yes;
    }

    /// The answer is not kept in the cache (a fallback of another API answered it, in that API's format).
    pub(crate) fn not_cached(&mut self) {
        self.cache = None;
    }

    /// A fallback or another deployment of an alias answered: the usage record names it, and it is charged at its
    /// model's price.
    pub(crate) fn served_by(&mut self, provider: &str, model: &str, price: Option<Price>) {
        if self.provider != provider {
            self.provider = provider.to_string();
        }
        if !model.is_empty() && self.model != model {
            self.model = model.to_string();
            self.price = price;
        }
    }

    /// Ends the request: replaces its reservation with what it cost, keeps a cacheable answer, and writes the
    /// usage record. `usage` is what the provider reported, if it did.
    pub(crate) fn settle(
        self,
        status: StatusCode,
        ended: Ended,
        usage: Option<Usage>,
        hit: bool,
        answer: Option<(Option<HeaderValue>, Bytes)>,
    ) {
        let mut me = self;
        let Some(log) = me.audit.clone() else {
            me.close(status, ended, usage, hit, answer);
            return;
        };
        let decision = me.decision.clone();
        log.append_later(
            move || me.close(status, ended, usage, hit, answer),
            move |result| written(&decision, result),
        );
    }

    /// Settles a whole answer from its frames. Joining them and reading their usage happen on the audit writer's
    /// thread too.
    fn settle_whole(
        self,
        status: StatusCode,
        content_type: Option<HeaderValue>,
        frames: Vec<Bytes>,
    ) {
        let read = move |frames: Vec<Bytes>| {
            let body = match frames.as_slice() {
                [one] => one.clone(),
                _ => Bytes::from(frames.concat()),
            };
            (Usage::from_body(&body), Some((content_type, body)))
        };
        let mut me = self;
        let Some(log) = me.audit.clone() else {
            let (usage, answer) = read(frames);
            me.close(status, Ended::Complete, usage, false, answer);
            return;
        };
        let decision = me.decision.clone();
        log.append_later(
            move || {
                let (usage, answer) = read(frames);
                me.close(status, Ended::Complete, usage, false, answer)
            },
            move |result| written(&decision, result),
        );
    }

    /// The work of [`Admitted::settle`], and the usage record when there is a log to write it to.
    fn close(
        &mut self,
        status: StatusCode,
        ended: Ended,
        usage: Option<Usage>,
        hit: bool,
        answer: Option<(Option<HeaderValue>, Bytes)>,
    ) -> Option<Map<String, Value>> {
        self.forwarded = false;
        let left = ended == Ended::CallerLeft;
        let now = audit::timestamp();
        if let (Some(capture), Some(request), false) =
            (self.spend.capture.clone(), self.captured.take(), hit)
        {
            let stream = self.stream_copy.take();
            capture.take(crate::Captured {
                decision: self.decision.clone(),
                person: self.person.clone(),
                team: self.team.clone(),
                model: self.model.clone(),
                provider: self.provider.clone(),
                route: self.route.clone(),
                request,
                streamed: stream.is_some(),
                answer: match stream {
                    Some(frames) => Some(Bytes::from(frames.concat())),
                    None => answer.as_ref().map(|(_, body)| body.clone()),
                },
            });
        }
        let complete = !matches!(ended, Ended::CutOff | Ended::CallerLeft);
        // An image model priced by the image is charged for each image the answer holds.
        let images = self
            .price
            .as_ref()
            .and_then(|p| p.per_image)
            .filter(|_| self.route.starts_with("/v1/images") && status.is_success())
            .zip(answer.as_ref())
            .and_then(|(each, (_, body))| {
                let answer: Value = serde_json::from_slice(body).ok()?;
                Some(each * answer["data"].as_array()?.len() as f64)
            });
        let cost = if hit {
            Some(0.0)
        } else if images.is_some() {
            images
        } else {
            usage.zip(self.price.as_ref()).map(|(u, p)| p.cost_usd(&u))
        };
        // What the request used against a tokens-per-minute limit: what the provider reported, else what it held.
        let used =
            usage.map(|u| u.input + u.output + u.cache_read + u.cache_write + u.cache_write_1h);
        for (scope, held, grant) in self.tokens.drain(..) {
            let counted = if hit { Some(0) } else { used.or(Some(held)) };
            self.spend.settle_tokens(&scope, held, counted, grant);
        }
        let captured = self.keep_body(answer.as_ref().map(|(_, b)| b), &now);
        // Every budget reserved the same most-it-could-cost, so one of them says what was reserved.
        let reserved = self.reservations.first().map(|r| r.usd);
        // The usage of an answer cut off before its final counts is only what was generated before the cut: the
        // provider bills what it generated, which the caller can make much larger by closing early.
        let partial = !hit && !complete;
        let ceiling = || reserved.or_else(|| self.estimate());
        // An answer that says nothing of its usage, or was cut off before its final counts, is charged the most it
        // could have cost: a budget must not count it as free or cheap. The record says so; the cost stays what was
        // reported.
        // A stream the provider finished without usage (an OpenAI stream without include_usage) and without a
        // budget is charged its streamed text and its prompt estimate, never more than the ceiling. Under a budget
        // it is charged its reservation (QA12-1): a reasoning model's hidden reasoning tokens are billed but never
        // streamed, so the text would let them pass the limit.
        let streamed = self
            .streamed
            .filter(|_| reserved.is_none() && !partial && status.is_success() && cost.is_none())
            .zip(self.price.as_ref())
            .map(|(output, price)| most_cost(price, self.body_len, 0, output));
        let charged = match cost {
            _ if hit => 0.0,
            None if left => ceiling().unwrap_or_default(),
            Some(cost) if status.is_success() && partial => cost.max(ceiling().unwrap_or(0.0)),
            Some(cost) => cost,
            None if status.is_success() => match (streamed, ceiling()) {
                (Some(estimate), Some(ceiling)) => estimate.min(ceiling),
                (Some(estimate), None) => estimate,
                (None, ceiling) => ceiling.unwrap_or_default(),
            },
            None => 0.0,
        };
        // The record holds both figures; the log line makes a wrong limit visible (QA12-4: a max_context below the
        // stored context the provider added, or a max_output below what it generated).
        if let (Some(cost), Some(reserved)) = (cost, reserved) {
            if cost > reserved * 1.001 && !hit {
                eprintln!(
                    "gantry: decision {} cost ${cost:.6}, more than the ${reserved:.6} reserved for it: the price of model \"{}\" under prices: in the policy has a max_context or max_output below what the provider used. Raise it to the model's whole context window and output limit.",
                    self.decision, self.model
                );
            }
        }
        match &self.spend.store {
            // Only a request under a budget reaches the store: its holds given back and its cost counted, in one
            // statement, where every gateway's budgets read it.
            Some(store) if !self.reservations.is_empty() => {
                let mut changes: Vec<Change> = self
                    .reservations
                    .drain(..)
                    .map(|r| Change {
                        bucket: r.bucket(),
                        spent: 0.0,
                        reserved: -r.usd,
                    })
                    .collect();
                if charged > 0.0 && charged.is_finite() {
                    changes.extend(
                        buckets(
                            &self.person_scope,
                            &self.team_scope,
                            &self.key,
                            &self.counted,
                            &now,
                        )
                        .into_iter()
                        .map(|bucket| Change {
                            bucket,
                            spent: charged,
                            reserved: 0.0,
                        }),
                    );
                }
                store.settle(changes);
            }
            _ => {
                for reservation in self.reservations.drain(..) {
                    self.spend.release(&reservation);
                }
            }
        }
        if self.caller_paid != Some(false) {
            self.spend.add(
                &self.person_scope,
                &self.team_scope,
                &self.key,
                &self.counted,
                charged,
                &now,
            );
        }
        for hold in self.parallel.drain(..) {
            self.spend.release_parallel(&hold);
        }
        self.spend.metrics.charged(&self.team, &self.model, charged);
        // What caching saved: a hit, what its answer cost when made; a provider's prompt cache, the prompt priced
        // as if none of it were cached, less what it cost. A cache write costs more than input, so that can be less
        // than nothing.
        let saved = match (hit, usage, self.price.as_ref()) {
            (true, _, _) => self.saved.map(|usd| ("answer", usd)),
            (false, Some(u), Some(price))
                if u.cache_read + u.cache_write + u.cache_write_1h > 0 =>
            {
                let uncached = Usage {
                    input: u.input + u.cache_read + u.cache_write + u.cache_write_1h,
                    output: u.output,
                    ..Usage::default()
                };
                Some(("prompt", price.cost_usd(&uncached) - price.cost_usd(&u)))
            }
            _ => None,
        };
        if let Some((kind, usd)) = saved {
            self.spend.metrics.saved(&self.team, kind, usd);
        }
        if let (Some(keep), Some((content_type, body)), true) = (
            self.cache.take(),
            answer,
            status.is_success() && complete && !hit,
        ) {
            let spend = self.spend.clone();
            let cached = Cached {
                status,
                content_type,
                body,
                expires: Instant::now() + keep.ttl,
                used: 0,
                scope: keep.scope,
                origin: self.decision.clone(),
                cost: charged,
            };
            let (key, vector) = (keep.key, keep.vector);
            let commit: Commit = Box::new(move || {
                locked(&spend.cache).put(key, cached, CACHE_BYTES);
                if let Some((partition, vector)) = vector {
                    locked(&spend.vectors).push(Vector {
                        partition,
                        vector,
                        key,
                    });
                }
            });
            match keep.gate {
                Some(gate) => gate.settled(commit),
                None => commit(),
            }
        }
        self.audit.as_ref()?;
        let mut record = Map::new();
        record.insert("event".into(), "usage".into());
        record.insert("id".into(), self.decision.as_str().into());
        record.insert("time".into(), now.into());
        record.insert("person".into(), self.person.as_str().into());
        record.insert("team".into(), self.team.as_str().into());
        record.insert("key".into(), self.key.as_str().into());
        // Only when set, so records of an install without organizations, customers or tags keep their shape.
        if !self.org.is_empty() {
            record.insert("org".into(), self.org.as_str().into());
        }
        if let Some(customer) = &self.customer {
            record.insert("customer".into(), customer.as_str().into());
        }
        if !self.tags.is_empty() {
            record.insert("tags".into(), self.tags.clone().into());
        }
        if let Some(alias) = &self.alias {
            record.insert("alias".into(), alias.as_str().into());
        }
        record.insert("model".into(), self.model.as_str().into());
        record.insert("provider".into(), self.provider.as_str().into());
        // No answer reached a caller who left before it started.
        record.insert(
            "status".into(),
            if left {
                Value::Null
            } else {
                status.as_u16().into()
            },
        );
        record.insert(
            "ended".into(),
            if complete { "complete" } else { "cut_off" }.into(),
        );
        if hit {
            record.insert("cache".into(), "hit".into());
        }
        let reported = match (hit, usage) {
            (true, _) => "cache_hit",
            _ if left => "caller_left",
            (false, Some(_)) if partial => "partial",
            (false, Some(_)) => "reported",
            (false, None) if streamed.is_some() => "estimated",
            (false, None) => "not_reported",
        };
        record.insert("usage".into(), reported.into());
        let tokens = |n: fn(&Usage) -> u64| match (hit, usage) {
            (true, _) => Value::from(0),
            (false, Some(u)) => Value::from(n(&u)),
            (false, None) => Value::Null,
        };
        record.insert("input_tokens".into(), tokens(|u| u.input));
        record.insert("output_tokens".into(), tokens(|u| u.output));
        record.insert("cache_read_tokens".into(), tokens(|u| u.cache_read));
        record.insert(
            "cache_write_tokens".into(),
            tokens(|u| u.cache_write + u.cache_write_1h),
        );
        record.insert(
            "price".into(),
            if self.price.is_some() {
                "known"
            } else {
                "none"
            }
            .into(),
        );
        record.insert(
            "price_source".into(),
            self.price
                .as_ref()
                .map_or(Value::Null, |p| p.source.as_str().into()),
        );
        record.insert("cost_usd".into(), cost.map_or(Value::Null, Value::from));
        record.insert(
            "reserved_usd".into(),
            reserved.map_or(Value::Null, Value::from),
        );
        record.insert("charged_usd".into(), charged.into());
        if let Some((_, usd)) = saved {
            record.insert("cache_saved_usd".into(), usd.into());
        }
        if let Some(counted) = self.caller_paid {
            record.insert("caller_paid".into(), true.into());
            record.insert(
                "budget".into(),
                if counted { "counted" } else { "not_counted" }.into(),
            );
        }
        record.insert(
            "latency_ms".into(),
            u64::try_from(self.started.elapsed().as_millis())
                .unwrap_or(u64::MAX)
                .into(),
        );
        if captured {
            // The chain says a body was kept, and the console offers it only then.
            record.insert("body".into(), "captured".into());
        }
        record.insert("policy_sha256".into(), self.version.0.as_str().into());
        record.insert("keys_sha256".into(), self.version.1.as_str().into());
        Some(record)
    }
}

impl Admitted {
    /// Keeps the request and its answer, redacted, when its rule captures them. Returns whether it did. Nothing is
    /// kept when the detectors cannot run: a body is never kept unredacted.
    fn keep_body(&mut self, answer: Option<&Bytes>, now: &str) -> bool {
        let (Some(capture), Some(bodies)) = (self.capture.take(), self.spend.bodies.as_ref())
        else {
            return false;
        };
        let answer = answer.cloned().or(capture.answer).unwrap_or_default();
        let redact = |bytes: &Bytes| {
            gantry_core::guard::redact(&String::from_utf8_lossy(bytes))
                .map(|text| gantry_core::insights::cut_body(&text))
        };
        let (request, answer) = match (redact(&capture.request), redact(&answer)) {
            (Ok(request), Ok(answer)) => (request, answer),
            (Err(err), _) | (_, Err(err)) => {
                eprintln!(
                    "gantry: the body of decision {} was not kept: {err}",
                    self.decision
                );
                return false;
            }
        };
        bodies.keep(gantry_core::insights::Body {
            id: self.decision.clone(),
            time: now.to_string(),
            rule: capture.rule,
            expires: gantry_core::insights::now_secs() + u64::from(capture.days) * 86_400,
            viewers: capture.viewers,
            request,
            answer,
        });
        true
    }

    /// The most a request without a budget could have cost, for the charge of one cut off or without usage.
    fn estimate(&self) -> Option<f64> {
        let ((body, route), price) = self.estimate_from.as_ref().zip(self.price.as_ref())?;
        let hints = hints(body).unwrap_or_default();
        let output = output_tokens(&hints, Some(price), route).unwrap_or(UNBUDGETED_OUTPUT_GUESS);
        let stored = stored_tokens(&hints, price, route).unwrap_or(0);
        Some(most_cost(price, body.len(), stored, output))
    }
}

/// How an answer ended, as far as its usage goes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ended {
    /// The whole answer reached the caller.
    Complete,
    /// The caller went after the event that carries the final usage: the counts are whole.
    AfterUsage,
    /// The caller went, or the provider stopped, before the final usage: the counts are only partial.
    CutOff,
    /// The caller went after the request was forwarded and before any answer: there are no counts.
    CallerLeft,
}

fn written(decision: &str, result: std::io::Result<()>) {
    if let Err(err) = result {
        eprintln!("gantry: the usage record of decision {decision} could not be written: {err}");
    }
}

/// The provider's answer on its way to the caller. Each frame is passed on as it comes; usage is read by a scanner
/// as a stream passes, or from the frames of a whole answer, kept by reference (not copied) until it ends. When the
/// answer ends or the caller goes, the request is settled on the audit writer's thread, off the answer's path.
pub(crate) struct Metered {
    inner: Body,
    admitted: Option<Admitted>,
    status: StatusCode,
    content_type: Option<HeaderValue>,
    scanner: Option<UsageScanner>,
    frames: Option<Vec<Bytes>>,
    kept: usize,
    ended: bool,
}

impl Metered {
    pub(crate) fn wrap(response: Response, admitted: Admitted) -> Response {
        let status = response.status();
        let content_type = response.headers().get(header::CONTENT_TYPE).cloned();
        let stream = content_type
            .as_ref()
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("text/event-stream"));
        let keep = !stream || admitted.capture.is_some() || admitted.captured.is_some();
        response.map(|inner| {
            Body::new(Metered {
                inner,
                admitted: Some(admitted),
                status,
                content_type,
                // A captured stream is kept too, for its body.
                frames: keep.then(Vec::new),
                scanner: stream.then(UsageScanner::new),
                kept: 0,
                ended: false,
            })
        })
    }

    fn finish(&mut self) {
        let Some(admitted) = self.admitted.take() else {
            return;
        };
        let complete = self.ended || self.inner.is_end_stream();
        let (status, content_type) = (self.status, self.content_type.take());
        match (self.scanner.take(), self.frames.take()) {
            (Some(scanner), frames) => {
                let mut admitted = admitted;
                if let (Some(capture), Some(frames)) = (admitted.capture.as_mut(), &frames) {
                    capture.answer = Some(Bytes::from(frames.concat()));
                }
                // Handed to the embedder's capture only when it wants this request's text.
                if admitted.captured.is_some() {
                    admitted.stream_copy = frames;
                }
                admitted.streamed = scanner.streamed_output();
                let (usage, done) = scanner.finish_final();
                let ended = match (complete, done) {
                    (true, _) => Ended::Complete,
                    (false, true) => Ended::AfterUsage,
                    (false, false) => Ended::CutOff,
                };
                admitted.settle(status, ended, usage, false, None)
            }
            (None, Some(frames)) if complete => admitted.settle_whole(status, content_type, frames),
            _ => admitted.settle(status, Ended::CutOff, None, false, None),
        }
    }
}

impl http_body::Body for Metered {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = &mut *self;
        let polled = Pin::new(&mut this.inner).poll_frame(cx);
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    if let Some(scanner) = &mut this.scanner {
                        scanner.feed(data);
                    }
                    this.kept += data.len();
                    if this.kept > MAX_ANSWER_COPY {
                        this.frames = None;
                    }
                    if let Some(frames) = &mut this.frames {
                        // A reference to the same bytes, not a copy.
                        frames.push(data.clone());
                    }
                }
            }
            Poll::Ready(None) => {
                this.ended = true;
                this.finish();
            }
            _ => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for Metered {
    fn drop(&mut self) {
        self.finish();
    }
}

/// What a batch line could cost at its model's full price, as a budget reserves a live request: Err says why that
/// is unknown.
pub(crate) fn most_for(body: &[u8], route: &str, price: &Price) -> Result<f64, String> {
    let hints = hints(body)?;
    let output = output_tokens(&hints, Some(price), route).ok_or_else(|| {
        "it does not say how many output tokens it may use (max_tokens, or max_output_tokens on /v1/responses), and its model has no max_output in its price".to_string()
    })?;
    let stored = stored_tokens(&hints, price, route).map_err(|fields| {
        format!("it names stored context ({fields}), which the provider adds to the prompt and Gantry cannot see")
    })?;
    Ok(
        match price.per_image.filter(|_| route.starts_with("/v1/images")) {
            Some(each) => each * hints.n.unwrap_or(1) as f64,
            None => most_cost(price, body.len(), stored, output),
        },
    )
}

impl Reservation {
    /// The reservation as a batch's record keeps it, so a restart holds it again until the batch is settled.
    pub(crate) fn to_json(&self) -> Value {
        serde_json::json!({ "scope": self.scope, "per": self.per.word(), "period": self.period, "usd": self.usd })
    }

    pub(crate) fn from_json(value: &Value) -> Option<Self> {
        let per = match value["per"].as_str()? {
            "day" => Period::Day,
            "month" => Period::Month,
            _ => return None,
        };
        Some(Self {
            scope: value["scope"].as_str()?.to_string(),
            per,
            period: value["period"].as_str()?.to_string(),
            usd: value["usd"]
                .as_f64()
                .filter(|usd| usd.is_finite() && *usd >= 0.0)?,
        })
    }
}

impl Spend {
    /// Holds again, after a restart, what a batch still in flight reserved. With a store the store kept it.
    pub(crate) fn hold(&self, reservation: &Reservation) {
        if self.store.is_some() {
            return;
        }
        let mut ledger = locked(&self.ledger);
        if let Some(bucket) = Self::bucket(
            &mut ledger,
            &reservation.scope,
            reservation.per,
            &reservation.period,
        ) {
            bucket.reserved += reservation.usd;
        }
    }
}

/// One metered unit that is not a live answer: a line of a finished batch, or one response of a realtime session.
pub(crate) struct Line<'a> {
    /// The decision that admitted it, as the usage record's id.
    pub decision: &'a str,
    pub person: &'a str,
    pub team: &'a str,
    pub key: &'a str,
    /// The organization, end customer and tags, for the usage record and the counters they name.
    pub org: &'a str,
    pub customer: Option<&'a str>,
    pub tags: &'a [String],
    /// Every budget counter the line counts against beyond its person, team and key (`counted_for`).
    pub counted: &'a [(String, Period)],
    pub model: &'a str,
    pub provider: &'a str,
    pub version: (&'a str, &'a str),
    pub price: Option<Price>,
    pub usage: Option<Usage>,
    /// The part of the model's price charged: batch lines cost half (OpenAI and Anthropic batch pricing).
    pub share: f64,
    /// Charged when the provider says it answered and reports no usage: the line's part of what was reserved.
    pub unreported: f64,
    pub succeeded: bool,
    /// Fields the usage record carries besides the usual ones: the batch, the line, the session.
    pub extra: Map<String, Value>,
}

/// Counts what a line cost against its person, team and key, as an answer's settlement does, and returns the usage
/// record to write. It reserves nothing: whatever reserved for it is given back by its owner.
pub(crate) fn charge(spend: &Spend, line: Line<'_>) -> (f64, Map<String, Value>) {
    let now = audit::timestamp();
    let cost = line
        .usage
        .zip(line.price.as_ref())
        .map(|(u, p)| p.cost_usd(&u) * line.share);
    let charged = match cost {
        Some(cost) => cost,
        None if line.succeeded => line.unreported,
        None => 0.0,
    };
    // Inside the organization, as an answer's settlement counts them.
    let who = Principal {
        name: line.person.to_string(),
        team: line.team.to_string(),
        org: line.org.to_string(),
        ..Principal::default()
    };
    let (person_scope, team_scope) = (who.person_scope(), who.team_scope());
    if charged > 0.0 && charged.is_finite() {
        if let Some(store) = &spend.store {
            store.settle(
                buckets(&person_scope, &team_scope, line.key, line.counted, &now)
                    .into_iter()
                    .map(|bucket| Change {
                        bucket,
                        spent: charged,
                        reserved: 0.0,
                    })
                    .collect(),
            );
        }
        spend.add(
            &person_scope,
            &team_scope,
            line.key,
            line.counted,
            charged,
            &now,
        );
    }
    spend.metrics.charged(line.team, line.model, charged);
    let mut record = Map::new();
    record.insert("event".into(), "usage".into());
    record.insert("id".into(), line.decision.into());
    record.insert("time".into(), now.into());
    record.insert("person".into(), line.person.into());
    record.insert("team".into(), line.team.into());
    record.insert("key".into(), line.key.into());
    // Only when set, as on an answer's record, so a restart counts the line against the same budgets.
    if !line.org.is_empty() {
        record.insert("org".into(), line.org.into());
    }
    if let Some(customer) = line.customer {
        record.insert("customer".into(), customer.into());
    }
    if !line.tags.is_empty() {
        record.insert("tags".into(), line.tags.to_vec().into());
    }
    record.insert("model".into(), line.model.into());
    record.insert("provider".into(), line.provider.into());
    record.insert("ended".into(), "complete".into());
    let reported = match (line.usage, line.succeeded) {
        (Some(_), _) => "reported",
        (None, true) => "not_reported",
        (None, false) => "failed",
    };
    record.insert("usage".into(), reported.into());
    let tokens = |n: fn(&Usage) -> u64| line.usage.map_or(Value::Null, |u| Value::from(n(&u)));
    record.insert("input_tokens".into(), tokens(|u| u.input));
    record.insert("output_tokens".into(), tokens(|u| u.output));
    record.insert("cache_read_tokens".into(), tokens(|u| u.cache_read));
    record.insert(
        "cache_write_tokens".into(),
        tokens(|u| u.cache_write + u.cache_write_1h),
    );
    // Audio is priced apart (realtime): its counts are written only when there were any.
    if line
        .usage
        .is_some_and(|u| u.input_audio + u.output_audio + u.cache_read_audio > 0)
    {
        record.insert("input_audio_tokens".into(), tokens(|u| u.input_audio));
        record.insert("output_audio_tokens".into(), tokens(|u| u.output_audio));
        record.insert(
            "cache_read_audio_tokens".into(),
            tokens(|u| u.cache_read_audio),
        );
    }
    record.insert(
        "price".into(),
        if line.price.is_some() {
            "known"
        } else {
            "none"
        }
        .into(),
    );
    record.insert(
        "price_source".into(),
        line.price
            .as_ref()
            .map_or(Value::Null, |p| p.source.as_str().into()),
    );
    record.insert("price_share".into(), line.share.into());
    record.insert("cost_usd".into(), cost.map_or(Value::Null, Value::from));
    record.insert("charged_usd".into(), charged.into());
    record.insert("policy_sha256".into(), line.version.0.into());
    record.insert("keys_sha256".into(), line.version.1.into());
    record.extend(line.extra);
    (charged, record)
}

/// Whether every budget in `budgets` (from `Policy::applied`) still has room: false once one is spent, or when the
/// store that keeps them cannot be asked. A realtime session ends at the first false.
pub(crate) async fn room(spend: &Spend, budgets: &[Applied]) -> bool {
    let now = audit::timestamp();
    for applied in budgets {
        let Limit::Budget(budget) = applied.limit else {
            continue;
        };
        // Nothing is reserved: a reservation of zero only asks whether spent and reserved already fill the budget.
        if spend
            .reserve_shared(&applied.scope, budget, 0.0, &now)
            .await
            .is_err()
        {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn periods_and_their_ends() {
        let now = "2026-12-31T23:59:59.999Z";
        assert_eq!(period_of(now, Period::Month), "2026-12");
        assert_eq!(period_of(now, Period::Day), "2026-12-31");
        assert_eq!(resets("2026-12", Period::Month), "2027-01-01 00:00 UTC");
        assert_eq!(resets("2026-11", Period::Month), "2026-12-01 00:00 UTC");
        assert_eq!(resets("2026-12-31", Period::Day), "2027-01-01 00:00 UTC");
        assert_eq!(resets("2028-02-28", Period::Day), "2028-02-29 00:00 UTC");
        assert_eq!(resets("2026-02-28", Period::Day), "2026-03-01 00:00 UTC");
        assert_eq!(resets("2026-11-13", Period::Day), "2026-11-14 00:00 UTC");
    }

    #[test]
    fn a_reservation_counts_until_it_is_settled_and_a_new_period_starts_at_zero() {
        let spend = Spend::default();
        let budget = Budget {
            usd: 10.0,
            per: Period::Month,
        };
        let now = audit::timestamp();
        let first = spend.reserve("team:t", budget, 6.0, &now);
        assert!(first.is_ok());
        // 6 reserved: another 6 would pass 10.
        let over = spend.reserve("team:t", budget, 6.0, &now).err();
        assert!(over.is_some_and(|o| o.reserved == 6.0 && o.spent == 0.0));
        if let Ok(first) = first {
            spend.release(&first);
        }
        spend.add("person:p", "team:t", "", &[], 1.5, &now);
        assert_eq!(spend.spent("team:t", Period::Month), 1.5);
        assert_eq!(spend.spent("person:p", Period::Day), 1.5);
        assert!(spend.reserve("team:t", budget, 8.5, &now).is_ok());
        // Spend from an earlier month is not counted, and a record from last month does not reset this one.
        spend.add(
            "person:p",
            "team:t",
            "",
            &[],
            100.0,
            "2000-01-01T00:00:00.000Z",
        );
        assert_eq!(spend.spent("team:t", Period::Month), 1.5);
    }

    #[test]
    fn the_rate_is_a_sliding_minute() {
        let spend = Spend::default();
        let start = Instant::now();
        assert!(spend.rate("p", 2, start).is_ok());
        assert!(spend.rate("p", 2, start + Duration::from_secs(20)).is_ok());
        assert_eq!(spend.rate("p", 2, start + Duration::from_secs(30)), Err(30));
        assert!(spend.rate("q", 2, start + Duration::from_secs(30)).is_ok());
        assert!(spend.rate("p", 2, start + Duration::from_secs(60)).is_ok());
    }

    #[test]
    fn the_cache_drops_the_least_recently_used_answer_to_stay_in_size() {
        let mut cache = Cache::default();
        let now = Instant::now();
        let entry = |text: &'static str, expires| Cached {
            status: StatusCode::OK,
            content_type: None,
            body: Bytes::from_static(text.as_bytes()),
            expires,
            used: 0,
            scope: "s".to_string(),
            origin: String::new(),
            cost: 0.0,
        };
        let later = now + Duration::from_secs(60);
        cache.put([1; 32], entry("aaaa", later), 10);
        cache.put([2; 32], entry("bbbb", later), 10);
        assert!(cache.get(&[1; 32], "s", now).is_some());
        // 12 bytes do not fit in 10: b, used least recently, goes.
        cache.put([3; 32], entry("cccc", later), 10);
        assert!(cache.get(&[2; 32], "s", now).is_none());
        assert!(cache.get(&[1; 32], "s", now).is_some() && cache.get(&[3; 32], "s", now).is_some());
        assert_eq!(cache.bytes, 8);
        cache.put([4; 32], entry("much too large", later), 10);
        assert!(cache.get(&[4; 32], "s", now).is_none());
        cache.put([5; 32], entry("e", now), 10);
        assert!(cache.get(&[5; 32], "s", now).is_none());
        assert_eq!(cache.bytes, 8);
    }

    #[test]
    fn a_cached_answer_is_read_only_in_its_own_scope() {
        let mut cache = Cache::default();
        let now = Instant::now();
        let entry = Cached {
            status: StatusCode::OK,
            content_type: None,
            body: Bytes::from_static(b"a"),
            expires: now + Duration::from_secs(60),
            used: 0,
            scope: "rule\0person:cara".to_string(),
            origin: "d1".to_string(),
            cost: 0.5,
        };
        cache.put([1; 32], entry, 10);
        assert!(cache.get(&[1; 32], "rule\0person:otto", now).is_none());
        assert!(!cache.live(&[1; 32], "rule\0team:ops", now));
        let found = cache.get(&[1; 32], "rule\0person:cara", now);
        assert_eq!(
            found.map(|f| (f.origin, f.cost)),
            Some(("d1".to_string(), 0.5))
        );
    }

    #[test]
    fn the_semantic_index_compares_only_within_a_partition_and_above_the_threshold() {
        let mut vectors = Vectors::default();
        let push = |vectors: &mut Vectors, partition: u8, vector: Vec<f32>, key: u8| {
            vectors.push(Vector {
                partition: [partition; 32],
                vector,
                key: [key; 32],
            });
        };
        push(&mut vectors, 1, vec![1.0, 0.0], 10);
        push(&mut vectors, 1, vec![0.0, 1.0], 11);
        push(&mut vectors, 2, vec![1.0, 0.0], 20);
        push(&mut vectors, 1, vec![1.0, 0.0, 0.0], 12);
        let near = vectors.near(&[1; 32], &[0.9, 0.1], 0.9);
        assert_eq!(near.iter().map(|n| n.0).collect::<Vec<_>>(), vec![[10; 32]]);
        assert!(vectors.near(&[3; 32], &[1.0, 0.0], 0.1).is_empty());
        assert_eq!(cosine(&[0.0, 0.0], &[1.0, 0.0]), None);
        // The oldest goes first once the index is full.
        for i in 0..MAX_VECTORS {
            let mut key = [9; 32];
            key[..8].copy_from_slice(&(i as u64).to_le_bytes());
            vectors.push(Vector {
                partition: [9; 32],
                vector: vec![1.0],
                key,
            });
        }
        assert!(vectors.0.len() <= MAX_VECTORS);
        assert!(vectors.near(&[2; 32], &[1.0, 0.0], 0.9).is_empty());
    }

    #[test]
    fn a_gated_answer_is_kept_only_after_an_explicit_pass_in_either_order() {
        let kept = Arc::new(Mutex::new(0));
        let commit = |kept: &Arc<Mutex<i32>>| -> Commit {
            let kept = kept.clone();
            Box::new(move || *locked(&kept) += 1)
        };
        let gate = Gate::default();
        gate.settled(commit(&kept));
        gate.passed(true);
        let gate = Gate::default();
        gate.passed(true);
        gate.settled(commit(&kept));
        assert_eq!(*locked(&kept), 2);
        let gate = Gate::default();
        gate.settled(commit(&kept));
        gate.passed(false);
        let gate = Gate::default();
        gate.passed(false);
        gate.settled(commit(&kept));
        // Never decided: a check that failed or was never recorded.
        Gate::default().settled(commit(&kept));
        assert_eq!(*locked(&kept), 2);
    }

    #[test]
    fn the_semantic_text_leaves_roles_and_parameters_in_the_partition() {
        let mut body = serde_json::json!({
            "model": "m",
            "temperature": 0,
            "system": "be terse",
            "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}]
        });
        let mut texts = Vec::new();
        take_texts(&mut body, &mut texts);
        assert_eq!(texts, vec!["be terse", "hi"]);
        assert_eq!(body["messages"][0]["role"], "user");
        assert_eq!(body["temperature"], 0);
        assert_eq!(body["messages"][0]["content"][0]["text"], "");
    }

    #[test]
    fn the_most_a_request_could_cost_uses_the_dearest_prompt_price() {
        let price = Price {
            input: 2.0,
            output: 10.0,
            cache_read: None,
            cache_write: None,
            cache_write_1h: Some(4.0),
            long_context: None,
            max_output: None,
            max_context: None,
            per_image: None,
            ..Price::default()
        };
        // 3,000,000 bytes is 1,000,000 tokens at 4 dollars, and 1000 output tokens at 10 dollars per million.
        let most = most_cost(&price, 3_000_000, 0, 1000);
        assert!((most - 4.01).abs() < 1e-9, "{most}");
    }

    #[test]
    fn the_output_reserved_is_the_largest_asked_else_the_model_maximum() -> Result<(), String> {
        let price = Price {
            input: 1.0,
            output: 1.0,
            cache_read: None,
            cache_write: None,
            cache_write_1h: None,
            long_context: None,
            max_output: Some(16384),
            max_context: None,
            per_image: None,
            ..Price::default()
        };
        let out = |body: &str, route: &str| {
            hints(body.as_bytes()).map(|h| output_tokens(&h, Some(&price), route))
        };
        assert_eq!(
            out(
                r#"{"max_tokens":1,"max_completion_tokens":900}"#,
                "/v1/chat/completions"
            )?,
            Some(900)
        );
        assert_eq!(
            out(
                r#"{"max_output_tokens":5,"max_tokens":null}"#,
                "/v1/responses"
            )?,
            Some(5)
        );
        assert_eq!(
            out(r#"{"model":"m"}"#, "/v1/chat/completions")?,
            Some(16384)
        );
        assert_eq!(out(r#"{"input":"x"}"#, "/v1/embeddings")?, Some(0));
        let unpriced = Price {
            max_output: None,
            ..price.clone()
        };
        assert_eq!(
            hints(b"{}").map(|h| output_tokens(&h, Some(&unpriced), "/v1/messages"))?,
            None
        );
        for bad in [
            r#"{"max_tokens":1,"max_tokens":2}"#,
            r#"{"max_tokens":"9"}"#,
            r#"{"max_tokens":1.5}"#,
            r#"{"max_tokens":-1}"#,
            r#"{"stream":"yes"}"#,
            r#"{"model":"a","model":"b"}"#,
            r#"{"messages":[],"messages":[]}"#,
            r#"{"max\u005ftokens":1,"max_tokens":2}"#,
            "[1]",
            "{} {}",
        ] {
            assert!(hints(bad.as_bytes()).is_err(), "{bad}");
        }
        Ok(())
    }
}
