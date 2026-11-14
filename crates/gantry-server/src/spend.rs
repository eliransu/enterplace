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
    policy::{Budget, Period, Principal, Rule, Who},
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
    /// With a store: this gateway's lease on each rate-limit scope. One lease asked for at a time per scope, so a
    /// burst waits for it instead of leasing the whole limit in pieces.
    leases: Mutex<HashMap<String, Arc<tokio::sync::Mutex<Leased>>>>,
    pub(crate) metrics: Arc<crate::metrics::Metrics>,
    /// Shared with other gateways when the policy has `store:`: budgets are then reserved and settled there, and
    /// the ledger above only counts for this process.
    pub(crate) store: Option<Arc<dyn Store>>,
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
fn period_of(time: &str, per: Period) -> &str {
    let len = match per {
        Period::Month => 7,
        Period::Day => 10,
    };
    time.get(..len).unwrap_or(time)
}

/// When a period ends, as `2026-12-01 00:00 UTC`.
fn resets(period: &str) -> String {
    let mut parts = period.split('-').map(|p| p.parse::<u32>().unwrap_or(1));
    let (year, month, day) = (
        parts.next().unwrap_or(1970),
        parts.next().unwrap_or(1),
        parts.next(),
    );
    let next_month = |y: u32, m: u32| if m == 12 { (y + 1, 1) } else { (y, m + 1) };
    let (y, m, d) = match day {
        None => {
            let (y, m) = next_month(year, month);
            (y, m, 1)
        }
        Some(day) => {
            let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
            let last = match month {
                2 if leap => 29,
                2 => 28,
                4 | 6 | 9 | 11 => 30,
                _ => 31,
            };
            if day < last {
                (year, month, day + 1)
            } else {
                let (y, m) = next_month(year, month);
                (y, m, 1)
            }
        }
    };
    format!("{y:04}-{m:02}-{d:02} 00:00 UTC")
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

/// The buckets a cost counts in: its person, team and key, for the day and the month of `time`.
fn buckets(person: &str, team: &str, key: &str, time: &str) -> Vec<Counter> {
    let mut scopes = vec![format!("person:{person}"), format!("team:{team}")];
    // Records written before keys were named in usage records have no key: they count for person and team only.
    if !key.is_empty() {
        scopes.push(format!("key:{key}"));
    }
    let mut buckets = Vec::with_capacity(scopes.len() * 2);
    for scope in scopes {
        for per in [Period::Day, Period::Month] {
            buckets.push(Counter {
                scope: scope.clone(),
                per,
                period: period_of(time, per).to_string(),
            });
        }
    }
    buckets
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
        let mut ledger = locked(&self.ledger);
        let Some(bucket) = Self::bucket(&mut ledger, scope, budget.per, period) else {
            // The clock went back past a period boundary. Counting nothing would let spend through unchecked.
            return Err(Over {
                spent: 0.0,
                reserved: 0.0,
                resets: resets(period),
            });
        };
        if bucket.spent + bucket.reserved + usd > budget.usd {
            return Err(Over {
                spent: bucket.spent,
                reserved: bucket.reserved,
                resets: resets(period),
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
        let period = period_of(now, budget.per).to_string();
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
                resets: resets(&period),
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

    /// Counts what a request cost against its person, its team and its key, for the day and the month of `time`.
    fn add(&self, person: &str, team: &str, key: &str, usd: f64, time: &str) {
        if usd <= 0.0 || !usd.is_finite() {
            return;
        }
        let mut ledger = locked(&self.ledger);
        for b in buckets(person, team, key, time) {
            if let Some(bucket) = Self::bucket(&mut ledger, &b.scope, b.per, &b.period) {
                bucket.spent += usd;
            }
        }
    }

    /// Sums the usage records of the current month from the audit log, so a restart does not forget spend.
    // ponytail: reads the whole log at start, as the chain check before it does. A checkpoint comes with that one.
    pub(crate) fn replay(&self, path: &Path) -> Result<(), String> {
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
        let month = period_of(&now, Period::Month);
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
            if period_of(text("time"), Period::Month) != month {
                continue;
            }
            // Caller-paid spend the rule kept out of its budgets stays out after a restart too.
            if record["budget"] == "not_counted" {
                continue;
            }
            let charged = record["charged_usd"].as_f64().unwrap_or_default();
            self.add(
                text("person"),
                text("team"),
                text("key"),
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

    fn get(
        &mut self,
        key: &[u8; 32],
        now: Instant,
    ) -> Option<(StatusCode, Option<HeaderValue>, Bytes)> {
        if self.entries.get(key).is_some_and(|c| c.expires <= now) {
            self.remove(key);
        }
        self.tick += 1;
        let tick = self.tick;
        let entry = self.entries.get_mut(key)?;
        self.order.remove(&entry.used);
        entry.used = tick;
        self.order.insert(tick, *key);
        Some((entry.status, entry.content_type.clone(), entry.body.clone()))
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
    cache: Option<([u8; 32], Duration)>,
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
}

/// What `admit` decided.
pub(crate) enum Admit {
    /// The cache holds the answer: it never reaches the provider.
    Hit(Response, Box<Admitted>),
    Go(Meter, Option<&'static str>),
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
}

/// Applies the rule's cache, rate and budget to an allowed request, in that order: a cached answer costs nothing
/// and uses no provider capacity, so it is neither rate limited nor charged.
pub(crate) async fn admit(
    spend: &Arc<Spend>,
    audit: Option<&Arc<AuditLog>>,
    ask: Ask<'_>,
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
        body_len: ask.body.len(),
        streamed: None,
        route: ask.route.to_string(),
        tokens: Vec::new(),
        forwarded: false,
        caller_paid: ask.caller_paid,
    };
    // The caller pays their provider: unless the rule says otherwise, budgets (what the organization pays) do not
    // reserve or count it. Rate and token limits still hold.
    let budgeted =
        (limits.budget.is_some() || ask.person.budget.is_some()) && ask.caller_paid != Some(false);
    let tpm = limits.tpm.is_some() || ask.person.tpm.is_some();
    if !budgeted && !ask.free {
        admitted.estimate_from = Some((ask.body.clone(), ask.route.to_string()));
    }
    // An audio upload is a form, not JSON: it carries none of the fields read here.
    let form = ask.route.starts_with("/v1/audio/transcriptions");
    let hints: Hints = if (budgeted || tpm || limits.cache_ttl_seconds.is_some()) && !form {
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
    let no_store = ask
        .headers
        .get_all(header::CACHE_CONTROL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.to_ascii_lowercase().contains("no-store"));
    // Counting tokens is cheap and its answer is not an answer to the request: it is never cached. Nor is a Responses
    // request naming stored context (QA12-4): the conversation or stored prompt can change while the body does not.
    let stored = !hints.stored.is_empty() && ask.route.starts_with("/v1/responses");
    if let Some(ttl) = limits.cache_ttl_seconds {
        if hints.stream != Some(true) && !no_store && !ask.free && !stored {
            let key = cache_key(&ask);
            if let Some((status, content_type, body)) =
                locked(&spend.cache).get(&key, Instant::now())
            {
                let mut response = (status, body).into_response();
                if let Some(content_type) = content_type {
                    response
                        .headers_mut()
                        .insert(header::CONTENT_TYPE, content_type);
                }
                response.headers_mut().insert(
                    HeaderName::from_static("x-gantry-cache"),
                    HeaderValue::from_static("hit"),
                );
                return Ok(Admit::Hit(response, Box::new(admitted)));
            }
            cache_word = Some("miss");
            admitted.cache = Some((key, Duration::from_secs(ttl)));
        }
    }
    if let Some(rpm) = limits.rpm {
        let counted = match &spend.store {
            None => spend.rate(&ask.person.name, rpm, Instant::now()),
            Some(store) => match spend
                .take(
                    store,
                    &format!("rpm:{}", ask.person.name),
                    1,
                    u64::from(rpm),
                )
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
                    "Refused: \"{}\" has sent {rpm} requests in the last minute, the most rule \"{}\" allows. Send this one again in {wait} seconds.",
                    ask.person.name, ask.rule.name
                ),
            );
            refusal.retry_after = Some(wait);
            refusal.record = Some(Box::new(
                serde_json::json!({ "limit": { "kind": "rpm", "of": "rule", "value": rpm } }),
            ));
            return Err(refusal);
        }
    }
    if tpm && !ask.free {
        // The most tokens this request could use: every three bytes of its body one, and the output it may write.
        let output = output_tokens(&hints, admitted.price.as_ref(), ask.route).ok_or_else(|| {
            Refusal::new(
                StatusCode::BAD_REQUEST,
                "max_tokens_needed",
                format!(
                    "Refused: a tokens-per-minute limit applies to this request, and it does not say how many output tokens it may use, and {named} has no max_output in its price, so the tokens it could use are unknown. Send max_tokens (max_output_tokens on /v1/responses) with the request, or ask a Gantry admin to set max_output for the model under prices: in the policy."
                ),
            )
        })?;
        let most = (ask.body.len().div_ceil(3) as u64).saturating_add(output);
        let team_scope = match &ask.rule.who {
            Who::Team(team) => format!("team:{team}"),
            Who::Name(_) | Who::Any => format!("person:{}", ask.person.name),
        };
        let limits = [
            limits
                .tpm
                .map(|n| (team_scope, n, format!("rule \"{}\"", ask.rule.name), "rule")),
            ask.person.tpm.map(|n| {
                (
                    format!("key:{}", ask.person.key),
                    n,
                    format!("the key {} of \"{}\"", ask.person.key, ask.person.name),
                    "key",
                )
            }),
        ];
        for (scope, limit, whose, of) in limits.into_iter().flatten() {
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
                    refusal.record = Some(Box::new(
                        serde_json::json!({ "limit": { "kind": "tpm", "of": of, "value": limit, "request_could_use": most } }),
                    ));
                    return Err(refusal);
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
    if budgeted && !ask.free {
        let Some(price) = &admitted.price else {
            // The loader refuses a rule budget over an unpriced model, so only a key budget or a policy built in
            // code gets here.
            return Err(Refusal::new(
                StatusCode::FORBIDDEN,
                "no_price",
                format!(
                    "Refused: a budget applies to this request (rule \"{}\" or the key of \"{}\") and {named} has no price, so its spend could not be counted. Ask a Gantry admin to add its price under prices: in the policy.",
                    ask.rule.name, ask.person.name
                ),
            ));
        };
        let Some(output) = output_tokens(&hints, Some(price), ask.route) else {
            let whose = match (limits.budget.is_some(), ask.person.budget.is_some()) {
                (true, true) => format!(
                    "the budget of rule \"{}\" and of the key of \"{}\" apply",
                    ask.rule.name, ask.person.name
                ),
                (true, false) => format!("the budget of rule \"{}\" applies", ask.rule.name),
                _ => format!("the key of \"{}\" has a budget", ask.person.name),
            };
            // Each API names its output limit differently; the caller can only send its own route's.
            let images = ask.route.starts_with("/v1/images");
            if images || ask.route.starts_with("/v1/audio/speech") {
                let per_image = if images { "per_image or " } else { "" };
                return Err(Refusal::new(
                    StatusCode::BAD_REQUEST,
                    "max_tokens_needed",
                    format!(
                        "Refused: {whose} to this request, and {named} is priced by the token with no max_output, so the most its generated output could cost is unknown. Ask a Gantry admin to set {per_image}max_output for the model under prices: in the policy."
                    ),
                ));
            }
            let field = if ask.route.starts_with("/v1/responses") {
                "max_output_tokens"
            } else if ask.route.starts_with("/v1/messages") {
                "max_tokens"
            } else {
                "max_tokens (or max_completion_tokens)"
            };
            return Err(Refusal::new(
                StatusCode::BAD_REQUEST,
                "max_tokens_needed",
                format!(
                    "Refused: {whose} to this request, and it does not say how many output tokens it may use, and {named} has no max_output in its price, so the most it could cost is unknown. Send {field} with the request, or ask a Gantry admin to set max_output for the model under prices: in the policy."
                ),
            ));
        };
        let context = stored_tokens(&hints, price, ask.route).map_err(|fields| {
            Refusal::new(
                StatusCode::BAD_REQUEST,
                "stored_context",
                format!(
                    "Refused: a budget applies to this request and it names stored context ({fields}), which the provider adds to the prompt and Gantry cannot see, so the most it could cost is unknown. Send the whole conversation in input instead (as Codex does, with store: false), or ask a Gantry admin to set max_context for model \"{}\" under prices: in the policy, so such a request reserves the model's whole context.",
                    ask.model
                ),
            )
        })?;
        let most = match price
            .per_image
            .filter(|_| ask.route.starts_with("/v1/images"))
        {
            Some(each) => each * hints.n.unwrap_or(1) as f64,
            None => most_cost(price, ask.body.len(), context, output),
        };
        let now = audit::timestamp();
        if let Some(budget) = limits.budget {
            let (scope, whose) = match &ask.rule.who {
                Who::Team(team) => (format!("team:{team}"), format!("team \"{team}\"")),
                Who::Name(_) | Who::Any => (
                    format!("person:{}", ask.person.name),
                    format!("\"{}\"", ask.person.name),
                ),
            };
            let under = format!(" under rule \"{}\"", ask.rule.name);
            let reservation = spend
                .reserve_shared(&scope, budget, most, &now)
                .await
                .map_err(|over| match over {
                    Ok(over) => over_budget(&over, "budget_exceeded", &whose, budget, &under, most),
                    Err(err) => store_unavailable(&err),
                })?;
            admitted.reservations.push(reservation);
        }
        if let Some(budget) = ask.person.budget {
            let whose = format!("the key {} of \"{}\"", ask.person.key, ask.person.name);
            let reservation = spend
                .reserve_shared(&format!("key:{}", ask.person.key), budget, most, &now)
                .await
                .map_err(|over| match over {
                    Ok(over) => over_budget(&over, "key_budget_exceeded", &whose, budget, "", most),
                    Err(err) => store_unavailable(&err),
                })?;
            admitted.reservations.push(reservation);
        }
    }
    Ok(Admit::Go(
        Meter(Arc::new(Mutex::new(Some(admitted)))),
        cache_word,
    ))
}

/// The cache key: the same body means the same answer only on the same route of the same provider and model, with
/// the same headers that change what the provider does.
fn cache_key(ask: &Ask<'_>) -> [u8; 32] {
    let mut joined = Vec::with_capacity(256);
    for part in [ask.provider, ask.model, ask.route] {
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
            "Refused: {whose} has spent {} of its {} budget for this {}{under}{held}. This request could cost up to {}, which would pass it.{smaller} The budget starts again at {}. Ask a Gantry admin to raise it if you need more before then.",
            dollars(over.spent),
            dollars(budget.usd),
            budget.per.word(),
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
                        buckets(&self.person, &self.team, &self.key, &now)
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
            self.spend
                .add(&self.person, &self.team, &self.key, charged, &now);
        }
        self.spend.metrics.charged(&self.team, &self.model, charged);
        if let (Some((key, ttl)), Some((content_type, body)), true) = (
            self.cache.take(),
            answer,
            status.is_success() && complete && !hit,
        ) {
            locked(&self.spend.cache).put(
                key,
                Cached {
                    status,
                    content_type,
                    body,
                    expires: Instant::now() + ttl,
                    used: 0,
                },
                CACHE_BYTES,
            );
        }
        self.audit.as_ref()?;
        let mut record = Map::new();
        record.insert("event".into(), "usage".into());
        record.insert("id".into(), self.decision.as_str().into());
        record.insert("time".into(), now.into());
        record.insert("person".into(), self.person.as_str().into());
        record.insert("team".into(), self.team.as_str().into());
        record.insert("key".into(), self.key.as_str().into());
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
        if let Some(counted) = self.caller_paid {
            record.insert("caller_paid".into(), true.into());
            record.insert(
                "budget".into(),
                if counted { "counted" } else { "not_counted" }.into(),
            );
        }
        record.insert("policy_sha256".into(), self.version.0.as_str().into());
        record.insert("keys_sha256".into(), self.version.1.as_str().into());
        Some(record)
    }
}

impl Admitted {
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
        response.map(|inner| {
            Body::new(Metered {
                inner,
                admitted: Some(admitted),
                status,
                content_type,
                scanner: stream.then(UsageScanner::new),
                frames: (!stream).then(Vec::new),
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
            (Some(scanner), _) => {
                let mut admitted = admitted;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn periods_and_their_ends() {
        let now = "2026-12-31T23:59:59.999Z";
        assert_eq!(period_of(now, Period::Month), "2026-12");
        assert_eq!(period_of(now, Period::Day), "2026-12-31");
        assert_eq!(resets("2026-12"), "2027-01-01 00:00 UTC");
        assert_eq!(resets("2026-11"), "2026-12-01 00:00 UTC");
        assert_eq!(resets("2026-12-31"), "2027-01-01 00:00 UTC");
        assert_eq!(resets("2028-02-28"), "2028-02-29 00:00 UTC");
        assert_eq!(resets("2026-02-28"), "2026-03-01 00:00 UTC");
        assert_eq!(resets("2026-11-13"), "2026-11-14 00:00 UTC");
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
        spend.add("p", "t", "", 1.5, &now);
        assert_eq!(spend.spent("team:t", Period::Month), 1.5);
        assert_eq!(spend.spent("person:p", Period::Day), 1.5);
        assert!(spend.reserve("team:t", budget, 8.5, &now).is_ok());
        // Spend from an earlier month is not counted, and a record from last month does not reset this one.
        spend.add("p", "t", "", 100.0, "2000-01-01T00:00:00.000Z");
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
        };
        let later = now + Duration::from_secs(60);
        cache.put([1; 32], entry("aaaa", later), 10);
        cache.put([2; 32], entry("bbbb", later), 10);
        assert!(cache.get(&[1; 32], now).is_some());
        // 12 bytes do not fit in 10: b, used least recently, goes.
        cache.put([3; 32], entry("cccc", later), 10);
        assert!(cache.get(&[2; 32], now).is_none());
        assert!(cache.get(&[1; 32], now).is_some() && cache.get(&[3; 32], now).is_some());
        assert_eq!(cache.bytes, 8);
        cache.put([4; 32], entry("much too large", later), 10);
        assert!(cache.get(&[4; 32], now).is_none());
        cache.put([5; 32], entry("e", now), 10);
        assert!(cache.get(&[5; 32], now).is_none());
        assert_eq!(cache.bytes, 8);
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
            source: Default::default(),
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
            source: Default::default(),
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
