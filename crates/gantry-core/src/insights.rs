//! The request log and its analytics: one row per request, folded from the request's audit records (its decision,
//! its usage and its answer guardrails), never from prompt or answer text. Without a store the console folds the
//! local chain; with one, each replica copies its rows into a Postgres index and the console asks it. Both answer the
//! same [`Query`] with the same rows, so the pages read one shape.
//!
//! Redacted prompt and answer bodies are kept apart from both, per rule (`capture:` in the policy), in a [`Bodies`]
//! store with its own retention.

use std::{
    collections::{BTreeMap, HashMap},
    io::{BufRead, Write as _},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, mpsc},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::store::Pending;

/// A field requests are grouped and filtered by. A new one (a customer, an org) is one entry here and the same
/// field on the request record: the index keeps every dimension in one `labels` column, so it needs no migration.
#[derive(Clone, Copy, Debug)]
pub struct Dimension {
    /// The name in queries and links: `?team=payments`.
    pub name: &'static str,
    pub label: &'static str,
    /// The field of the request record it is read from: a string or a list of strings.
    pub field: &'static str,
}

pub const DIMENSIONS: &[Dimension] = &[
    Dimension {
        name: "provider",
        label: "Provider",
        field: "provider",
    },
    Dimension {
        name: "model",
        label: "Model",
        field: "model",
    },
    Dimension {
        name: "team",
        label: "Team",
        field: "team",
    },
    Dimension {
        name: "person",
        label: "Person",
        field: "person",
    },
    Dimension {
        name: "key",
        label: "Key",
        field: "key",
    },
    Dimension {
        name: "tag",
        label: "Tag",
        field: "tags",
    },
    Dimension {
        name: "agent",
        label: "Coding agent",
        field: "user_agent",
    },
    Dimension {
        name: "org",
        label: "Organization",
        field: "org",
    },
    Dimension {
        name: "customer",
        label: "Customer",
        field: "customer",
    },
];

/// One request, as its audit records tell it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Row {
    /// The decision ID.
    pub id: String,
    pub time: String,
    /// The gateway whose chain holds the decision record. Empty for the local chain.
    pub replica: String,
    /// The decision record's number and hash in that chain.
    pub n: u64,
    pub hash: String,
    /// Whether the record's `prev` is the hash of the record before it, as read in order.
    pub linked: bool,
    /// The decision record as written, so its hash can be checked again by whoever reads the row. It holds no
    /// prompt text: no record does.
    pub line: String,
    pub path: String,
    /// Dimension name to its values.
    pub labels: BTreeMap<String, Vec<String>>,
    /// `allow` or `refused`, as decided.
    pub verdict: String,
    /// The refusal code, or `guardrail_blocked` when an answer guardrail withheld the answer. Empty otherwise.
    pub code: String,
    pub rule: String,
    /// Every kind a guardrail found, on the request and on the answer.
    pub findings: Vec<String>,
    pub status: Option<u16>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cost_usd: Option<f64>,
    pub charged_usd: f64,
    pub latency_ms: Option<u64>,
    /// A redacted body was kept for it.
    pub body: bool,
}

/// What became of a request, for filters and charts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Allowed,
    Refused,
    /// Allowed, and the provider answered with an error status.
    Error,
}

impl Row {
    /// The first value of a dimension, or "".
    pub fn label(&self, dimension: &str) -> &str {
        self.labels
            .get(dimension)
            .and_then(|v| v.first())
            .map_or("", String::as_str)
    }

    pub fn outcome(&self) -> Outcome {
        if self.verdict == "refused" || self.code == "guardrail_blocked" {
            Outcome::Refused
        } else if self.status.is_some_and(|s| s >= 400) {
            Outcome::Error
        } else {
            Outcome::Allowed
        }
    }

    /// Whether the decision record still hashes to the hash the chain holds for it.
    pub fn checks_out(&self) -> bool {
        crate::audit::line_holds(&self.line)
            && serde_json::from_str::<Value>(&self.line).is_ok_and(|v| {
                v.get("hash").and_then(Value::as_str) == Some(self.hash.as_str())
                    && v.get("n").and_then(Value::as_u64) == Some(self.n)
                    && v.get("id").and_then(Value::as_str) == Some(self.id.as_str())
            })
    }
}

/// What one audit record adds to the rows.
#[derive(Clone, Debug, PartialEq)]
pub enum Fact {
    /// A decision: a new row.
    Request(Box<Row>),
    /// The answer ended: who answered, what it used and cost, and how long it took.
    Usage(Box<Usage>),
    /// No provider answered (`upstream_error`): the status and code Gantry answered with instead.
    Failure {
        id: String,
        status: Option<u16>,
        code: String,
        latency_ms: Option<u64>,
    },
    /// The answer guardrails ran.
    Answer {
        id: String,
        blocked: bool,
        findings: Vec<String>,
    },
    /// Audit retention removed this replica's records through `through`: their rows and bodies go with them.
    Retired { through: u64 },
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Usage {
    pub id: String,
    pub provider: String,
    pub model: String,
    pub status: Option<u16>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cost_usd: Option<f64>,
    pub charged_usd: f64,
    pub latency_ms: Option<u64>,
    pub body: bool,
}

fn text(record: &Value, field: &str) -> String {
    record
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn kinds(guardrails: Option<&Value>) -> Vec<String> {
    guardrails
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|f| f.get("kind").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

fn labels_of(record: &Value) -> BTreeMap<String, Vec<String>> {
    let mut labels = BTreeMap::new();
    for dimension in DIMENSIONS {
        let values: Vec<String> = match record.get(dimension.field) {
            Some(Value::String(one)) if !one.is_empty() => vec![one.clone()],
            Some(Value::Array(many)) => many
                .iter()
                .filter_map(Value::as_str)
                .filter(|v| !v.is_empty())
                .map(str::to_string)
                .collect(),
            _ => Vec::new(),
        };
        let values: Vec<String> = if dimension.name == "agent" {
            values
                .iter()
                .map(|a| crate::audit::tool_of(Some(a)))
                .collect()
        } else {
            values
        };
        if !values.is_empty() {
            labels.insert(dimension.name.to_string(), values);
        }
    }
    labels
}

/// What the record on `line` adds to the rows, or `None` when it adds nothing. `prev` is the hash of the record
/// read before it, when known, to say whether the two are linked.
pub fn fact(line: &str, replica: &str, prev: Option<&str>) -> Option<Fact> {
    let record: Value = serde_json::from_str(line).ok()?;
    if record.get("event").and_then(Value::as_str) == Some("audit_retired") {
        // Segments kept elsewhere (`audit::retire_kept`) are still the chain's: their rows stay.
        if record.get("kept").is_some() {
            return None;
        }
        return Some(Fact::Retired {
            through: record.get("through_n").and_then(Value::as_u64)?,
        });
    }
    let id = text(&record, "id");
    if id.is_empty() {
        return None;
    }
    let number = |field: &str| record.get(field).and_then(Value::as_u64);
    match record.get("event").and_then(Value::as_str) {
        None if record.get("verdict").is_some() && record.get("method").is_some() => {
            let hash = text(&record, "hash");
            Some(Fact::Request(Box::new(Row {
                id,
                time: text(&record, "time"),
                replica: replica.to_string(),
                n: number("n")?,
                linked: prev.is_none_or(|p| record.get("prev").and_then(Value::as_str) == Some(p)),
                hash,
                line: line.to_string(),
                path: text(&record, "path"),
                labels: labels_of(&record),
                verdict: text(&record, "verdict"),
                code: text(&record, "code"),
                rule: text(&record, "rule"),
                findings: kinds(record.get("guardrails")),
                ..Row::default()
            })))
        }
        Some("usage") => Some(Fact::Usage(Box::new(Usage {
            id,
            provider: text(&record, "provider"),
            model: text(&record, "model"),
            status: number("status").and_then(|s| u16::try_from(s).ok()),
            input_tokens: number("input_tokens"),
            output_tokens: number("output_tokens"),
            cost_usd: record.get("cost_usd").and_then(Value::as_f64),
            charged_usd: record
                .get("charged_usd")
                .and_then(Value::as_f64)
                .unwrap_or_default(),
            latency_ms: number("latency_ms"),
            body: record.get("body").and_then(Value::as_str) == Some("captured"),
        }))),
        Some("upstream_error") => Some(Fact::Failure {
            id,
            status: number("status").and_then(|s| u16::try_from(s).ok()),
            code: text(&record, "code"),
            latency_ms: number("latency_ms"),
        }),
        Some("answer_guardrails") => Some(Fact::Answer {
            id,
            blocked: record.get("verdict").and_then(Value::as_str) == Some("block"),
            findings: kinds(record.get("guardrails")),
        }),
        _ => None,
    }
}

impl Usage {
    /// Puts what the usage record says on its row. A fallback that answered is the provider and model now.
    pub fn apply(&self, row: &mut Row) {
        for (dimension, value) in [("provider", &self.provider), ("model", &self.model)] {
            if !value.is_empty() {
                row.labels
                    .insert(dimension.to_string(), vec![value.to_string()]);
            }
        }
        row.status = self.status;
        row.input_tokens = self.input_tokens;
        row.output_tokens = self.output_tokens;
        row.cost_usd = self.cost_usd;
        row.charged_usd = self.charged_usd;
        row.latency_ms = self.latency_ms;
        row.body = self.body;
    }
}

/// The hash a record line carries, if it has one.
pub fn hash_of_line(line: &str) -> Option<String> {
    let at = line.rfind(",\"hash\":\"")?;
    line.get(at + 9..)?.strip_suffix("\"}").map(str::to_string)
}

/// Every request in a chain, newest first.
pub fn fold(reader: impl BufRead, replica: &str) -> Vec<Row> {
    let mut rows: Vec<Row> = Vec::new();
    let mut at: HashMap<String, usize> = HashMap::new();
    let mut prev: Option<String> = None;
    for line in reader.lines() {
        let Ok(line) = line else { break };
        let this = hash_of_line(&line);
        match fact(&line, replica, prev.as_deref()) {
            Some(Fact::Request(row)) => {
                at.insert(row.id.clone(), rows.len());
                rows.push(*row);
            }
            Some(Fact::Usage(usage)) => {
                if let Some(row) = at.get(&usage.id).and_then(|i| rows.get_mut(*i)) {
                    usage.apply(row);
                }
            }
            Some(Fact::Failure {
                id,
                status,
                code,
                latency_ms,
            }) => {
                if let Some(row) = at.get(&id).and_then(|i| rows.get_mut(*i)) {
                    row.status = status;
                    row.code = code;
                    row.latency_ms = latency_ms;
                }
            }
            Some(Fact::Answer {
                id,
                blocked,
                findings,
            }) => {
                if let Some(row) = at.get(&id).and_then(|i| rows.get_mut(*i)) {
                    if blocked {
                        row.code = "guardrail_blocked".into();
                    }
                    row.findings.extend(findings);
                }
            }
            // The retired records are gone from the files read here, so their rows never were folded.
            Some(Fact::Retired { .. }) | None => {}
        }
        prev = this;
    }
    rows.reverse();
    rows
}

/// Every request in the chain at `path`, its sealed segments included, newest first.
pub fn fold_chain(path: &Path) -> Result<Vec<Row>, String> {
    if !crate::audit::has_records(path) {
        return Ok(Vec::new());
    }
    let reader = crate::audit::chain_reader(path)
        .map_err(|err| format!("the audit log at {} cannot be read: {err}.", path.display()))?;
    Ok(fold(reader, ""))
}

/// What the request log is asked for. Every field narrows it; an empty field does not.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Query {
    /// Dimension name and the value it must have.
    pub labels: Vec<(String, String)>,
    /// `allowed`, `refused` or `error`.
    pub outcome: String,
    pub code: String,
    /// A kind a guardrail found, such as `email_address`.
    pub finding: String,
    pub id: String,
    /// A date (`2026-11-14`) or a time as records write it. `to` takes the whole of a date.
    pub from: String,
    pub to: String,
    pub min_cost: Option<f64>,
    pub max_cost: Option<f64>,
    pub min_ms: Option<u64>,
    pub max_ms: Option<u64>,
    /// Most rows to answer with, newest first, after skipping `offset`.
    pub limit: usize,
    pub offset: usize,
}

/// Most rows one query answers with. Analytics of the local chain fold this many at most; the store's index sums
/// them in SQL, with no cap.
pub const MAX_ROWS: usize = 200_000;

/// The query fields that are not dimensions, in the order links write them.
pub const FIELDS: &[&str] = &[
    "outcome", "code", "finding", "id", "from", "to", "min_cost", "max_cost", "min_ms", "max_ms",
];

fn time_ok(value: &str) -> bool {
    let date = value.get(..10).is_some_and(|d| {
        d.bytes().enumerate().all(|(i, b)| {
            if i == 4 || i == 7 {
                b == b'-'
            } else {
                b.is_ascii_digit()
            }
        })
    });
    date && value
        .bytes()
        .all(|b| b.is_ascii_digit() || b"-:.TZ".contains(&b))
}

impl Query {
    /// Reads a query from form fields. `Err` names the field and the fix.
    pub fn parse(get: &dyn Fn(&str) -> String) -> Result<Self, String> {
        let mut query = Self {
            limit: 50,
            ..Self::default()
        };
        for dimension in DIMENSIONS {
            let value = get(dimension.name).trim().to_string();
            if !value.is_empty() {
                query.labels.push((dimension.name.to_string(), value));
            }
        }
        query.outcome = get("outcome").trim().to_string();
        if !["", "allowed", "refused", "error"].contains(&query.outcome.as_str()) {
            return Err(format!(
                "outcome is \"{}\". It is allowed, refused or error; leave it empty for every request.",
                query.outcome
            ));
        }
        query.code = get("code").trim().to_string();
        query.finding = get("finding").trim().to_string();
        query.id = get("id").trim().to_string();
        for (field, slot) in [("from", &mut query.from), ("to", &mut query.to)] {
            let value = get(field).trim().to_string();
            if !value.is_empty() && !time_ok(&value) {
                return Err(format!(
                    "{field} is \"{value}\". Write a date as 2026-11-14, or a time as 2026-11-14T09:30:00Z."
                ));
            }
            *slot = value;
        }
        let cost = |field: &str| -> Result<Option<f64>, String> {
            let value = get(field);
            let value = value.trim();
            if value.is_empty() {
                return Ok(None);
            }
            value
                .parse::<f64>()
                .ok()
                .filter(|v| v.is_finite() && *v >= 0.0)
                .map(Some)
                .ok_or_else(|| {
                    format!("{field} is \"{value}\". Write dollars as a number, for example 0.05.")
                })
        };
        query.min_cost = cost("min_cost")?;
        query.max_cost = cost("max_cost")?;
        let ms = |field: &str| -> Result<Option<u64>, String> {
            let value = get(field);
            let value = value.trim();
            if value.is_empty() {
                return Ok(None);
            }
            value.parse::<u64>().map(Some).map_err(|_| {
                format!("{field} is \"{value}\". Write milliseconds as a whole number, for example 2000.")
            })
        };
        query.min_ms = ms("min_ms")?;
        query.max_ms = ms("max_ms")?;
        Ok(query)
    }

    /// The fields set, as (name, value), for a link to the same query.
    pub fn pairs(&self) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = self.labels.clone();
        let number = |v: Option<f64>| v.map(|v| v.to_string()).unwrap_or_default();
        let whole = |v: Option<u64>| v.map(|v| v.to_string()).unwrap_or_default();
        for (field, value) in [
            ("outcome", self.outcome.clone()),
            ("code", self.code.clone()),
            ("finding", self.finding.clone()),
            ("id", self.id.clone()),
            ("from", self.from.clone()),
            ("to", self.to.clone()),
            ("min_cost", number(self.min_cost)),
            ("max_cost", number(self.max_cost)),
            ("min_ms", whole(self.min_ms)),
            ("max_ms", whole(self.max_ms)),
        ] {
            if !value.is_empty() {
                out.push((field.to_string(), value));
            }
        }
        out
    }

    pub fn matches(&self, row: &Row) -> bool {
        let outcome = match self.outcome.as_str() {
            "allowed" => row.outcome() == Outcome::Allowed,
            "refused" => row.outcome() == Outcome::Refused,
            "error" => row.outcome() == Outcome::Error,
            _ => true,
        };
        let to = row
            .time
            .get(..self.to.len().min(row.time.len()))
            .unwrap_or_default();
        outcome
            && self
                .labels
                .iter()
                .all(|(d, v)| row.labels.get(d).is_some_and(|vs| vs.contains(v)))
            && (self.code.is_empty() || row.code == self.code)
            && (self.finding.is_empty() || row.findings.contains(&self.finding))
            && (self.id.is_empty() || row.id == self.id)
            && (self.from.is_empty() || row.time.as_str() >= self.from.as_str())
            && (self.to.is_empty() || to <= self.to.as_str())
            && self
                .min_cost
                .is_none_or(|m| row.cost_usd.is_some_and(|c| c >= m))
            && self
                .max_cost
                .is_none_or(|m| row.cost_usd.is_some_and(|c| c <= m))
            && self
                .min_ms
                .is_none_or(|m| row.latency_ms.is_some_and(|l| l >= m))
            && self
                .max_ms
                .is_none_or(|m| row.latency_ms.is_some_and(|l| l <= m))
    }

    /// The rows of `rows` (newest first) this query asks for.
    pub fn select(&self, rows: &[Row]) -> Vec<Row> {
        rows.iter()
            .filter(|r| self.matches(r))
            .skip(self.offset)
            .take(self.limit)
            .cloned()
            .collect()
    }
}

/// Requests, tokens, cost and latency of a group of rows.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Stats {
    pub requests: u64,
    pub refused: u64,
    pub errors: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_usd: f64,
    /// Sorted, once the group is complete.
    pub latencies: Vec<u64>,
    /// The p50, p95 and p99 latencies when the store computed them, in place of `latencies`.
    pub quantiles: Option<[Option<u64>; 3]>,
}

impl Stats {
    pub fn add(&mut self, row: &Row) {
        self.requests += 1;
        match row.outcome() {
            Outcome::Refused => self.refused += 1,
            Outcome::Error => self.errors += 1,
            Outcome::Allowed => {}
        }
        self.input_tokens += row.input_tokens.unwrap_or_default();
        self.output_tokens += row.output_tokens.unwrap_or_default();
        self.cost_usd += row.cost_usd.unwrap_or_default();
        if let Some(ms) = row.latency_ms {
            self.latencies.push(ms);
        }
    }

    /// The latency `p` (0 to 100) of the requests are at or under, by nearest rank. `None` without latencies.
    pub fn percentile(&self, p: f64) -> Option<u64> {
        if let Some(q) = self.quantiles {
            return [(50.0, q[0]), (95.0, q[1]), (99.0, q[2])]
                .into_iter()
                .find(|(at, _)| *at == p)
                .and_then(|(_, v)| v);
        }
        if self.latencies.is_empty() {
            return None;
        }
        let rank = ((p / 100.0) * self.latencies.len() as f64).ceil() as usize;
        self.latencies
            .get(rank.clamp(1, self.latencies.len()) - 1)
            .copied()
    }

    fn done(mut self) -> Self {
        self.latencies.sort_unstable();
        self
    }
}

pub fn totals(rows: &[Row]) -> Stats {
    let mut stats = Stats::default();
    for row in rows {
        stats.add(row);
    }
    stats.done()
}

/// Stats per hour (`2026-11-14T09`) or per day (`2026-11-14`), oldest first.
pub fn series(rows: &[Row], hourly: bool) -> Vec<(String, Stats)> {
    let width = if hourly { 13 } else { 10 };
    let mut groups: BTreeMap<String, Stats> = BTreeMap::new();
    for row in rows {
        let bucket = row.time.get(..width).unwrap_or_default().to_string();
        groups.entry(bucket).or_default().add(row);
    }
    groups.into_iter().map(|(k, s)| (k, s.done())).collect()
}

/// Stats per value of a dimension, most costly first, then most requests. A request with no value is counted
/// under "".
pub fn ranking(rows: &[Row], dimension: &str) -> Vec<(String, Stats)> {
    let mut groups: HashMap<String, Stats> = HashMap::new();
    for row in rows {
        match row.labels.get(dimension) {
            Some(values) if !values.is_empty() => {
                for value in values {
                    groups.entry(value.clone()).or_default().add(row);
                }
            }
            _ => groups.entry(String::new()).or_default().add(row),
        }
    }
    let mut ranked: Vec<(String, Stats)> = groups.into_iter().map(|(k, s)| (k, s.done())).collect();
    rank(&mut ranked);
    ranked
}

/// Most costly first, then most requests, then by name.
pub fn rank(ranked: &mut [(String, Stats)]) {
    ranked.sort_by(|a, b| {
        b.1.cost_usd
            .total_cmp(&a.1.cost_usd)
            .then(b.1.requests.cmp(&a.1.requests))
            .then(a.0.cmp(&b.0))
    });
}

/// What the analytics page shows for a window: its totals, per hour or day, and per value of one dimension.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Analytics {
    pub totals: Stats,
    pub series: Vec<(String, Stats)>,
    pub ranking: Vec<(String, Stats)>,
}

/// The analytics of rows folded here, from the local chain.
pub fn analytics(rows: &[Row], hourly: bool, dimension: &str) -> Analytics {
    Analytics {
        totals: totals(rows),
        series: series(rows, hourly),
        ranking: ranking(rows, dimension),
    }
}

/// Days since 1970-01-01 of a calendar date (Howard Hinnant's days-from-civil).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Seconds since 1970 of a time as records write it, or of a date at midnight UTC.
pub fn unix_secs(time: &str) -> Option<u64> {
    let part = |range: std::ops::Range<usize>| time.get(range).and_then(|p| p.parse::<i64>().ok());
    let days = days_from_civil(part(0..4)?, part(5..7)?, part(8..10)?);
    let clock = if time.len() >= 19 {
        part(11..13)? * 3600 + part(14..16)? * 60 + part(17..19)?
    } else {
        0
    };
    u64::try_from(days * 86_400 + clock).ok()
}

/// The start and end, in seconds since 1970, of the UTC day or month that holds `now`.
pub fn period(now: u64, per_day: bool) -> (u64, u64) {
    let today = crate::audit::rfc3339(UNIX_EPOCH + Duration::from_secs(now));
    let part = |range: std::ops::Range<usize>| {
        today
            .get(range)
            .and_then(|p| p.parse::<i64>().ok())
            .unwrap_or(1)
    };
    let (year, month, day) = (part(0..4), part(5..7), part(8..10));
    let secs = |days: i64| u64::try_from(days * 86_400).unwrap_or_default();
    if per_day {
        let start = days_from_civil(year, month, day);
        (secs(start), secs(start + 1))
    } else {
        let next = if month == 12 {
            days_from_civil(year + 1, 1, 1)
        } else {
            days_from_civil(year, month + 1, 1)
        };
        (secs(days_from_civil(year, month, 1)), secs(next))
    }
}

/// Where a budget is heading at the pace it has been spent at since its period started.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Pace {
    /// Nothing spent yet.
    Idle,
    /// Spent or past its limit already.
    Spent,
    /// Lasts to the end of its period.
    Lasts,
    /// Runs out at this time, in seconds since 1970, before its period ends.
    RunsOut(u64),
}

/// The pace of a budget of `limit` dollars that has `spent` between `start` and `now`, in a period ending at `end`.
pub fn pace(spent: f64, limit: f64, start: u64, now: u64, end: u64) -> Pace {
    if spent >= limit {
        return Pace::Spent;
    }
    if spent <= 0.0 {
        return Pace::Idle;
    }
    let elapsed = now.saturating_sub(start).max(60) as f64;
    let at = start as f64 + limit / (spent / elapsed);
    if at >= end as f64 {
        Pace::Lasts
    } else {
        Pace::RunsOut(at as u64)
    }
}

/// Seconds since 1970 now.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A request and its answer as kept for investigation: redacted by the built-in secrets and PII detectors before
/// it is kept, for the days its rule says, readable only by the rule's viewers.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Body {
    pub id: String,
    pub time: String,
    pub rule: String,
    /// When it is deleted, in seconds since 1970.
    pub expires: u64,
    /// Who may read it, as the rule said when it was kept: a name, `team:<team>` or `role:<role>`.
    pub viewers: Vec<String>,
    pub request: String,
    pub answer: String,
}

/// Most bytes of a request or an answer kept. The rest is cut, and the cut is marked.
pub const MAX_BODY: usize = 64 * 1024;

/// Text cut to [`MAX_BODY`] bytes on a character boundary, with a mark when it was cut.
pub fn cut_body(text: &str) -> String {
    if text.len() <= MAX_BODY {
        return text.to_string();
    }
    let mut end = MAX_BODY;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "{}\n[cut: {} more bytes not kept]",
        &text[..end],
        text.len() - end
    )
}

/// Whether someone with this name, team and console role is among `viewers`.
pub fn may_view(viewers: &[String], name: &str, team: &str, role: &str) -> bool {
    viewers.iter().any(|v| {
        if let Some(t) = v.strip_prefix("team:") {
            !team.is_empty() && t == team
        } else if let Some(r) = v.strip_prefix("role:") {
            !role.is_empty() && r == role
        } else {
            !name.is_empty() && v == name
        }
    })
}

/// Seals a kept body before it is written and opens it when it is read: the gateway's master key
/// (`GANTRY_MASTER_KEY`), AES-256-GCM with the decision ID as associated data, so a body moved to another ID
/// does not open.
pub trait Seal: Send + Sync + std::fmt::Debug {
    fn seal(&self, id: &str, plain: &[u8]) -> Result<Vec<u8>, String>;
    fn open(&self, id: &str, sealed: &[u8]) -> Result<Vec<u8>, String>;
}

/// The bytes a body is kept as: sealed JSON.
pub fn seal_body(seal: &dyn Seal, body: &Body) -> Result<Vec<u8>, String> {
    let plain = serde_json::to_vec(body).map_err(|err| err.to_string())?;
    seal.seal(&format!("body:{}", body.id), &plain)
}

/// A body from the bytes [`seal_body`] made for `id`.
pub fn open_body(seal: &dyn Seal, id: &str, sealed: &[u8]) -> Result<Body, String> {
    let plain = seal.open(&format!("body:{id}"), sealed)?;
    let body: Body = serde_json::from_slice(&plain)
        .map_err(|err| format!("the kept body of decision {id} is not one Gantry wrote: {err}"))?;
    if body.id == id {
        Ok(body)
    } else {
        Err(format!(
            "the kept body of decision {id} names another decision"
        ))
    }
}

/// Where kept bodies are.
pub trait Bodies: Send + Sync + std::fmt::Debug {
    /// Keeps a body. Does not wait: it is written off the request's path.
    fn keep(&self, body: Body);
    /// The body of a decision, unless there is none or it has expired.
    fn body(&self, id: &str) -> Pending<Option<Body>>;
}

/// The request log of every gateway on one store.
pub trait Index: Send + Sync + std::fmt::Debug {
    /// The rows the query asks for, newest first.
    fn rows(&self, query: &Query) -> Pending<Vec<Row>>;
    /// The analytics of every request the query matches, summed where the rows are kept, so no window is cut
    /// at [`MAX_ROWS`]. `dimension` is one of [`DIMENSIONS`].
    fn analytics(&self, query: &Query, hourly: bool, dimension: &str) -> Pending<Analytics>;
}

/// What the gateway serves for an audit log: the index of every gateway on its store, when it has one, and where
/// bodies are kept, when capture is possible (a master key is set).
#[derive(Clone, Debug)]
pub struct Shared {
    pub index: Option<Arc<dyn Index>>,
    pub bodies: Option<Arc<dyn Bodies>>,
}

// The console names the audit log by its path, as the keys are named by theirs (crate::store::attach). Held here
// for the life of the process: one gateway serves one audit log.
static ATTACHED: Mutex<Vec<(PathBuf, Shared)>> = Mutex::new(Vec::new());

/// Serves the request log and the bodies of the audit log at `audit`.
pub fn attach(audit: &Path, index: Option<Arc<dyn Index>>, bodies: Option<Arc<dyn Bodies>>) {
    let mut attached = ATTACHED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    attached.retain(|(path, _)| path != audit);
    attached.push((audit.to_path_buf(), Shared { index, bodies }));
}

/// What serves the audit log at `audit`. Without an entry, the console folds the local chain and shows no bodies.
pub fn attached(audit: &Path) -> Shared {
    ATTACHED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .rev()
        .find(|(path, _)| path == audit)
        .map_or(
            Shared {
                index: None,
                bodies: None,
            },
            |(_, shared)| shared.clone(),
        )
}

// Legal hold, per audit log, as an embedder (Gantry Enterprise retention) sets it: while it is on, no kept body
// is deleted, expired or not. Retention itself never runs under a hold, so index rows are kept too.
static HELD: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// Turns legal hold on or off for the kept bodies of the audit log at `audit`.
pub fn hold(audit: &Path, on: bool) {
    let mut held = HELD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    held.retain(|p| p != audit);
    if on {
        held.push(audit.to_path_buf());
    }
}

/// Whether legal hold is on for the audit log at `audit`.
pub fn held(audit: &Path) -> bool {
    HELD.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .any(|p| p == audit)
}

/// A decision ID as Gantry makes them: letters and digits only, so it is safe as a file name.
pub fn id_ok(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Bodies kept as files beside the audit log, for a gateway without a store: one directory per day they expire
/// on, so retention deletes whole days.
#[derive(Debug)]
pub struct FileBodies {
    audit: PathBuf,
    dir: PathBuf,
    seal: Arc<dyn Seal>,
    writer: OnceLock<Mutex<mpsc::Sender<Body>>>,
}

/// The directory bodies of the audit log at `audit` are kept in.
pub fn bodies_dir(audit: &Path) -> PathBuf {
    let mut name = audit.as_os_str().to_owned();
    name.push(".bodies");
    PathBuf::from(name)
}

impl FileBodies {
    pub fn beside(audit: &Path, seal: Arc<dyn Seal>) -> Self {
        Self {
            audit: audit.to_path_buf(),
            dir: bodies_dir(audit),
            seal,
            writer: OnceLock::new(),
        }
    }

    fn day_of(secs: u64) -> String {
        crate::audit::rfc3339(UNIX_EPOCH + Duration::from_secs(secs))
            .get(..10)
            .unwrap_or_default()
            .to_string()
    }

    /// Deletes the days that have passed, unless the log is under legal hold.
    pub fn sweep(&self) {
        if held(&self.audit) {
            return;
        }
        let today = Self::day_of(now_secs());
        let Ok(days) = std::fs::read_dir(&self.dir) else {
            return;
        };
        for day in days.flatten() {
            let name = day.file_name().to_string_lossy().into_owned();
            if name.len() == 10 && name < today {
                if let Err(err) = std::fs::remove_dir_all(day.path()) {
                    eprintln!(
                        "gantry: kept bodies in {} are past their retention and could not be deleted: {err}. Delete the directory by hand.",
                        day.path().display()
                    );
                }
            }
        }
    }

    /// Writes a body now. `Err` says why it was not kept.
    pub fn write(&self, body: &Body) -> Result<(), String> {
        if !id_ok(&body.id) {
            return Err(format!(
                "decision ID \"{}\" is not one Gantry makes",
                body.id
            ));
        }
        let day = self.dir.join(Self::day_of(body.expires));
        let failed = |err: std::io::Error| format!("{} cannot be written: {err}", day.display());
        std::fs::create_dir_all(&day).map_err(failed)?;
        let text = seal_body(self.seal.as_ref(), body)?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Redacted is not public: only the gateway's user reads them.
            options.mode(0o600);
        }
        let mut file = options
            .open(day.join(format!("{}.sealed", body.id)))
            .map_err(failed)?;
        file.write_all(&text).map_err(failed)
    }

    fn read(&self, id: &str) -> Option<Body> {
        if !id_ok(id) {
            return None;
        }
        let today = Self::day_of(now_secs());
        let days = std::fs::read_dir(&self.dir).ok()?;
        days.flatten()
            .filter(|d| d.file_name().to_string_lossy().as_ref() >= today.as_str())
            .find_map(|d| std::fs::read(d.path().join(format!("{id}.sealed"))).ok())
            .and_then(|bytes| match open_body(self.seal.as_ref(), id, &bytes) {
                Ok(body) => Some(body),
                Err(err) => {
                    eprintln!("gantry: {err}.");
                    None
                }
            })
            .filter(|b| b.expires > now_secs())
    }
}

impl Bodies for FileBodies {
    fn keep(&self, body: Body) {
        let sender = self.writer.get_or_init(|| {
            let (tell, told) = mpsc::channel::<Body>();
            let me = Self {
                audit: self.audit.clone(),
                dir: self.dir.clone(),
                seal: self.seal.clone(),
                writer: OnceLock::new(),
            };
            std::thread::Builder::new()
                .name("gantry-bodies".into())
                .spawn(move || {
                    let mut swept = None::<std::time::Instant>;
                    for body in told {
                        if let Err(err) = me.write(&body) {
                            eprintln!(
                                "gantry: the body of decision {} was not kept: {err}.",
                                body.id
                            );
                        }
                        if swept.is_none_or(|at| at.elapsed() > Duration::from_secs(3600)) {
                            me.sweep();
                            swept = Some(std::time::Instant::now());
                        }
                    }
                })
                .map_err(|err| eprintln!("gantry: the body writer could not start: {err}"))
                .ok();
            Mutex::new(tell)
        });
        let sent = sender
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .send(body);
        if sent.is_err() {
            eprintln!("gantry: a body was not kept: the body writer is not running.");
        }
    }

    fn body(&self, id: &str) -> Pending<Option<Body>> {
        let found = self.read(id);
        Box::pin(async move { Ok(found) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn chain() -> Result<(PathBuf, crate::audit::AuditLog), Box<dyn std::error::Error>> {
        let dir =
            std::env::temp_dir().join(format!("gantry-insights-{}", crate::id::random_hex(6)));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("audit.jsonl");
        Ok((path.clone(), crate::audit::AuditLog::open(&path)?))
    }

    fn request(
        id: &str,
        team: &str,
        allowed: bool,
        code: Option<&str>,
    ) -> serde_json::Map<String, Value> {
        let mut r = crate::audit::record(&crate::audit::Entry {
            id,
            person: Some("maya.cohen"),
            team: Some(team),
            key: Some("5d1e4a07"),
            method: "POST",
            path: "/v1/chat/completions",
            model: Some("gpt-4o"),
            allowed,
            code,
            rule: Some("payments-team"),
            provider: if allowed { "openai" } else { "" },
            ..crate::audit::Entry::default()
        });
        r.insert(
            "user_agent".into(),
            "claude-cli/2.0.1 (external, cli)".into(),
        );
        r.insert("tags".into(), serde_json::json!(["search", "beta"]));
        r
    }

    fn usage(id: &str, status: u16, cost: f64, ms: u64) -> serde_json::Map<String, Value> {
        let value = serde_json::json!({
            "event": "usage", "id": id, "time": "2026-11-14T09:00:01.000Z", "provider": "openai-backup",
            "model": "gpt-4o", "status": status, "input_tokens": 100, "output_tokens": 20,
            "cost_usd": cost, "charged_usd": cost, "latency_ms": ms, "body": "captured"
        });
        value.as_object().cloned().unwrap_or_default()
    }

    #[test]
    fn a_chain_folds_into_one_row_per_request_with_its_usage_and_proof() -> TestResult {
        let (path, log) = chain()?;
        log.append_record(&request("D1", "payments", true, None))?;
        log.append_record(&request("D2", "search", false, Some("model_not_allowed")))?;
        log.append_record(&usage("D1", 200, 0.25, 840))?;
        log.append_record(&request("D3", "payments", true, None))?;
        log.append_record(&usage("D3", 502, 0.0, 30))?;
        let answer = serde_json::json!({"event": "answer_guardrails", "id": "D3", "verdict": "block",
            "guardrails": [{"guardrail": "g", "detector": "pii", "kind": "email_address", "action": "block", "count": 1}]});
        log.append_record(answer.as_object().ok_or("not an object")?)?;
        log.append_record(&request("D4", "payments", true, None))?;
        let failed = serde_json::json!({"event": "upstream_error", "id": "D4", "status": 504, "code": "upstream_timeout", "latency_ms": 30000});
        log.append_record(failed.as_object().ok_or("not an object")?)?;
        log.flush();
        let rows = fold_chain(&path)?;
        let d4 = rows.first().ok_or("no D4")?;
        assert_eq!(
            (d4.outcome(), d4.code.as_str(), d4.latency_ms),
            (Outcome::Error, "upstream_timeout", Some(30000))
        );
        let rows = rows.get(1..).unwrap_or_default().to_vec();
        assert_eq!(
            rows.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            ["D3", "D2", "D1"]
        );
        let d1 = rows.get(2).ok_or("no D1")?;
        assert_eq!(
            d1.label("provider"),
            "openai-backup",
            "the provider that answered"
        );
        assert_eq!(d1.label("agent"), "claude-code");
        assert_eq!(
            d1.labels.get("tag"),
            Some(&vec!["search".to_string(), "beta".to_string()])
        );
        assert_eq!(
            (d1.status, d1.cost_usd, d1.latency_ms, d1.body),
            (Some(200), Some(0.25), Some(840), true)
        );
        assert_eq!(d1.outcome(), Outcome::Allowed);
        assert!(d1.checks_out() && d1.linked && d1.n == 1);
        assert_eq!(rows.get(1).map(Row::outcome), Some(Outcome::Refused));
        let d3 = rows.first().ok_or("no D3")?;
        assert_eq!(
            d3.outcome(),
            Outcome::Refused,
            "an answer guardrail withheld it"
        );
        assert_eq!(d3.findings, ["email_address"]);

        // A record changed after it was written no longer checks out.
        let mut forged = d1.clone();
        forged.line = forged.line.replace("payments", "platform");
        assert!(!forged.checks_out());
        Ok(())
    }

    #[test]
    fn queries_filter_by_dimension_outcome_time_cost_and_latency() -> TestResult {
        let (path, log) = chain()?;
        log.append_record(&request("D1", "payments", true, None))?;
        log.append_record(&usage("D1", 200, 0.25, 840))?;
        log.append_record(&request("D2", "search", false, Some("model_not_allowed")))?;
        log.append_record(&request("D3", "payments", true, None))?;
        log.append_record(&usage("D3", 500, 0.01, 3000))?;
        log.flush();
        let rows = fold_chain(&path)?;
        let ids = |q: &Query| {
            q.select(&rows)
                .into_iter()
                .map(|r| r.id)
                .collect::<Vec<_>>()
        };
        let fields = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == name)
                    .map_or(String::new(), |(_, v)| (*v).to_string())
            }
        };
        let q = Query::parse(&fields(&[("team", "payments")]))?;
        assert_eq!(ids(&q), ["D3", "D1"]);
        let q = Query::parse(&fields(&[("outcome", "error")]))?;
        assert_eq!(ids(&q), ["D3"]);
        let q = Query::parse(&fields(&[
            ("outcome", "refused"),
            ("code", "model_not_allowed"),
        ]))?;
        assert_eq!(ids(&q), ["D2"]);
        let q = Query::parse(&fields(&[("min_cost", "0.1")]))?;
        assert_eq!(ids(&q), ["D1"]);
        let q = Query::parse(&fields(&[("min_ms", "1000"), ("agent", "claude-code")]))?;
        assert_eq!(ids(&q), ["D3"]);
        let q = Query::parse(&fields(&[("tag", "beta"), ("to", "2000-01-01")]))?;
        assert!(ids(&q).is_empty());
        let today = crate::audit::timestamp();
        let q = Query {
            from: today.get(..10).unwrap_or_default().into(),
            to: today.get(..10).unwrap_or_default().into(),
            limit: 10,
            ..Query::default()
        };
        assert_eq!(ids(&q).len(), 3, "a date takes the whole day");
        let bad = Query::parse(&fields(&[("min_ms", "fast")]))
            .err()
            .unwrap_or_default();
        assert!(
            bad.contains("min_ms") && bad.contains("whole number"),
            "{bad}"
        );
        let bad = Query::parse(&fields(&[("from", "yesterday")]))
            .err()
            .unwrap_or_default();
        assert!(bad.contains("2026-11-14"), "{bad}");
        Ok(())
    }

    #[test]
    fn stats_rank_and_take_percentiles_by_nearest_rank() {
        let row = |team: &str, ms: u64, cost: f64| Row {
            labels: BTreeMap::from([("team".to_string(), vec![team.to_string()])]),
            verdict: "allow".into(),
            status: Some(200),
            latency_ms: Some(ms),
            cost_usd: Some(cost),
            time: "2026-11-14T09:30:00.000Z".into(),
            ..Row::default()
        };
        let rows: Vec<Row> = (1..=100)
            .map(|ms| row(if ms % 2 == 0 { "a" } else { "b" }, ms, 0.01))
            .chain([row("c", 5, 9.0)])
            .collect();
        let all = totals(&rows);
        assert_eq!(all.requests, 101);
        assert_eq!(all.percentile(50.0), Some(50));
        assert_eq!(all.percentile(99.0), Some(99));
        let ranked = ranking(&rows, "team");
        assert_eq!(
            ranked.first().map(|r| r.0.as_str()),
            Some("c"),
            "most costly first"
        );
        assert_eq!(
            series(&rows, true).first().map(|s| s.0.as_str()),
            Some("2026-11-14T09")
        );
        assert_eq!(Stats::default().percentile(95.0), None);
    }

    #[test]
    fn a_budget_runs_out_at_its_pace() {
        let (start, end) = period(unix_secs("2026-11-14T12:00:00Z").unwrap_or_default(), false);
        assert_eq!(start, unix_secs("2026-11-01").unwrap_or_default());
        assert_eq!(end, unix_secs("2026-12-01").unwrap_or_default());
        let now = start + 10 * 86_400;
        // 100 of 200 in 10 days: out on day 20.
        assert_eq!(
            pace(100.0, 200.0, start, now, end),
            Pace::RunsOut(start + 20 * 86_400)
        );
        assert_eq!(pace(10.0, 200.0, start, now, end), Pace::Lasts);
        assert_eq!(pace(200.0, 200.0, start, now, end), Pace::Spent);
        assert_eq!(pace(0.0, 200.0, start, now, end), Pace::Idle);
        let (day_start, day_end) =
            period(unix_secs("2026-12-31T23:00:00Z").unwrap_or_default(), true);
        assert_eq!(day_end - day_start, 86_400);
    }

    #[test]
    fn viewers_are_names_teams_or_roles() {
        let viewers = vec![
            "noa.bar".to_string(),
            "team:security".into(),
            "role:owner".into(),
        ];
        assert!(may_view(&viewers, "noa.bar", "", ""));
        assert!(may_view(&viewers, "x", "security", ""));
        assert!(may_view(&viewers, "x", "", "owner"));
        assert!(!may_view(&viewers, "maya.cohen", "payments", "admin"));
        assert!(!may_view(&viewers, "", "", ""));
    }

    /// Not a cipher: it only proves the store hands every body through its sealer and checks the name.
    #[derive(Debug)]
    struct Tagged;

    impl Seal for Tagged {
        fn seal(&self, id: &str, plain: &[u8]) -> Result<Vec<u8>, String> {
            Ok([id.as_bytes(), b"|", plain].concat())
        }
        fn open(&self, id: &str, sealed: &[u8]) -> Result<Vec<u8>, String> {
            sealed
                .strip_prefix(format!("{id}|").as_bytes())
                .map(<[u8]>::to_vec)
                .ok_or_else(|| "sealed for another name".to_string())
        }
    }

    #[test]
    fn file_bodies_are_sealed_kept_read_back_and_expire() -> TestResult {
        let (path, _log) = chain()?;
        let bodies = FileBodies::beside(&path, Arc::new(Tagged));
        let body = Body {
            id: "01ABC".into(),
            expires: now_secs() + 86_400,
            request: "hi".into(),
            ..Body::default()
        };
        bodies.write(&body)?;
        assert_eq!(bodies.read("01ABC"), Some(body.clone()));
        let day = FileBodies::day_of(body.expires);
        let file = bodies_dir(&path).join(&day).join("01ABC.sealed");
        assert!(
            std::fs::read(&file)?.starts_with(b"body:01ABC|"),
            "written through the sealer"
        );
        // A body copied under another decision's name does not open.
        std::fs::copy(&file, bodies_dir(&path).join(&day).join("01XYZ.sealed"))?;
        assert_eq!(bodies.read("01XYZ"), None);
        assert_eq!(bodies.read("../etc"), None, "only decision IDs name a file");
        bodies.write(&Body {
            id: "01OLD".into(),
            expires: now_secs().saturating_sub(3 * 86_400),
            ..body
        })?;
        assert_eq!(bodies.read("01OLD"), None, "an expired body is not shown");
        bodies.sweep();
        let days = std::fs::read_dir(bodies_dir(&path))?.count();
        assert_eq!(days, 1, "the passed day was deleted");
        assert!(
            bodies
                .write(&Body {
                    id: "a/b".into(),
                    ..Body::default()
                })
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn long_bodies_are_cut_and_say_so() {
        let long = "é".repeat(MAX_BODY);
        let cut = cut_body(&long);
        assert!(cut.len() < long.len() && cut.contains("more bytes not kept"));
        assert_eq!(cut_body("short"), "short");
    }
}
