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
    // `watch` on what a coding tool reported about itself (watch records), absent on requests Enterplace decided.
    Dimension {
        name: "source",
        label: "Source",
        field: "source",
    },
];

/// What links a request to its conversation: the session and the turn an events guardrail gave it. Filtered and
/// grouped by like a dimension (`?session=ses_...`, `group_by=turn`), and not listed among the console's filters.
pub const LINKS: &[Dimension] = &[
    Dimension {
        name: "session",
        label: "Session",
        field: "session",
    },
    Dimension {
        name: "turn",
        label: "Turn",
        field: "turn",
    },
];

/// Every field requests are filtered and grouped by.
pub fn dimensions() -> impl Iterator<Item = &'static Dimension> {
    DIMENSIONS.iter().chain(LINKS)
}

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
    /// The cost is an estimate at API prices: the request went with the caller's own subscription login, which is
    /// paid for by the seat.
    pub estimate: bool,
    pub charged_usd: f64,
    pub latency_ms: Option<u64>,
    /// A redacted body was kept for it.
    pub body: bool,
    /// Where its time went inside Enterplace, in milliseconds, in the order it passed them: the stages of its usage
    /// record's `stages_ms`, then each guardrail call as `guardrail <name>`.
    pub stages: Vec<(String, f64)>,
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
    /// No provider answered (`upstream_error`): the status and code Enterplace answered with instead.
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
    pub stages: Vec<(String, f64)>,
}

/// A usage record's `stages_ms`, then its `guardrail_ms` as `guardrail <name>`.
fn stages_of(record: &Value) -> Vec<(String, f64)> {
    let entries = |field: &str, prefix: &str| -> Vec<(String, f64)> {
        record
            .get(field)
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .filter_map(|(name, ms)| Some((format!("{prefix}{name}"), ms.as_f64()?)))
            .collect()
    };
    let mut out = entries("stages_ms", "");
    out.extend(entries("guardrail_ms", "guardrail "));
    out
}

fn text(record: &Value, field: &str) -> String {
    record
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// The kinds a request record's `guardrails` found.
pub fn kinds(guardrails: Option<&Value>) -> Vec<String> {
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
    for dimension in dimensions() {
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
                .map(|a| crate::audit::agent_of(Some(a)))
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
    // A row as its record opens it: what a later usage record would add is left empty.
    let row = |verdict: String, path: String| -> Option<Box<Row>> {
        Some(Box::new(Row {
            id: id.clone(),
            time: text(&record, "time"),
            replica: replica.to_string(),
            n: number("n")?,
            linked: prev.is_none_or(|p| record.get("prev").and_then(Value::as_str) == Some(p)),
            hash: text(&record, "hash"),
            line: line.to_string(),
            path,
            labels: labels_of(&record),
            verdict,
            code: text(&record, "code"),
            rule: text(&record, "rule"),
            findings: kinds(record.get("guardrails")),
            estimate: text(&record, "auth") == "passthrough",
            ..Row::default()
        }))
    };
    match record.get("event").and_then(Value::as_str) {
        None if record.get("verdict").is_some() && record.get("method").is_some() => Some(
            Fact::Request(row(text(&record, "verdict"), text(&record, "path"))?),
        ),
        // A model request a watched coding tool reported (a `watch` record): Enterplace did not decide or forward it, so
        // it is a row of its own with what the tool said it used, and it counts against no budget. The other watch
        // kinds (tool decisions, prompts, metrics) are not requests.
        Some("watch") => {
            let kind = text(&record, "kind");
            if !matches!(kind.as_str(), "api_request" | "api_error" | "api_refusal") {
                return None;
            }
            let mut row = row("allow".into(), format!("watch/{kind}"))?;
            if kind != "api_request" {
                row.code = kind;
            }
            row.status = number("status").and_then(|s| u16::try_from(s).ok());
            row.input_tokens = number("input_tokens");
            row.output_tokens = number("output_tokens");
            row.cost_usd = record.get("cost_usd").and_then(Value::as_f64);
            row.latency_ms = number("latency_ms");
            Some(Fact::Request(row))
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
            stages: stages_of(&record),
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
        row.stages.clone_from(&self.stages);
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
    let failed =
        |err: std::io::Error| format!("the audit log at {} cannot be read: {err}.", path.display());
    // Every organization's chain too (`audit: { per_org: true }`), each folded as its own chain.
    let mut rows = Vec::new();
    for (_, at) in crate::audit::chains(path).map_err(failed)? {
        rows.extend(fold(crate::audit::chain_reader(&at).map_err(failed)?, ""));
    }
    rows.sort_by(|a, b| b.time.cmp(&a.time));
    Ok(rows)
}

/// What the request log is asked for. Every field narrows it; an empty field does not.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Query {
    /// Dimension name and the value it must have.
    pub labels: Vec<(String, String)>,
    /// Dimension name and the values one of which it must have: the reach of a person kept to some teams or
    /// customers. Never from a form, so a viewer cannot widen it.
    pub within: Vec<(String, Vec<String>)>,
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
        for dimension in dimensions() {
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
            && self.within.iter().all(|(d, any)| {
                row.labels
                    .get(d)
                    .is_some_and(|vs| vs.iter().any(|v| any.contains(v)))
            })
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
    /// The part of `cost_usd` that is an estimate: requests sent with the caller's own subscription login.
    pub estimated_usd: f64,
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
        if row.estimate {
            self.estimated_usd += row.cost_usd.unwrap_or_default();
        }
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
    split(rows, dimension, &[])
        .into_iter()
        .map(|(value, stats, _)| (value, stats))
        .collect()
}

/// The values of a dimension a request counts under: each one it has, or "" when it has none.
fn values_of<'a>(row: &'a Row, dimension: &str) -> Vec<&'a str> {
    match row.labels.get(dimension) {
        Some(values) if !values.is_empty() => values.iter().map(String::as_str).collect(),
        _ => vec![""],
    }
}

/// One value of a ranking, its stats, and its requests split by more dimensions: each part names one value of each.
pub type Split = (String, Stats, Vec<(Vec<String>, Stats)>);

/// [`ranking`] by `dimension`, each value's requests split again by the dimensions of `then` together (a person by
/// coding agent and model), most costly part first. With `then` empty there are no parts.
pub fn split(rows: &[Row], dimension: &str, then: &[&str]) -> Vec<Split> {
    type Parts = HashMap<Vec<String>, Stats>;
    let mut groups: HashMap<String, (Stats, Parts)> = HashMap::new();
    for row in rows {
        // Every combination of the `then` values, as a request with two tags counts under both.
        let mut keys: Vec<Vec<String>> = vec![Vec::new()];
        for d in then {
            keys = keys
                .into_iter()
                .flat_map(|k| {
                    values_of(row, d).into_iter().map(move |v| {
                        let mut k = k.clone();
                        k.push(v.to_string());
                        k
                    })
                })
                .collect();
        }
        for value in values_of(row, dimension) {
            let group = groups.entry(value.to_string()).or_default();
            group.0.add(row);
            if !then.is_empty() {
                for key in &keys {
                    group.1.entry(key.clone()).or_default().add(row);
                }
            }
        }
    }
    let mut ranked: Vec<Split> = groups
        .into_iter()
        .map(|(value, (stats, parts))| {
            let mut parts: Vec<(Vec<String>, Stats)> =
                parts.into_iter().map(|(k, s)| (k, s.done())).collect();
            parts.sort_by(|a, b| costlier((&a.0, &a.1), (&b.0, &b.1)));
            (value, stats.done(), parts)
        })
        .collect();
    ranked.sort_by(|a, b| costlier((&a.0, &a.1), (&b.0, &b.1)));
    ranked
}

/// The dimensions a ranking by `group` is split by, from `then=agent,model`: at most two, each a dimension other than
/// `group`. `Err` says what to send instead.
pub fn then_of(text: &str, group: &str) -> Result<Vec<&'static str>, String> {
    let mut out: Vec<&'static str> = Vec::new();
    for name in text.split(',').map(str::trim).filter(|n| !n.is_empty()) {
        let Some(d) = dimensions().find(|d| d.name == name) else {
            return Err(format!(
                "{name} is not a dimension. Split by one or two of {}.",
                dimensions().map(|d| d.name).collect::<Vec<_>>().join(", ")
            ));
        };
        if d.name == group || out.contains(&d.name) {
            return Err(format!(
                "{name} is named twice. Split by dimensions other than the one ranked."
            ));
        }
        out.push(d.name);
    }
    if out.len() > 2 {
        return Err("Split by at most two dimensions, for example agent,model.".into());
    }
    Ok(out)
}

/// The columns of a usage export, in order after the group's own: what `/admin/usage` and the console's CSV write.
pub const USAGE_COLUMNS: [&str; 10] = [
    "requests",
    "refused",
    "errors",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "spend_usd",
    "latency_p50_ms",
    "latency_p95_ms",
    "estimated_usd",
];

/// A group's stats as the usage API writes them, plain numbers.
pub fn usage_json(stats: &Stats) -> serde_json::Map<String, Value> {
    let mut out = serde_json::Map::new();
    out.insert("requests".into(), stats.requests.into());
    out.insert("refused".into(), stats.refused.into());
    out.insert("errors".into(), stats.errors.into());
    out.insert("input_tokens".into(), stats.input_tokens.into());
    out.insert("output_tokens".into(), stats.output_tokens.into());
    out.insert(
        "total_tokens".into(),
        (stats.input_tokens + stats.output_tokens).into(),
    );
    out.insert("spend_usd".into(), stats.cost_usd.into());
    out.insert("latency_p50_ms".into(), stats.percentile(50.0).into());
    out.insert("latency_p95_ms".into(), stats.percentile(95.0).into());
    out.insert("estimated_usd".into(), stats.estimated_usd.into());
    out
}

/// A text cell of a CSV export, quoted, and never read as a formula by a spreadsheet.
pub fn csv_field(text: &str) -> String {
    let text = if text.starts_with(['=', '+', '-', '@']) {
        format!("'{text}")
    } else {
        text.to_string()
    };
    format!("\"{}\"", text.replace('"', "\"\""))
}

/// A ranking as CSV: a column for the group and each `then` dimension, then [`USAGE_COLUMNS`]. With `then` set,
/// one line per part, so a spreadsheet can pivot it either way.
pub fn usage_csv(group: &str, then: &[&str], ranked: &[Split]) -> String {
    let mut out = std::iter::once(group)
        .chain(then.iter().copied())
        .chain(USAGE_COLUMNS)
        .collect::<Vec<_>>()
        .join(",");
    out.push('\n');
    let mut line = |names: Vec<&str>, stats: &Stats| {
        let row = usage_json(stats);
        let cells = names
            .into_iter()
            .map(csv_field)
            .chain(USAGE_COLUMNS.iter().map(|c| match &row[*c] {
                Value::Null => String::new(),
                v => v.to_string(),
            }))
            .collect::<Vec<_>>();
        out.push_str(&cells.join(","));
        out.push('\n');
    };
    for (value, stats, parts) in ranked {
        if then.is_empty() {
            line(vec![value], stats);
        }
        for (names, stats) in parts {
            line(
                std::iter::once(value.as_str())
                    .chain(names.iter().map(String::as_str))
                    .collect(),
                stats,
            );
        }
    }
    out
}

/// Most costly first, then most requests, then by name.
pub fn rank(ranked: &mut [(String, Stats)]) {
    ranked.sort_by(|a, b| costlier((&a.0, &a.1), (&b.0, &b.1)));
}

fn costlier<K: Ord>(a: (&K, &Stats), b: (&K, &Stats)) -> std::cmp::Ordering {
    b.1.cost_usd
        .total_cmp(&a.1.cost_usd)
        .then(b.1.requests.cmp(&a.1.requests))
        .then(a.0.cmp(b.0))
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
/// (`ENTERPLACE_MASTER_KEY`), AES-256-GCM with the decision ID as associated data, so a body moved to another ID
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
    let body: Body = serde_json::from_slice(&plain).map_err(|err| {
        format!("the kept body of decision {id} is not one Enterplace wrote: {err}")
    })?;
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
    /// What the requests the query matches were charged against budgets (`charged_usd`), by each value of
    /// `dimension` (a request counts under each value it has), summed where the rows are kept. What a budget
    /// forecast reads for its own window.
    fn spent(&self, query: &Query, dimension: &str) -> Pending<Vec<(String, f64)>>;
    /// The decision records of every gateway since `since` (RFC 3339), as written, oldest first: the newest `max`
    /// of them when there are more. What a policy dry run replays.
    fn lines(&self, since: &str, max: usize) -> Pending<Vec<String>>;
    /// What the requests the query matches cost, by day, organization, team, provider and model, summed where the
    /// rows are kept. What a cost export writes ([`cost_lines`] over the local chain).
    fn cost_lines(&self, query: &Query) -> Pending<Vec<CostLine>>;
}

/// One line of a cost export: what one team's requests to one model at one provider cost in one UTC day.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CostLine {
    /// `2026-11-15`.
    pub day: String,
    pub org: String,
    pub team: String,
    pub provider: String,
    pub model: String,
    pub requests: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_usd: f64,
}

/// [`Index::cost_lines`] over rows folded here, from the local chain. A refused request reached no provider and
/// cost nothing, so it is no line.
pub fn cost_lines(rows: &[Row]) -> Vec<CostLine> {
    let mut by: BTreeMap<[String; 5], CostLine> = BTreeMap::new();
    for row in rows.iter().filter(|r| r.verdict != "refused") {
        let key = [
            row.time.get(..10).unwrap_or_default().to_string(),
            row.label("org").to_string(),
            row.label("team").to_string(),
            row.label("provider").to_string(),
            row.label("model").to_string(),
        ];
        let line = by.entry(key.clone()).or_insert_with(|| {
            let [day, org, team, provider, model] = key;
            CostLine {
                day,
                org,
                team,
                provider,
                model,
                ..CostLine::default()
            }
        });
        line.requests += 1;
        line.input_tokens += row.input_tokens.unwrap_or_default();
        line.output_tokens += row.output_tokens.unwrap_or_default();
        line.cost_usd += row.cost_usd.unwrap_or_default();
    }
    by.into_values().collect()
}

/// [`Index::spent`] over rows folded here, from the local chain.
pub fn spent(rows: &[Row], dimension: &str, from_secs: u64) -> Vec<(String, f64)> {
    let mut by: std::collections::BTreeMap<String, f64> = std::collections::BTreeMap::new();
    for row in rows {
        if unix_secs(&row.time).is_some_and(|t| t >= from_secs) {
            for value in row.labels.get(dimension).into_iter().flatten() {
                *by.entry(value.clone()).or_default() += row.charged_usd;
            }
        }
    }
    by.into_iter().collect()
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

// Legal hold, per audit log, as an embedder (Enterplace Enterprise retention) sets it: while it is on, no kept body
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

/// A decision ID as Enterplace makes them: letters and digits only, so it is safe as a file name.
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
                        "enterplace: kept bodies in {} are past their retention and could not be deleted: {err}. Delete the directory by hand.",
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
                "decision ID \"{}\" is not one Enterplace makes",
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
                    eprintln!("enterplace: {err}.");
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
                .name("enterplace-bodies".into())
                .spawn(move || {
                    let mut swept = None::<std::time::Instant>;
                    for body in told {
                        if let Err(err) = me.write(&body) {
                            eprintln!(
                                "enterplace: the body of decision {} was not kept: {err}.",
                                body.id
                            );
                        }
                        if swept.is_none_or(|at| at.elapsed() > Duration::from_secs(3600)) {
                            me.sweep();
                            swept = Some(std::time::Instant::now());
                        }
                    }
                })
                .map_err(|err| eprintln!("enterplace: the body writer could not start: {err}"))
                .ok();
            Mutex::new(tell)
        });
        let sent = sender
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .send(body);
        if sent.is_err() {
            eprintln!("enterplace: a body was not kept: the body writer is not running.");
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
            std::env::temp_dir().join(format!("enterplace-insights-{}", crate::id::random_hex(6)));
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
    fn a_usage_records_stages_go_on_its_row_in_order() {
        let lines = [
            r#"{"id":"S1","time":"2026-11-15T10:00:00.000Z","method":"POST","path":"/v1/chat/completions","verdict":"allow","n":1,"hash":"h1"}"#,
            r#"{"event":"usage","id":"S1","latency_ms":12,"stages_ms":{"auth":0.02,"policy":0.1,"first_byte":9.5,"stream":2.0},"guardrail_ms":{"lakera":3.25},"n":2,"hash":"h2"}"#,
        ];
        let rows = fold(std::io::Cursor::new(lines.join("\n")), "");
        let names: Vec<&str> = rows[0].stages.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            ["auth", "policy", "first_byte", "stream", "guardrail lakera"]
        );
        assert_eq!(rows[0].stages[4].1, 3.25);
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
    fn a_watched_request_is_a_row_of_source_watch_and_other_watch_records_are_not() -> TestResult {
        let (path, log) = chain()?;
        log.append_record(&request("D1", "payments", true, None))?;
        let watch = |id: &str, kind: &str, more: Value| -> serde_json::Map<String, Value> {
            let mut r = serde_json::json!({
                "event": "watch", "id": id, "time": crate::audit::timestamp(), "source": "watch", "kind": kind,
                "person": "maya@acme.co", "team": "payments", "user_agent": "claude-code/2.1.325",
                "provider": "anthropic", "model": "claude-sonnet-5-5"
            });
            if let (Some(r), Value::Object(more)) = (r.as_object_mut(), more) {
                r.extend(more);
            }
            r.as_object().cloned().unwrap_or_default()
        };
        log.append_record(&watch(
            "W1",
            "api_request",
            serde_json::json!({"input_tokens": 1200, "output_tokens": 40, "cost_usd": 0.00405, "latency_ms": 7}),
        ))?;
        log.append_record(&watch(
            "W2",
            "api_error",
            serde_json::json!({"status": 529}),
        ))?;
        log.append_record(&watch(
            "W3",
            "tool_decision",
            serde_json::json!({"tool": "Bash"}),
        ))?;
        log.flush();
        let rows = fold_chain(&path)?;
        assert_eq!(
            rows.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            ["W2", "W1", "D1"],
            "a tool decision is not a request"
        );
        let w1 = rows.get(1).ok_or("no W1")?;
        assert_eq!(
            (
                w1.label("source"),
                w1.label("person"),
                w1.label("agent"),
                w1.label("model")
            ),
            ("watch", "maya@acme.co", "claude-code", "claude-sonnet-5-5")
        );
        assert_eq!(
            (
                w1.input_tokens,
                w1.output_tokens,
                w1.cost_usd,
                w1.latency_ms
            ),
            (Some(1200), Some(40), Some(0.00405), Some(7))
        );
        // Watched spend is seen, never charged: budgets count only what Enterplace forwarded.
        assert_eq!(w1.charged_usd, 0.0);
        assert_eq!(
            (w1.path.as_str(), w1.outcome()),
            ("watch/api_request", Outcome::Allowed)
        );
        assert!(w1.checks_out());
        let w2 = rows.first().ok_or("no W2")?;
        assert_eq!(
            (w2.code.as_str(), w2.outcome()),
            ("api_error", Outcome::Error)
        );
        // The request Enterplace decided has no source, so `source=watch` selects the watched ones alone.
        let only = Query {
            labels: vec![("source".into(), "watch".into())],
            limit: 10,
            ..Query::default()
        };
        assert_eq!(only.select(&rows).len(), 2);
        assert_eq!(totals(&only.select(&rows)).cost_usd, 0.00405);
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
        let (start, end) = crate::policy::Period::Month.window(1_794_657_600); // 2026-11-14T12:00:00Z
        let (start, end) = (start as u64, end as u64);
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
