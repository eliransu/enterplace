//! The request log across replicas, and kept bodies, in Postgres (tables of the `insights` namespace).
//!
//! Each replica copies the rows of its own audit chain into `gantry_requests`, after a cursor it keeps in
//! `gantry_insights_replicas`: the decision record as written (no prompt text is in it), its number and hash, and
//! what its usage, upstream error and answer guardrail records add. Every dimension is in one `labels` column, so a
//! new one needs no migration. Kept bodies are sealed with the master key before they reach `gantry_bodies`, and
//! deleted when they expire. Nothing here is on the request path: copying runs every two seconds.

use std::{
    io::{BufRead, BufReader, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use gantry_core::{
    audit,
    insights::{self, Bodies, Body, Fact, Index, Query, Row, Seal},
    store::Pending,
};
use tokio_postgres::{Client, types::ToSql};

use crate::{credentials::MasterKey, store::PgStore};

pub const NAMESPACE: &str = "insights";

/// Never edit an entry that has shipped: add one.
pub const MIGRATIONS: &[&str] = &["
CREATE TABLE gantry_requests (
    id text PRIMARY KEY,
    time timestamptz NOT NULL,
    replica text NOT NULL,
    n bigint NOT NULL,
    hash text NOT NULL,
    linked boolean NOT NULL,
    line text NOT NULL,
    path text NOT NULL,
    labels jsonb NOT NULL,
    verdict text NOT NULL,
    code text NOT NULL,
    rule text NOT NULL,
    findings text[] NOT NULL,
    status integer,
    input_tokens bigint,
    output_tokens bigint,
    cost_usd double precision,
    charged_usd double precision NOT NULL DEFAULT 0,
    latency_ms bigint,
    body boolean NOT NULL DEFAULT false
);
CREATE INDEX gantry_requests_time ON gantry_requests (time DESC, id DESC);
CREATE INDEX gantry_requests_labels ON gantry_requests USING gin (labels jsonb_path_ops);
CREATE TABLE gantry_insights_replicas (
    id text PRIMARY KEY,
    n bigint NOT NULL,
    hash text NOT NULL,
    seen_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE gantry_bodies (
    id text PRIMARY KEY,
    expires timestamptz NOT NULL,
    sealed bytea NOT NULL
);
CREATE INDEX gantry_bodies_expires ON gantry_bodies (expires);
"];

/// Most records copied in one pass.
const BATCH: usize = 5000;

/// The master key, sealing bodies as it seals provider credentials, under the name `body:<decision ID>`.
#[derive(Debug)]
pub struct Sealer(pub MasterKey);

impl Seal for Sealer {
    fn seal(&self, id: &str, plain: &[u8]) -> Result<Vec<u8>, String> {
        self.0.seal(id, plain)
    }

    fn open(&self, id: &str, sealed: &[u8]) -> Result<Vec<u8>, String> {
        self.0.open(id, sealed).map_err(|_| {
            format!("the kept {id} does not open with this gateway's GANTRY_MASTER_KEY: it was sealed with another master key, or changed. Set the master key the other gateways use.")
        })
    }
}

/// Where the next read of the live log starts: its byte offset, and the record number expected there.
type Hint = Option<(u64, u64)>;

/// The request log of every replica on the store, and this replica's copier into it.
pub struct PgIndex {
    pg: Arc<PgStore>,
    replica: String,
    path: PathBuf,
    seal: Option<Arc<dyn Seal>>,
    queue: Mutex<Vec<Body>>,
    hint: Mutex<Hint>,
    /// One copy pass at a time.
    copying: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for PgIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgIndex")
            .field("replica", &self.replica)
            .finish_non_exhaustive()
    }
}

fn db(err: tokio_postgres::Error) -> String {
    format!("the request index in the store failed: {err}")
}

/// This replica's name: the host and the first hash of its chain, so a new chain on the same host is a new
/// replica rather than a repeat of the old numbers. Kept beside the log, since record 1 may be retired.
pub fn replica_id(path: &Path) -> String {
    let mut name = path.as_os_str().to_owned();
    name.push(".replica");
    let file = PathBuf::from(name);
    let host: String = std::env::var("HOSTNAME")
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
        .take(48)
        .collect();
    let host = if host.is_empty() {
        "gantry".into()
    } else {
        host
    };
    let first = audit::chain_reader(path).ok().and_then(|mut reader| {
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        line.trim_end()
            .starts_with("{\"n\":1,")
            .then(|| insights::hash_of_line(line.trim_end()))
            .flatten()
    });
    let kept = std::fs::read_to_string(&file)
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty());
    let id = match (kept, first) {
        (Some(kept), Some(hash)) if hash.get(..12).is_some_and(|h| kept.ends_with(h)) => kept,
        (_, Some(hash)) => format!("{host}-{}", hash.get(..12).unwrap_or_default()),
        (Some(kept), None) => kept,
        (None, None) => format!("{host}-{}", gantry_core::id::random_hex(6)),
    };
    if let Err(err) = std::fs::write(&file, &id) {
        eprintln!(
            "gantry: {} could not be written ({err}); this replica's name in the request index may change at the next start.",
            file.display()
        );
    }
    id
}

/// The number of a record line.
fn number(line: &str) -> Option<u64> {
    line.strip_prefix("{\"n\":")?
        .split(',')
        .next()?
        .parse()
        .ok()
}

/// Records after `after`, oldest first, at most `max`, with their numbers. Reads the live log from where the last
/// read stopped; the whole chain, sealed segments too, when that does not hold.
fn read_after(
    path: &Path,
    after: u64,
    hint: &mut Hint,
    max: usize,
) -> Result<Vec<(u64, String)>, String> {
    let failed =
        |err: std::io::Error| format!("the audit log at {} cannot be read: {err}", path.display());
    let mut out = Vec::new();
    if let Ok(file) = std::fs::File::open(path) {
        let start = match *hint {
            Some((offset, next)) if next == after + 1 => offset,
            _ => 0,
        };
        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::Start(start)).map_err(failed)?;
        let mut offset = start;
        let mut line = String::new();
        let mut first = true;
        loop {
            line.clear();
            let read = reader.read_line(&mut line).map_err(failed)?;
            if read == 0 || !line.ends_with('\n') || out.len() >= max {
                break;
            }
            let text = line.trim_end();
            let Some(n) = number(text) else { break };
            if first && n > after + 1 {
                // The live log starts past what is wanted: those records are in sealed segments.
                out.clear();
                break;
            }
            first = false;
            offset += read as u64;
            if n > after {
                out.push((n, text.to_string()));
            }
        }
        if !out.is_empty() || (!first && start == 0) {
            *hint = out
                .last()
                .map_or(Some((offset, after + 1)), |(n, _)| Some((offset, n + 1)));
            return Ok(out);
        }
        if start > 0 && first {
            // Nothing new where the last read stopped, or the log was sealed: look again from its start next time.
            let len = std::fs::metadata(path).map_or(0, |m| m.len());
            if len >= start {
                return Ok(out);
            }
        }
    }
    *hint = None;
    if !audit::has_records(path) {
        return Ok(out);
    }
    let reader = audit::chain_reader(path).map_err(failed)?;
    for line in reader.lines() {
        let line = line.map_err(failed)?;
        match number(&line) {
            Some(n) if n > after => out.push((n, line)),
            _ => {}
        }
        if out.len() >= max {
            break;
        }
    }
    Ok(out)
}

fn int(v: Option<u64>) -> Option<i64> {
    v.and_then(|v| i64::try_from(v).ok())
}

const COLUMNS: &str = "id, to_char(time AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'), replica, n, hash, linked, line, path, labels::text, verdict, code, rule, findings, status, input_tokens, output_tokens, cost_usd, charged_usd, latency_ms, body";

fn row_of(r: &tokio_postgres::Row) -> Result<Row, String> {
    let get = |i: usize| r.try_get::<_, String>(i).map_err(db);
    let unsigned = |v: Option<i64>| v.and_then(|v| u64::try_from(v).ok());
    Ok(Row {
        id: get(0)?,
        time: get(1)?,
        replica: get(2)?,
        n: u64::try_from(r.try_get::<_, i64>(3).map_err(db)?).unwrap_or_default(),
        hash: get(4)?,
        linked: r.try_get(5).map_err(db)?,
        line: get(6)?,
        path: get(7)?,
        labels: serde_json::from_str(&get(8)?).unwrap_or_default(),
        verdict: get(9)?,
        code: get(10)?,
        rule: get(11)?,
        findings: r.try_get(12).map_err(db)?,
        status: r
            .try_get::<_, Option<i32>>(13)
            .map_err(db)?
            .and_then(|s| u16::try_from(s).ok()),
        input_tokens: unsigned(r.try_get(14).map_err(db)?),
        output_tokens: unsigned(r.try_get(15).map_err(db)?),
        cost_usd: r.try_get(16).map_err(db)?,
        charged_usd: r.try_get(17).map_err(db)?,
        latency_ms: unsigned(r.try_get(18).map_err(db)?),
        body: r.try_get(19).map_err(db)?,
    })
}

/// The WHERE clause and its parameters for a query. Means what [`Query::matches`] means.
fn clause(query: &Query) -> (String, Vec<Box<dyn ToSql + Sync + Send>>) {
    let mut terms: Vec<String> = Vec::new();
    let mut params: Vec<Box<dyn ToSql + Sync + Send>> = Vec::new();
    let mut add = |term: &str, value: Box<dyn ToSql + Sync + Send>| {
        params.push(value);
        terms.push(term.replace('?', &format!("${}", params.len())));
    };
    for (dimension, value) in &query.labels {
        let wanted = serde_json::json!({ dimension: [value] }).to_string();
        add("labels @> CAST(? AS text)::jsonb", Box::new(wanted));
    }
    if !query.code.is_empty() {
        add("code = ?", Box::new(query.code.clone()));
    }
    if !query.finding.is_empty() {
        add("? = ANY(findings)", Box::new(query.finding.clone()));
    }
    if !query.id.is_empty() {
        add("id = ?", Box::new(query.id.clone()));
    }
    if !query.from.is_empty() {
        add(
            "time >= CAST(? AS text)::timestamptz",
            Box::new(query.from.clone()),
        );
    }
    if query.to.len() == 10 {
        add(
            "time < CAST(? AS text)::date + 1",
            Box::new(query.to.clone()),
        );
    } else if !query.to.is_empty() {
        add(
            "time <= CAST(? AS text)::timestamptz",
            Box::new(query.to.clone()),
        );
    }
    if let Some(v) = query.min_cost {
        add("cost_usd >= ?", Box::new(v));
    }
    if let Some(v) = query.max_cost {
        add("cost_usd <= ?", Box::new(v));
    }
    if let Some(v) = int(query.min_ms) {
        add("latency_ms >= ?", Box::new(v));
    }
    if let Some(v) = int(query.max_ms) {
        add("latency_ms <= ?", Box::new(v));
    }
    let blocked = "code = 'guardrail_blocked'";
    match query.outcome.as_str() {
        "allowed" => terms.push(format!(
            "verdict = 'allow' AND NOT {blocked} AND coalesce(status, 0) < 400"
        )),
        "refused" => terms.push(format!("(verdict = 'refused' OR {blocked})")),
        "error" => terms.push(format!(
            "verdict <> 'refused' AND NOT {blocked} AND status >= 400"
        )),
        _ => {}
    }
    let clause = if terms.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", terms.join(" AND "))
    };
    (clause, params)
}

impl PgIndex {
    /// Creates the tables, and serves the request log (and the bodies, when `seal` is set) of the audit log at
    /// `path` from the store. `copy` starts the copier, every two seconds; tests call [`PgIndex::copy`] themselves.
    pub fn open(
        pg: Arc<PgStore>,
        path: &Path,
        seal: Option<Arc<dyn Seal>>,
        copy: bool,
    ) -> Result<Arc<Self>, String> {
        pg.migrate(NAMESPACE, MIGRATIONS)?;
        let index = Arc::new(Self {
            pg,
            replica: replica_id(path),
            path: path.to_path_buf(),
            seal,
            queue: Mutex::default(),
            hint: Mutex::default(),
            copying: tokio::sync::Mutex::const_new(()),
        });
        if copy {
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                let weak = Arc::downgrade(&index);
                runtime.spawn(async move {
                    let mut reported = false;
                    loop {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        let Some(index) = weak.upgrade() else { return };
                        match index.copy().await {
                            Ok(_) => reported = false,
                            // Said once per outage: the next pass picks up from the same cursor.
                            Err(err) if !reported => {
                                eprintln!("gantry: {err}. The request log in the console is behind until it can copy again.");
                                reported = true;
                            }
                            Err(_) => {}
                        }
                    }
                });
            }
        }
        Ok(index)
    }

    pub fn replica(&self) -> &str {
        &self.replica
    }

    /// Copies this replica's records written since the last pass, writes the bodies kept since, and deletes the
    /// bodies that expired. Returns how many records it read.
    pub async fn copy(&self) -> Result<usize, String> {
        let _one = self.copying.lock().await;
        let mut client = self.pg.connect().await?;
        self.write_bodies(&client).await?;
        // Under legal hold nothing kept is deleted, however old.
        if !insights::held(&self.path) {
            client
                .execute("DELETE FROM gantry_bodies WHERE expires < now()", &[])
                .await
                .map_err(db)?;
        }
        let cursor = client
            .query_opt(
                "SELECT n, hash FROM gantry_insights_replicas WHERE id = $1",
                &[&self.replica],
            )
            .await
            .map_err(db)?;
        let (after, mut prev): (u64, Option<String>) = match cursor {
            Some(row) => (
                u64::try_from(row.try_get::<_, i64>(0).map_err(db)?).unwrap_or_default(),
                Some(row.try_get::<_, String>(1).map_err(db)?).filter(|h| !h.is_empty()),
            ),
            None => (0, None),
        };
        let path = self.path.clone();
        let mut hint = *self
            .hint
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (lines, hint) = tokio::task::spawn_blocking(move || {
            read_after(&path, after, &mut hint, BATCH).map(|lines| (lines, hint))
        })
        .await
        .map_err(|err| format!("the audit reader stopped: {err}"))??;
        *self
            .hint
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = hint;
        let Some((last, last_line)) = lines.last().cloned() else {
            return Ok(0);
        };
        let tx = client.transaction().await.map_err(db)?;
        for (_, line) in &lines {
            let fact = insights::fact(line, &self.replica, prev.as_deref());
            prev = insights::hash_of_line(line);
            match fact {
                Some(Fact::Request(row)) => {
                    let labels = serde_json::to_string(&row.labels).unwrap_or_else(|_| "{}".into());
                    tx.execute(
                        "INSERT INTO gantry_requests (id, time, replica, n, hash, linked, line, path, labels, verdict, code, rule, findings) \
                         VALUES ($1, CAST($2 AS text)::timestamptz, $3, $4, $5, $6, $7, $8, CAST($9 AS text)::jsonb, $10, $11, $12, $13) ON CONFLICT (id) DO NOTHING",
                        &[&row.id, &row.time, &row.replica, &int(Some(row.n)), &row.hash, &row.linked, &row.line, &row.path, &labels, &row.verdict, &row.code, &row.rule, &row.findings],
                    )
                    .await
                    .map_err(db)?;
                }
                Some(Fact::Usage(usage)) => {
                    let mut moved = serde_json::Map::new();
                    for (d, v) in [("provider", &usage.provider), ("model", &usage.model)] {
                        if !v.is_empty() {
                            moved.insert(d.into(), serde_json::json!([v]));
                        }
                    }
                    tx.execute(
                        "UPDATE gantry_requests SET labels = labels || CAST($2 AS text)::jsonb, status = $3, input_tokens = $4, output_tokens = $5, \
                         cost_usd = $6, charged_usd = $7, latency_ms = $8, body = $9 WHERE id = $1",
                        &[&usage.id, &serde_json::Value::Object(moved).to_string(), &usage.status.map(i32::from), &int(usage.input_tokens), &int(usage.output_tokens), &usage.cost_usd, &usage.charged_usd, &int(usage.latency_ms), &usage.body],
                    )
                    .await
                    .map_err(db)?;
                }
                Some(Fact::Failure {
                    id,
                    status,
                    code,
                    latency_ms,
                }) => {
                    tx.execute(
                        "UPDATE gantry_requests SET status = $2, code = $3, latency_ms = $4 WHERE id = $1",
                        &[&id, &status.map(i32::from), &code, &int(latency_ms)],
                    )
                    .await
                    .map_err(db)?;
                }
                Some(Fact::Answer {
                    id,
                    blocked,
                    findings,
                }) => {
                    tx.execute(
                        "UPDATE gantry_requests SET code = CASE WHEN $2 THEN 'guardrail_blocked' ELSE code END, findings = findings || $3 WHERE id = $1",
                        &[&id, &blocked, &findings],
                    )
                    .await
                    .map_err(db)?;
                }
                // Retention removed these records from the chain: their rows and kept bodies follow, so the index
                // never holds what the audit log no longer does. Retention does not run under legal hold.
                Some(Fact::Retired { through }) => {
                    tx.execute(
                        "DELETE FROM gantry_bodies WHERE id IN (SELECT id FROM gantry_requests WHERE replica = $1 AND n <= $2)",
                        &[&self.replica, &int(Some(through))],
                    )
                    .await
                    .map_err(db)?;
                    tx.execute(
                        "DELETE FROM gantry_requests WHERE replica = $1 AND n <= $2",
                        &[&self.replica, &int(Some(through))],
                    )
                    .await
                    .map_err(db)?;
                }
                None => {}
            }
        }
        let hash = insights::hash_of_line(&last_line).unwrap_or_default();
        tx.execute(
            "INSERT INTO gantry_insights_replicas (id, n, hash) VALUES ($1, $2, $3) \
             ON CONFLICT (id) DO UPDATE SET n = excluded.n, hash = excluded.hash, seen_at = now()",
            &[&self.replica, &int(Some(last)), &hash],
        )
        .await
        .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(lines.len())
    }

    async fn write_bodies(&self, client: &Client) -> Result<(), String> {
        let waiting: Vec<Body> = std::mem::take(
            &mut *self
                .queue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let Some(seal) = &self.seal else {
            return Ok(());
        };
        for (i, body) in waiting.iter().enumerate() {
            let written = match insights::seal_body(seal.as_ref(), body) {
                Ok(sealed) => client
                    .execute(
                        "INSERT INTO gantry_bodies (id, expires, sealed) VALUES ($1, to_timestamp($2), $3) ON CONFLICT (id) DO NOTHING",
                        &[&body.id, &(body.expires as f64), &sealed],
                    )
                    .await
                    .map(|_| ())
                    .map_err(db),
                Err(err) => {
                    eprintln!("gantry: the body of decision {} was not kept: {err}.", body.id);
                    Ok(())
                }
            };
            if let Err(err) = written {
                // Put back what was not written, for the next pass.
                self.queue
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .extend(waiting.into_iter().skip(i));
                return Err(err);
            }
        }
        Ok(())
    }
}

impl Index for PgIndex {
    fn analytics(
        &self,
        query: &Query,
        hourly: bool,
        dimension: &str,
    ) -> Pending<insights::Analytics> {
        let pg = self.pg.clone();
        let query = query.clone();
        let dimension = dimension.to_string();
        Box::pin(async move {
            let client = pg.connect().await?;
            let (clause, mut params) = clause(&query);
            let bucket = if hourly {
                "to_char(time AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24')"
            } else {
                "to_char(time AT TIME ZONE 'UTC', 'YYYY-MM-DD')"
            };
            let totals = format!("SELECT '' AS k, {GROUP_STATS} FROM gantry_requests {clause}");
            let series = format!(
                "SELECT {bucket} AS k, {GROUP_STATS} FROM gantry_requests {clause} GROUP BY 1 ORDER BY 1"
            );
            params.push(Box::new(dimension));
            // A request counts once under each value it has, and under "" when it has none, as `ranking` folds it.
            let ranking = format!(
                "SELECT v.k, {GROUP_STATS} FROM gantry_requests CROSS JOIN LATERAL jsonb_array_elements_text( \
                   CASE WHEN jsonb_typeof(labels -> ${n}) = 'array' AND jsonb_array_length(labels -> ${n}) > 0 \
                   THEN labels -> ${n} ELSE '[\"\"]'::jsonb END) AS v(k) {clause} GROUP BY 1",
                n = params.len()
            );
            let refs: Vec<&(dyn ToSql + Sync)> = params
                .iter()
                .map(|p| p.as_ref() as &(dyn ToSql + Sync))
                .collect();
            let all = &refs[..refs.len() - 1];
            let totals = client.query_one(&totals, all).await.map_err(db)?;
            let series = client.query(&series, all).await.map_err(db)?;
            let ranking = client.query(&ranking, &refs).await.map_err(db)?;
            let mut ranked = ranking
                .iter()
                .map(stats_of)
                .collect::<Result<Vec<_>, _>>()?;
            insights::rank(&mut ranked);
            Ok(insights::Analytics {
                totals: stats_of(&totals)?.1,
                series: series.iter().map(stats_of).collect::<Result<_, _>>()?,
                ranking: ranked,
            })
        })
    }

    fn rows(&self, query: &Query) -> Pending<Vec<Row>> {
        let pg = self.pg.clone();
        let query = query.clone();
        Box::pin(async move {
            let client = pg.connect().await?;
            let (clause, mut params) = clause(&query);
            params.push(Box::new(int(Some(
                query.limit.min(insights::MAX_ROWS) as u64
            ))));
            params.push(Box::new(int(Some(query.offset as u64))));
            let sql = format!(
                "SELECT {COLUMNS} FROM gantry_requests {clause} ORDER BY time DESC, id DESC LIMIT ${} OFFSET ${}",
                params.len() - 1,
                params.len()
            );
            let refs: Vec<&(dyn ToSql + Sync)> = params
                .iter()
                .map(|p| p.as_ref() as &(dyn ToSql + Sync))
                .collect();
            let rows = client.query(&sql, &refs).await.map_err(db)?;
            rows.iter().map(row_of).collect()
        })
    }
}

/// The sums and nearest-rank latency percentiles (`percentile_disc`, as [`insights::Stats::percentile`] takes
/// them) of each group, as `(key, stats)`.
const GROUP_STATS: &str = "count(*), count(*) FILTER (WHERE verdict = 'refused' OR code = 'guardrail_blocked'), \
    count(*) FILTER (WHERE verdict <> 'refused' AND code <> 'guardrail_blocked' AND status >= 400), \
    coalesce(sum(input_tokens), 0)::bigint, coalesce(sum(output_tokens), 0)::bigint, coalesce(sum(cost_usd), 0)::float8, \
    percentile_disc(0.5) WITHIN GROUP (ORDER BY latency_ms), percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms), \
    percentile_disc(0.99) WITHIN GROUP (ORDER BY latency_ms)";

fn stats_of(r: &tokio_postgres::Row) -> Result<(String, insights::Stats), String> {
    let n = |i: usize| -> Result<u64, String> {
        Ok(u64::try_from(r.try_get::<_, i64>(i).map_err(db)?).unwrap_or_default())
    };
    let q = |i: usize| -> Result<Option<u64>, String> {
        Ok(r.try_get::<_, Option<i64>>(i)
            .map_err(db)?
            .and_then(|v| u64::try_from(v).ok()))
    };
    Ok((
        r.try_get(0).map_err(db)?,
        insights::Stats {
            requests: n(1)?,
            refused: n(2)?,
            errors: n(3)?,
            input_tokens: n(4)?,
            output_tokens: n(5)?,
            cost_usd: r.try_get(6).map_err(db)?,
            latencies: Vec::new(),
            quantiles: Some([q(7)?, q(8)?, q(9)?]),
        },
    ))
}

impl Bodies for PgIndex {
    fn keep(&self, body: Body) {
        self.queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(body);
    }

    fn body(&self, id: &str) -> Pending<Option<Body>> {
        let pg = self.pg.clone();
        let seal = self.seal.clone();
        let id = id.to_string();
        Box::pin(async move {
            let Some(seal) = seal else { return Ok(None) };
            let client = pg.connect().await?;
            let row = client
                .query_opt(
                    "SELECT sealed FROM gantry_bodies WHERE id = $1 AND expires > now()",
                    &[&id],
                )
                .await
                .map_err(db)?;
            match row {
                Some(row) => {
                    let sealed: Vec<u8> = row.try_get(0).map_err(db)?;
                    insights::open_body(seal.as_ref(), &id, &sealed).map(Some)
                }
                None => Ok(None),
            }
        })
    }
}

/// Why capture cannot be on, one problem per rule that asks for it, or none. A body is never kept unsealed.
pub fn capture_problems(rules: &[gantry_core::policy::Rule], master_key: bool) -> Vec<String> {
    if master_key {
        return Vec::new();
    }
    rules
        .iter()
        .filter(|r| r.limits.capture.is_some())
        .map(|r| {
            format!(
                "rule \"{}\" has capture:, and GANTRY_MASTER_KEY is not set, so the bodies it keeps could not be sealed. Set GANTRY_MASTER_KEY (or GANTRY_MASTER_KEY_FILE) to 64 hex characters made with `openssl rand -hex 32`, the same on every gateway, and restart; or remove capture: from the rule.",
                r.name
            )
        })
        .collect()
}
