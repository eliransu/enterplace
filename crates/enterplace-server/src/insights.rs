//! The request log across replicas, and kept bodies, in Postgres (tables of the `insights` namespace).
//!
//! Each replica copies the rows of its own audit chain into `enterplace_requests`, after a cursor it keeps in
//! `enterplace_insights_replicas`: the decision record as written (no prompt text is in it), its number and hash, and
//! what its usage, upstream error and answer guardrail records add. Every dimension is in one `labels` column, so a
//! new one needs no migration. Kept bodies are sealed with the master key before they reach `enterplace_bodies`, and
//! deleted when they expire. Nothing here is on the request path: copying runs every two seconds.

use std::{
    io::{BufRead, BufReader, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use crate::sql::Conn as Client;
use enterplace_core::{
    audit,
    insights::{self, Bodies, Body, Fact, Index, Query, Row, Seal},
    store::Pending,
};
use tokio_postgres::types::ToSql;

use crate::{
    credentials::MasterKey,
    sql::{self, Db, Sql},
};

pub const NAMESPACE: &str = "insights";

/// Never edit an entry that has shipped: add one.
pub const MIGRATIONS: &[&str] = &[
    "
CREATE TABLE enterplace_requests (
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
CREATE INDEX enterplace_requests_time ON enterplace_requests (time DESC, id DESC);
CREATE INDEX enterplace_requests_labels ON enterplace_requests USING gin (labels jsonb_path_ops);
CREATE TABLE enterplace_insights_replicas (
    id text PRIMARY KEY,
    n bigint NOT NULL,
    hash text NOT NULL,
    seen_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE enterplace_bodies (
    id text PRIMARY KEY,
    expires timestamptz NOT NULL,
    sealed bytea NOT NULL
);
CREATE INDEX enterplace_bodies_expires ON enterplace_bodies (expires);
",
    "
ALTER TABLE enterplace_requests ADD COLUMN stages text;
",
];

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
            format!("the kept {id} does not open with this gateway's ENTERPLACE_MASTER_KEY: it was sealed with another master key, or changed. Set the master key the other gateways use.")
        })
    }
}

/// Where the next read of the live log starts: its byte offset, and the record number expected there.
type Hint = Option<(u64, u64)>;

/// The request log of every replica on the store, and this replica's copier into it.
pub struct PgIndex {
    pg: Db,
    replica: String,
    path: PathBuf,
    seal: Option<Arc<dyn Seal>>,
    queue: Mutex<Vec<Body>>,
    hint: Mutex<Hint>,
    /// One copy pass at a time.
    copying: tokio::sync::Mutex<()>,
    /// The number of the last record of this replica the index holds: 0 until the first pass has read the cursor.
    copied: Arc<AtomicU64>,
}

impl std::fmt::Debug for PgIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgIndex")
            .field("replica", &self.replica)
            .finish_non_exhaustive()
    }
}

fn db(err: crate::sql::Error) -> String {
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
        "enterplace".into()
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
        (None, None) => format!("{host}-{}", enterplace_core::id::random_hex(6)),
    };
    if let Err(err) = std::fs::write(&file, &id) {
        eprintln!(
            "enterplace: {} could not be written ({err}); this replica's name in the request index may change at the next start.",
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

const COLUMNS: &str = "id, to_char(time AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'), replica, n, hash, linked, line, path, labels::text, verdict, code, rule, findings, status, input_tokens, output_tokens, cost_usd, charged_usd, latency_ms, body, coalesce(stages, '[]')";

fn row_of(r: &crate::sql::Row) -> Result<Row, String> {
    let get = |i: usize| r.try_get::<_, String>(i).map_err(db);
    let unsigned = |v: Option<i64>| v.and_then(|v| u64::try_from(v).ok());
    let line = get(6)?;
    // Read from the decision record itself, so the index needs no column of its own.
    let estimate = serde_json::from_str::<serde_json::Value>(&line)
        .is_ok_and(|record| record["auth"] == "passthrough");
    Ok(Row {
        id: get(0)?,
        time: get(1)?,
        replica: get(2)?,
        n: u64::try_from(r.try_get::<_, i64>(3).map_err(db)?).unwrap_or_default(),
        hash: get(4)?,
        linked: r.try_get(5).map_err(db)?,
        line,
        estimate,
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
        stages: serde_json::from_str(&get(20)?).unwrap_or_default(),
    })
}

/// A WHERE clause for each database: Postgres, and the SQLite that keeps labels and findings as JSON text.
struct Clause {
    pg: String,
    lite: String,
}

/// The WHERE clause and its parameters for a query. Means what [`Query::matches`] means. Both texts number the
/// parameters `$N`; the SQLite one goes through [`sql::lite`] with the statement around it.
fn clause(query: &Query) -> (Clause, Vec<Box<dyn ToSql + Sync + Send>>) {
    let mut terms: Vec<(String, String)> = Vec::new();
    let mut params: Vec<Box<dyn ToSql + Sync + Send>> = Vec::new();
    let mut add = |pg: &str, lite: &str, value: Box<dyn ToSql + Sync + Send>| {
        params.push(value);
        let n = format!("${}", params.len());
        terms.push((pg.replace('?', &n), lite.replace('?', &n)));
    };
    for (dimension, value) in &query.labels {
        let wanted = serde_json::json!({ dimension: [value] }).to_string();
        add(
            "labels @> CAST(? AS text)::jsonb",
            // `wanted` has one dimension with one value: containment is that value among the row's.
            "EXISTS (SELECT 1 FROM json_each(?) w, json_each(w.value) x, json_each(labels -> w.key) l WHERE l.value = x.value)",
            Box::new(wanted),
        );
    }
    for (dimension, any) in &query.within {
        // The name goes in the SQL itself, so only a dimension Enterplace defines is accepted; anything else matches
        // nothing rather than everything.
        if enterplace_core::insights::dimensions().any(|d| d.name == dimension) {
            add(
                &format!("jsonb_exists_any(labels -> '{dimension}', CAST(? AS text[]))"),
                &format!(
                    "EXISTS (SELECT 1 FROM json_each(labels -> '{dimension}') l, json_each(?) w WHERE l.value = w.value)"
                ),
                Box::new(any.clone()),
            );
        } else {
            add(
                "false AND CAST(? AS text[]) IS NOT NULL",
                "0 AND ? IS NOT NULL",
                Box::new(any.clone()),
            );
        }
    }
    if !query.code.is_empty() {
        add("code = ?", "code = ?", Box::new(query.code.clone()));
    }
    if !query.finding.is_empty() {
        add(
            "? = ANY(findings)",
            "EXISTS (SELECT 1 FROM json_each(findings) f WHERE f.value = ?)",
            Box::new(query.finding.clone()),
        );
    }
    if !query.id.is_empty() {
        add("id = ?", "id = ?", Box::new(query.id.clone()));
    }
    if !query.from.is_empty() {
        add(
            "time >= CAST(? AS text)::timestamptz",
            &format!("time >= strftime('{TIME}', ?)"),
            Box::new(query.from.clone()),
        );
    }
    if query.to.len() == 10 {
        add(
            "time < CAST(? AS text)::date + 1",
            &format!("time < strftime('{TIME}', ?, '+1 day')"),
            Box::new(query.to.clone()),
        );
    } else if !query.to.is_empty() {
        add(
            "time <= CAST(? AS text)::timestamptz",
            &format!("time <= strftime('{TIME}', ?)"),
            Box::new(query.to.clone()),
        );
    }
    if let Some(v) = query.min_cost {
        add("cost_usd >= ?", "cost_usd >= ?", Box::new(v));
    }
    if let Some(v) = query.max_cost {
        add("cost_usd <= ?", "cost_usd <= ?", Box::new(v));
    }
    if let Some(v) = int(query.min_ms) {
        add("latency_ms >= ?", "latency_ms >= ?", Box::new(v));
    }
    if let Some(v) = int(query.max_ms) {
        add("latency_ms <= ?", "latency_ms <= ?", Box::new(v));
    }
    let blocked = "code = 'guardrail_blocked'";
    let outcome = match query.outcome.as_str() {
        "allowed" => Some(format!(
            "verdict = 'allow' AND NOT {blocked} AND coalesce(status, 0) < 400"
        )),
        "refused" => Some(format!("(verdict = 'refused' OR {blocked})")),
        "error" => Some(format!(
            "verdict <> 'refused' AND NOT {blocked} AND status >= 400"
        )),
        _ => None,
    };
    if let Some(term) = outcome {
        terms.push((term.clone(), term));
    }
    let join = |pick: fn(&(String, String)) -> &String| {
        if terms.is_empty() {
            String::new()
        } else {
            format!(
                "WHERE {}",
                terms
                    .iter()
                    .map(pick)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" AND ")
            )
        }
    };
    let clause = Clause {
        pg: join(|t| &t.0),
        lite: join(|t| &t.1),
    };
    (clause, params)
}

/// The time text SQLite keeps, as `strftime` makes it: a time compared with a column is put in it first, so text
/// order is time order.
const TIME: &str = "%Y-%m-%dT%H:%M:%fZ";

fn refs(params: &[Box<dyn ToSql + Sync + Send>]) -> Vec<&(dyn ToSql + Sync)> {
    params
        .iter()
        .map(|p| p.as_ref() as &(dyn ToSql + Sync))
        .collect()
}

impl PgIndex {
    /// Creates the tables, and serves the request log (and the bodies, when `seal` is set) of the audit log at
    /// `path` from the store. `copy` starts the copier, every two seconds; tests call [`PgIndex::copy`] themselves.
    pub fn open(
        pg: Db,
        path: &Path,
        seal: Option<Arc<dyn Seal>>,
        copy: bool,
    ) -> Result<Arc<Self>, String> {
        pg.migrate(NAMESPACE, MIGRATIONS, &[])?;
        let index = Arc::new(Self {
            pg,
            replica: replica_id(path),
            path: path.to_path_buf(),
            seal,
            queue: Mutex::default(),
            hint: Mutex::default(),
            copying: tokio::sync::Mutex::const_new(()),
            copied: Arc::new(AtomicU64::new(0)),
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
                                eprintln!("enterplace: {err}. The request log in the console is behind until it can copy again.");
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

    /// The number of the last record of this replica the index has copied, kept up to date by every pass. Whatever
    /// removes records from the disk (a binary that ships sealed segments elsewhere) waits until this has passed
    /// them, or their rows are never copied: the copier reads the chain from the disk.
    pub fn copied(&self) -> Arc<AtomicU64> {
        self.copied.clone()
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
                .execute("DELETE FROM enterplace_bodies WHERE expires < now()", &[])
                .await
                .map_err(db)?;
        }
        let cursor = client
            .query_opt(
                "SELECT n, hash FROM enterplace_insights_replicas WHERE id = $1",
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
        self.copied.fetch_max(after, Ordering::SeqCst);
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
        // Every write of the pass lands together, so the cursor never moves past rows that were not written. On the
        // Cloudflare store only `atomic` gives that.
        type Params = Vec<Box<dyn ToSql + Sync + Send>>;
        let mut writes: Vec<(Sql, Params)> = Vec::new();
        for (_, line) in &lines {
            let fact = insights::fact(line, &self.replica, prev.as_deref());
            prev = insights::hash_of_line(line);
            match fact {
                Some(Fact::Request(row)) => {
                    let labels = serde_json::to_string(&row.labels).unwrap_or_else(|_| "{}".into());
                    writes.push((
                        // What a request's usage record fills in later is empty here; a watch row, which has no
                        // usage record, arrives with its own.
                        Sql::both(
                            "INSERT INTO enterplace_requests (id, time, replica, n, hash, linked, line, path, labels, verdict, code, rule, findings, \
                             status, input_tokens, output_tokens, cost_usd, latency_ms) \
                             VALUES ($1, CAST($2 AS text)::timestamptz, $3, $4, $5, $6, $7, $8, CAST($9 AS text)::jsonb, $10, $11, $12, $13, \
                             $14, $15, $16, $17, $18) ON CONFLICT (id) DO NOTHING",
                            sql::lite(&format!(
                                "INSERT INTO enterplace_requests (id, time, replica, n, hash, linked, line, path, labels, verdict, code, rule, findings, \
                                 status, input_tokens, output_tokens, cost_usd, latency_ms) \
                                 VALUES ($1, strftime('{TIME}', $2), $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, \
                                 $14, $15, $16, $17, $18) ON CONFLICT (id) DO NOTHING"
                            )),
                        ),
                        vec![Box::new(row.id), Box::new(row.time), Box::new(row.replica), Box::new(int(Some(row.n))), Box::new(row.hash), Box::new(row.linked), Box::new(row.line), Box::new(row.path), Box::new(labels), Box::new(row.verdict), Box::new(row.code), Box::new(row.rule), Box::new(row.findings),
                             Box::new(row.status.map(i32::from)), Box::new(int(row.input_tokens)), Box::new(int(row.output_tokens)), Box::new(row.cost_usd), Box::new(int(row.latency_ms))],
                    ));
                }
                Some(Fact::Usage(usage)) => {
                    let mut moved = serde_json::Map::new();
                    for (d, v) in [("provider", &usage.provider), ("model", &usage.model)] {
                        if !v.is_empty() {
                            moved.insert(d.into(), serde_json::json!([v]));
                        }
                    }
                    let set = "status = $3, input_tokens = $4, output_tokens = $5, cost_usd = $6, charged_usd = $7, latency_ms = $8, body = $9, stages = $10 WHERE id = $1";
                    writes.push((
                        Sql::both(
                            format!("UPDATE enterplace_requests SET labels = labels || CAST($2 AS text)::jsonb, {set}"),
                            // json_patch replaces a top-level key as `||` does.
                            sql::lite(&format!("UPDATE enterplace_requests SET labels = json_patch(labels, $2), {set}")),
                        ),
                        vec![Box::new(usage.id), Box::new(serde_json::Value::Object(moved).to_string()), Box::new(usage.status.map(i32::from)), Box::new(int(usage.input_tokens)), Box::new(int(usage.output_tokens)), Box::new(usage.cost_usd), Box::new(usage.charged_usd), Box::new(int(usage.latency_ms)), Box::new(usage.body),
                             Box::new(serde_json::to_string(&usage.stages).unwrap_or_else(|_| "[]".into()))],
                    ));
                }
                Some(Fact::Failure {
                    id,
                    status,
                    code,
                    latency_ms,
                }) => {
                    writes.push((
                        "UPDATE enterplace_requests SET status = $2, code = $3, latency_ms = $4 WHERE id = $1".into(),
                        vec![Box::new(id), Box::new(status.map(i32::from)), Box::new(code), Box::new(int(latency_ms))],
                    ));
                }
                Some(Fact::Answer {
                    id,
                    blocked,
                    findings,
                }) => {
                    writes.push((
                        Sql::both(
                            "UPDATE enterplace_requests SET code = CASE WHEN $2 THEN 'guardrail_blocked' ELSE code END, findings = findings || $3 WHERE id = $1",
                            // The row's findings, then the answer's, in order, as `||` appends.
                            "UPDATE enterplace_requests SET code = CASE WHEN ?2 THEN 'guardrail_blocked' ELSE code END, \
                             findings = (SELECT json_group_array(value) FROM (SELECT 0 AS s, key AS k, value FROM json_each(findings) \
                             UNION ALL SELECT 1, key, value FROM json_each(?3) ORDER BY s, k)) WHERE id = ?1",
                        ),
                        vec![Box::new(id), Box::new(blocked), Box::new(findings)],
                    ));
                }
                // Retention removed these records from the chain: their rows and kept bodies follow, so the index
                // never holds what the audit log no longer does. Retention does not run under legal hold.
                Some(Fact::Retired { through }) => {
                    writes.push((
                        "DELETE FROM enterplace_bodies WHERE id IN (SELECT id FROM enterplace_requests WHERE replica = $1 AND n <= $2)".into(),
                        vec![Box::new(self.replica.clone()), Box::new(int(Some(through)))],
                    ));
                    writes.push((
                        "DELETE FROM enterplace_requests WHERE replica = $1 AND n <= $2".into(),
                        vec![Box::new(self.replica.clone()), Box::new(int(Some(through)))],
                    ));
                }
                None => {}
            }
        }
        let hash = insights::hash_of_line(&last_line).unwrap_or_default();
        writes.push((
            "INSERT INTO enterplace_insights_replicas (id, n, hash) VALUES ($1, $2, $3) \
             ON CONFLICT (id) DO UPDATE SET n = excluded.n, hash = excluded.hash, seen_at = now()"
                .into(),
            vec![
                Box::new(self.replica.clone()),
                Box::new(int(Some(last))),
                Box::new(hash),
            ],
        ));
        client
            .atomic(
                writes
                    .iter()
                    .map(|(sql, params)| (sql.clone(), refs(params), None))
                    .collect(),
            )
            .await
            .map_err(db)?;
        self.copied.fetch_max(last, Ordering::SeqCst);
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
                        Sql::both(
                            "INSERT INTO enterplace_bodies (id, expires, sealed) VALUES ($1, to_timestamp($2), $3) ON CONFLICT (id) DO NOTHING",
                            format!("INSERT INTO enterplace_bodies (id, expires, sealed) VALUES (?1, strftime('{TIME}', ?2, 'unixepoch'), ?3) ON CONFLICT (id) DO NOTHING"),
                        ),
                        &[&body.id, &(body.expires as f64), &sealed],
                    )
                    .await
                    .map(|_| ())
                    .map_err(db),
                Err(err) => {
                    eprintln!("enterplace: the body of decision {} was not kept: {err}.", body.id);
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
            let lite = client.is_lite();
            let bucket = if hourly {
                "to_char(time AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24')"
            } else {
                "to_char(time AT TIME ZONE 'UTC', 'YYYY-MM-DD')"
            };
            let totals = Sql::both(
                format!(
                    "SELECT '' AS k, {GROUP_STATS} FROM enterplace_requests {}",
                    clause.pg
                ),
                sql::lite(&format!(
                    "SELECT '' AS k, {GROUP_STATS_LITE} FROM enterplace_requests {}",
                    clause.lite
                )),
            );
            let series = Sql::both(
                format!(
                    "SELECT {bucket} AS k, {GROUP_STATS} FROM enterplace_requests {} GROUP BY 1 ORDER BY 1",
                    clause.pg
                ),
                sql::lite(&format!(
                    "SELECT {bucket} AS k, {GROUP_STATS_LITE} FROM enterplace_requests {} GROUP BY 1 ORDER BY 1",
                    clause.lite
                )),
            );
            params.push(Box::new(dimension));
            let n = params.len();
            // A request counts once under each value it has, and under "" when it has none, as `ranking` folds it.
            // On SQLite the rows are filtered first: json_each's own columns (id, path) would make the clause's
            // ambiguous.
            let ranking = Sql::both(
                format!(
                    "SELECT v.k, {GROUP_STATS} FROM enterplace_requests CROSS JOIN LATERAL jsonb_array_elements_text( \
                       CASE WHEN jsonb_typeof(labels -> ${n}) = 'array' AND jsonb_array_length(labels -> ${n}) > 0 \
                       THEN labels -> ${n} ELSE '[\"\"]'::jsonb END) AS v(k) {} GROUP BY 1",
                    clause.pg
                ),
                sql::lite(&format!(
                    "SELECT v.value, {GROUP_STATS_LITE} FROM (SELECT * FROM enterplace_requests {}) r CROSS JOIN json_each( \
                       CASE WHEN json_type(r.labels -> ${n}) = 'array' AND json_array_length(r.labels -> ${n}) > 0 \
                       THEN r.labels -> ${n} ELSE '[\"\"]' END) AS v GROUP BY 1",
                    clause.lite
                )),
            );
            let refs = refs(&params);
            let all = &refs[..refs.len() - 1];
            let totals = client.query_one(totals, all).await.map_err(db)?;
            let series = client.query(series, all).await.map_err(db)?;
            let ranking = client.query(ranking, &refs).await.map_err(db)?;
            let stats_of = |r: &sql::Row| stats_of(r, lite);
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

    fn cost_lines(&self, query: &Query) -> Pending<Vec<insights::CostLine>> {
        let pg = self.pg.clone();
        let query = query.clone();
        Box::pin(async move {
            let client = pg.connect().await?;
            let (clause, params) = clause(&query);
            let allowed = |clause: &str| {
                if clause.is_empty() {
                    "WHERE verdict <> 'refused'".to_string()
                } else {
                    format!("{clause} AND verdict <> 'refused'")
                }
            };
            // The first value of each label, as `Row::label` reads it, so both ways of counting agree. `->` and
            // `->>` mean the same on SQLite.
            let text = |allowed: String| {
                format!(
                    "SELECT to_char(time AT TIME ZONE 'UTC', 'YYYY-MM-DD'), coalesce(labels -> 'org' ->> 0, ''), \
                 coalesce(labels -> 'team' ->> 0, ''), coalesce(labels -> 'provider' ->> 0, ''), coalesce(labels -> 'model' ->> 0, ''), \
                 count(*), coalesce(sum(input_tokens), 0)::bigint, coalesce(sum(output_tokens), 0)::bigint, coalesce(sum(cost_usd), 0)::float8 \
                 FROM enterplace_requests {allowed} GROUP BY 1, 2, 3, 4, 5 ORDER BY 1, 2, 3, 4, 5"
                )
            };
            let sql = Sql::both(
                text(allowed(&clause.pg)),
                sql::lite(&text(allowed(&clause.lite))),
            );
            let rows = client.query(sql, &refs(&params)).await.map_err(db)?;
            rows.iter()
                .map(|r| {
                    let text = |i: usize| r.try_get::<_, String>(i).map_err(db);
                    let count = |i: usize| -> Result<u64, String> {
                        Ok(u64::try_from(r.try_get::<_, i64>(i).map_err(db)?).unwrap_or_default())
                    };
                    Ok(insights::CostLine {
                        day: text(0)?,
                        org: text(1)?,
                        team: text(2)?,
                        provider: text(3)?,
                        model: text(4)?,
                        requests: count(5)?,
                        input_tokens: count(6)?,
                        output_tokens: count(7)?,
                        cost_usd: r.try_get(8).map_err(db)?,
                    })
                })
                .collect()
        })
    }

    fn spent(&self, query: &Query, dimension: &str) -> Pending<Vec<(String, f64)>> {
        let pg = self.pg.clone();
        let query = query.clone();
        let dimension = dimension.to_string();
        Box::pin(async move {
            let client = pg.connect().await?;
            let (clause, mut params) = clause(&query);
            params.push(Box::new(dimension));
            // One sum per value of the dimension, over the index's own rows: nothing is folded here.
            let n = params.len();
            let sql = Sql::both(
                format!(
                    "SELECT v.k, COALESCE(sum(charged_usd), 0) FROM enterplace_requests CROSS JOIN LATERAL jsonb_array_elements_text( \
                       CASE WHEN jsonb_typeof(labels -> ${n}) = 'array' THEN labels -> ${n} ELSE '[]'::jsonb END) AS v(k) \
                       {} GROUP BY 1",
                    clause.pg
                ),
                // Filtered first, as in `analytics`.
                sql::lite(&format!(
                    "SELECT v.value, COALESCE(sum(charged_usd), 0) * 1.0 FROM (SELECT * FROM enterplace_requests {}) r CROSS JOIN json_each( \
                       CASE WHEN json_type(r.labels -> ${n}) = 'array' THEN r.labels -> ${n} ELSE '[]' END) AS v GROUP BY 1",
                    clause.lite
                )),
            );
            client
                .query(sql, &refs(&params))
                .await
                .map_err(db)?
                .iter()
                .map(|r| Ok((r.try_get(0).map_err(db)?, r.try_get(1).map_err(db)?)))
                .collect()
        })
    }

    fn lines(&self, since: &str, max: usize) -> Pending<Vec<String>> {
        let pg = self.pg.clone();
        let since = since.to_string();
        let max = i64::try_from(max).unwrap_or(i64::MAX);
        Box::pin(async move {
            let client = pg.connect().await?;
            let rows = client
                .query(
                    Sql::both(
                        "SELECT line, input_tokens, output_tokens, cost_usd FROM (SELECT line, time, id, input_tokens, output_tokens, cost_usd \
                         FROM enterplace_requests WHERE time >= $1::text::timestamptz \
                         ORDER BY time DESC, id DESC LIMIT $2) newest ORDER BY time, id",
                        format!(
                            "SELECT line, input_tokens, output_tokens, cost_usd FROM (SELECT line, time, id, input_tokens, output_tokens, cost_usd \
                             FROM enterplace_requests WHERE time >= strftime('{TIME}', ?1) \
                             ORDER BY time DESC, id DESC LIMIT ?2) newest ORDER BY time, id"
                        ),
                    ),
                    &[&since, &max],
                )
                .await
                .map_err(db)?;
            // Each request's usage as the usage record the audit log holds after it, so a dry run counts tokens
            // and spend the same from either source.
            let mut out = Vec::with_capacity(rows.len() * 2);
            for row in &rows {
                let line: String = row.try_get(0).map_err(db)?;
                let input: Option<i64> = row.try_get(1).map_err(db)?;
                let output: Option<i64> = row.try_get(2).map_err(db)?;
                let cost: Option<f64> = row.try_get(3).map_err(db)?;
                let usage = serde_json::from_str::<serde_json::Value>(&line)
                    .ok()
                    .filter(|_| input.is_some() || output.is_some() || cost.is_some())
                    .map(|r| {
                        serde_json::json!({
                            "event": "usage",
                            "id": r["id"],
                            "time": r["time"],
                            "input_tokens": input,
                            "output_tokens": output,
                            "cost_usd": cost,
                        })
                        .to_string()
                    });
                out.push(line);
                out.extend(usage);
            }
            Ok(out)
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
            let n = params.len();
            let text = |clause: &str| {
                format!(
                    "SELECT {COLUMNS} FROM enterplace_requests {clause} ORDER BY time DESC, id DESC LIMIT ${} OFFSET ${n}",
                    n - 1
                )
            };
            let sql = Sql::both(text(&clause.pg), sql::lite(&text(&clause.lite)));
            let rows = client.query(sql, &refs(&params)).await.map_err(db)?;
            rows.iter().map(row_of).collect()
        })
    }
}

/// The sums, nearest-rank latency percentiles (`percentile_disc`, as [`insights::Stats::percentile`] takes
/// them) of each group, as `(key, stats)`.
const GROUP_STATS: &str = "count(*), count(*) FILTER (WHERE verdict = 'refused' OR code = 'guardrail_blocked'), \
    count(*) FILTER (WHERE verdict <> 'refused' AND code <> 'guardrail_blocked' AND status >= 400), \
    coalesce(sum(input_tokens), 0)::bigint, coalesce(sum(output_tokens), 0)::bigint, coalesce(sum(cost_usd), 0)::float8, \
    percentile_disc(0.5) WITHIN GROUP (ORDER BY latency_ms), percentile_disc(0.95) WITHIN GROUP (ORDER BY latency_ms), \
    percentile_disc(0.99) WITHIN GROUP (ORDER BY latency_ms), \
    coalesce(sum(cost_usd) FILTER (WHERE line LIKE '%\"auth\":\"passthrough\"%'), 0)::float8";

/// [`GROUP_STATS`] on SQLite, which has no `percentile_disc`: the group's latencies instead, for
/// [`insights::Stats::percentile`] to rank. Written in Postgres for [`sql::lite`].
const GROUP_STATS_LITE: &str = "count(*), count(*) FILTER (WHERE verdict = 'refused' OR code = 'guardrail_blocked'), \
    count(*) FILTER (WHERE verdict <> 'refused' AND code <> 'guardrail_blocked' AND status >= 400), \
    coalesce(sum(input_tokens), 0)::bigint, coalesce(sum(output_tokens), 0)::bigint, coalesce(sum(cost_usd), 0)::float8, \
    json_group_array(latency_ms) FILTER (WHERE latency_ms IS NOT NULL), \
    coalesce(sum(cost_usd) FILTER (WHERE line LIKE '%\"auth\":\"passthrough\"%'), 0)::float8";

fn stats_of(r: &sql::Row, lite: bool) -> Result<(String, insights::Stats), String> {
    let n = |i: usize| -> Result<u64, String> {
        Ok(u64::try_from(r.try_get::<_, i64>(i).map_err(db)?).unwrap_or_default())
    };
    let q = |i: usize| -> Result<Option<u64>, String> {
        Ok(r.try_get::<_, Option<i64>>(i)
            .map_err(db)?
            .and_then(|v| u64::try_from(v).ok()))
    };
    // Last of the columns: after the three percentiles, or after the one list of latencies on SQLite.
    let estimated_usd: f64 = r.try_get(if lite { 8 } else { 10 }).map_err(db)?;
    let (latencies, quantiles) = if lite {
        let text: String = r.try_get(7).map_err(db)?;
        let mut all: Vec<u64> = serde_json::from_str(&text).map_err(|err| {
            format!(
                "the request index in the store sent latencies that are not a list ({err}): {text}"
            )
        })?;
        all.sort_unstable();
        (all, None)
    } else {
        (Vec::new(), Some([q(7)?, q(8)?, q(9)?]))
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
            estimated_usd,
            latencies,
            quantiles,
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
                    "SELECT sealed FROM enterplace_bodies WHERE id = $1 AND expires > now()",
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
pub fn capture_problems(rules: &[enterplace_core::policy::Rule], master_key: bool) -> Vec<String> {
    if master_key {
        return Vec::new();
    }
    rules
        .iter()
        .filter(|r| r.limits.capture.is_some())
        .map(|r| {
            format!(
                "rule \"{}\" has capture:, and ENTERPLACE_MASTER_KEY is not set, so the bodies it keeps could not be sealed. Set ENTERPLACE_MASTER_KEY (or ENTERPLACE_MASTER_KEY_FILE) to 64 hex characters made with `openssl rand -hex 32`, the same on every gateway, and restart; or remove capture: from the rule.",
                r.name
            )
        })
        .collect()
}
