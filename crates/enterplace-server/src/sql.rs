//! The database of the features that keep tables of their own (the request log, batches, MCP state and the
//! enterprise features): the Postgres of `store: { postgres_url_env: ... }`, or with `store: { cloudflare: true }`
//! the SQLite of the template's `EnterplaceStore` Durable Object, so those features run on Cloudflare too.
//!
//! Callers write Postgres, as they always have, through [`Conn`], whose calls mirror `tokio_postgres::Client`'s. On
//! the Durable Object each statement is translated to SQLite ([`lite`]) unless the caller gives a SQLite text of its
//! own ([`Sql::both`]) for what does not translate (jsonb and array operators, `LATERAL`). Parameters and rows keep
//! Postgres's types: a parameter is encoded by its own `ToSql` and sent as JSON, and a JSON cell is encoded in
//! Postgres's binary format for the type the caller reads, then decoded by that type's own `FromSql`.
//!
//! Timestamps are kept on SQLite as UTC text, `2026-11-24T10:00:00.123Z`, which sorts as time does.
//!
//! A transaction on the Durable Object holds the object for itself (no other connection's statement runs until it
//! ends), so a read and the write it decides are isolated as `FOR UPDATE` makes them. Its statements apply as they
//! run: one that needs several writes to land together or not at all uses [`Conn::atomic`], which runs them in one
//! SQLite transaction on either backend.

use std::{
    borrow::Cow,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::BytesMut;
use serde_json::{Value, json};
use tokio_postgres::types::{FromSql, IsNull, ToSql, Type};

use crate::{cloudflare_store::CfStore, store::PgStore};

/// A statement: its Postgres text, and its SQLite text when the translation would not do.
#[derive(Clone, Debug)]
pub struct Sql {
    pg: Cow<'static, str>,
    lite: Option<Cow<'static, str>>,
}

impl Sql {
    /// A statement written for each database.
    pub fn both(pg: impl Into<Cow<'static, str>>, lite: impl Into<Cow<'static, str>>) -> Self {
        Self {
            pg: pg.into(),
            lite: Some(lite.into()),
        }
    }

    fn text(&self, lite: bool) -> Cow<'_, str> {
        match (&self.lite, lite) {
            (_, false) => Cow::Borrowed(&self.pg),
            (Some(text), true) => Cow::Borrowed(text),
            (None, true) => Cow::Owned(self::lite(&self.pg)),
        }
    }
}

impl From<&'static str> for Sql {
    fn from(pg: &'static str) -> Self {
        Self {
            pg: Cow::Borrowed(pg),
            lite: None,
        }
    }
}

impl From<String> for Sql {
    fn from(pg: String) -> Self {
        Self {
            pg: Cow::Owned(pg),
            lite: None,
        }
    }
}

impl From<&String> for Sql {
    fn from(pg: &String) -> Self {
        Self::from(pg.clone())
    }
}

/// An error of either database, as text.
#[derive(Debug, Clone)]
pub struct Error(String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<tokio_postgres::Error> for Error {
    fn from(err: tokio_postgres::Error) -> Self {
        Self(err.to_string())
    }
}

impl From<String> for Error {
    fn from(err: String) -> Self {
        Self(err)
    }
}

impl From<Error> for String {
    fn from(err: Error) -> Self {
        err.0
    }
}

pub type Params<'a> = &'a [&'a (dyn ToSql + Sync)];

/// The database the policy's store names, for features with tables of their own.
#[derive(Clone)]
pub enum Db {
    Postgres(Arc<PgStore>),
    Cloudflare(Arc<CfStore>),
}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Postgres(_) => "Db::Postgres",
            Self::Cloudflare(_) => "Db::Cloudflare",
        })
    }
}

impl Db {
    /// Whether this is the Durable Object, whose statements run as SQLite.
    pub fn lite(&self) -> bool {
        matches!(self, Self::Cloudflare(_))
    }

    /// The Postgres store, for what only it can do.
    pub fn postgres(&self) -> Option<&Arc<PgStore>> {
        match self {
            Self::Postgres(pg) => Some(pg),
            Self::Cloudflare(_) => None,
        }
    }

    /// The master key the store's credentials are sealed with, once the store was unlocked with it.
    pub fn master(&self) -> Result<&crate::credentials::MasterKey, String> {
        match self {
            Self::Postgres(pg) => pg.master(),
            Self::Cloudflare(cf) => cf.master(),
        }
    }

    /// A connection of its own, which may hold a transaction.
    pub async fn connect(&self) -> Result<Conn, String> {
        Ok(match self {
            Self::Postgres(pg) => Conn::Postgres(pg.connect().await?, pg.clone()),
            Self::Cloudflare(cf) => Conn::Cloudflare {
                store: cf.clone(),
                session: None,
            },
        })
    }

    /// Creates or updates the tables of `namespace`: entry N of `migrations` runs once, in order. On the Durable
    /// Object each entry is translated, or `lite` gives entry N in SQLite when it is not empty.
    pub fn migrate(
        &self,
        namespace: &str,
        migrations: &'static [&'static str],
        lite: &'static [&'static str],
    ) -> Result<(), String> {
        match self {
            Self::Postgres(pg) => pg.migrate(namespace, migrations),
            Self::Cloudflare(cf) => {
                let list: Vec<String> = migrations
                    .iter()
                    .enumerate()
                    .map(|(i, pg)| match lite.get(i) {
                        Some(text) if !text.trim().is_empty() => (*text).to_string(),
                        _ => self::lite(pg),
                    })
                    .collect();
                cf.migrate_sql(namespace, list)
            }
        }
    }
}

/// One connection: a Postgres client, or calls to the Durable Object.
pub enum Conn {
    /// The client, and its store, whose thread runs the connection: kept so the connection outlives a store the
    /// caller let go of.
    Postgres(tokio_postgres::Client, Arc<PgStore>),
    Cloudflare {
        store: Arc<CfStore>,
        /// The transaction that holds the object, while one is open.
        session: Option<String>,
    },
}

/// A row of either database.
pub enum Row {
    Postgres(tokio_postgres::Row),
    Lite {
        columns: Arc<Vec<String>>,
        cells: Vec<Cell>,
    },
}

/// A value of a row from the Durable Object, with its encodings in Postgres's binary format for each type it can
/// be read as, made when the row arrives so a borrowed read (`&str`) borrows from the row.
pub struct Cell {
    value: Value,
    encoded: Vec<(Type, Vec<u8>)>,
}

impl Cell {
    fn new(value: Value) -> Self {
        let types: &[Type] = match &value {
            Value::Null => &[],
            Value::Bool(_) => &[Type::BOOL],
            Value::Number(n) if n.is_f64() => &[Type::FLOAT8, Type::FLOAT4, Type::INT8, Type::TEXT],
            Value::Number(_) => &[
                Type::INT8,
                Type::INT4,
                Type::INT2,
                Type::FLOAT8,
                Type::FLOAT4,
                Type::BOOL,
                Type::TEXT,
            ],
            Value::String(text) if text.starts_with('[') => &[
                Type::TEXT,
                Type::TEXT_ARRAY,
                Type::INT8_ARRAY,
                Type::INT4_ARRAY,
                Type::FLOAT8_ARRAY,
                Type::FLOAT4_ARRAY,
                Type::BOOL_ARRAY,
                Type::JSONB,
                Type::JSON,
            ],
            Value::String(text) if text.starts_with('{') => &[Type::TEXT, Type::JSONB, Type::JSON],
            Value::String(_) => &[Type::TEXT, Type::TIMESTAMPTZ, Type::INT8, Type::FLOAT8],
            Value::Object(_) => &[Type::BYTEA],
            Value::Array(_) => &[Type::TEXT_ARRAY],
        };
        let encoded = types
            .iter()
            .filter_map(|ty| Some((ty.clone(), to_binary(ty, &value).ok()?)))
            .collect();
        Self { value, encoded }
    }
}

/// A column of a row, by position or name.
pub trait Index: std::fmt::Display + Copy {
    fn pg(self, row: &tokio_postgres::Row) -> Option<usize>;
    fn lite(self, columns: &[String]) -> Option<usize>;
}

impl Index for usize {
    fn pg(self, row: &tokio_postgres::Row) -> Option<usize> {
        (self < row.len()).then_some(self)
    }
    fn lite(self, columns: &[String]) -> Option<usize> {
        (self < columns.len()).then_some(self)
    }
}

impl Index for &str {
    fn pg(self, row: &tokio_postgres::Row) -> Option<usize> {
        row.columns().iter().position(|c| c.name() == self)
    }
    fn lite(self, columns: &[String]) -> Option<usize> {
        columns.iter().position(|c| c == self)
    }
}

impl Row {
    pub fn len(&self) -> usize {
        match self {
            Self::Postgres(row) => row.len(),
            Self::Lite { cells, .. } => cells.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The value of a column as `T`, which reads it as from Postgres.
    pub fn try_get<'a, I: Index, T: FromSql<'a>>(&'a self, idx: I) -> Result<T, Error> {
        match self {
            Self::Postgres(row) => {
                let at = idx
                    .pg(row)
                    .ok_or_else(|| Error(format!("no column {idx}")))?;
                row.try_get(at).map_err(Error::from)
            }
            Self::Lite { columns, cells } => {
                let cell = idx
                    .lite(columns)
                    .and_then(|at| cells.get(at))
                    .ok_or_else(|| Error(format!("no column {idx}")))?;
                decode(cell).map_err(|err| Error(format!("column {idx} ({}): {err}", cell.value)))
            }
        }
    }

    /// [`try_get`](Self::try_get), which panics as `tokio_postgres::Row::get` does on a column that is not there or
    /// not of the type: a mistake in the statement, never in the data.
    pub fn get<'a, I: Index, T: FromSql<'a>>(&'a self, idx: I) -> T {
        match self.try_get(idx) {
            Ok(v) => v,
            Err(err) => panic!("error retrieving column {idx}: {err}"),
        }
    }
}

impl Conn {
    pub fn is_closed(&self) -> bool {
        match self {
            Self::Postgres(client, _) => client.is_closed(),
            Self::Cloudflare { .. } => false,
        }
    }

    pub fn is_lite(&self) -> bool {
        matches!(self, Self::Cloudflare { .. })
    }

    pub async fn query(&self, sql: impl Into<Sql>, params: Params<'_>) -> Result<Vec<Row>, Error> {
        let sql = sql.into();
        match self {
            Self::Postgres(client, _) => Ok(client
                .query(sql.text(false).as_ref(), params)
                .await?
                .into_iter()
                .map(Row::Postgres)
                .collect()),
            Self::Cloudflare { store, session } => {
                let mut out = run(
                    store,
                    session.as_deref(),
                    vec![(sql.text(true).into_owned(), encode_params(params)?, None)],
                    false,
                )
                .await?;
                Ok(out.pop().map(|(rows, _)| rows).unwrap_or_default())
            }
        }
    }

    pub async fn query_one(&self, sql: impl Into<Sql>, params: Params<'_>) -> Result<Row, Error> {
        let mut rows = self.query(sql, params).await?;
        match rows.len() {
            1 => rows.pop().ok_or_else(|| Error("no row".into())),
            n => Err(Error(format!("the query returned {n} rows, not one"))),
        }
    }

    pub async fn query_opt(
        &self,
        sql: impl Into<Sql>,
        params: Params<'_>,
    ) -> Result<Option<Row>, Error> {
        let mut rows = self.query(sql, params).await?;
        match rows.len() {
            0 | 1 => Ok(rows.pop()),
            n => Err(Error(format!(
                "the query returned {n} rows, not one or none"
            ))),
        }
    }

    /// Runs a statement and returns how many rows it changed.
    pub async fn execute(&self, sql: impl Into<Sql>, params: Params<'_>) -> Result<u64, Error> {
        let sql = sql.into();
        match self {
            Self::Postgres(client, _) => {
                Ok(client.execute(sql.text(false).as_ref(), params).await?)
            }
            Self::Cloudflare { store, session } => {
                let out = run(
                    store,
                    session.as_deref(),
                    vec![(sql.text(true).into_owned(), encode_params(params)?, None)],
                    false,
                )
                .await?;
                Ok(out.first().map_or(0, |(_, changed)| *changed))
            }
        }
    }

    /// Statements separated by `;`, without parameters.
    pub async fn batch_execute(&self, sql: impl Into<Sql>) -> Result<(), Error> {
        let sql = sql.into();
        match self {
            Self::Postgres(client, _) => Ok(client.batch_execute(sql.text(false).as_ref()).await?),
            Self::Cloudflare { store, session } => {
                let statements = split(&sql.text(true))
                    .into_iter()
                    .map(|s| (s, Vec::new(), None))
                    .collect();
                run(store, session.as_deref(), statements, false)
                    .await
                    .map(|_| ())
            }
        }
    }

    /// Several writes that land together or not at all: each with the rows it must change, when that matters.
    /// `Ok(false)` when one changed another count, and nothing was written.
    pub async fn atomic(
        &mut self,
        statements: Vec<(Sql, Vec<&(dyn ToSql + Sync)>, Option<u64>)>,
    ) -> Result<bool, Error> {
        match self {
            Self::Postgres(client, _) => {
                let tx = client.transaction().await?;
                for (sql, params, expect) in &statements {
                    let changed = tx.execute(sql.text(false).as_ref(), params).await?;
                    if expect.is_some_and(|n| n != changed) {
                        return Ok(false);
                    }
                }
                tx.commit().await?;
                Ok(true)
            }
            Self::Cloudflare { store, session } => {
                let mut list = Vec::with_capacity(statements.len());
                for (sql, params, expect) in &statements {
                    list.push((sql.text(true).into_owned(), encode_params(params)?, *expect));
                }
                match run(store, session.as_deref(), list, true).await {
                    Ok(_) => Ok(true),
                    Err(err) if err.0.contains(UNEXPECTED) => Ok(false),
                    Err(err) => Err(err),
                }
            }
        }
    }

    /// A transaction. On the Durable Object it holds the object until it ends.
    pub async fn transaction(&mut self) -> Result<Transaction<'_>, Error> {
        match self {
            Self::Postgres(client, _) => Ok(Transaction::Postgres(client.transaction().await?)),
            Self::Cloudflare { store, session } => {
                let answer = store.sql_call("sql_begin", json!({})).await?;
                let id = answer["session"]
                    .as_str()
                    .ok_or_else(|| Error("the store opened no transaction".into()))?
                    .to_string();
                *session = Some(id);
                Ok(Transaction::Lite(LiteTx {
                    conn: self,
                    wrote: AtomicBool::new(false),
                }))
            }
        }
    }
}

/// A transaction on either database. Dropped without [`commit`](Self::commit), it is rolled back on Postgres; on
/// the Durable Object what it wrote stays, which is why one that writes more than once uses [`Conn::atomic`].
pub enum Transaction<'a> {
    Postgres(tokio_postgres::Transaction<'a>),
    Lite(LiteTx<'a>),
}

/// A transaction holding the Durable Object. Ended when dropped, if it was not committed.
pub struct LiteTx<'a> {
    conn: &'a mut Conn,
    wrote: AtomicBool,
}

impl Drop for LiteTx<'_> {
    fn drop(&mut self) {
        if let Conn::Cloudflare { store, session } = &mut *self.conn {
            if let Some(id) = session.take() {
                store.sql_end(id);
            }
        }
    }
}

impl Transaction<'_> {
    pub async fn query(&self, sql: impl Into<Sql>, params: Params<'_>) -> Result<Vec<Row>, Error> {
        let sql = sql.into();
        match self {
            Self::Postgres(tx) => Ok(tx
                .query(sql.text(false).as_ref(), params)
                .await?
                .into_iter()
                .map(Row::Postgres)
                .collect()),
            Self::Lite(tx) => {
                Self::second_write(&tx.wrote, writes(&sql))?;
                tx.conn.query(sql, params).await
            }
        }
    }

    pub async fn query_one(&self, sql: impl Into<Sql>, params: Params<'_>) -> Result<Row, Error> {
        let mut rows = self.query(sql, params).await?;
        match rows.len() {
            1 => rows.pop().ok_or_else(|| Error("no row".into())),
            n => Err(Error(format!("the query returned {n} rows, not one"))),
        }
    }

    pub async fn query_opt(
        &self,
        sql: impl Into<Sql>,
        params: Params<'_>,
    ) -> Result<Option<Row>, Error> {
        let mut rows = self.query(sql, params).await?;
        match rows.len() {
            0 | 1 => Ok(rows.pop()),
            n => Err(Error(format!(
                "the query returned {n} rows, not one or none"
            ))),
        }
    }

    pub async fn execute(&self, sql: impl Into<Sql>, params: Params<'_>) -> Result<u64, Error> {
        let sql = sql.into();
        match self {
            Self::Postgres(tx) => Ok(tx.execute(sql.text(false).as_ref(), params).await?),
            Self::Lite(tx) => {
                Self::second_write(&tx.wrote, writes(&sql))?;
                tx.conn.execute(sql, params).await
            }
        }
    }

    pub async fn batch_execute(&self, sql: impl Into<Sql>) -> Result<(), Error> {
        let sql = sql.into();
        match self {
            Self::Postgres(tx) => Ok(tx.batch_execute(sql.text(false).as_ref()).await?),
            Self::Lite(tx) => {
                Self::second_write(&tx.wrote, writes(&sql))?;
                tx.conn.batch_execute(sql).await
            }
        }
    }

    /// [`Conn::atomic`] inside this transaction, for writes decided by what it read: on the Durable Object they
    /// run while it still holds the object. Counts as its one write. `Ok(false)` when one changed another count,
    /// and nothing of the batch was written.
    pub async fn atomic(
        &mut self,
        statements: Vec<(Sql, Vec<&(dyn ToSql + Sync)>, Option<u64>)>,
    ) -> Result<bool, Error> {
        match self {
            Self::Postgres(tx) => {
                // Dropped without commit, the savepoint undoes the batch alone.
                let batch = tx.savepoint("atomic").await?;
                for (sql, params, expect) in &statements {
                    let changed = batch.execute(sql.text(false).as_ref(), params).await?;
                    if expect.is_some_and(|n| n != changed) {
                        return Ok(false);
                    }
                }
                batch.commit().await?;
                Ok(true)
            }
            Self::Lite(tx) => {
                Self::second_write(&tx.wrote, true)?;
                let Conn::Cloudflare { store, session } = &*tx.conn else {
                    return Err(Error("a Durable Object transaction on Postgres".into()));
                };
                let mut list = Vec::with_capacity(statements.len());
                for (sql, params, expect) in &statements {
                    list.push((sql.text(true).into_owned(), encode_params(params)?, *expect));
                }
                match run(store, session.as_deref(), list, true).await {
                    Ok(_) => Ok(true),
                    Err(err) if err.0.contains(UNEXPECTED) => Ok(false),
                    Err(err) => Err(err),
                }
            }
        }
    }

    pub async fn commit(self) -> Result<(), Error> {
        match self {
            Self::Postgres(tx) => Ok(tx.commit().await?),
            Self::Lite(tx) => {
                end(tx.conn).await;
                Ok(())
            }
        }
    }

    pub async fn rollback(self) -> Result<(), Error> {
        match self {
            Self::Postgres(tx) => Ok(tx.rollback().await?),
            Self::Lite(tx) => {
                end(tx.conn).await;
                Ok(())
            }
        }
    }

    /// A second write in one transaction could be left half done on the Durable Object, which cannot roll back
    /// across calls. Tests refuse it, so every such transaction uses `Conn::atomic` instead.
    fn second_write(wrote: &AtomicBool, writes: bool) -> Result<(), Error> {
        if writes && wrote.swap(true, Ordering::Relaxed) && cfg!(debug_assertions) {
            return Err(Error(
                "this transaction writes twice: on the Cloudflare store a failure between the writes cannot be rolled back. Use Conn::atomic for them.".into(),
            ));
        }
        Ok(())
    }
}

async fn end(conn: &mut Conn) {
    if let Conn::Cloudflare { store, session } = conn {
        if let Some(id) = session.take() {
            let _ = store.sql_call("sql_end", json!({ "session": id })).await;
        }
    }
}

fn writes(sql: &Sql) -> bool {
    let text = sql.pg.trim_start().to_ascii_uppercase();
    let changes = ["INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP"]
        .iter()
        .any(|word| text.contains(word));
    let read = text.starts_with("SELECT") || (text.starts_with("WITH") && !changes);
    !read
}

const UNEXPECTED: &str = "unexpected row count";

/// Runs statements on the Durable Object: each with its parameters and, in an atomic batch, the rows it must
/// change. Their rows, and how many rows each changed.
async fn run(
    store: &CfStore,
    session: Option<&str>,
    statements: Vec<(String, Vec<Value>, Option<u64>)>,
    atomic: bool,
) -> Result<Vec<(Vec<Row>, u64)>, Error> {
    let body = json!({
        "session": session,
        "atomic": atomic,
        "statements": statements
            .iter()
            .map(|(sql, params, expect)| json!({ "sql": sql, "params": params, "expect": expect }))
            .collect::<Vec<_>>(),
    });
    let answer = store.sql_call("sql", body).await?;
    let mut out = Vec::new();
    for result in answer["results"].as_array().map_or(&[][..], Vec::as_slice) {
        let columns: Arc<Vec<String>> = Arc::new(
            result["columns"]
                .as_array()
                .map_or(&[][..], Vec::as_slice)
                .iter()
                .map(|c| c.as_str().unwrap_or_default().to_string())
                .collect(),
        );
        let rows = result["rows"]
            .as_array()
            .map_or(&[][..], Vec::as_slice)
            .iter()
            .map(|row| Row::Lite {
                columns: columns.clone(),
                cells: row
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(Cell::new)
                    .collect(),
            })
            .collect();
        out.push((rows, result["changed"].as_u64().unwrap_or(0)));
    }
    Ok(out)
}

/// Statements of a batch, split at `;` outside quotes.
fn split(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let (mut current, mut quoted) = (String::new(), false);
    for c in text.chars() {
        match c {
            '\'' => {
                quoted = !quoted;
                current.push(c);
            }
            ';' if !quoted => {
                if !current.trim().is_empty() {
                    out.push(current.trim().to_string());
                }
                current.clear();
            }
            _ => current.push(c),
        }
    }
    if !current.trim().is_empty() {
        out.push(current.trim().to_string());
    }
    out
}

/// The types a parameter is tried as, in order: the first its `ToSql` takes says what JSON it becomes.
const PARAM_TYPES: &[Type] = &[
    Type::BOOL,
    Type::INT2,
    Type::INT4,
    Type::INT8,
    Type::FLOAT4,
    Type::FLOAT8,
    Type::TEXT,
    Type::BYTEA,
    Type::TIMESTAMPTZ,
    Type::JSONB,
    Type::TEXT_ARRAY,
    Type::INT8_ARRAY,
    Type::INT4_ARRAY,
    Type::FLOAT8_ARRAY,
    Type::FLOAT4_ARRAY,
    Type::BYTEA_ARRAY,
    Type::BOOL_ARRAY,
];

fn encode_params(params: &[&(dyn ToSql + Sync)]) -> Result<Vec<Value>, Error> {
    params.iter().map(|p| param(*p)).collect()
}

/// A parameter as the JSON the store binds: a number, text, `null`, `{"$b64": ...}` for bytes, and a JSON text for
/// an array or jsonb, which is how SQLite keeps them here.
fn param(value: &(dyn ToSql + Sync)) -> Result<Value, Error> {
    for ty in PARAM_TYPES {
        let mut out = BytesMut::new();
        match value.to_sql_checked(ty, &mut out) {
            Ok(IsNull::Yes) => return Ok(Value::Null),
            Ok(IsNull::No) => return from_binary(ty, &out),
            Err(_) => continue,
        }
    }
    Err(Error(format!(
        "a parameter of a type the Cloudflare store does not take: {value:?}"
    )))
}

fn be<const N: usize>(raw: &[u8]) -> Result<[u8; N], Error> {
    raw.get(..N)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| Error("a value shorter than its type".into()))
}

/// Postgres's binary format of `ty` as JSON.
fn from_binary(ty: &Type, raw: &[u8]) -> Result<Value, Error> {
    Ok(match *ty {
        Type::BOOL => json!(raw.first().is_some_and(|b| *b != 0)),
        Type::INT2 => json!(i16::from_be_bytes(be(raw)?)),
        Type::INT4 => json!(i32::from_be_bytes(be(raw)?)),
        Type::INT8 => json!(i64::from_be_bytes(be(raw)?)),
        Type::FLOAT4 => json!(f32::from_be_bytes(be(raw)?)),
        Type::FLOAT8 => json!(f64::from_be_bytes(be(raw)?)),
        Type::TEXT => json!(String::from_utf8_lossy(raw)),
        Type::BYTEA => json!({ "$b64": enterplace_core::x509::base64_encode(raw) }),
        Type::TIMESTAMPTZ => {
            let micros = i64::from_be_bytes(be(raw)?);
            json!(timestamp(micros))
        }
        // jsonb's binary form is a version byte, then the text.
        Type::JSONB => json!(String::from_utf8_lossy(raw.get(1..).unwrap_or_default())),
        _ => {
            let element = match *ty {
                Type::TEXT_ARRAY => Type::TEXT,
                Type::INT8_ARRAY => Type::INT8,
                Type::INT4_ARRAY => Type::INT4,
                Type::FLOAT8_ARRAY => Type::FLOAT8,
                Type::FLOAT4_ARRAY => Type::FLOAT4,
                Type::BYTEA_ARRAY => Type::BYTEA,
                _ => Type::BOOL,
            };
            let list = array_items(raw)?
                .into_iter()
                .map(|item| match item {
                    None => Ok(Value::Null),
                    Some(bytes) => from_binary(&element, bytes),
                })
                .collect::<Result<Vec<_>, _>>()?;
            json!(Value::Array(list).to_string())
        }
    })
}

/// The elements of a one-dimensional array in Postgres's binary format.
fn array_items(raw: &[u8]) -> Result<Vec<Option<&[u8]>>, Error> {
    let int = |at: usize| -> Result<i32, Error> {
        Ok(i32::from_be_bytes(be(raw.get(at..).unwrap_or_default())?))
    };
    let dims = int(0)?;
    if dims == 0 {
        return Ok(Vec::new());
    }
    let count = usize::try_from(int(12)?).unwrap_or(0);
    let mut at = 20;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let len = int(at)?;
        at += 4;
        if len < 0 {
            out.push(None);
            continue;
        }
        let len = usize::try_from(len).unwrap_or(0);
        out.push(Some(raw.get(at..at + len).ok_or_else(|| {
            Error("an array shorter than its length".into())
        })?));
        at += len;
    }
    Ok(out)
}

/// Microseconds since 2000-01-01, as the text SQLite keeps.
fn timestamp(micros: i64) -> String {
    let base = UNIX_EPOCH + Duration::from_secs(946_684_800);
    let at = if micros >= 0 {
        base + Duration::from_micros(micros.unsigned_abs())
    } else {
        base - Duration::from_micros(micros.unsigned_abs())
    };
    enterplace_core::audit::rfc3339(at)
}

/// A cell read as `T`: the first encoding of it that `T` takes, decoded by `T`'s own `FromSql`.
fn decode<'a, T: FromSql<'a>>(cell: &'a Cell) -> Result<T, String> {
    if cell.value.is_null() {
        return [
            Type::TEXT,
            Type::INT8,
            Type::INT4,
            Type::INT2,
            Type::BOOL,
            Type::FLOAT8,
            Type::FLOAT4,
            Type::BYTEA,
            Type::TIMESTAMPTZ,
        ]
        .iter()
        .find(|ty| T::accepts(ty))
        .map_or_else(
            || Err("NULL where a value is needed".to_string()),
            |ty| T::from_sql_null(ty).map_err(|err| err.to_string()),
        );
    }
    let (ty, bytes) = cell
        .encoded
        .iter()
        .find(|(ty, _)| T::accepts(ty))
        .ok_or("a value of another type")?;
    T::from_sql(ty, bytes).map_err(|err| err.to_string())
}

/// A JSON cell in Postgres's binary format for `ty`.
fn to_binary(ty: &Type, value: &Value) -> Result<Vec<u8>, String> {
    let number = || value.as_f64().or_else(|| value.as_str()?.parse().ok());
    let int = || {
        value
            .as_i64()
            .or_else(|| value.as_f64().map(|f| f as i64))
            .or_else(|| value.as_str()?.parse().ok())
            .ok_or_else(|| format!("{value} is not a whole number"))
    };
    Ok(match *ty {
        Type::BOOL => vec![u8::from(match value {
            Value::Bool(b) => *b,
            _ => int()? != 0,
        })],
        Type::INT2 => i16::try_from(int()?)
            .map_err(|e| e.to_string())?
            .to_be_bytes()
            .to_vec(),
        Type::INT4 => i32::try_from(int()?)
            .map_err(|e| e.to_string())?
            .to_be_bytes()
            .to_vec(),
        Type::INT8 => int()?.to_be_bytes().to_vec(),
        Type::FLOAT4 => (number().ok_or("not a number")? as f32)
            .to_be_bytes()
            .to_vec(),
        Type::FLOAT8 => number().ok_or("not a number")?.to_be_bytes().to_vec(),
        Type::TEXT | Type::JSON => match value {
            Value::String(s) => s.as_bytes().to_vec(),
            other => other.to_string().into_bytes(),
        },
        Type::JSONB => {
            let mut out = vec![1];
            out.extend(value.as_str().unwrap_or_default().as_bytes());
            out
        }
        Type::BYTEA => {
            enterplace_core::x509::base64_decode(value["$b64"].as_str().ok_or("not bytes")?)
                .ok_or("bytes that are not base64")?
        }
        Type::TIMESTAMPTZ => {
            let text = value.as_str().ok_or("not a time")?;
            // `2026-11-24T10:00:00.123Z`, or with a space, or a date alone.
            if text.len() < 10 || text.as_bytes().get(4) != Some(&b'-') {
                return Err(format!("{text} is not a time"));
            }
            let secs = enterplace_core::policy::unix_seconds(text)
                .ok_or_else(|| format!("{text} is not a time"))?;
            let fraction: String = text
                .get(19..)
                .and_then(|rest| rest.strip_prefix('.'))
                .map(|rest| {
                    rest.chars()
                        .take_while(char::is_ascii_digit)
                        .take(6)
                        .collect()
                })
                .unwrap_or_default();
            let micros_part = format!("{fraction:0<6}").parse::<i64>().unwrap_or(0);
            ((secs - 946_684_800) * 1_000_000 + micros_part)
                .to_be_bytes()
                .to_vec()
        }
        _ => {
            let (element, oid) = match *ty {
                Type::TEXT_ARRAY => (Type::TEXT, Type::TEXT.oid()),
                Type::INT8_ARRAY => (Type::INT8, Type::INT8.oid()),
                Type::INT4_ARRAY => (Type::INT4, Type::INT4.oid()),
                Type::FLOAT8_ARRAY => (Type::FLOAT8, Type::FLOAT8.oid()),
                Type::FLOAT4_ARRAY => (Type::FLOAT4, Type::FLOAT4.oid()),
                Type::BYTEA_ARRAY => (Type::BYTEA, Type::BYTEA.oid()),
                _ => (Type::BOOL, Type::BOOL.oid()),
            };
            let items: Vec<Value> = match value {
                Value::Array(items) => items.clone(),
                Value::String(text) => serde_json::from_str(text).map_err(|e| e.to_string())?,
                _ => return Err("not a list".into()),
            };
            let mut out = Vec::new();
            out.extend(1i32.to_be_bytes());
            out.extend(i32::from(items.iter().any(Value::is_null)).to_be_bytes());
            out.extend(oid.to_be_bytes());
            out.extend(i32::try_from(items.len()).unwrap_or(i32::MAX).to_be_bytes());
            out.extend(1i32.to_be_bytes());
            for item in &items {
                if item.is_null() {
                    out.extend((-1i32).to_be_bytes());
                } else {
                    let bytes = to_binary(&element, item)?;
                    out.extend(i32::try_from(bytes.len()).unwrap_or(i32::MAX).to_be_bytes());
                    out.extend(bytes);
                }
            }
            out
        }
    })
}

/// The SQLite text of a Postgres statement, for what translates word for word. Statements that do not (jsonb and
/// array operators, `LATERAL`, `FILTER` over arrays) are given in SQLite by the caller with [`Sql::both`].
pub fn lite(pg: &str) -> String {
    let mut s = pg.to_string();
    // DDL types and what SQLite has no use for.
    for (from, to) in [
        ("bigserial PRIMARY KEY", "INTEGER PRIMARY KEY"),
        ("BIGSERIAL PRIMARY KEY", "INTEGER PRIMARY KEY"),
        ("serial PRIMARY KEY", "INTEGER PRIMARY KEY"),
        ("double precision", "REAL"),
        ("timestamptz", "TEXT"),
        ("TIMESTAMPTZ", "TEXT"),
        ("jsonb", "TEXT"),
        ("bytea", "BLOB"),
        ("text[]", "TEXT"),
        ("bigint[]", "TEXT"),
        ("integer[]", "TEXT"),
        ("real[]", "TEXT"),
        (" FOR UPDATE SKIP LOCKED", ""),
        (" FOR UPDATE", ""),
        (" ILIKE ", " LIKE "),
        ("greatest(", "max("),
        ("GREATEST(", "MAX("),
        ("least(", "min("),
        ("LEAST(", "MIN("),
        ("clock_timestamp()", NOW),
        ("now()", NOW),
        ("NOW()", NOW),
        ("CURRENT_TIMESTAMP", NOW),
    ] {
        s = s.replace(from, to);
    }
    s = time_arithmetic(&s);
    s = to_char(&s);
    s = strip_casts(&s);
    s = dollar_params(&s);
    s = s.replace(&format!("DEFAULT {NOW}"), &format!("DEFAULT ({NOW})"));
    // One ADD COLUMN per ALTER TABLE, and no GIN indexes.
    split(&s)
        .into_iter()
        .filter(|st| !st.contains(" USING gin"))
        .flat_map(|st| alter_columns(&st))
        .collect::<Vec<_>>()
        .join(";\n")
}

/// `now()` on SQLite, as the text timestamps are kept in.
const NOW: &str = "strftime('%Y-%m-%dT%H:%M:%fZ','now')";

/// `<time> + interval '30 days'` and `<time> - $2 * interval '1 second'` as SQLite date arithmetic.
fn time_arithmetic(s: &str) -> String {
    let mut out = s.to_string();
    // A literal interval on now(): the common case.
    loop {
        let Some(at) = out
            .find(&format!("{NOW} - interval '"))
            .or_else(|| out.find(&format!("{NOW} + interval '")))
        else {
            break;
        };
        let sign = if out[at + NOW.len()..].starts_with(" -") {
            "-"
        } else {
            "+"
        };
        let start = at + NOW.len() + " - interval '".len();
        let Some(len) = out[start..].find('\'') else {
            break;
        };
        let amount = out[start..start + len].to_string();
        let replaced = format!(
            "strftime('%Y-%m-%dT%H:%M:%fZ','now','{sign}{}')",
            plural(&amount)
        );
        out.replace_range(at..start + len + 1, &replaced);
    }
    // A parameter count of seconds (or another unit) on now().
    for unit in ["second", "minute", "hour", "day"] {
        for sign in ['-', '+'] {
            let pattern = format!("{NOW} {sign} $");
            while let Some(at) = out.find(&pattern) {
                let digits: String = out[at + pattern.len()..]
                    .chars()
                    .take_while(char::is_ascii_digit)
                    .collect();
                let tail = format!(" * interval '1 {unit}'");
                let end = at + pattern.len() + digits.len();
                if !out[end..].starts_with(&tail) {
                    break;
                }
                let replaced = format!(
                    "strftime('%Y-%m-%dT%H:%M:%fZ','now','{sign}' || ${digits} || ' {unit}s')"
                );
                out.replace_range(at..end + tail.len(), &replaced);
            }
        }
    }
    out
}

fn plural(amount: &str) -> String {
    let amount = amount.trim();
    if amount.ends_with('s') {
        amount.to_string()
    } else {
        format!("{amount}s")
    }
}

/// `to_char(<time> AT TIME ZONE 'UTC', '<format>')` as `strftime`.
fn to_char(s: &str) -> String {
    let mut out = s.to_string();
    while let Some(at) = out.find("to_char(") {
        let open = at + "to_char(".len();
        let Some(close) = closing(&out, open) else {
            break;
        };
        let inner = out[open..close].to_string();
        let Some(comma) = inner.rfind(", '") else {
            break;
        };
        let value = inner[..comma]
            .replace(" AT TIME ZONE 'UTC'", "")
            .trim()
            .to_string();
        let format = inner[comma + 3..].trim_end_matches('\'').to_string();
        let format = format
            .replace("\\\"", "\"")
            .replace("YYYY", "%Y")
            .replace("MM", "%m")
            .replace("DD", "%d")
            .replace("HH24", "%H")
            .replace("MI", "%M")
            .replace("SS", "%S")
            .replace(".MS", ".%f_MS")
            .replace('"', "");
        // %f is seconds with milliseconds: `SS.MS` is `%f` alone.
        let format = format.replace("%S.%f_MS", "%f");
        out.replace_range(at..=close, &format!("strftime('{format}', {value})"));
    }
    out
}

/// Where the parenthesis opened before `from` closes.
fn closing(s: &str, from: usize) -> Option<usize> {
    let mut depth = 1;
    let mut quoted = false;
    for (i, c) in s[from..].char_indices() {
        match c {
            '\'' => quoted = !quoted,
            '(' if !quoted => depth += 1,
            ')' if !quoted => {
                depth -= 1;
                if depth == 0 {
                    return Some(from + i);
                }
            }
            _ => {}
        }
    }
    None
}

/// `::text`, `::bigint` and the like: SQLite keeps what it is given. A cast to a floating point number stays, as
/// `CAST(... AS REAL)` of the value just before it when that is a call or a parenthesis, so a division is not done
/// on whole numbers.
fn strip_casts(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes: Vec<char> = s.chars().collect();
    let mut i = 0;
    let mut quoted = false;
    while i < bytes.len() {
        let c = bytes[i];
        if c == '\'' {
            quoted = !quoted;
        }
        if !quoted && c == ':' && bytes.get(i + 1) == Some(&':') {
            let mut j = i + 2;
            while j < bytes.len()
                && (bytes[j].is_ascii_alphanumeric()
                    || bytes[j] == '_'
                    || bytes[j] == '['
                    || bytes[j] == ']')
            {
                j += 1;
            }
            let ty: String = bytes[i + 2..j].iter().collect();
            if matches!(
                ty.as_str(),
                "float8" | "float" | "real" | "numeric" | "float4"
            ) {
                out.push_str(" * 1.0");
            }
            i = j;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// `$1` as `?1`, which SQLite binds by position.
fn dollar_params(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut quoted = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\'' {
            quoted = !quoted;
        }
        if c == '$' && !quoted && chars.peek().is_some_and(char::is_ascii_digit) {
            out.push('?');
            continue;
        }
        out.push(c);
    }
    out
}

/// `ALTER TABLE t ADD COLUMN a ..., ADD COLUMN b ...` as one statement per column.
fn alter_columns(st: &str) -> Vec<String> {
    let upper = st.to_ascii_uppercase();
    if !upper.starts_with("ALTER TABLE") || upper.matches("ADD COLUMN").count() < 2 {
        return vec![st.to_string()];
    }
    let Some(first) = upper.find("ADD COLUMN") else {
        return vec![st.to_string()];
    };
    let head = st[..first].trim();
    st[first..]
        .split(", ADD COLUMN")
        .map(|part| {
            let part = part.trim().trim_start_matches("ADD COLUMN").trim();
            format!("{head} ADD COLUMN {part}")
        })
        .collect()
}

/// Seconds since 1970 as the time text the Cloudflare store keeps, for a caller that formats a time itself.
pub fn lite_time(at: SystemTime) -> String {
    enterplace_core::audit::rfc3339(at)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statements_translate_to_sqlite() {
        assert_eq!(
            lite(
                "SELECT id FROM t WHERE at > now() - interval '1 day' AND n = $1::bigint FOR UPDATE"
            ),
            "SELECT id FROM t WHERE at > strftime('%Y-%m-%dT%H:%M:%fZ','now','-1 days') AND n = ?1"
        );
        assert_eq!(
            lite("SELECT to_char(at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM t"),
            "SELECT strftime('%Y-%m-%dT%H:%M:%SZ', at) FROM t"
        );
        assert_eq!(
            lite("DELETE FROM t WHERE seen < clock_timestamp() - $1 * interval '1 second'"),
            "DELETE FROM t WHERE seen < strftime('%Y-%m-%dT%H:%M:%fZ','now','-' || ?1 || ' seconds')"
        );
        assert_eq!(
            lite(
                "CREATE TABLE t (id bigserial PRIMARY KEY, at timestamptz NOT NULL DEFAULT now(), b bytea);\nCREATE INDEX ti ON t USING gin (b)"
            ),
            "CREATE TABLE t (id INTEGER PRIMARY KEY, at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), b BLOB)"
        );
        assert_eq!(
            lite("ALTER TABLE t ADD COLUMN a text, ADD COLUMN b integer"),
            "ALTER TABLE t ADD COLUMN a text;\nALTER TABLE t ADD COLUMN b integer"
        );
    }

    #[test]
    fn parameters_and_cells_keep_their_postgres_types() -> Result<(), Error> {
        let at = UNIX_EPOCH + Duration::from_millis(1_795_540_535_735);
        let names = vec!["a".to_string(), "b".to_string()];
        let none: Option<i64> = None;
        let values = encode_params(&[&7i64, &"x", &true, &at, &names, &none, &vec![1u8, 2]])?;
        assert_eq!(values[0], json!(7));
        assert_eq!(values[1], json!("x"));
        assert_eq!(values[2], json!(true));
        assert_eq!(values[3], json!("2026-11-24T17:15:35.735Z"));
        assert_eq!(values[4], json!("[\"a\",\"b\"]"));
        assert_eq!(values[5], Value::Null);
        let row = Row::Lite {
            columns: Arc::new((0..7).map(|i| i.to_string()).collect()),
            cells: vec![
                json!(7),
                json!("x"),
                json!(1),
                values[3].clone(),
                values[4].clone(),
                Value::Null,
                values[6].clone(),
            ]
            .into_iter()
            .map(Cell::new)
            .collect(),
        };
        assert_eq!(row.try_get::<_, i64>(0)?, 7);
        assert_eq!(row.try_get::<_, i32>(0)?, 7);
        assert_eq!(row.try_get::<_, String>(1)?, "x");
        assert_eq!(row.try_get::<_, &str>(1)?, "x");
        assert!(row.try_get::<_, bool>(2)?);
        assert_eq!(row.try_get::<_, SystemTime>(3)?, at);
        assert_eq!(row.try_get::<_, Vec<String>>(4)?, names);
        assert_eq!(row.try_get::<_, Option<i64>>(5)?, None);
        assert_eq!(row.try_get::<_, Option<i32>>(5)?, None);
        assert_eq!(row.try_get::<_, Option<String>>(1)?, Some("x".into()));
        assert_eq!(row.try_get::<_, Vec<u8>>(6)?, vec![1, 2]);
        assert!(row.try_get::<_, i64>(5).is_err());
        Ok(())
    }
}
