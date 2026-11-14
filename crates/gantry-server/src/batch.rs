//! Files, batches and fine-tuning jobs, governed natively rather than passed through.
//!
//! OpenAI's `/v1/files`, `/v1/batches` and `/v1/fine_tuning/jobs`, and Anthropic's `/v1/messages/batches`:
//!
//! - Each file, batch and job belongs to the person who created it through Gantry. Anyone else is answered as if it
//!   did not exist, unless their key is an admin's. Lists show only what is yours.
//! - Every line of a batch is decided before the provider sees any of it: its model by the caller's rule, its text
//!   by the rule's guardrails. A refused line refuses the whole upload and is named by its number.
//! - A batch reserves what its lines could cost at batch prices (half the model's price, as OpenAI and Anthropic
//!   bill batches) against the budgets, when it is created. When it ends, each result line is charged at what the
//!   provider reported, one usage record per line, and the reservation is given back.
//! - A file is kept for the days the rule's `file_retention_days` sets: OpenAI is told to expire it, and Gantry
//!   deletes what the provider still holds when the time is up.
//!
//! Who owns what is written to the audit log (`owned`, `owned_settled`, `owned_deleted` records). With a store it is
//! also kept in Postgres (namespace `batches`), so every replica answers for every object; without one it is read
//! back from the audit log at start, so ownership and open reservations survive a restart.

use std::{
    collections::{BTreeMap, HashMap},
    ops::Range,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, Version, header},
    response::{IntoResponse, Response},
    routing::any,
};
use gantry_core::{
    audit::{self, Entry},
    config::Kind,
    guard,
    policy::{Applied, Decision, Limit, Policy, Principal, Rule},
    usage::{Usage, price_for},
};
use http_body_util::BodyExt;
use serde_json::{Map, Value, json};

use crate::{AppState, MIB, Refusal, Seen, Snapshot, Upstream, spend};

/// The part of a model's price a batch line costs: OpenAI and Anthropic both bill batches at half price.
const BATCH_SHARE: f64 = 0.5;

/// The endpoints an OpenAI batch line may name.
const ENDPOINTS: [&str; 5] = [
    "/v1/chat/completions",
    "/v1/responses",
    "/v1/embeddings",
    "/v1/completions",
    "/v1/moderations",
];

/// How often open batches are asked whether they ended, and expired files deleted.
const POLL: Duration = Duration::from_secs(60);

/// Most bytes of a batch's results read to meter it.
// ponytail: results are read whole; a batch of more than 256 MiB of results is metered from what fits and the rest
// charged its reservation. Streaming the lines comes when someone runs batches that large through Gantry.
const MAX_RESULTS: usize = 256 * MIB;

/// Where a caller names the provider a file goes to, when more than one could take it.
const PROVIDER_HEADER: &str = "x-gantry-provider";

const ANTHROPIC_VERSION: &str = "2023-06-01";

/// The routes. They own `keep`, the state the poller reaches only through a weak reference: when the router is
/// dropped the poller stops, and the audit log it would write to is closed with the rest.
pub(crate) fn routes(keep: Arc<AppState>) -> Router<AppState> {
    let route = move || {
        let keep = keep.clone();
        any(move |state: State<AppState>, request: Request| {
            let _owner = &keep;
            handle(state, request)
        })
    };
    let mut router = Router::new();
    for path in [
        "/v1/files",
        "/v1/batches",
        "/v1/messages/batches",
        "/v1/fine_tuning/jobs",
    ] {
        router = router
            .route(path, route())
            .route(&format!("{path}/{{*rest}}"), route());
    }
    router
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Item {
    File,
    Batch,
    MessageBatch,
    FineTune,
}

impl Item {
    fn word(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Batch => "batch",
            Self::MessageBatch => "message_batch",
            Self::FineTune => "fine_tuning_job",
        }
    }

    fn from_word(word: &str) -> Option<Self> {
        [Self::File, Self::Batch, Self::MessageBatch, Self::FineTune]
            .into_iter()
            .find(|i| i.word() == word)
    }
}

/// A file, batch or job created through Gantry, and who it belongs to.
#[derive(Clone, Debug)]
struct Owned {
    item: Item,
    provider: String,
    person: String,
    team: String,
    key: String,
    /// The owner's organization, and the end customer and tags of the request that created it, for the budgets it
    /// is charged to.
    org: String,
    customer: Option<String>,
    tags: Vec<String>,
    /// A file's purpose; a batch's endpoint.
    purpose: String,
    models: Vec<String>,
    /// The model of each request of a batch that names more than one.
    model_of: BTreeMap<String, String>,
    lines: usize,
    /// What the lines could cost at the model's full price. None when a line's model has no price.
    estimate: Option<f64>,
    /// A batch's reservations, held until it is settled.
    reserved: Vec<Value>,
    /// Seconds since the epoch after which it is deleted at the provider.
    expires_at: Option<u64>,
    /// The rule's retention, for files a batch writes.
    retention_days: Option<u32>,
    decision: String,
    settled: bool,
    /// For a file or batch Gantry keeps for a Bedrock or Vertex AI provider: the object key, the job, the region
    /// and the model the provider knows. Null for OpenAI and Anthropic objects, which the provider keeps.
    cloud: Value,
}

impl Owned {
    fn new(
        item: Item,
        provider: &str,
        person: &Principal,
        seen: &Seen<'_>,
        decision: &str,
    ) -> Self {
        Self {
            item,
            provider: provider.to_string(),
            person: person.name.clone(),
            team: person.team.clone(),
            key: person.key.clone(),
            org: person.org.clone(),
            customer: seen.customer.clone(),
            tags: seen.tags.clone(),
            purpose: String::new(),
            models: Vec::new(),
            model_of: BTreeMap::new(),
            lines: 0,
            estimate: None,
            reserved: Vec::new(),
            expires_at: None,
            retention_days: None,
            decision: decision.to_string(),
            settled: false,
            cloud: Value::Null,
        }
    }

    fn record(&self, id: &str) -> Map<String, Value> {
        let mut record = Map::new();
        record.insert("event".into(), "owned".into());
        record.insert("id".into(), self.decision.as_str().into());
        record.insert("time".into(), audit::timestamp().into());
        record.insert("object".into(), self.item.word().into());
        record.insert("object_id".into(), id.into());
        record.insert("provider".into(), self.provider.as_str().into());
        record.insert("person".into(), self.person.as_str().into());
        record.insert("team".into(), self.team.as_str().into());
        record.insert("key".into(), self.key.as_str().into());
        if !self.org.is_empty() {
            record.insert("org".into(), self.org.as_str().into());
        }
        if let Some(customer) = &self.customer {
            record.insert("customer".into(), customer.as_str().into());
        }
        if !self.tags.is_empty() {
            record.insert("tags".into(), json!(self.tags));
        }
        record.insert("purpose".into(), self.purpose.as_str().into());
        record.insert("models".into(), json!(self.models));
        record.insert("model_of".into(), json!(self.model_of));
        record.insert("lines".into(), self.lines.into());
        record.insert(
            "estimate_usd".into(),
            self.estimate.map_or(Value::Null, Value::from),
        );
        record.insert("reserved".into(), Value::Array(self.reserved.clone()));
        record.insert(
            "expires_at".into(),
            self.expires_at.map_or(Value::Null, Value::from),
        );
        record.insert(
            "retention_days".into(),
            self.retention_days.map_or(Value::Null, Value::from),
        );
        if !self.cloud.is_null() {
            record.insert("cloud".into(), self.cloud.clone());
        }
        record
    }

    fn from_record(record: &Value) -> Option<(String, Self)> {
        let text = |key: &str| record[key].as_str().unwrap_or_default().to_string();
        let owned = Self {
            item: Item::from_word(record["object"].as_str()?)?,
            provider: text("provider"),
            person: text("person"),
            team: text("team"),
            key: text("key"),
            org: text("org"),
            customer: record["customer"].as_str().map(String::from),
            tags: serde_json::from_value(record["tags"].clone()).unwrap_or_default(),
            purpose: text("purpose"),
            models: serde_json::from_value(record["models"].clone()).unwrap_or_default(),
            model_of: serde_json::from_value(record["model_of"].clone()).unwrap_or_default(),
            lines: record["lines"].as_u64().unwrap_or_default() as usize,
            estimate: record["estimate_usd"].as_f64(),
            reserved: record["reserved"].as_array().cloned().unwrap_or_default(),
            expires_at: record["expires_at"].as_u64(),
            retention_days: record["retention_days"]
                .as_u64()
                .and_then(|d| u32::try_from(d).ok()),
            decision: text("id"),
            settled: false,
            cloud: record["cloud"].clone(),
        };
        Some((record["object_id"].as_str()?.to_string(), owned))
    }

    /// The owner, inside their organization: the same name in two organizations is two people.
    fn owner(&self) -> String {
        gantry_core::policy::within(&self.org, &self.person)
    }

    fn reachable_by(&self, person: &Principal) -> bool {
        self.owner() == person.within(&person.name) || person.admin
    }
}

/// The table that keeps who owns what when the policy has a store, so every replica answers for every file, batch
/// and job. Namespace `batches`.
pub(crate) const NAMESPACE: &str = "batches";
pub(crate) const MIGRATIONS: &[&str] = &["
CREATE TABLE gantry_batches_owned (
    object_id text PRIMARY KEY,
    record jsonb NOT NULL,
    settled boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);
"];

/// Every file, batch and job created through Gantry, by the provider's ID. With a store it is kept in Postgres and
/// shared by every replica, the map in memory holding what this one has read. Without one it is this gateway's own,
/// rebuilt from its audit log at start, and another replica refuses those objects as unknown (fail closed).
#[derive(Default)]
pub(crate) struct Registry {
    map: Mutex<HashMap<String, Owned>>,
    pg: Option<Arc<crate::store::PgStore>>,
}

impl Registry {
    /// Keeps ownership in the store's `batches` namespace, created here.
    pub(crate) fn with_store(pg: Arc<crate::store::PgStore>) -> Result<Self, String> {
        pg.migrate(NAMESPACE, MIGRATIONS)?;
        Ok(Self {
            map: Mutex::default(),
            pg: Some(pg),
        })
    }

    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<String, Owned>> {
        match self.map.lock() {
            Ok(map) => map,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    async fn client(&self) -> Option<tokio_postgres::Client> {
        let pg = self.pg.as_ref()?;
        match pg.connect().await {
            Ok(client) => Some(client),
            Err(err) => {
                eprintln!(
                    "gantry: who owns which files and batches could not be read from the store: {err}"
                );
                None
            }
        }
    }

    /// The owner of `id`. With a store, one another replica created is read from it; a store that cannot be
    /// reached answers None, so the object is refused as unknown rather than served to anyone.
    async fn get(&self, id: &str) -> Option<Owned> {
        if self.pg.is_none() {
            return self.map().get(id).cloned();
        }
        let client = self.client().await?;
        let row = client
            .query_opt(
                "SELECT record::text, settled FROM gantry_batches_owned WHERE object_id = $1",
                &[&id],
            )
            .await
            .ok()??;
        let record: Value = serde_json::from_str(&row.try_get::<_, String>(0).ok()?).ok()?;
        let (_, mut owned) = Owned::from_record(&record)?;
        owned.settled = row.try_get(1).ok()?;
        self.map().insert(id.to_string(), owned.clone());
        Some(owned)
    }

    async fn put(&self, id: &str, owned: Owned) {
        if let Some(client) = self.client().await {
            let record = Value::Object(owned.record(id)).to_string();
            if let Err(err) = client
                .execute(
                    "INSERT INTO gantry_batches_owned (object_id, record, settled) VALUES ($1, CAST($2 AS text)::jsonb, $3) \
                     ON CONFLICT (object_id) DO UPDATE SET record = excluded.record, settled = excluded.settled",
                    &[&id, &record, &owned.settled],
                )
                .await
            {
                eprintln!("gantry: the owner of {id} could not be written to the store: {err}. Other replicas refuse it as unknown.");
            }
        }
        self.map().insert(id.to_string(), owned);
    }

    async fn remove(&self, id: &str) {
        if let Some(client) = self.client().await {
            let _ = client
                .execute(
                    "DELETE FROM gantry_batches_owned WHERE object_id = $1",
                    &[&id],
                )
                .await;
        }
        self.map().remove(id);
    }

    /// Marks a batch settled and returns it, unless it already was: a batch is metered once, also when several
    /// replicas see it end at the same time (one UPDATE wins).
    async fn begin_settle(&self, id: &str) -> Option<Owned> {
        if self.pg.is_some() {
            let client = self.client().await?;
            let row = client
                .query_opt(
                    "UPDATE gantry_batches_owned SET settled = true WHERE object_id = $1 AND NOT settled RETURNING record::text",
                    &[&id],
                )
                .await
                .ok()??;
            let record: Value = serde_json::from_str(&row.try_get::<_, String>(0).ok()?).ok()?;
            let (_, mut owned) = Owned::from_record(&record)?;
            owned.settled = true;
            self.map().insert(id.to_string(), owned.clone());
            return Some(owned);
        }
        let mut map = self.map();
        let owned = map.get_mut(id)?;
        if owned.settled {
            return None;
        }
        owned.settled = true;
        Some(owned.clone())
    }

    async fn unsettle(&self, id: &str) {
        if let Some(client) = self.client().await {
            let _ = client
                .execute(
                    "UPDATE gantry_batches_owned SET settled = false WHERE object_id = $1",
                    &[&id],
                )
                .await;
        }
        if let Some(owned) = self.map().get_mut(id) {
            owned.settled = false;
        }
    }

    /// A settled batch holds nothing any more.
    async fn settled(&self, id: &str) {
        let owned = self.map().get_mut(id).map(|owned| {
            owned.reserved.clear();
            owned.clone()
        });
        if let (Some(owned), true) = (owned, self.pg.is_some()) {
            self.put(id, owned).await;
        }
    }

    async fn all(&self) -> Vec<(String, Owned)> {
        if self.pg.is_some() {
            let Some(client) = self.client().await else {
                return Vec::new();
            };
            let Ok(rows) = client
                .query(
                    "SELECT record::text, settled FROM gantry_batches_owned ORDER BY created_at",
                    &[],
                )
                .await
            else {
                return Vec::new();
            };
            return rows
                .iter()
                .filter_map(|row| {
                    let record: Value =
                        serde_json::from_str(&row.try_get::<_, String>(0).ok()?).ok()?;
                    let (id, mut owned) = Owned::from_record(&record)?;
                    owned.settled = row.try_get(1).ok()?;
                    Some((id, owned))
                })
                .collect();
        }
        self.map()
            .iter()
            .map(|(id, o)| (id.clone(), o.clone()))
            .collect()
    }

    /// Reads ownership back from the audit log, and holds again what batches still open reserved.
    pub(crate) fn replay(&self, path: &Path, spend: &spend::Spend) -> Result<(), String> {
        // With a store, ownership is read from it as needed, and reservations are held there.
        if self.pg.is_some() {
            return Ok(());
        }
        let file = match audit::chain_reader(path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => {
                return Err(format!(
                    "the audit log at {} cannot be read to find who owns which files and batches: {err}. Fix its permissions and start again.",
                    path.display()
                ));
            }
        };
        let mut map = self.map();
        for line in std::io::BufRead::lines(file) {
            let line = line.map_err(|err| {
                format!(
                    "the audit log at {} cannot be read to find who owns which files and batches: {err}.",
                    path.display()
                )
            })?;
            if !line.contains("\"event\":\"owned") {
                continue;
            }
            let Ok(record) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            let id = record["object_id"].as_str().unwrap_or_default();
            match record["event"].as_str() {
                Some("owned") => {
                    if let Some((id, owned)) = Owned::from_record(&record) {
                        map.insert(id, owned);
                    }
                }
                Some("owned_settled") => {
                    if let Some(owned) = map.get_mut(id) {
                        owned.settled = true;
                        owned.reserved.clear();
                    }
                }
                Some("owned_deleted") => {
                    map.remove(id);
                }
                _ => {}
            }
        }
        for owned in map.values().filter(|o| !o.settled) {
            for reservation in owned
                .reserved
                .iter()
                .filter_map(spend::Reservation::from_json)
            {
                spend.hold(&reservation);
            }
        }
        Ok(())
    }
}

/// What a request asks for.
enum Op {
    FileUpload,
    FileList,
    File(String),
    FileContent(String),
    FileDelete(String),
    BatchCreate,
    BatchList,
    Batch(String),
    BatchCancel(String),
    MessageBatchCreate,
    MessageBatchList,
    MessageBatch(String),
    MessageBatchResults(String),
    MessageBatchCancel(String),
    MessageBatchDelete(String),
    TuneCreate,
    TuneList,
    /// A job, and what of it: "" for the job, or cancel, pause, resume, events, checkpoints.
    Tune(String, String),
}

fn op(method: &Method, path: &str) -> Option<Op> {
    let id_ok = |id: &str| {
        !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-:.".contains(&b))
            && id != "."
            && id != ".."
    };
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let get = method == Method::GET;
    let post = method == Method::POST;
    let delete = method == Method::DELETE;
    let id = |s: &str| id_ok(s).then(|| s.to_string());
    Some(match segments.as_slice() {
        ["v1", "files"] if post => Op::FileUpload,
        ["v1", "files"] if get => Op::FileList,
        ["v1", "files", f] if get => Op::File(id(f)?),
        ["v1", "files", f] if delete => Op::FileDelete(id(f)?),
        ["v1", "files", f, "content"] if get => Op::FileContent(id(f)?),
        ["v1", "batches"] if post => Op::BatchCreate,
        ["v1", "batches"] if get => Op::BatchList,
        ["v1", "batches", b] if get => Op::Batch(id(b)?),
        ["v1", "batches", b, "cancel"] if post => Op::BatchCancel(id(b)?),
        ["v1", "messages", "batches"] if post => Op::MessageBatchCreate,
        ["v1", "messages", "batches"] if get => Op::MessageBatchList,
        ["v1", "messages", "batches", b] if get => Op::MessageBatch(id(b)?),
        ["v1", "messages", "batches", b] if delete => Op::MessageBatchDelete(id(b)?),
        ["v1", "messages", "batches", b, "results"] if get => Op::MessageBatchResults(id(b)?),
        ["v1", "messages", "batches", b, "cancel"] if post => Op::MessageBatchCancel(id(b)?),
        ["v1", "fine_tuning", "jobs"] if post => Op::TuneCreate,
        ["v1", "fine_tuning", "jobs"] if get => Op::TuneList,
        ["v1", "fine_tuning", "jobs", j] if get => Op::Tune(id(j)?, String::new()),
        [
            "v1",
            "fine_tuning",
            "jobs",
            j,
            what @ ("events" | "checkpoints"),
        ] if get => Op::Tune(id(j)?, (*what).to_string()),
        [
            "v1",
            "fine_tuning",
            "jobs",
            j,
            what @ ("cancel" | "pause" | "resume"),
        ] if post => Op::Tune(id(j)?, (*what).to_string()),
        _ => return None,
    })
}

fn unknown_batch_route() -> Refusal {
    Refusal::new(
        StatusCode::NOT_FOUND,
        "unknown_route",
        "Refused: Gantry serves these file and batch routes: POST and GET /v1/files, GET and DELETE /v1/files/<id>, GET /v1/files/<id>/content, POST and GET /v1/batches, GET /v1/batches/<id>, POST /v1/batches/<id>/cancel, POST and GET /v1/messages/batches, GET and DELETE /v1/messages/batches/<id>, GET /v1/messages/batches/<id>/results, POST /v1/messages/batches/<id>/cancel, POST and GET /v1/fine_tuning/jobs, GET /v1/fine_tuning/jobs/<id> with /events and /checkpoints, and POST /v1/fine_tuning/jobs/<id>/cancel, /pause and /resume. Check the method and the path.",
    )
}

/// What to do with the provider's answer.
enum Then {
    /// It created this: its `id` is recorded as the caller's.
    Create(Box<Owned>),
    /// A list: only the caller's own are shown.
    List,
    /// One object: a batch that has ended is settled.
    Read(String),
    Delete(String),
    /// Passed on as it comes: file content, batch results, job events.
    Stream,
    /// Batch results read whole and passed through the owner's answer guardrails line by line.
    Guard(Box<GuardResults>),
    /// Served by Gantry for a file or batch it keeps for a Bedrock or Vertex AI provider.
    Cloud(Cloud),
}

/// What Gantry does itself for a file or batch it keeps for a Bedrock or Vertex AI provider.
enum Cloud {
    /// Writes the translated lines (the request body) to the bucket and records the file.
    Upload(Box<Owned>),
    /// Starts the provider's job on a file and records the batch.
    Create {
        batch: Box<Owned>,
        file: Box<Owned>,
        file_id: String,
    },
    Batch(String),
    Cancel(String),
    File(String),
    Content(String, Option<Box<GuardResults>>),
    Delete(String),
    /// A list of the caller's own files or batches Gantry keeps, without asking any provider.
    List(Item),
}

struct Ready {
    provider: usize,
    method: Method,
    target: String,
    body: Bytes,
    headers: HeaderMap,
    then: Then,
    /// A batch's reservations, given back if the provider does not take it.
    reserved: Vec<Value>,
    person: String,
    admin: bool,
}

async fn handle(State(state): State<AppState>, request: Request) -> Response {
    let decision = gantry_core::id::decision_id();
    let anthropic = request.uri().path().starts_with("/v1/messages/");
    let version = state.version();
    let outcome = match &version.policy {
        // Without a policy nothing is allowed, so nothing here is served.
        None => Err(crate::unknown_route()),
        Some(policy) => serve(&state, &version, policy, request, &decision).await,
    };
    let mut response = outcome.unwrap_or_else(|refusal| refusal.respond(&decision, anthropic));
    if let Ok(value) = HeaderValue::from_str(&decision) {
        response.headers_mut().insert(crate::DECISION, value);
    }
    response
}

async fn serve(
    state: &AppState,
    version: &Snapshot,
    policy: &Policy,
    request: Request,
    decision: &str,
) -> Result<Response, Refusal> {
    // The client's own address, as the model routes record it: from a trusted proxy, the one it names.
    let client = crate::client_ip(policy, request.extensions().get(), request.headers())
        .map(|ip| ip.to_string());
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    // Holds the person a JWT names, for as long as the record of this request needs it.
    let minted = std::sync::OnceLock::new();
    let mut seen = Seen::default();
    let mut extra = user_agent_of(request.headers());
    let prepared = prepare(
        state, version, policy, request, decision, &minted, &mut seen, &mut extra,
    )
    .await;
    if let Ok(ready) = &prepared {
        seen.provider = Some(ready.provider);
    }
    let written = record_decision(
        state,
        version,
        decision,
        client.as_deref(),
        &method,
        &path,
        &seen,
        prepared.as_ref().err(),
        extra,
    )
    .await;
    let ready = prepared?;
    if let Err(refusal) = written {
        release(state, &ready.reserved);
        return Err(refusal);
    }
    if matches!(ready.then, Then::Cloud(_)) {
        return run_cloud(state, version, decision, ready).await;
    }
    let provider = &version.providers[ready.provider];
    let answer = match fetch(
        state,
        provider,
        ready.method.clone(),
        &ready.target,
        ready.headers.clone(),
        ready.body.clone(),
    )
    .await
    {
        Ok(answer) => answer,
        Err(refusal) => {
            release(state, &ready.reserved);
            return Err(refusal);
        }
    };
    after(state, version, decision, ready, answer).await
}

/// The caller's `user-agent` as the decision record's field, cut as `audit::record` cuts it: the coverage report
/// and the request log read it.
pub(crate) fn user_agent_of(headers: &HeaderMap) -> Map<String, Value> {
    let mut fields = Map::new();
    if let Some(agent) = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
    {
        fields.insert(
            "user_agent".into(),
            agent.chars().take(200).collect::<String>().into(),
        );
    }
    fields
}

fn release(state: &AppState, reserved: &[Value]) {
    spend::release_all(
        &state.spend,
        reserved
            .iter()
            .filter_map(spend::Reservation::from_json)
            .collect(),
    );
}

pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn bad(code: &'static str, message: String) -> Refusal {
    Refusal::new(StatusCode::BAD_REQUEST, code, message)
}

/// Answered for an ID that is not the caller's, whether or not it exists: telling the two apart would let anyone
/// find out which IDs others hold.
fn not_yours(word: &str, id: &str) -> Refusal {
    Refusal::new(
        StatusCode::NOT_FOUND,
        "not_found",
        format!(
            "Refused: Gantry knows no {word} \"{id}\" of yours. A {word} is reachable only by the person who created it through Gantry, and by a Gantry admin. Check the ID, or ask its owner."
        ),
    )
}

/// The caller's own file, batch or job, and its provider by position.
#[allow(clippy::too_many_arguments)]
async fn owned(
    state: &AppState,
    version: &Snapshot,
    policy: &Policy,
    person: &Principal,
    id: &str,
    item: Item,
    seen: &mut Seen<'_>,
) -> Result<(Owned, usize), Refusal> {
    let word = item.word().replace('_', " ");
    let found = state
        .owned
        .get(id)
        .await
        .filter(|o| o.item == item && o.reachable_by(person))
        .ok_or_else(|| not_yours(&word, id))?;
    if found.expires_at.is_some_and(|at| at <= now_secs()) && item == Item::File {
        return Err(Refusal::new(
            StatusCode::NOT_FOUND,
            "expired",
            format!(
                "Refused: file \"{id}\" passed the retention the policy sets (file_retention_days) and is deleted. Upload it again if you still need it."
            ),
        ));
    }
    let index = version
        .providers
        .iter()
        .position(|p| p.name == found.provider)
        .ok_or_else(|| {
            Refusal::new(
                StatusCode::CONFLICT,
                "unknown_provider",
                format!(
                    "Refused: {word} \"{id}\" is held by provider \"{}\", which the policy no longer names. Ask a Gantry admin to add the provider back, or create it again.",
                    found.provider
                ),
            )
        })?;
    seen.provider = Some(index);
    if let Some(rule) = seen.rule
        && let Some(regions) = &rule.limits.regions
        && !found.cloud["region"]
            .as_str()
            .is_some_and(|r| regions.iter().any(|x| x == r))
    {
        // Only a file or batch Gantry keeps for a deployment labelled with one of the rule's regions shows where
        // it is.
        crate::enforce(
            seen,
            Refusal::new(
                StatusCode::FORBIDDEN,
                "region_not_allowed",
                format!(
                    "Refused: rule \"{}\" keeps requests in {}, and {word} \"{id}\" is not kept for a deployment labelled with one of them. Send it under a rule without regions:.",
                    rule.name,
                    regions.join(", ")
                ),
            ),
            policy.observing(rule.shadow_until.as_deref()),
        )?;
    }
    Ok((found, index))
}

/// The provider a new object goes to: the one the caller names, else the one serving `model`, else the only one
/// of `kind`.
fn pick(
    version: &Snapshot,
    kind: Kind,
    headers: &HeaderMap,
    model: Option<&str>,
) -> Result<usize, Refusal> {
    let of_kind = |p: &Upstream| p.kind == kind;
    if let Some(named) = headers.get(PROVIDER_HEADER).and_then(|v| v.to_str().ok()) {
        return version
            .providers
            .iter()
            .position(|p| p.name == named && of_kind(p) && model.is_none_or(|m| p.serves(m)))
            .ok_or_else(|| {
                bad(
                    "unknown_provider",
                    format!(
                        "Refused: {PROVIDER_HEADER} names \"{named}\", which is not a provider of kind {} that serves this request. Name one of the policy's {} providers, or leave the header out.",
                        kind.word(),
                        kind.word()
                    ),
                )
            });
    }
    if let Some(model) = model {
        return version
            .providers
            .iter()
            .position(|p| of_kind(p) && p.serves(model))
            .ok_or_else(|| {
                Refusal::new(
                    StatusCode::FORBIDDEN,
                    "unknown_model",
                    format!(
                        "Refused: no provider of kind {} serves model \"{model}\", and its batches go to such a provider. Check the model name, or ask a Gantry admin to add it to a provider.",
                        kind.word()
                    ),
                )
            });
    }
    let all: Vec<usize> = (0..version.providers.len())
        .filter(|i| of_kind(&version.providers[*i]))
        .collect();
    match all.as_slice() {
        [one] => Ok(*one),
        [] => Err(Refusal::new(
            StatusCode::NOT_FOUND,
            "unknown_provider",
            format!(
                "Refused: this Gantry has no provider of kind {}, which this route needs. Ask a Gantry admin to add one.",
                kind.word()
            ),
        )),
        _ => Err(bad(
            "provider_needed",
            format!(
                "Refused: more than one provider of kind {} could take this, and files and lists are kept per provider. Name one in the {PROVIDER_HEADER} header.",
                kind.word()
            ),
        )),
    }
}

/// The query of a list or events read, forwarded as sent once its names and values are known safe.
fn checked_query(uri: &Uri, key: &str) -> Result<String, Refusal> {
    let Some(query) = uri.query() else {
        return Ok(String::new());
    };
    const NAMES: [&str; 7] = [
        "after",
        "limit",
        "order",
        "purpose",
        "before_id",
        "after_id",
        "metadata",
    ];
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let plain = value.len() <= 128
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.:".contains(&b));
        if !NAMES.contains(&name) || !plain {
            return Err(bad(
                "bad_query",
                format!(
                    "Refused: the query parameter \"{name}\" is not one Gantry forwards on this route, or its value holds more than letters, digits and _-.:. These may be sent: {}.",
                    NAMES.join(", ")
                ),
            ));
        }
        // The caller's Gantry key must never reach a provider.
        if key.len() >= 8
            && value
                .to_ascii_lowercase()
                .contains(&key.to_ascii_lowercase())
        {
            return Err(bad(
                "key_in_query",
                "Refused: the query carries your Gantry key, which must never reach a provider. Send it in the Authorization header only.".into(),
            ));
        }
    }
    Ok(format!("?{query}"))
}

#[allow(clippy::too_many_arguments)]
async fn prepare<'a>(
    state: &AppState,
    version: &Snapshot,
    policy: &'a Policy,
    request: Request,
    decision: &str,
    minted: &'a std::sync::OnceLock<Principal>,
    seen: &mut Seen<'a>,
    extra: &mut Map<String, Value>,
) -> Result<Ready, Refusal> {
    let (mut parts, body) = request.into_parts();
    let key = crate::caller_key(&parts.headers)?.to_string();
    let client_ip = crate::client_ip(policy, parts.extensions.get(), &parts.headers);
    let (person, key_sha256) = crate::identify(
        state,
        policy,
        &key,
        parts.uri.path(),
        client_ip,
        minted,
        seen,
    )
    .await?;
    if parts.headers.contains_key(crate::CALLER_PROVIDER_KEY) {
        return Err(bad(
            "caller_provider_key_not_here",
            format!(
                "Refused: files, batches and fine-tuning jobs are kept at the organization's provider account, so {} is not taken on these routes. Send the request without it.",
                crate::CALLER_PROVIDER_KEY
            ),
        ));
    }
    let rule = crate::rule_or_observed(policy, person, crate::no_rule(person), |r, by| {
        crate::observed(seen, r, by);
    })?;
    seen.rule = Some(rule);
    let by = policy.observing(rule.shadow_until.as_deref());
    // The end customer and tags the objects are charged to, as on the model routes.
    crate::customer_and_tags(&mut parts.headers, person, rule, seen, by)?;
    let op = op(&parts.method, parts.uri.path()).ok_or_else(unknown_batch_route)?;
    // A file or batch Gantry keeps for a region-labelled Bedrock or Vertex AI deployment shows its region, and is
    // checked where it is resolved. The rest are kept at one provider account, with no region Gantry can show.
    let kept_lists = version
        .providers
        .iter()
        .any(|p| crate::cloud_batch::is_cloud(p) && p.batch.is_some());
    let cloud_capable = (kept_lists && matches!(op, Op::FileList | Op::BatchList))
        || matches!(
            op,
            Op::FileUpload
                | Op::File(_)
                | Op::FileContent(_)
                | Op::FileDelete(_)
                | Op::BatchCreate
                | Op::Batch(_)
                | Op::BatchCancel(_)
        );
    if let Some(regions) = rule.limits.regions.as_ref().filter(|_| !cloud_capable) {
        crate::enforce(
            seen,
            Refusal::new(
                StatusCode::FORBIDDEN,
                "region_not_allowed",
                format!(
                    "Refused: rule \"{}\" keeps requests in {}, and files, batches and fine-tuning jobs are kept at the provider's account, with no region Gantry can show. Send these requests under a rule without regions:.",
                    rule.name,
                    regions.join(", ")
                ),
            ),
            by,
        )?;
    }
    let query = checked_query(&parts.uri, &key)?;
    let mut headers = HeaderMap::new();
    let ready = |provider: usize, method: Method, target: String, body: Bytes, then: Then| Ready {
        provider,
        method,
        target,
        body,
        headers: HeaderMap::new(),
        then,
        reserved: Vec::new(),
        person: person.within(&person.name),
        admin: person.admin,
    };
    let json_type = HeaderValue::from_static("application/json");
    let anthropic_headers = |headers: &mut HeaderMap| {
        headers.insert(
            HeaderName::from_static("anthropic-version"),
            parts
                .headers
                .get("anthropic-version")
                .cloned()
                .unwrap_or(HeaderValue::from_static(ANTHROPIC_VERSION)),
        );
        if let Some(beta) = parts.headers.get("anthropic-beta") {
            headers.insert(HeaderName::from_static("anthropic-beta"), beta.clone());
        }
    };
    let mut out = match &op {
        Op::FileUpload => {
            let (bytes, _held) =
                crate::read_body(Some(&person.name), state, &parts.headers, body).await?;
            let content_type = parts
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let upload = upload(
                state,
                version,
                policy,
                person,
                rule,
                &key_sha256,
                seen,
                decision,
                &parts.headers,
                &content_type,
                &bytes,
            )
            .await?;
            if upload.owned.purpose == "batch" {
                check_max_lines(policy, rule, upload.owned.lines, seen)?;
            }
            count_creation(
                state,
                policy,
                person,
                rule,
                upload.owned.models.first().map(String::as_str),
                seen,
            )
            .await?;
            extra.insert("object".into(), "file".into());
            extra.insert("purpose".into(), upload.owned.purpose.as_str().into());
            extra.insert("lines".into(), upload.owned.lines.into());
            if !upload.found.is_empty() {
                extra.insert("guardrails".into(), Value::Array(upload.found));
            }
            seen.would_refuse.extend(upload.would_refuse);
            if upload.cloud {
                return Ok(ready(
                    upload.provider,
                    Method::POST,
                    String::new(),
                    upload.body,
                    Then::Cloud(Cloud::Upload(Box::new(upload.owned))),
                ));
            }
            if let Ok(value) = HeaderValue::from_str(&content_type) {
                headers.insert(header::CONTENT_TYPE, value);
            }
            Ok(ready(
                upload.provider,
                Method::POST,
                "/v1/files".into(),
                upload.body,
                Then::Create(Box::new(upload.owned)),
            ))
        }
        Op::FileList | Op::BatchList | Op::TuneList => {
            let path = match op {
                Op::FileList => "/v1/files",
                Op::BatchList => "/v1/batches",
                _ => "/v1/fine_tuning/jobs",
            };
            let openai = version.providers.iter().any(|p| p.kind == Kind::OpenAi);
            let kept = match op {
                Op::FileList => Some(Item::File),
                Op::BatchList => Some(Item::Batch),
                _ => None,
            };
            // A rule with regions reaches only what Gantry keeps; so does a gateway with no OpenAI provider.
            if let Some(item) = kept.filter(|_| rule.limits.regions.is_some() || !openai) {
                return Ok(ready(
                    0,
                    Method::GET,
                    String::new(),
                    Bytes::new(),
                    Then::Cloud(Cloud::List(item)),
                ));
            }
            let provider = pick(version, Kind::OpenAi, &parts.headers, None)?;
            Ok(ready(
                provider,
                Method::GET,
                format!("{path}{query}"),
                Bytes::new(),
                Then::List,
            ))
        }
        Op::MessageBatchList => {
            let provider = pick(version, Kind::Anthropic, &parts.headers, None)?;
            anthropic_headers(&mut headers);
            Ok(ready(
                provider,
                Method::GET,
                format!("/v1/messages/batches{query}"),
                Bytes::new(),
                Then::List,
            ))
        }
        Op::File(id) | Op::FileContent(id) | Op::FileDelete(id) => {
            let id = id.clone();
            let (file, provider) =
                owned(state, version, policy, person, &id, Item::File, seen).await?;
            extra.insert("object_id".into(), id.as_str().into());
            if !file.cloud.is_null() {
                let cloud = match op {
                    Op::File(_) => Cloud::File(id),
                    Op::FileContent(_) => {
                        let guard = (file.purpose == "batch_output")
                            .then(|| result_guards(policy, &file, &id, Results::OpenAi))
                            .flatten();
                        Cloud::Content(id, guard)
                    }
                    _ => Cloud::Delete(id),
                };
                return Ok(ready(
                    provider,
                    Method::GET,
                    String::new(),
                    Bytes::new(),
                    Then::Cloud(cloud),
                ));
            }
            let (method, target, then) = match op {
                Op::File(_) => (Method::GET, format!("/v1/files/{id}"), Then::Read(id)),
                Op::FileContent(_) => {
                    let then = (file.purpose == "batch_output")
                        .then(|| result_guards(policy, &file, &id, Results::OpenAi))
                        .flatten()
                        .map_or(Then::Stream, Then::Guard);
                    (Method::GET, format!("/v1/files/{id}/content"), then)
                }
                _ => (Method::DELETE, format!("/v1/files/{id}"), Then::Delete(id)),
            };
            Ok(ready(provider, method, target, Bytes::new(), then))
        }
        Op::Batch(id) | Op::BatchCancel(id) => {
            let id = id.clone();
            let (batch, provider) =
                owned(state, version, policy, person, &id, Item::Batch, seen).await?;
            extra.insert("object_id".into(), id.as_str().into());
            if !batch.cloud.is_null() {
                let cloud = match op {
                    Op::Batch(_) => Cloud::Batch(id),
                    _ => Cloud::Cancel(id),
                };
                return Ok(ready(
                    provider,
                    Method::GET,
                    String::new(),
                    Bytes::new(),
                    Then::Cloud(cloud),
                ));
            }
            let (method, target) = match op {
                Op::Batch(_) => (Method::GET, format!("/v1/batches/{id}")),
                _ => (Method::POST, format!("/v1/batches/{id}/cancel")),
            };
            Ok(ready(
                provider,
                method,
                target,
                Bytes::new(),
                Then::Read(id),
            ))
        }
        Op::MessageBatch(id)
        | Op::MessageBatchResults(id)
        | Op::MessageBatchCancel(id)
        | Op::MessageBatchDelete(id) => {
            let id = id.clone();
            let (batch, provider) = owned(
                state,
                version,
                policy,
                person,
                &id,
                Item::MessageBatch,
                seen,
            )
            .await?;
            extra.insert("object_id".into(), id.as_str().into());
            anthropic_headers(&mut headers);
            let base = format!("/v1/messages/batches/{id}");
            let (method, target, then) = match op {
                Op::MessageBatch(_) => (Method::GET, base, Then::Read(id)),
                Op::MessageBatchResults(_) => {
                    let then = result_guards(policy, &batch, &id, Results::Anthropic)
                        .map_or(Then::Stream, Then::Guard);
                    (Method::GET, format!("{base}/results"), then)
                }
                Op::MessageBatchCancel(_) => {
                    (Method::POST, format!("{base}/cancel"), Then::Read(id))
                }
                _ => (Method::DELETE, base, Then::Delete(id)),
            };
            Ok(ready(provider, method, target, Bytes::new(), then))
        }
        Op::Tune(id, what) => {
            let id = id.clone();
            let (_, provider) =
                owned(state, version, policy, person, &id, Item::FineTune, seen).await?;
            extra.insert("object_id".into(), id.as_str().into());
            let mut target = format!("/v1/fine_tuning/jobs/{id}");
            let (method, then) = match what.as_str() {
                "" => (Method::GET, Then::Read(id)),
                "events" | "checkpoints" => {
                    target = format!("{target}/{what}{query}");
                    (Method::GET, Then::Stream)
                }
                _ => {
                    target = format!("{target}/{what}");
                    (Method::POST, Then::Read(id))
                }
            };
            Ok(ready(provider, method, target, Bytes::new(), then))
        }
        Op::BatchCreate => {
            let (bytes, _held) =
                crate::read_body(Some(&person.name), state, &parts.headers, body).await?;
            let body = object(&bytes)?;
            let file_id = body["input_file_id"].as_str().ok_or_else(|| {
                bad(
                    "unreadable_request",
                    "Refused: a batch names its input file in \"input_file_id\", a string. Upload the file to /v1/files through Gantry first and send its ID.".into(),
                )
            })?;
            let (file, provider) =
                owned(state, version, policy, person, file_id, Item::File, seen).await?;
            if file.purpose != "batch" || file.person != person.name {
                return Err(bad(
                    "not_a_batch_file",
                    format!(
                        "Refused: file \"{file_id}\" was not uploaded by you with purpose batch, so Gantry has not checked its lines. Upload the batch input with purpose batch and use that file's ID."
                    ),
                ));
            }
            if let Some(endpoint) = body["endpoint"].as_str()
                && !file.models.is_empty()
                && endpoint != file.model_of.get("").map_or("", String::as_str)
            {
                return Err(bad(
                    "endpoint_mismatch",
                    format!(
                        "Refused: the batch names endpoint {endpoint}, and the lines of file \"{file_id}\" were checked for {}. Send the endpoint the lines name.",
                        file.model_of.get("").map_or("", String::as_str)
                    ),
                ));
            }
            // The policy may have changed since the upload: every model is decided again now.
            for model in &file.models {
                decide_model(
                    policy,
                    person,
                    rule,
                    model,
                    "the batch",
                    &mut seen.would_refuse,
                )?;
                crate::killed(state, person, &key_sha256, Some(model))?;
            }
            seen.model = file.models.first().cloned();
            // The policy may have changed since the upload: its batch limits hold now too.
            check_max_lines(policy, rule, file.lines, seen)?;
            check_max_open(state, policy, person, rule, seen).await?;
            count_creation(
                state,
                policy,
                person,
                rule,
                seen.model.clone().as_deref(),
                seen,
            )
            .await?;
            let reserved = reserve(state, policy, person, rule, &file, file_id, seen).await?;
            let mut created = Owned::new(Item::Batch, &file.provider, person, seen, decision);
            created.purpose = file.model_of.get("").cloned().unwrap_or_default();
            created.models = file.models.clone();
            created.lines = file.lines;
            created.estimate = file.estimate;
            created.reserved = reserved.clone();
            created.retention_days = rule.limits.file_retention_days;
            extra.insert("object".into(), "batch".into());
            extra.insert("input_file_id".into(), file_id.into());
            extra.insert("lines".into(), file.lines.into());
            if !file.cloud.is_null() {
                let mut ready = ready(
                    provider,
                    Method::POST,
                    String::new(),
                    Bytes::new(),
                    Then::Cloud(Cloud::Create {
                        batch: Box::new(created),
                        file: Box::new(file.clone()),
                        file_id: file_id.to_string(),
                    }),
                );
                ready.reserved = reserved;
                return Ok(ready);
            }
            headers.insert(header::CONTENT_TYPE, json_type);
            let mut ready = ready(
                provider,
                Method::POST,
                "/v1/batches".into(),
                bytes,
                Then::Create(Box::new(created)),
            );
            ready.reserved = reserved;
            Ok(ready)
        }
        Op::MessageBatchCreate => {
            let (bytes, _held) =
                crate::read_body(Some(&person.name), state, &parts.headers, body).await?;
            let mut body = object(&bytes)?;
            let Some(requests) = body["requests"].as_array() else {
                return Err(bad(
                    "unreadable_request",
                    "Refused: a message batch carries its requests in \"requests\", a list of objects with custom_id and params. Send it in that shape.".into(),
                ));
            };
            let mut items = Vec::with_capacity(requests.len());
            for (i, request) in requests.iter().enumerate() {
                let custom_id = request["custom_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                if !request["params"].is_object() || custom_id.is_empty() {
                    return Err(bad(
                        "unreadable_request",
                        format!(
                            "Refused: request {} of the batch has no custom_id or no params object. Give each request both.",
                            i + 1
                        ),
                    ));
                }
                items.push((i + 1, custom_id, "/v1/messages", request["params"].clone()));
            }
            check_max_lines(policy, rule, items.len(), seen)?;
            check_max_open(state, policy, person, rule, seen).await?;
            let checked = check_lines(
                state,
                policy,
                person,
                rule,
                &key_sha256,
                seen,
                decision,
                items,
                "request",
            )
            .await?;
            seen.would_refuse
                .extend(checked.would_refuse.iter().cloned());
            let first = checked.models.first().cloned().unwrap_or_default();
            count_creation(state, policy, person, rule, Some(&first), seen).await?;
            let provider = pick(version, Kind::Anthropic, &parts.headers, Some(&first))?;
            if let Some(other) = checked
                .models
                .iter()
                .find(|m| !version.providers[provider].serves(m))
            {
                return Err(bad(
                    "mixed_providers",
                    format!(
                        "Refused: the batch's models are served by different providers (\"{first}\" and \"{other}\"), and one batch goes to one provider. Send a batch per provider."
                    ),
                ));
            }
            let mut body_bytes = bytes;
            if checked.masked.iter().any(Option::is_some) {
                if let Some(requests) = body["requests"].as_array_mut() {
                    for (request, masked) in requests.iter_mut().zip(&checked.masked) {
                        if let Some(masked) = masked {
                            request["params"] = masked.clone();
                        }
                    }
                }
                body_bytes =
                    Bytes::from(serde_json::to_vec(&body).map_err(|_| masked_unwritable())?);
            }
            let mut created = Owned::new(
                Item::MessageBatch,
                &version.providers[provider].name,
                person,
                seen,
                decision,
            );
            created.models = checked.models.clone();
            if checked.models.len() > 1 {
                created.model_of = checked.model_of;
            }
            created.lines = checked.masked.len();
            created.estimate = checked.estimate;
            created.retention_days = rule.limits.file_retention_days;
            created.expires_at = rule
                .limits
                .file_retention_days
                .map(|days| now_secs() + u64::from(days) * 86_400);
            seen.model = Some(first);
            let reserved = reserve(
                state,
                policy,
                person,
                rule,
                &created,
                "this message batch",
                seen,
            )
            .await?;
            created.reserved = reserved.clone();
            extra.insert("object".into(), "message_batch".into());
            extra.insert("lines".into(), created.lines.into());
            if !checked.found.is_empty() {
                extra.insert("guardrails".into(), Value::Array(checked.found));
            }
            headers.insert(header::CONTENT_TYPE, json_type);
            anthropic_headers(&mut headers);
            let mut ready = ready(
                provider,
                Method::POST,
                "/v1/messages/batches".into(),
                body_bytes,
                Then::Create(Box::new(created)),
            );
            ready.reserved = reserved;
            Ok(ready)
        }
        Op::TuneCreate => {
            let (bytes, _held) =
                crate::read_body(Some(&person.name), state, &parts.headers, body).await?;
            let body = object(&bytes)?;
            let model = body["model"].as_str().ok_or_else(|| {
                bad(
                    "unreadable_request",
                    "Refused: a fine-tuning job names its base model in \"model\", a string. Send one.".into(),
                )
            })?;
            seen.model = Some(model.to_string());
            decide_model(
                policy,
                person,
                rule,
                model,
                "the fine-tuning job",
                &mut seen.would_refuse,
            )?;
            crate::killed(state, person, &key_sha256, Some(model))?;
            let training = body["training_file"].as_str().ok_or_else(|| {
                bad(
                    "unreadable_request",
                    "Refused: a fine-tuning job names its training file in \"training_file\". Upload it to /v1/files through Gantry first and send its ID.".into(),
                )
            })?;
            let (file, provider) =
                owned(state, version, policy, person, training, Item::File, seen).await?;
            if let Some(validation) = body["validation_file"].as_str() {
                let (other, _) =
                    owned(state, version, policy, person, validation, Item::File, seen).await?;
                if other.provider != file.provider {
                    return Err(bad(
                        "mixed_providers",
                        "Refused: the training and validation files are at different providers. Upload both to the same one.".into(),
                    ));
                }
            }
            let mut created = Owned::new(Item::FineTune, &file.provider, person, seen, decision);
            created.models = vec![model.to_string()];
            extra.insert("object".into(), "fine_tuning_job".into());
            extra.insert("training_file".into(), training.into());
            headers.insert(header::CONTENT_TYPE, json_type);
            Ok(ready(
                provider,
                Method::POST,
                "/v1/fine_tuning/jobs".into(),
                bytes,
                Then::Create(Box::new(created)),
            ))
        }
    }?;
    out.headers = headers;
    Ok(out)
}

/// A file or batch creation is one request against every rpm limit that applies (the rule's, the key's and the
/// `limits:` list's), as a model request is.
async fn count_creation(
    state: &AppState,
    policy: &Policy,
    person: &Principal,
    rule: &Rule,
    model: Option<&str>,
    seen: &mut Seen<'_>,
) -> Result<(), Refusal> {
    let model = model.unwrap_or_default();
    let applied = policy.applied(
        person,
        rule,
        gantry_core::policy::Context {
            sent: model,
            model,
            customer: seen.customer.as_deref(),
            tags: &seen.tags,
        },
    );
    let mut observed = Vec::new();
    spend::count_rpm(&state.spend, &applied, rule, &mut observed).await?;
    for (refusal, by) in observed {
        crate::observed(seen, refusal, by);
    }
    Ok(())
}

/// The rule's `batch: { max_lines }`: a batch of more lines is refused before the provider sees it.
fn check_max_lines(
    policy: &Policy,
    rule: &Rule,
    lines: usize,
    seen: &mut Seen<'_>,
) -> Result<(), Refusal> {
    let Some(most) = rule.limits.batch_max_lines else {
        return Ok(());
    };
    if lines <= most as usize {
        return Ok(());
    }
    crate::enforce(
        seen,
        bad(
            "batch_too_many_lines",
            format!(
                "Refused: the batch holds {lines} lines, and rule \"{}\" allows at most {most} in one batch (batch.max_lines). Split it into batches of {most} lines or fewer.",
                rule.name
            ),
        ),
        policy.observing(rule.shadow_until.as_deref()),
    )
}

/// The rule's `batch: { max_open }`: a person with that many batches not yet ended is refused another.
async fn check_max_open(
    state: &AppState,
    policy: &Policy,
    person: &Principal,
    rule: &Rule,
    seen: &mut Seen<'_>,
) -> Result<(), Refusal> {
    let Some(most) = rule.limits.batch_max_open else {
        return Ok(());
    };
    let me = person.within(&person.name);
    let open = state
        .owned
        .all()
        .await
        .into_iter()
        .filter(|(_, o)| {
            matches!(o.item, Item::Batch | Item::MessageBatch) && !o.settled && o.owner() == me
        })
        .count();
    if open < most as usize {
        return Ok(());
    }
    crate::enforce(
        seen,
        Refusal::new(
            StatusCode::TOO_MANY_REQUESTS,
            "batch_too_many_open",
            format!(
                "Refused: you have {open} batches that have not ended, and rule \"{}\" allows at most {most} open at once (batch.max_open). Wait for one to end, or cancel one, and send this again.",
                rule.name
            ),
        ),
        policy.observing(rule.shadow_until.as_deref()),
    )
}

fn masked_unwritable() -> Refusal {
    Refusal::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        guard::BLOCKED_CODE,
        "Refused: the masked batch could not be written, so it was not sent. Tell your Gantry admin.",
    )
}

fn object(bytes: &[u8]) -> Result<Value, Refusal> {
    match serde_json::from_slice::<Value>(bytes) {
        Ok(value @ Value::Object(_)) => Ok(value),
        _ => Err(bad(
            "unreadable_request",
            "Refused: the request body must be a JSON object. Send one.".into(),
        )),
    }
}

pub(crate) fn decide_model(
    policy: &Policy,
    person: &Principal,
    rule: &Rule,
    model: &str,
    what: &str,
    would_refuse: &mut Vec<Value>,
) -> Result<(), Refusal> {
    let shadow = match policy.decide(person, model) {
        Decision::Allow(_) => return Ok(()),
        Decision::ModelNotAllowed(rule) => policy.observing(rule.shadow_until.as_deref()),
        _ => policy.observing(None),
    };
    let refusal = Refusal::new(
        StatusCode::FORBIDDEN,
        "model_not_allowed",
        format!(
            "Refused: {what} asks for model \"{model}\", which rule \"{}\" does not allow for \"{}\". {} Change the model, or ask a Gantry admin to change the policy.",
            rule.name,
            person.name,
            crate::allowed_models(rule)
        ),
    );
    match shadow {
        Some(by) => {
            would_refuse.push(crate::would_refuse_entry(refusal, by));
            Ok(())
        }
        None => Err(refusal),
    }
}

/// Reserves a batch's estimate at batch prices against the budgets that apply. Nothing when none applies.
async fn reserve(
    state: &AppState,
    policy: &Policy,
    person: &Principal,
    rule: &Rule,
    batch: &Owned,
    what: &str,
    seen: &mut Seen<'_>,
) -> Result<Vec<Value>, Refusal> {
    let budgets = budgets_of(policy, person, rule, batch);
    if budgets.is_empty() {
        return Ok(Vec::new());
    }
    let budgets: Vec<&Applied> = budgets.iter().collect();
    let shadow = spend::all_shadowed(&budgets);
    let Some(estimate) = batch.estimate else {
        // Observed budgets: the batch goes on with nothing reserved, and what would have refused it is recorded.
        return crate::enforce(seen, bad(
            "no_estimate",
            format!(
                "Refused: a budget applies to {what}, and the most its lines could cost was not known when they were checked (a model without a price, or a line without max_tokens and no max_output for its model). Ask a Gantry admin to set the model's price with max_output under prices:, or give every line max_tokens, then upload the lines again."
            ),
        ), shadow).map(|()| Vec::new());
    };
    let mut observed = Vec::new();
    let (held, _) = spend::reserve_budgets(
        &state.spend,
        &budgets,
        rule,
        estimate * BATCH_SHARE,
        "This batch",
        Some(&mut observed),
    )
    .await?;
    for (refusal, by) in observed {
        crate::observed(seen, refusal, by);
    }
    Ok(held.iter().map(spend::Reservation::to_json).collect())
}

/// Every budget a batch counts against, from `Policy::applied` for each model its lines name, each once: the rule's,
/// the key's and those of the `limits:` list for its organization, team, customer, tags and models.
fn budgets_of(policy: &Policy, person: &Principal, rule: &Rule, batch: &Owned) -> Vec<Applied> {
    let mut all: Vec<Applied> = Vec::new();
    for model in &batch.models {
        let ctx = gantry_core::policy::Context {
            sent: model,
            model,
            customer: batch.customer.as_deref(),
            tags: &batch.tags,
        };
        for applied in policy.applied(person, rule, ctx) {
            if let Limit::Budget(budget) = applied.limit
                && !all.iter().any(|a| {
                    a.scope == applied.scope
                        && matches!(a.limit, Limit::Budget(b) if b.per == budget.per)
                })
            {
                all.push(applied);
            }
        }
    }
    all
}

/// The budget counters one result line is charged to: those its owner counts against for its model under the policy
/// in force, as a restart counts its usage record.
fn counted(
    version: &Snapshot,
    owned: &Owned,
    model: &str,
) -> Vec<(String, gantry_core::policy::Period)> {
    let Some(policy) = &version.policy else {
        return Vec::new();
    };
    let who = owner_of(policy, owned);
    let Some(rule) = policy.rule_for(&who) else {
        return Vec::new();
    };
    spend::counted_for(
        policy,
        &who,
        rule,
        model,
        model,
        owned.customer.as_deref(),
        &owned.tags,
    )
}

/// The owner of a file or batch as the policy in force knows them: their key's entry, else who the record names.
fn owner_of(policy: &Policy, owned: &Owned) -> Principal {
    policy
        .entries()
        .find(|(_, p)| p.key == owned.key)
        .map(|(_, p)| p.clone())
        .unwrap_or_else(|| Principal {
            name: owned.person.clone(),
            team: owned.team.clone(),
            key: owned.key.clone(),
            org: owned.org.clone(),
            ..Principal::default()
        })
}

/// What checks a batch's results on the way to the caller: the `on: [answer]` guardrails of the owner's rule
/// (as observe mode runs them), and whose results they are. None when that rule runs none on answers.
fn result_guards(
    policy: &Policy,
    owned: &Owned,
    object_id: &str,
    api: Results,
) -> Option<Box<GuardResults>> {
    let who = owner_of(policy, owned);
    let rule = policy.rule_for(&who)?;
    let guards: Vec<_> = crate::observed_guards(policy, &rule.guardrails)
        .unwrap_or_else(|| rule.guardrails.clone())
        .into_iter()
        .filter(|g| g.on.answer)
        .collect();
    (!guards.is_empty()).then(|| {
        Box::new(GuardResults {
            object_id: object_id.to_string(),
            guards,
            person: who.name,
            team: who.team,
            api,
        })
    })
}

/// Which batch API's result lines a file holds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Results {
    /// `{"custom_id", "response": {"status_code", "body"}, "error"}`, as OpenAI's output files (and Gantry's own
    /// for Bedrock and Vertex AI batches) hold them.
    OpenAi,
    /// `{"custom_id", "result": {"type": "succeeded", "message"}}`, as Anthropic's results stream holds them.
    Anthropic,
}

struct GuardResults {
    object_id: String,
    guards: Vec<gantry_core::guard::Guardrail>,
    person: String,
    team: String,
    api: Results,
}

/// Runs the answer guardrails on every result line: a blocked line's answer is replaced with an error object, a
/// masked one is masked, and each line they found something in gets a `batch_result_guardrails` record. The
/// caller gets the processed lines; a line Gantry cannot read is passed on as it is.
async fn guard_results(
    state: &AppState,
    check: &GuardResults,
    decision: &str,
    body: &[u8],
) -> Result<Bytes, Refusal> {
    let mut out = Vec::with_capacity(body.len());
    for (i, raw) in body.split(|b| *b == b'\n').enumerate() {
        if raw.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let Ok(mut line) = serde_json::from_slice::<Value>(raw) else {
            out.extend_from_slice(raw);
            out.push(b'\n');
            continue;
        };
        let pointer = match check.api {
            Results::OpenAi => "/response/body",
            Results::Anthropic => "/result/message",
        };
        let ok = match check.api {
            Results::OpenAi => line["response"]["status_code"]
                .as_u64()
                .is_some_and(|s| (200..300).contains(&s)),
            Results::Anthropic => line["result"]["type"] == "succeeded",
        };
        let Some(answer) = line.pointer(pointer).filter(|_| ok).cloned() else {
            out.extend_from_slice(raw);
            out.push(b'\n');
            continue;
        };
        let path = match check.api {
            Results::OpenAi => "/v1/batches",
            Results::Anthropic => "/v1/messages/batches",
        };
        let (verdict, found) = crate::check_answer(
            state,
            &check.guards,
            &check.person,
            &check.team,
            path,
            decision,
            &answer,
        )
        .await;
        let word = match &verdict {
            Err(_) => "block",
            Ok(after) if *after != answer => "mask",
            Ok(_) => "pass",
        };
        match verdict {
            Err(message) => match check.api {
                Results::OpenAi => {
                    line["response"] = Value::Null;
                    line["error"] = json!({ "code": guard::BLOCKED_CODE, "message": message });
                }
                Results::Anthropic => {
                    line["result"] = json!({
                        "type": "errored",
                        "error": { "type": "error", "error": { "type": "permission_error", "message": message } }
                    });
                }
            },
            Ok(after) => {
                if let Some(slot) = line.pointer_mut(pointer) {
                    *slot = after;
                }
            }
        }
        if !found.is_empty() {
            let mut record = Map::new();
            record.insert("event".into(), "batch_result_guardrails".into());
            record.insert("id".into(), decision.into());
            record.insert("time".into(), audit::timestamp().into());
            record.insert("object_id".into(), check.object_id.as_str().into());
            record.insert("line".into(), (i + 1).into());
            record.insert("custom_id".into(), line["custom_id"].clone());
            record.insert("verdict".into(), word.into());
            record.insert(
                "guardrails".into(),
                serde_json::to_value(&found).unwrap_or_default(),
            );
            if !write(state, record).await {
                return Err(Refusal::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "audit_unavailable",
                    "Refused: Gantry could not write the guardrails' check of these batch results to its audit log, and it does not pass on what it cannot record. Tell your Gantry admin.",
                ));
            }
        }
        out.extend_from_slice(line.to_string().as_bytes());
        out.push(b'\n');
    }
    Ok(Bytes::from(out))
}

/// The lines of a batch after their checks.
struct Checked {
    models: Vec<String>,
    model_of: BTreeMap<String, String>,
    /// Each line's body as the guardrails masked it, when they did.
    masked: Vec<Option<Value>>,
    estimate: Option<f64>,
    /// What the guardrails found, by line.
    found: Vec<Value>,
    /// What observe mode or a shadow period let through, for the decision record.
    would_refuse: Vec<Value>,
}

/// Decides every line: its model by the rule, its text by the guardrails, and what it could cost. `word` names a
/// line in a refusal ("line" in a file, "request" in a message batch).
#[allow(clippy::too_many_arguments)]
async fn check_lines(
    state: &AppState,
    policy: &Policy,
    person: &Principal,
    rule: &Rule,
    key_sha256: &str,
    seen: &Seen<'_>,
    decision: &str,
    items: Vec<(usize, String, &str, Value)>,
    word: &str,
) -> Result<Checked, Refusal> {
    let at = |n: usize, mut refusal: Refusal| {
        let rest = refusal
            .message
            .strip_prefix("Refused: ")
            .unwrap_or(&refusal.message)
            .to_string();
        refusal.message = format!("Refused: {word} {n} of the batch: {rest}");
        refusal
    };
    let observe = policy.mode() == gantry_core::policy::Mode::Observe;
    let guards: Vec<_> = crate::observed_guards(policy, &rule.guardrails)
        .unwrap_or_else(|| rule.guardrails.clone())
        .into_iter()
        .filter(|g| g.on.request)
        .collect();
    // A budget of the rule, the key or any scope of the limits: list may count these lines, so each needs its most.
    let budgeted = !rule.limits.budgets.is_empty()
        || person.budget.is_some()
        || policy.scope_limits().iter().any(|l| !l.budgets.is_empty());
    let mut checked = Checked {
        models: Vec::new(),
        model_of: BTreeMap::new(),
        masked: Vec::with_capacity(items.len()),
        estimate: Some(0.0),
        found: Vec::new(),
        would_refuse: Vec::new(),
    };
    for (n, custom_id, route, body) in items {
        let Some(model) = body["model"].as_str().map(String::from) else {
            return Err(at(
                n,
                bad(
                    "unreadable_request",
                    "it names no model, so the policy cannot be checked. Give every line a \"model\" string.".into(),
                ),
            ));
        };
        decide_model(
            policy,
            person,
            rule,
            &model,
            "it",
            &mut checked.would_refuse,
        )
        .map_err(|r| at(n, r))?;
        crate::killed(state, person, key_sha256, Some(&model)).map_err(|r| at(n, r))?;
        if checked
            .model_of
            .insert(custom_id.clone(), model.clone())
            .is_some()
        {
            return Err(at(
                n,
                bad(
                    "duplicate_custom_id",
                    format!(
                        "custom_id \"{custom_id}\" is used twice, so its results could not be told apart. Give every line its own custom_id."
                    ),
                ),
            ));
        }
        if !checked.models.contains(&model) {
            checked.models.push(model.clone());
        }
        let mut bytes = Bytes::from(body.to_string());
        if !guards.is_empty() {
            let (parts, ()) = axum::http::Request::builder()
                .method(Method::POST)
                .uri(route)
                .header(header::CONTENT_TYPE, "application/json")
                .body(())
                .map_err(|_| masked_unwritable())?
                .into_parts();
            let (result, entries) =
                crate::guarded(state, &guards, seen, decision, parts, bytes.clone()).await;
            if observe {
                checked
                    .would_refuse
                    .extend(crate::would_block(rule, &entries));
            }
            if !entries.is_empty() {
                checked
                    .found
                    .push(json!({ word: n, "guardrails": serde_json::to_value(&entries).unwrap_or_default() }));
            }
            let (_, after) = result.map_err(|r| at(n, r))?;
            if after != bytes {
                let masked: Value =
                    serde_json::from_slice(&after).map_err(|_| masked_unwritable())?;
                checked.masked.push(Some(masked));
                bytes = after;
            } else {
                checked.masked.push(None);
            }
        } else {
            checked.masked.push(None);
        }
        // An alias is estimated at its first deployment's price; its batch is charged at the one that ran it.
        let priced = state
            .version()
            .aliases
            .iter()
            .find(|a| a.name == model)
            .and_then(|a| a.deployments.first())
            .map_or_else(|| model.clone(), |d| d.model.clone());
        let price = price_for(&priced, policy.prices());
        let most = match &price {
            Some(price) => spend::most_for(&bytes, route, price).map_err(|why| {
                at(
                    n,
                    bad(
                        "max_tokens_needed",
                        format!("{why}, so the most it could cost is unknown and a budget applies. Give the line max_tokens, or ask a Gantry admin to set max_output for model \"{model}\" under prices: in the policy."),
                    ),
                )
            }),
            None => Err(at(
                n,
                Refusal::new(
                    StatusCode::FORBIDDEN,
                    "no_price",
                    format!("a budget applies, and model \"{model}\" has no price, so its spend could not be counted. Ask a Gantry admin to add its price under prices: in the policy."),
                ),
            )),
        };
        match most {
            Ok(most) => checked.estimate = checked.estimate.map(|sum| sum + most),
            // In observe mode the batch's no_estimate is recorded when it is created, and nothing refused.
            Err(refusal) if budgeted && !observe => return Err(refusal),
            // Without a budget the estimate is only what a line without usage is charged.
            Err(_) => checked.estimate = None,
        }
    }
    if checked.models.is_empty() {
        return Err(bad(
            "empty_batch",
            format!("Refused: the batch has no {word}s. Send at least one."),
        ));
    }
    Ok(checked)
}

struct Upload {
    provider: usize,
    body: Bytes,
    /// The file is kept by Gantry in a Bedrock or Vertex AI provider's bucket, `body` being its translated lines.
    cloud: bool,
    owned: Owned,
    found: Vec<Value>,
    would_refuse: Vec<Value>,
}

/// Checks an upload: a batch input line by line, and the retention the policy sets for every file.
#[allow(clippy::too_many_arguments)]
async fn upload(
    state: &AppState,
    version: &Snapshot,
    policy: &Policy,
    person: &Principal,
    rule: &Rule,
    key_sha256: &str,
    seen: &Seen<'_>,
    decision: &str,
    headers: &HeaderMap,
    content_type: &str,
    bytes: &Bytes,
) -> Result<Upload, Refusal> {
    let unreadable = |why: &str| {
        bad(
            "unreadable_request",
            format!(
                "Refused: {why}. Send the file as multipart/form-data with one purpose field and one file part."
            ),
        )
    };
    let boundary = crate::alias::boundary(content_type)
        .ok_or_else(|| unreadable("the body is not multipart/form-data"))?
        .to_string();
    let parts = crate::alias::form_parts(content_type, bytes).map_err(unreadable)?;
    let one = |name: &str, file: bool| {
        let mut found = parts.iter().filter(|p| p.name == name);
        match (found.next(), found.next()) {
            (Some(part), None) if part.file == file => Ok(Some(part.value.clone())),
            (None, _) => Ok(None),
            _ => Err(unreadable(&format!(
                "the form has more than one {name}, or {name} is of the wrong kind"
            ))),
        }
    };
    let text = |range: Range<usize>| String::from_utf8_lossy(&bytes[range]).trim().to_string();
    let purpose = one("purpose", false)?
        .map(text)
        .ok_or_else(|| unreadable("the form has no purpose field"))?;
    let file = one("file", true)?.ok_or_else(|| unreadable("the form has no file part"))?;
    let mut owned_file = Owned::new(Item::File, "", person, seen, decision);
    owned_file.purpose = purpose.clone();
    let mut found = Vec::new();
    let mut would_refuse = Vec::new();
    let mut new_file = None;
    let mut model = None;
    if purpose == "batch" {
        let content = std::str::from_utf8(&bytes[file.clone()])
            .map_err(|_| unreadable("the batch file is not UTF-8 text"))?;
        let mut lines: Vec<(usize, Value)> = Vec::new();
        let mut endpoint: Option<String> = None;
        for (i, raw) in content.lines().enumerate() {
            if raw.trim().is_empty() {
                continue;
            }
            let n = i + 1;
            let line: Value = serde_json::from_str(raw).map_err(|_| {
                bad("unreadable_request", format!("Refused: line {n} of the batch file is not a JSON object. Write one request per line."))
            })?;
            let url = line["url"].as_str().unwrap_or_default();
            if line["method"] != "POST"
                || !ENDPOINTS.contains(&url)
                || !line["body"].is_object()
                || !line["custom_id"].is_string()
            {
                return Err(bad(
                    "unreadable_request",
                    format!(
                        "Refused: line {n} of the batch file needs custom_id, method POST, a url of {} and a body object. Fix the line.",
                        ENDPOINTS.join(", ")
                    ),
                ));
            }
            match &endpoint {
                Some(first) if first != url => {
                    return Err(bad(
                        "mixed_endpoints",
                        format!(
                            "Refused: line {n} of the batch file names {url} and an earlier line {first}; one batch runs one endpoint. Split the file."
                        ),
                    ));
                }
                Some(_) => {}
                None => endpoint = Some(url.to_string()),
            }
            lines.push((n, line));
        }
        let endpoint = endpoint.unwrap_or_default();
        let items = lines
            .iter()
            .map(|(n, line)| {
                (
                    *n,
                    line["custom_id"].as_str().unwrap_or_default().to_string(),
                    endpoint.as_str(),
                    line["body"].clone(),
                )
            })
            .collect();
        let checked = check_lines(
            state, policy, person, rule, key_sha256, seen, decision, items, "line",
        )
        .await?;
        if checked.models.len() > 1 {
            return Err(bad(
                "mixed_models",
                format!(
                    "Refused: the batch file names models {}, and OpenAI runs one model per batch file. Split it by model.",
                    checked.models.join(", ")
                ),
            ));
        }
        if checked.masked.iter().any(Option::is_some) {
            let mut out = String::with_capacity(content.len());
            for ((_, line), masked) in lines.iter().zip(&checked.masked) {
                let mut line = line.clone();
                if let Some(masked) = masked {
                    line["body"] = masked.clone();
                }
                out.push_str(&line.to_string());
                out.push('\n');
            }
            new_file = Some(out.into_bytes());
        }
        owned_file.lines = lines.len();
        owned_file.estimate = checked.estimate;
        owned_file.models = checked.models.clone();
        // The endpoint the lines were checked for, kept under the empty custom_id.
        owned_file.model_of.insert(String::new(), endpoint.clone());
        found = checked.found;
        would_refuse = checked.would_refuse;
        model = checked.models.first().cloned();
        let observing = policy.observing(rule.shadow_until.as_deref());
        let target = match &model {
            Some(model) => {
                match crate::cloud_batch::target(version, model, rule.limits.regions.as_deref()) {
                    Ok(target) => target,
                    // Observed: recorded as what would have refused it, and the batch goes where it would without regions.
                    Err(refusal) => match observing {
                        Some(by) => {
                            would_refuse.push(crate::would_refuse_entry(refusal, by));
                            crate::cloud_batch::target(version, model, None)?
                        }
                        None => return Err(refusal),
                    },
                }
            }
            None => None,
        };
        if let Some(target) = target {
            let provider = &version.providers[target.provider];
            crate::cloud_batch::settings(provider)?;
            if endpoint != "/v1/chat/completions" {
                return Err(bad(
                    "wrong_endpoint",
                    format!(
                        "Refused: the batch's model runs on provider \"{}\" of kind {}, whose batch jobs Gantry runs for /v1/chat/completions lines only, and the lines name {endpoint}. Write chat completions lines.",
                        provider.name,
                        provider.kind.word()
                    ),
                ));
            }
            let id = format!("file-gantry-{}", decision.to_ascii_lowercase());
            let mut out = String::new();
            let mut ids = Map::new();
            for ((n, line), masked) in lines.iter().zip(&checked.masked) {
                let custom_id = line["custom_id"].as_str().unwrap_or_default();
                let body = masked.as_ref().unwrap_or(&line["body"]);
                let translated = crate::cloud_batch::input_line(provider.kind, custom_id, body)
                    .map_err(|why| {
                        bad(
                            "untranslatable",
                            format!("Refused: line {n} of the batch file: {why}"),
                        )
                    })?;
                if provider.kind == Kind::Vertex {
                    ids.insert(
                        crate::cloud_batch::request_key(&translated["request"]),
                        custom_id.into(),
                    );
                }
                out.push_str(&translated.to_string());
                out.push('\n');
            }
            let filename = file_name(bytes, content_type);
            owned_file.provider = provider.name.clone();
            owned_file.retention_days = rule.limits.file_retention_days;
            owned_file.expires_at = rule
                .limits
                .file_retention_days
                .map(|days| now_secs() + u64::from(days) * 86_400);
            owned_file.cloud = json!({
                "key": crate::cloud_batch::key(provider, &format!("input/{id}.jsonl")),
                "name": format!("{id}.jsonl"),
                "filename": filename,
                "bytes": out.len(),
                "created_at": now_secs(),
                "region": target.region,
                "model": target.model,
                "ids": ids,
                "id": id,
            });
            return Ok(Upload {
                provider: target.provider,
                body: Bytes::from(out),
                cloud: true,
                owned: owned_file,
                found,
                would_refuse,
            });
        }
    }
    if let Some(regions) = rule
        .limits
        .regions
        .as_ref()
        .filter(|_| !would_refuse_region(&would_refuse))
    {
        let refusal = bad(
            "region_not_allowed",
            format!(
                "Refused: rule \"{}\" keeps requests in {}, and only a batch file for a Bedrock or Vertex AI deployment labelled with one of them is kept where its region shows. Upload a batch file whose model is such an alias, or send it under a rule without regions:.",
                rule.name,
                regions.join(", ")
            ),
        );
        match policy.observing(rule.shadow_until.as_deref()) {
            Some(by) => would_refuse.push(crate::would_refuse_entry(refusal, by)),
            None => return Err(refusal),
        }
    }
    let provider = pick(version, Kind::OpenAi, headers, model.as_deref())?;
    owned_file.provider = version.providers[provider].name.clone();
    // Retention: OpenAI expires the file itself when told to, and Gantry deletes it at the same time if it did not.
    let given = one("expires_after[seconds]", false)?.map(text);
    let mut add = Vec::new();
    let mut seconds = None;
    if let Some(given) = &given {
        seconds = Some(given.parse::<u64>().map_err(|_| {
            bad(
                "unreadable_request",
                "Refused: expires_after[seconds] must be a whole number of seconds. Send one."
                    .into(),
            )
        })?);
    }
    if let Some(days) = rule.limits.file_retention_days {
        let most = u64::from(days) * 86_400;
        match seconds {
            Some(asked) if asked > most => {
                return Err(bad(
                    "retention_too_long",
                    format!(
                        "Refused: expires_after[seconds] asks to keep the file {asked} seconds, and rule \"{}\" keeps files at most {days} days ({most} seconds). Ask for {most} or fewer, or leave it out.",
                        rule.name
                    ),
                ));
            }
            Some(_) => {}
            None => {
                seconds = Some(most);
                add.push(("expires_after[seconds]", most.to_string()));
            }
        }
        if one("expires_after[anchor]", false)?.is_none() {
            add.insert(0, ("expires_after[anchor]", "created_at".to_string()));
        }
    }
    owned_file.expires_at = seconds.map(|s| now_secs() + s);
    owned_file.retention_days = rule.limits.file_retention_days;
    let body = if new_file.is_some() || !add.is_empty() {
        Bytes::from(rewrite_form(
            bytes,
            &boundary,
            file,
            new_file.as_deref(),
            &add,
        ))
    } else {
        bytes.clone()
    };
    Ok(Upload {
        provider,
        body,
        cloud: false,
        owned: owned_file,
        found,
        would_refuse,
    })
}

/// Whether residency already went on the record as what would have refused this upload.
fn would_refuse_region(would_refuse: &[Value]) -> bool {
    would_refuse
        .iter()
        .any(|w| w["code"] == "region_not_allowed")
}

/// The file part's filename, for the file object Gantry answers with when it keeps the file.
fn file_name(bytes: &[u8], content_type: &str) -> String {
    let Some(boundary) = crate::alias::boundary(content_type) else {
        return String::new();
    };
    let text = String::from_utf8_lossy(bytes);
    text.split(&format!("--{boundary}"))
        .find(|part| part.contains("name=\"file\""))
        .and_then(|part| part.split("filename=\"").nth(1))
        .and_then(|rest| rest.split('"').next())
        .map(|name| name.chars().take(200).collect())
        .unwrap_or_default()
}

/// The form with its file part's content replaced, and fields added before the closing delimiter.
fn rewrite_form(
    bytes: &[u8],
    boundary: &str,
    file: Range<usize>,
    content: Option<&[u8]>,
    add: &[(&str, String)],
) -> Vec<u8> {
    let close = format!("\r\n--{boundary}--");
    let end = bytes
        .windows(close.len())
        .rposition(|w| w == close.as_bytes())
        .unwrap_or(bytes.len());
    let mut out = Vec::with_capacity(bytes.len() + 256);
    out.extend_from_slice(&bytes[..file.start]);
    out.extend_from_slice(content.unwrap_or(&bytes[file.clone()]));
    out.extend_from_slice(&bytes[file.end..end]);
    for (name, value) in add {
        out.extend_from_slice(
            format!(
                "\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}"
            )
            .as_bytes(),
        );
    }
    out.extend_from_slice(&bytes[end..]);
    out
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn record_decision(
    state: &AppState,
    version: &Snapshot,
    decision: &str,
    client: Option<&str>,
    method: &str,
    path: &str,
    seen: &Seen<'_>,
    refused: Option<&Refusal>,
    extra: Map<String, Value>,
) -> Result<(), Refusal> {
    let provider = seen
        .provider
        .and_then(|i| version.providers.get(i))
        .map_or("", |p| p.name.as_str());
    state
        .metrics
        .decided(path, refused.map(|r| r.code), provider);
    if state.audit.is_none() {
        return Ok(());
    }
    let entry = Entry {
        id: decision,
        person: seen.person.map(|p| p.name.as_str()),
        team: seen.person.map(|p| p.team.as_str()),
        client,
        // Carried in `extra` (`user_agent_of`), so the decision record names the tool as on the model routes.
        user_agent: None,
        key: seen.key.as_deref(),
        method,
        path,
        model: seen.model.as_deref(),
        allowed: refused.is_none(),
        code: refused.map(|r| r.code),
        rule: seen.rule.map(|r| r.name.as_str()),
        rule_line: seen.rule.map(|r| r.line).filter(|l| *l > 0),
        provider,
        policy_sha256: &version.policy_sha256,
        keys_sha256: &version.keys_sha256,
        translated: false,
        cache: None,
    };
    let mut record = audit::record(&entry);
    record.extend(extra);
    crate::mark_would_refuse(&mut record, seen.would_refuse.clone(), refused.is_none());
    if write(state, record).await {
        return Ok(());
    }
    eprintln!("gantry: the audit log could not be written, so decision {decision} was refused");
    Err(Refusal::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "audit_unavailable",
        "Refused: Gantry could not write this request to its audit log, and it does not forward what it cannot record. Tell your Gantry admin.",
    ))
}

/// Writes a record and waits for it. True when it is written, or when there is no log.
pub(crate) async fn write(state: &AppState, record: Map<String, Value>) -> bool {
    let Some(audit) = &state.audit else {
        return true;
    };
    let (tell, written) = tokio::sync::oneshot::channel();
    audit.log.append_record_then(&record, move |result| {
        let _ = tell.send(result);
    });
    matches!(written.await, Ok(Ok(())))
}

/// One request to a provider's own API, with Gantry's provider key.
async fn fetch(
    state: &AppState,
    provider: &Upstream,
    method: Method,
    target: &str,
    mut headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Refusal> {
    if !matches!(provider.kind, Kind::OpenAi | Kind::Anthropic) {
        return Err(bad(
            "wrong_provider",
            format!(
                "Refused: provider \"{}\" is of kind {}, and Gantry serves files and batches for openai and anthropic providers. Reach this provider's own batch API through /passthrough/ on a path the rule names.",
                provider.name,
                provider.kind.word()
            ),
        ));
    }
    let uri = gantry_core::config::join(&provider.url, target)
        .parse::<Uri>()
        .map_err(|_| {
            bad(
                "bad_path",
                "Refused: the request path is not a valid URL path. Check the ID.".into(),
            )
        })?;
    if provider.kind == Kind::Anthropic {
        headers
            .entry(HeaderName::from_static("anthropic-version"))
            .or_insert(HeaderValue::from_static(ANTHROPIC_VERSION));
    }
    if let Some((name, value)) = &provider.key {
        headers.insert(name.clone(), value.clone());
    }
    let mut request = axum::http::Request::new(Body::from(body));
    *request.method_mut() = method;
    *request.uri_mut() = uri;
    *request.version_mut() = Version::HTTP_11;
    *request.headers_mut() = headers;
    crate::attempt(state, provider, request).await
}

async fn collect(body: Body, most: usize) -> Result<Bytes, String> {
    http_body_util::Limited::new(body, most)
        .collect()
        .await
        .map(|b| b.to_bytes())
        .map_err(|err| format!("the answer could not be read: {err}"))
}

async fn after(
    state: &AppState,
    version: &Snapshot,
    decision: &str,
    ready: Ready,
    answer: Response,
) -> Result<Response, Refusal> {
    let status = answer.status();
    let content_type = answer.headers().get(header::CONTENT_TYPE).cloned();
    let respond = |body: Bytes| {
        let mut response = (status, body).into_response();
        if let Some(content_type) = &content_type {
            response
                .headers_mut()
                .insert(header::CONTENT_TYPE, content_type.clone());
        }
        response
    };
    if matches!(ready.then, Then::Stream) {
        let mut response = Response::new(answer.into_body());
        *response.status_mut() = status;
        if let Some(content_type) = &content_type {
            response
                .headers_mut()
                .insert(header::CONTENT_TYPE, content_type.clone());
        }
        return Ok(response);
    }
    if let Then::Guard(check) = &ready.then {
        let body = collect(answer.into_body(), MAX_RESULTS)
            .await
            .map_err(|why| {
                Refusal::new(
                    StatusCode::BAD_GATEWAY,
                    "upstream_failed",
                    format!("{why}. Try again."),
                )
            })?;
        if !status.is_success() {
            return Ok(respond(body));
        }
        return Ok(respond(guard_results(state, check, decision, &body).await?));
    }
    let body = collect(answer.into_body(), crate::MAX_BODY_BYTES)
        .await
        .map_err(|why| {
            release(state, &ready.reserved);
            Refusal::new(
                StatusCode::BAD_GATEWAY,
                "upstream_failed",
                format!("{why}. Try again."),
            )
        })?;
    if !status.is_success() {
        release(state, &ready.reserved);
        return Ok(respond(body));
    }
    let mut value: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    match ready.then {
        Then::Create(owned) => {
            let Some(id) = value["id"].as_str() else {
                release(state, &ready.reserved);
                eprintln!(
                    "gantry: decision {decision}: the provider created an object and named no id"
                );
                return Ok(respond(body));
            };
            let owned = *owned;
            if !write(state, owned.record(id)).await {
                eprintln!(
                    "gantry: decision {decision}: the owner of {id} could not be written to the audit log"
                );
            }
            state.owned.put(id, owned).await;
            Ok(respond(body))
        }
        Then::List => {
            if !ready.admin
                && let Some(data) = value["data"].as_array_mut()
            {
                let mine: std::collections::HashSet<String> = state
                    .owned
                    .all()
                    .await
                    .into_iter()
                    .filter(|(_, o)| o.owner() == ready.person)
                    .map(|(id, _)| id)
                    .collect();
                data.retain(|item| item["id"].as_str().is_some_and(|id| mine.contains(id)));
            }
            // What Gantry keeps for Bedrock and Vertex AI providers is listed beside the provider's own.
            let item = if ready.target.starts_with("/v1/batches") {
                Some(Item::Batch)
            } else if ready.target.starts_with("/v1/files") {
                Some(Item::File)
            } else {
                None
            };
            if let (Some(item), Some(data)) = (item, value["data"].as_array_mut()) {
                data.extend(kept_list(state, &ready.person, ready.admin, item).await);
            }
            Ok(respond(Bytes::from(value.to_string())))
        }
        Then::Read(id) => {
            settle(state, version, &id, &value).await;
            Ok(respond(body))
        }
        Then::Delete(id) => {
            let mut record = Map::new();
            record.insert("event".into(), "owned_deleted".into());
            record.insert("id".into(), decision.into());
            record.insert("time".into(), audit::timestamp().into());
            record.insert("object_id".into(), id.as_str().into());
            record.insert("why".into(), format!("deleted by {}", ready.person).into());
            write(state, record).await;
            state.owned.remove(&id).await;
            Ok(respond(body))
        }
        Then::Stream | Then::Guard(_) | Then::Cloud(_) => Ok(respond(body)),
    }
}

/// Whether a batch or job object says it is over.
fn ended(item: Item, object: &Value) -> bool {
    match item {
        Item::Batch => matches!(
            object["status"].as_str(),
            Some("completed" | "failed" | "expired" | "cancelled")
        ),
        Item::MessageBatch => object["processing_status"] == "ended",
        Item::FineTune => matches!(
            object["status"].as_str(),
            Some("succeeded" | "failed" | "cancelled")
        ),
        Item::File => false,
    }
}

/// One result line: its custom_id, whether it succeeded, its usage.
type Outcome = (String, bool, Option<Usage>);

/// Meters a batch that ended, once: one usage record per result line at batch prices, the reservation given back,
/// and the files it wrote recorded as its owner's. A fine-tuning job that ended is recorded with its trained tokens.
async fn settle(state: &AppState, version: &Snapshot, id: &str, object: &Value) {
    let Some(item) = state.owned.get(id).await.map(|o| o.item) else {
        return;
    };
    if !ended(item, object) {
        return;
    }
    let Some(owned) = state.owned.begin_settle(id).await else {
        return;
    };
    let Some(provider) = version.providers.iter().find(|p| p.name == owned.provider) else {
        state.owned.unsettle(id).await;
        return;
    };
    let mut done = Map::new();
    done.insert("event".into(), "owned_settled".into());
    done.insert("id".into(), owned.decision.as_str().into());
    done.insert("time".into(), audit::timestamp().into());
    done.insert("object_id".into(), id.into());
    if item == Item::FineTune {
        // OpenAI's job object names the tokens trained, and no price for them: they are recorded, not charged.
        done.insert("status".into(), object["status"].clone());
        done.insert("trained_tokens".into(), object["trained_tokens"].clone());
        done.insert(
            "fine_tuned_model".into(),
            object["fine_tuned_model"].clone(),
        );
        write(state, done).await;
        return;
    }
    let results = match item {
        Item::Batch if !owned.cloud.is_null() => {
            cloud_results(state, provider, &owned, id, object).await
        }
        Item::Batch => openai_results(state, provider, object).await,
        _ => anthropic_results(state, provider, id).await,
    };
    let results = match results {
        Ok(results) => results,
        Err(why) => {
            eprintln!(
                "gantry: batch {id} ended and its results could not be read to meter it ({why}); trying again at the next poll"
            );
            state.owned.unsettle(id).await;
            return;
        }
    };
    let prices = version.policy.as_ref().map(Policy::prices);
    let per_line = owned.estimate.unwrap_or_default() * BATCH_SHARE / owned.lines.max(1) as f64;
    let (mut charged, mut succeeded) = (0.0, 0usize);
    for (n, (custom_id, ok, usage)) in results.iter().enumerate() {
        // A batch Gantry runs at Bedrock or Vertex AI is priced as the model its deployment runs.
        let model = owned.cloud["model"]
            .as_str()
            .map(String::from)
            .or_else(|| {
                owned
                    .model_of
                    .get(custom_id)
                    .or(owned.models.first())
                    .cloned()
            })
            .unwrap_or_default();
        let mut extra = Map::new();
        extra.insert("batch".into(), id.into());
        extra.insert("custom_id".into(), custom_id.as_str().into());
        extra.insert("line".into(), (n + 1).into());
        let counted = counted(version, &owned, &model);
        let (price, share) =
            prices
                .and_then(|p| price_for(&model, p))
                .map_or((None, BATCH_SHARE), |p| {
                    let (price, share) = p.for_batch(BATCH_SHARE);
                    (Some(price), share)
                });
        let (cost, record) = spend::charge(
            &state.spend,
            spend::Line {
                decision: &owned.decision,
                person: &owned.person,
                team: &owned.team,
                key: &owned.key,
                org: &owned.org,
                customer: owned.customer.as_deref(),
                tags: &owned.tags,
                counted: &counted,
                model: &model,
                provider: &owned.provider,
                version: (&version.policy_sha256, &version.keys_sha256),
                price,
                usage: *usage,
                share,
                unreported: per_line,
                succeeded: *ok,
                extra,
            },
        );
        charged += cost;
        succeeded += usize::from(*ok);
        write(state, record).await;
    }
    release(state, &owned.reserved);
    for key in ["output_file_id", "error_file_id"] {
        if let Some(file) = object[key].as_str() {
            let mut out = owned.clone();
            out.item = Item::File;
            out.purpose = "batch_output".into();
            out.reserved = Vec::new();
            out.expires_at = owned
                .retention_days
                .map(|d| now_secs() + u64::from(d) * 86_400);
            write(state, out.record(file)).await;
            state.owned.put(file, out).await;
        }
    }
    done.insert("lines".into(), results.len().into());
    done.insert("succeeded".into(), succeeded.into());
    done.insert("charged_usd".into(), charged.into());
    write(state, done).await;
    state.owned.settled(id).await;
}

async fn read_lines(state: &AppState, provider: &Upstream, target: &str) -> Result<Bytes, String> {
    let answer = fetch(
        state,
        provider,
        Method::GET,
        target,
        HeaderMap::new(),
        Bytes::new(),
    )
    .await
    .map_err(|r| r.message)?;
    if !answer.status().is_success() {
        return Err(format!("the provider answered {}", answer.status()));
    }
    collect(answer.into_body(), MAX_RESULTS).await
}

async fn openai_results(
    state: &AppState,
    provider: &Upstream,
    batch: &Value,
) -> Result<Vec<Outcome>, String> {
    let mut results = Vec::new();
    for key in ["output_file_id", "error_file_id"] {
        let Some(file) = batch[key].as_str() else {
            continue;
        };
        let bytes = read_lines(state, provider, &format!("/v1/files/{file}/content")).await?;
        for line in bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
            let Ok(line) = serde_json::from_slice::<Value>(line) else {
                continue;
            };
            let response = &line["response"];
            let ok = response["status_code"]
                .as_u64()
                .is_some_and(|s| (200..300).contains(&s));
            let usage = ok
                .then(|| Usage::from_body(response["body"].to_string().as_bytes()))
                .flatten();
            results.push((
                line["custom_id"].as_str().unwrap_or_default().to_string(),
                ok,
                usage,
            ));
        }
    }
    Ok(results)
}

async fn anthropic_results(
    state: &AppState,
    provider: &Upstream,
    id: &str,
) -> Result<Vec<Outcome>, String> {
    let bytes = read_lines(
        state,
        provider,
        &format!("/v1/messages/batches/{id}/results"),
    )
    .await?;
    Ok(bytes
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
        .map(|line| {
            let result = &line["result"];
            let ok = result["type"] == "succeeded";
            let usage = ok
                .then(|| Usage::from_body(result["message"].to_string().as_bytes()))
                .flatten();
            (
                line["custom_id"].as_str().unwrap_or_default().to_string(),
                ok,
                usage,
            )
        })
        .collect())
}

/// Asks every open batch and job whether it ended, and deletes what passed its retention, once a minute: a batch
/// nobody retrieves is still metered, and a file nobody deletes still goes.
pub(crate) fn spawn_poller(state: std::sync::Weak<AppState>) {
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        runtime.spawn(async move {
            loop {
                tokio::time::sleep(POLL).await;
                let Some(state) = state.upgrade() else {
                    return;
                };
                poll(&state).await;
            }
        });
    }
}

async fn poll(state: &AppState) {
    let version = state.version();
    let now = now_secs();
    for (id, owned) in state.owned.all().await {
        let Some(provider) = version.providers.iter().find(|p| p.name == owned.provider) else {
            continue;
        };
        let base = match owned.item {
            Item::File => format!("/v1/files/{id}"),
            Item::Batch => format!("/v1/batches/{id}"),
            Item::MessageBatch => format!("/v1/messages/batches/{id}"),
            Item::FineTune => format!("/v1/fine_tuning/jobs/{id}"),
        };
        if !owned.cloud.is_null() {
            if owned.item == Item::Batch && !owned.settled {
                if let Ok(object) = cloud_batch_object(state, provider, &id, &owned).await {
                    settle(state, &version, &id, &object).await;
                }
            } else if owned.item == Item::File
                && owned.expires_at.is_some_and(|at| at <= now)
                && let Some(key) = owned.cloud["key"].as_str()
                && crate::cloud_batch::delete(state, provider, key)
                    .await
                    .is_ok()
            {
                forget(state, &owned.decision, &id, "retention").await;
            }
            continue;
        }
        if !owned.settled && owned.item != Item::File {
            if let Ok(answer) = fetch(
                state,
                provider,
                Method::GET,
                &base,
                HeaderMap::new(),
                Bytes::new(),
            )
            .await
                && answer.status().is_success()
                && let Ok(body) = collect(answer.into_body(), crate::MAX_BODY_BYTES).await
                && let Ok(object) = serde_json::from_slice::<Value>(&body)
            {
                settle(state, &version, &id, &object).await;
            }
            continue;
        }
        if owned.expires_at.is_some_and(|at| at <= now)
            && matches!(owned.item, Item::File | Item::MessageBatch)
            && let Ok(answer) = fetch(
                state,
                provider,
                Method::DELETE,
                &base,
                HeaderMap::new(),
                Bytes::new(),
            )
            .await
            && (answer.status().is_success() || answer.status() == StatusCode::NOT_FOUND)
        {
            let mut record = Map::new();
            record.insert("event".into(), "owned_deleted".into());
            record.insert("id".into(), owned.decision.as_str().into());
            record.insert("time".into(), audit::timestamp().into());
            record.insert("object_id".into(), id.as_str().into());
            record.insert("why".into(), "retention".into());
            write(state, record).await;
            state.owned.remove(&id).await;
        }
    }
}

/// Writes that Gantry no longer holds a file or batch, and forgets it.
async fn forget(state: &AppState, decision: &str, id: &str, why: &str) {
    let mut record = Map::new();
    record.insert("event".into(), "owned_deleted".into());
    record.insert("id".into(), decision.into());
    record.insert("time".into(), audit::timestamp().into());
    record.insert("object_id".into(), id.into());
    record.insert("why".into(), why.into());
    write(state, record).await;
    state.owned.remove(id).await;
}

/// A file Gantry keeps, as OpenAI's file object.
fn file_object(id: &str, owned: &Owned) -> Value {
    let cloud = &owned.cloud;
    json!({
        "id": id,
        "object": "file",
        "bytes": cloud["bytes"],
        "created_at": cloud["created_at"],
        "filename": cloud["filename"],
        "purpose": owned.purpose,
        "status": "processed",
        "expires_at": owned.expires_at,
    })
}

/// A batch Gantry runs at Bedrock or Vertex AI, as OpenAI's batch object, with the status last seen.
fn batch_object(id: &str, owned: &Owned, status: &str) -> Value {
    let cloud = &owned.cloud;
    json!({
        "id": id,
        "object": "batch",
        "endpoint": owned.purpose,
        "errors": null,
        "input_file_id": cloud["input"],
        "completion_window": "24h",
        "status": status,
        "output_file_id": cloud["output_file_id"],
        "error_file_id": cloud["error_file_id"],
        "created_at": cloud["created_at"],
        "request_counts": {
            "total": owned.lines,
            "completed": cloud["completed"].as_u64().unwrap_or_default(),
            "failed": cloud["failed"].as_u64().unwrap_or_default(),
        },
        "metadata": { "provider": owned.provider },
    })
}

/// Asks the provider how a batch's job stands, as OpenAI's batch object (without output files until it is settled).
async fn cloud_batch_object(
    state: &AppState,
    provider: &Upstream,
    id: &str,
    owned: &Owned,
) -> Result<Value, crate::cloud_batch::Failed> {
    let job = crate::cloud_batch::job(
        state,
        provider,
        owned.cloud["job"].as_str().unwrap_or_default(),
    )
    .await?;
    let status = crate::cloud_batch::status(provider.kind, &job);
    let mut object = batch_object(id, owned, status);
    // The job's own answer, for settling: Bedrock names its output after the job's ID.
    object["job"] = job;
    Ok(object)
}

/// The caller's own files or batches that Gantry keeps (every one for an admin), as OpenAI objects.
async fn kept_list(state: &AppState, person: &str, admin: bool, item: Item) -> Vec<Value> {
    state
        .owned
        .all()
        .await
        .into_iter()
        .filter(|(_, o)| o.item == item && !o.cloud.is_null() && (admin || o.owner() == person))
        .map(|(id, o)| match item {
            Item::Batch => {
                let status = o.cloud["status"]
                    .as_str()
                    .unwrap_or("validating")
                    .to_string();
                batch_object(&id, &o, &status)
            }
            _ => file_object(&id, &o),
        })
        .collect()
}

/// Reads a Bedrock or Vertex AI batch's results, writes them as OpenAI output and error files in the bucket, and
/// records those files as the batch owner's.
async fn cloud_results(
    state: &AppState,
    provider: &Upstream,
    owned: &Owned,
    id: &str,
    object: &Value,
) -> Result<Vec<Outcome>, String> {
    let cloud = &owned.cloud;
    let ids = cloud["ids"].as_object().cloned().unwrap_or_default();
    let model = owned.models.first().map_or("", String::as_str);
    let lines = crate::cloud_batch::results(
        state,
        provider,
        &object["job"],
        cloud["output_key"].as_str().unwrap_or_default(),
        cloud["input_name"].as_str().unwrap_or_default(),
        &ids,
        model,
    )
    .await
    .map_err(|f| f.detail)?;
    let (mut output, mut errors) = (String::new(), String::new());
    for line in &lines {
        let to = if line.ok { &mut output } else { &mut errors };
        to.push_str(&line.openai.to_string());
        to.push('\n');
    }
    let mut batch = owned.clone();
    for (field, name, text) in [
        ("output_file_id", "output", &output),
        ("error_file_id", "errors", &errors),
    ] {
        if text.is_empty() {
            continue;
        }
        let file_id = format!("file-{name}-{id}");
        let key = crate::cloud_batch::key(provider, &format!("results/{id}.{name}.jsonl"));
        crate::cloud_batch::put(state, provider, &key, Bytes::from(text.clone()))
            .await
            .map_err(|f| f.detail)?;
        let mut out = owned.clone();
        out.item = Item::File;
        out.purpose = "batch_output".into();
        out.reserved = Vec::new();
        out.settled = false;
        out.expires_at = owned
            .retention_days
            .map(|d| now_secs() + u64::from(d) * 86_400);
        out.cloud = json!({
            "key": key,
            "bytes": text.len(),
            "filename": format!("{id}.{name}.jsonl"),
            "created_at": now_secs(),
            "region": cloud["region"],
        });
        write(state, out.record(&file_id)).await;
        state.owned.put(&file_id, out).await;
        batch.cloud[field] = file_id.into();
    }
    batch.cloud["status"] = object["status"].clone();
    batch.cloud["completed"] = lines.iter().filter(|l| l.ok).count().into();
    batch.cloud["failed"] = lines.iter().filter(|l| !l.ok).count().into();
    batch.settled = true;
    state.owned.put(id, batch).await;
    Ok(lines
        .into_iter()
        .map(|l| (l.custom_id, l.ok, l.usage))
        .collect())
}

/// Serves a request for a file or batch Gantry keeps for a Bedrock or Vertex AI provider, once its decision is
/// recorded.
async fn run_cloud(
    state: &AppState,
    version: &Snapshot,
    decision: &str,
    ready: Ready,
) -> Result<Response, Refusal> {
    let Then::Cloud(op) = ready.then else {
        return Err(unknown_batch_route());
    };
    let reply = |status: StatusCode, value: Value| {
        let mut response = (status, value.to_string()).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        response
    };
    let found = |id: &str| {
        let id = id.to_string();
        async move {
            state
                .owned
                .get(&id)
                .await
                .ok_or_else(|| not_yours("object", &id))
        }
    };
    if let Cloud::List(item) = op {
        let data = kept_list(state, &ready.person, ready.admin, item).await;
        return Ok(reply(
            StatusCode::OK,
            json!({ "object": "list", "data": data, "has_more": false }),
        ));
    }
    let provider = version
        .providers
        .get(ready.provider)
        .ok_or_else(unknown_batch_route)?;
    let cancel = matches!(op, Cloud::Cancel(_));
    match op {
        Cloud::Upload(owned) => {
            let mut owned = *owned;
            let id = owned.cloud["id"].as_str().unwrap_or_default().to_string();
            let key = owned.cloud["key"].as_str().unwrap_or_default().to_string();
            crate::cloud_batch::put(state, provider, &key, ready.body)
                .await
                .map_err(|f| f.refusal(provider, "keep the batch file in its bucket"))?;
            if let Some(map) = owned.cloud.as_object_mut() {
                map.remove("id");
            }
            if !write(state, owned.record(&id)).await {
                eprintln!(
                    "gantry: decision {decision}: the owner of {id} could not be written to the audit log"
                );
            }
            let object = file_object(&id, &owned);
            state.owned.put(&id, owned).await;
            Ok(reply(StatusCode::OK, object))
        }
        Cloud::Create {
            batch,
            file,
            file_id,
        } => {
            let mut batch = *batch;
            let id = format!("batch_gantry_{}", decision.to_ascii_lowercase());
            let model = file.cloud["model"].as_str().unwrap_or_default();
            let output_key = crate::cloud_batch::key(provider, &format!("output/{id}/"));
            let input_key = file.cloud["key"].as_str().unwrap_or_default();
            let job = match crate::cloud_batch::create_job(
                state,
                provider,
                &format!("gantry-{}", decision.to_ascii_lowercase()),
                model,
                input_key,
                &output_key,
            )
            .await
            {
                Ok(job) => job,
                Err(failed) => {
                    release(state, &ready.reserved);
                    return Err(failed.refusal(provider, "start the batch job"));
                }
            };
            batch.cloud = json!({
                "job": job,
                "input": file_id,
                "input_name": file.cloud["name"],
                "output_key": output_key,
                "created_at": now_secs(),
                "region": file.cloud["region"],
                "model": model,
                "ids": file.cloud["ids"],
                "status": "validating",
            });
            if !write(state, batch.record(&id)).await {
                eprintln!(
                    "gantry: decision {decision}: the owner of {id} could not be written to the audit log"
                );
            }
            let object = batch_object(&id, &batch, "validating");
            state.owned.put(&id, batch).await;
            Ok(reply(StatusCode::OK, object))
        }
        Cloud::Batch(id) | Cloud::Cancel(id) => {
            let owned = found(&id).await?;
            if cancel {
                crate::cloud_batch::cancel(
                    state,
                    provider,
                    owned.cloud["job"].as_str().unwrap_or_default(),
                )
                .await
                .map_err(|f| f.refusal(provider, "cancel the batch job"))?;
            }
            let mut object = cloud_batch_object(state, provider, &id, &owned)
                .await
                .map_err(|f| f.refusal(provider, "describe the batch job"))?;
            if !owned.settled {
                let mut seen = owned.clone();
                seen.cloud["status"] = object["status"].clone();
                state.owned.put(&id, seen).await;
            }
            settle(state, version, &id, &object).await;
            if let Some(owned) = state.owned.get(&id).await {
                let status = object["status"].as_str().unwrap_or_default().to_string();
                object = batch_object(&id, &owned, &status);
            }
            if let Some(map) = object.as_object_mut() {
                map.remove("job");
            }
            Ok(reply(StatusCode::OK, object))
        }
        Cloud::File(id) => {
            let owned = found(&id).await?;
            Ok(reply(StatusCode::OK, file_object(&id, &owned)))
        }
        Cloud::Content(id, guard) => {
            let owned = found(&id).await?;
            let bytes = crate::cloud_batch::get(
                state,
                provider,
                owned.cloud["key"].as_str().unwrap_or_default(),
            )
            .await
            .map_err(|f| f.refusal(provider, "read the file from its bucket"))?;
            let bytes = match guard {
                Some(check) => guard_results(state, &check, decision, &bytes).await?,
                None => bytes,
            };
            let mut response = (StatusCode::OK, bytes).into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            Ok(response)
        }
        Cloud::Delete(id) => {
            let owned = found(&id).await?;
            crate::cloud_batch::delete(
                state,
                provider,
                owned.cloud["key"].as_str().unwrap_or_default(),
            )
            .await
            .map_err(|f| f.refusal(provider, "delete the file from its bucket"))?;
            forget(
                state,
                decision,
                &id,
                &format!("deleted by {}", ready.person),
            )
            .await;
            Ok(reply(
                StatusCode::OK,
                json!({ "id": id, "object": "file", "deleted": true }),
            ))
        }
        Cloud::List(_) => Err(unknown_batch_route()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_form_gets_its_file_replaced_and_fields_added_before_the_close() -> Result<(), String> {
        let form = b"--b\r\nContent-Disposition: form-data; name=\"purpose\"\r\n\r\nbatch\r\n--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f\"\r\n\r\nOLD\r\n--b--\r\n";
        let parts = crate::alias::form_parts("multipart/form-data; boundary=b", form)
            .map_err(String::from)?;
        let file = parts
            .iter()
            .find(|p| p.file)
            .ok_or("no file")?
            .value
            .clone();
        let out = rewrite_form(
            form,
            "b",
            file,
            Some(b"NEW"),
            &[("expires_after[seconds]", "60".into())],
        );
        let out = String::from_utf8(out).map_err(|e| e.to_string())?;
        assert!(out.contains("\r\n\r\nNEW\r\n--b\r\nContent-Disposition: form-data; name=\"expires_after[seconds]\"\r\n\r\n60\r\n--b--\r\n"), "{out}");
        let again = crate::alias::form_parts("multipart/form-data; boundary=b", out.as_bytes())
            .map_err(String::from)?;
        assert_eq!(again.len(), 3, "the result still parses strictly");
        Ok(())
    }

    #[test]
    fn ownership_survives_a_record_round_trip() -> Result<(), String> {
        let person = Principal {
            name: "dana".into(),
            team: "data".into(),
            admin: false,
            key: "gk_1".into(),
            org: "acme".into(),
            ..Principal::default()
        };
        let mut owned = Owned::new(Item::Batch, "mock", &person, &Seen::default(), "d1");
        owned.models = vec!["m".into()];
        owned.reserved =
            vec![json!({"scope":"team:data","per":"month","period":"2026-11","usd":0.5})];
        let record = Value::Object(owned.record("batch_1"));
        let (id, back) = Owned::from_record(&record).ok_or("not read back")?;
        assert_eq!(id, "batch_1");
        assert_eq!(back.item, Item::Batch);
        assert_eq!(back.person, "dana");
        assert_eq!(back.reserved.len(), 1);
        assert!(spend::Reservation::from_json(&back.reserved[0]).is_some());
        Ok(())
    }
}
