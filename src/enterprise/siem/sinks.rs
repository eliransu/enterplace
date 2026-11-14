//! Where audit batches go, and how each destination is called. Every batch is one replica's records in chain order,
//! and says which part of the chain it holds: the replica, the first and last record's number and hash, and the hash
//! the first one follows (`prev`). A SIEM checks a batch against the chain by checking that each batch's `prev` is
//! the last batch's `last_hash`, and each record's `prev` the hash of the one before.
//!
//! Object storage (S3 and S3-compatible stores, Google Cloud Storage, Azure Blob Storage) gets one object per batch,
//! named by its range and hashes, so an archive is checked offline with nothing but the objects. Cloud credentials
//! come from the platform when none are given: the AWS default chain (environment, web identity, container, EC2
//! instance role), the Google metadata server (workload identity, an attached service account) and Azure managed
//! identity or workload identity. Endpoints of those services are moved with each SDK's own environment variables
//! (`AWS_EC2_METADATA_SERVICE_ENDPOINT`, `AWS_CONTAINER_CREDENTIALS_FULL_URI`, `AWS_ENDPOINT_URL_STS`,
//! `GCE_METADATA_HOST`, `IDENTITY_ENDPOINT`, `AZURE_AUTHORITY_HOST`).

use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use gantry_core::{id::sha256_hex, sigv4};
use serde_json::{Value, json};

/// Reads an environment variable. The process environment in the binary, a map in tests.
pub type Env = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Webhook,
    SplunkHec,
    Datadog,
    Elastic,
    Otlp,
    Sentinel,
    S3,
    Gcs,
    AzureBlob,
}

pub const KINDS: [Kind; 9] = [
    Kind::Webhook,
    Kind::SplunkHec,
    Kind::Datadog,
    Kind::Elastic,
    Kind::Otlp,
    Kind::Sentinel,
    Kind::S3,
    Kind::Gcs,
    Kind::AzureBlob,
];

impl Kind {
    pub fn word(self) -> &'static str {
        match self {
            Self::Webhook => "webhook",
            Self::SplunkHec => "splunk_hec",
            Self::Datadog => "datadog",
            Self::Elastic => "elastic",
            Self::Otlp => "otlp",
            Self::Sentinel => "sentinel",
            Self::S3 => "s3",
            Self::Gcs => "gcs",
            Self::AzureBlob => "azure_blob",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Webhook => "Webhook (signed HTTPS POST)",
            Self::SplunkHec => "Splunk HTTP Event Collector",
            Self::Datadog => "Datadog logs",
            Self::Elastic => "Elasticsearch bulk API",
            Self::Otlp => "OpenTelemetry logs (OTLP/HTTP JSON)",
            Self::Sentinel => "Microsoft Sentinel (Logs Ingestion API)",
            Self::S3 => "Amazon S3 or S3-compatible storage",
            Self::Gcs => "Google Cloud Storage",
            Self::AzureBlob => "Azure Blob Storage",
        }
    }

    pub fn parse(word: &str) -> Option<Self> {
        KINDS.into_iter().find(|k| k.word() == word)
    }

    /// Whether a destination of this kind cannot work without a secret.
    pub fn needs_secret(self) -> bool {
        matches!(
            self,
            Self::Webhook | Self::SplunkHec | Self::Datadog | Self::Elastic
        )
    }
}

/// A destination as the sender uses it: the secret in clear, the options as saved.
#[derive(Clone, Debug)]
pub struct Dest {
    pub id: i64,
    pub kind: Kind,
    pub url: String,
    pub secret: String,
    pub options: Value,
}

impl Dest {
    fn option(&self, name: &str) -> &str {
        self.options[name].as_str().unwrap_or_default().trim()
    }
}

/// One replica's records in chain order: each line exactly as the audit log holds it (with `n`, `prev` and `hash`),
/// so a receiver can hash it again, and the same records parsed.
#[derive(Clone, Debug)]
pub struct Batch {
    pub replica: String,
    pub lines: Vec<String>,
    pub records: Vec<Value>,
}

impl Batch {
    pub fn new(replica: String, lines: Vec<String>) -> Self {
        let records = lines
            .iter()
            .map(|l| serde_json::from_str(l).unwrap_or(Value::Null))
            .collect();
        Self {
            replica,
            lines,
            records,
        }
    }

    fn field(&self, last: bool, name: &str) -> Value {
        let record = if last {
            self.records.last()
        } else {
            self.records.first()
        };
        record.map_or(Value::Null, |r| r[name].clone())
    }

    /// The part of the chain this batch holds.
    pub fn range(&self) -> Value {
        json!({
            "replica": self.replica,
            "count": self.records.len(),
            "first_n": self.field(false, "n"),
            "last_n": self.field(true, "n"),
            "prev": self.field(false, "prev"),
            "first_hash": self.field(false, "hash"),
            "last_hash": self.field(true, "hash"),
        })
    }

    fn text(&self, last: bool, name: &str) -> String {
        match self.field(last, name) {
            Value::String(s) => s,
            Value::Null => String::new(),
            other => other.to_string(),
        }
    }

    /// The object name for storage: `<replica>/<first n>-<last n>-<first hash>-<last hash>.ndjson`, numbers padded so
    /// a listing is in chain order.
    pub fn object_name(&self) -> String {
        let number = |last| self.field(last, "n").as_u64().unwrap_or_default();
        format!(
            "{}/{:020}-{:020}-{}-{}.ndjson",
            self.replica,
            number(false),
            number(true),
            self.text(false, "hash"),
            self.text(true, "hash")
        )
    }

    pub fn ndjson(&self) -> String {
        self.lines.iter().map(|l| format!("{l}\n")).collect()
    }
}

/// An HTTP request a destination is sent, built apart from sending so each format is tested as it goes out.
#[derive(Debug)]
pub struct Out {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Out {
    fn post(url: String, content_type: &str, body: Vec<u8>) -> Self {
        Self {
            method: "POST",
            url,
            headers: vec![("content-type".into(), content_type.into())],
            body,
        }
    }

    fn header(mut self, name: &str, value: String) -> Self {
        self.headers.push((name.into(), value));
        self
    }
}

/// HMAC-SHA256 of `body` under `secret`, as hex: the webhook's `x-gantry-signature: sha256=<hex>`.
pub fn signature(secret: &str, body: &[u8]) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    gantry_core::id::hex(ring::hmac::sign(&key, body).as_ref())
}

/// Seconds since 1970 of a record's time, now when it has none that reads.
fn epoch_nanos(record: &Value) -> u128 {
    record["time"]
        .as_str()
        .and_then(parse_time)
        .unwrap_or_else(SystemTime::now)
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos())
}

/// `2026-11-13T09:14:02.120Z` as the audit log writes it.
pub fn parse_time(text: &str) -> Option<SystemTime> {
    let b = text.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[10] != b'T' {
        return None;
    }
    let num = |from: usize, to: usize| text.get(from..to)?.parse::<i64>().ok();
    let (y, m, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hh, mm, ss) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    let millis = if b.get(19) == Some(&b'.') {
        num(20, 23).unwrap_or(0)
    } else {
        0
    };
    // Days from civil, Howard Hinnant's algorithm, the inverse of the one the audit log writes times with.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + hh * 3600 + mm * 60 + ss;
    let secs = u64::try_from(secs).ok()?;
    Some(
        UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_millis(u64::try_from(millis).ok()?),
    )
}

/// The request each push destination takes. Object stores and Sentinel need a token first: see [`Sinks::deliver`].
pub fn request(dest: &Dest, batch: &Batch) -> Out {
    let range = batch.range();
    let (first, last) = (batch.text(false, "hash"), batch.text(true, "hash"));
    match dest.kind {
        Kind::Webhook => {
            // The records go in as the log wrote them, byte for byte, so each one's hash can be computed again.
            let head = range.to_string();
            let body = format!(
                "{},\"records\":[{}]}}",
                &head[..head.len() - 1],
                batch.lines.join(",")
            )
            .into_bytes();
            let signed = format!("sha256={}", signature(&dest.secret, &body));
            Out::post(dest.url.clone(), "application/json", body)
                .header("x-gantry-signature", signed)
                .header("x-gantry-first-hash", first)
                .header("x-gantry-last-hash", last)
        }
        Kind::SplunkHec => {
            // HEC takes event objects one after another in one POST.
            let body: String = batch
                .records
                .iter()
                .zip(&batch.lines)
                .map(|(r, line)| {
                    let head = json!({
                        "time": epoch_nanos(r) as f64 / 1e9,
                        "host": batch.replica,
                        "source": "gantry",
                        "sourcetype": "gantry:audit",
                        "fields": {
                            "replica": batch.replica,
                            "batch_first_hash": first,
                            "batch_last_hash": last,
                        },
                    })
                    .to_string();
                    format!("{},\"event\":{line}}}\n", &head[..head.len() - 1])
                })
                .collect();
            Out::post(dest.url.clone(), "application/json", body.into_bytes())
                .header("authorization", format!("Splunk {}", dest.secret))
        }
        Kind::Datadog => {
            let tags = format!(
                "replica:{},batch_first_hash:{first},batch_last_hash:{last}",
                batch.replica
            );
            let body: Vec<Value> = batch
                .lines
                .iter()
                .map(|line| {
                    json!({
                        "ddsource": "gantry",
                        "service": "gantry",
                        "hostname": batch.replica,
                        "ddtags": tags,
                        "message": line,
                    })
                })
                .collect();
            Out::post(
                dest.url.clone(),
                "application/json",
                Value::from(body).to_string().into_bytes(),
            )
            .header("dd-api-key", dest.secret.clone())
        }
        Kind::Elastic => {
            // `create` with the record's own ID: a batch sent twice (delivery is at least once) is stored once.
            let mut body = String::new();
            for r in &batch.records {
                let id = format!("{}-{}", batch.replica, r["n"]);
                body += &json!({ "create": { "_id": id } }).to_string();
                body.push('\n');
                let mut doc = r.clone();
                doc["@timestamp"] = r["time"].clone();
                doc["replica"] = Value::from(batch.replica.clone());
                doc["batch_first_hash"] = Value::from(first.clone());
                doc["batch_last_hash"] = Value::from(last.clone());
                body += &doc.to_string();
                body.push('\n');
            }
            Out::post(
                format!("{}/_bulk", dest.url.trim_end_matches('/')),
                "application/x-ndjson",
                body.into_bytes(),
            )
            .header("authorization", format!("ApiKey {}", dest.secret))
        }
        Kind::Otlp => {
            let attr = |key: &str, value: Value| {
                let value = match value {
                    Value::Number(n) => json!({ "intValue": n.to_string() }),
                    other => json!({ "stringValue": other.as_str().unwrap_or_default() }),
                };
                json!({ "key": key, "value": value })
            };
            let logs: Vec<Value> = batch
                .records
                .iter()
                .zip(&batch.lines)
                .map(|(r, line)| {
                    json!({
                        "timeUnixNano": epoch_nanos(r).to_string(),
                        "severityNumber": 9,
                        "severityText": "INFO",
                        "body": { "stringValue": line },
                        "attributes": [
                            attr("gantry.n", r["n"].clone()),
                            attr("gantry.hash", r["hash"].clone()),
                            attr("gantry.prev", r["prev"].clone()),
                            attr("gantry.event", r.get("event").cloned().unwrap_or(Value::from("request"))),
                        ],
                    })
                })
                .collect();
            let body = json!({ "resourceLogs": [{
                "resource": { "attributes": [
                    attr("service.name", Value::from("gantry")),
                    attr("gantry.replica", Value::from(batch.replica.clone())),
                    attr("gantry.batch.first_hash", Value::from(first)),
                    attr("gantry.batch.last_hash", Value::from(last)),
                    attr("gantry.batch.prev", range["prev"].clone()),
                ]},
                "scopeLogs": [{ "scope": { "name": "gantry.audit" }, "logRecords": logs }],
            }]});
            let out = Out::post(
                dest.url.clone(),
                "application/json",
                body.to_string().into_bytes(),
            );
            match (dest.option("header"), dest.secret.as_str()) {
                (_, "") => out,
                ("", secret) => out.header("authorization", format!("Bearer {secret}")),
                (name, secret) => out.header(&name.to_ascii_lowercase(), secret.to_string()),
            }
        }
        Kind::Sentinel => {
            // Columns of the data collection rule's stream: see the docs page for the table to create.
            let rows: Vec<Value> = batch
                .records
                .iter()
                .map(|r| {
                    json!({
                        "TimeGenerated": r["time"],
                        "Replica": batch.replica,
                        "N": r["n"],
                        "Hash": r["hash"],
                        "Prev": r["prev"],
                        "Event": r.get("event").cloned().unwrap_or(Value::from("request")),
                        "BatchFirstHash": first,
                        "BatchLastHash": last,
                        "Record": r,
                    })
                })
                .collect();
            Out::post(
                dest.url.clone(),
                "application/json",
                Value::from(rows).to_string().into_bytes(),
            )
        }
        Kind::S3 | Kind::Gcs | Kind::AzureBlob => {
            let body = batch.ndjson().into_bytes();
            let (url, method) = match dest.kind {
                Kind::Gcs => (gcs_upload_url(&dest.url, &batch.object_name()), "POST"),
                _ => (
                    format!("{}/{}", dest.url.trim_end_matches('/'), batch.object_name()),
                    "PUT",
                ),
            };
            Out {
                method,
                url,
                headers: vec![("content-type".into(), "application/x-ndjson".into())],
                body,
            }
        }
    }
}

/// `https://storage.googleapis.com/<bucket>/<prefix>` to the JSON API's media upload for `name` under the prefix.
fn gcs_upload_url(url: &str, name: &str) -> String {
    let (origin, rest) = split_url(url);
    let rest = rest.trim_matches('/');
    let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
    let object = if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{}/{name}", prefix.trim_matches('/'))
    };
    format!(
        "{origin}/upload/storage/v1/b/{bucket}/o?uploadType=media&name={}",
        sigv4::uri_encode(&object, false)
    )
}

/// `https://host:port/path?query` as (`https://host:port`, `/path?query`).
fn split_url(url: &str) -> (&str, &str) {
    let after = url.find("://").map_or(0, |i| i + 3);
    match url[after..].find('/') {
        Some(i) => url.split_at(after + i),
        None => (url, ""),
    }
}

/// Whether a destination URL may be used: https, or plain http to this machine only (a local collector, tests).
pub fn url_ok(url: &str) -> bool {
    let host_of = |rest: &str| {
        let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
        if let Some(v6) = host.strip_prefix('[') {
            v6.split(']').next().unwrap_or_default().to_string()
        } else {
            host.split(':').next().unwrap_or_default().to_string()
        }
    };
    if let Some(rest) = url.strip_prefix("https://") {
        return !host_of(rest).is_empty() && !url.contains(char::is_whitespace);
    }
    url.strip_prefix("http://")
        .is_some_and(|rest| matches!(host_of(rest).as_str(), "127.0.0.1" | "localhost" | "::1"))
}

/// Calls destinations and keeps the cloud tokens they need until shortly before they expire.
pub struct Sinks {
    env: Env,
    agent: ureq::Agent,
    // ponytail: a token is kept a fixed 10 minutes at most, shorter than any of these clouds issues; read each
    // token's expiry when one is issued for less.
    tokens: Mutex<HashMap<String, (Token, Instant)>>,
}

#[derive(Clone)]
enum Token {
    Bearer(String),
    Aws(sigv4::Credentials),
}

const TOKEN_FOR: Duration = Duration::from_secs(600);

impl Sinks {
    pub fn new(env: Env) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(10))
            // A redirect could lead past the https rule; the destination's final URL is what to save.
            .redirects(0)
            .build();
        Self {
            env,
            agent,
            tokens: Mutex::new(HashMap::new()),
        }
    }

    fn env(&self, name: &str) -> Option<String> {
        (self.env)(name).filter(|v| !v.trim().is_empty())
    }

    /// Sends `batch`. Blocking: run it off the async threads. The error names what failed and how to fix it.
    pub fn deliver(&self, dest: &Dest, batch: &Batch) -> Result<(), String> {
        let mut out = request(dest, batch);
        match dest.kind {
            Kind::S3 => self.sign_s3(dest, &mut out)?,
            Kind::Gcs => {
                let token = self.gcs_token(dest)?;
                out.headers
                    .push(("authorization".into(), format!("Bearer {token}")));
            }
            Kind::AzureBlob => {
                out.headers
                    .push(("x-ms-blob-type".into(), "BlockBlob".into()));
                out.headers
                    .push(("x-ms-version".into(), "2021-08-06".into()));
                if dest.secret.is_empty() {
                    let token = self.azure_token(dest, "https://storage.azure.com/")?;
                    out.headers
                        .push(("authorization".into(), format!("Bearer {token}")));
                } else {
                    // A SAS token: the query string the portal gives, with or without its `?`.
                    out.url = format!("{}?{}", out.url, dest.secret.trim_start_matches('?'));
                }
            }
            Kind::Sentinel => {
                let token = self.azure_token(dest, "https://monitor.azure.com")?;
                out.headers
                    .push(("authorization".into(), format!("Bearer {token}")));
            }
            _ => {}
        }
        let (status, body) = self.call(&out)?;
        if !(200..300).contains(&status) {
            return Err(match status {
                300..=399 => {
                    format!("HTTP {status}: the destination redirects. Save its final URL.")
                }
                401 | 403 => format!(
                    "HTTP {status}: the destination refused the credentials. Check the token or the identity's permissions."
                ),
                _ => format!("HTTP {status} from the destination."),
            });
        }
        if dest.kind == Kind::Elastic {
            // The bulk API answers 200 with per-document errors. A conflict is a document already stored.
            let answer: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
            if answer["errors"] == true {
                let failed = answer["items"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|i| i["create"]["status"].as_u64())
                    .find(|s| !(200..300).contains(s) && *s != 409);
                if let Some(status) = failed {
                    return Err(format!(
                        "Elasticsearch stored part of the batch and refused a record with status {status}. Check the index mapping and the API key's rights."
                    ));
                }
            }
        }
        Ok(())
    }

    /// Sends a request and returns the status and up to 64 KiB of the answer. Errors are transport errors only.
    fn call(&self, out: &Out) -> Result<(u16, String), String> {
        let mut request = self.agent.request(out.method, &out.url);
        for (name, value) in &out.headers {
            request = request.set(name, value);
        }
        let response = match request.send_bytes(&out.body) {
            Ok(response) => response,
            Err(ureq::Error::Status(_, response)) => response,
            Err(ureq::Error::Transport(err)) => {
                return Err(format!(
                    "{} could not be reached: {err}. Check the URL and that this replica can reach it.",
                    host(&out.url)
                ));
            }
        };
        let status = response.status();
        let mut body = String::new();
        let _ = response
            .into_reader()
            .take(64 * 1024)
            .read_to_string(&mut body);
        Ok((status, body))
    }

    fn cached(&self, key: &str) -> Option<Token> {
        let tokens = self
            .tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tokens
            .get(key)
            .filter(|(_, until)| Instant::now() < *until)
            .map(|(t, _)| t.clone())
    }

    fn keep(&self, key: &str, token: Token, expires_in: Option<u64>) {
        let life = expires_in
            .map(|s| Duration::from_secs(s.saturating_sub(60)))
            .map_or(TOKEN_FOR, |d| d.min(TOKEN_FOR));
        self.tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key.into(), (token, Instant::now() + life));
    }

    /// A GET or POST whose 2xx answer is JSON, for the credential services.
    fn json(&self, out: &Out, what: &str) -> Result<Value, String> {
        let (status, body) = self.call(out)?;
        if !(200..300).contains(&status) {
            return Err(format!(
                "{what} answered HTTP {status} at {}. Check the identity this replica runs as.",
                host(&out.url)
            ));
        }
        serde_json::from_str(&body).map_err(|_| format!("{what} did not answer with JSON."))
    }

    // ------------------------------------------------------------------ AWS

    fn sign_s3(&self, dest: &Dest, out: &mut Out) -> Result<(), String> {
        let region = match dest.option("region") {
            "" => "us-east-1",
            region => region,
        };
        let credentials = self.aws_credentials(dest, region)?;
        let (origin, path) = split_url(&out.url);
        let host = origin.split("://").nth(1).unwrap_or_default().to_string();
        let payload = sha256_hex(&out.body);
        let signed = sigv4::sign(
            &credentials,
            region,
            "s3",
            &sigv4::Request {
                method: out.method,
                path,
                query: "",
                headers: &[
                    ("host", &host),
                    ("content-type", "application/x-ndjson"),
                    ("x-amz-content-sha256", &payload),
                ],
                payload: &out.body,
            },
            &sigv4::amz_date_now(),
        );
        out.headers.push(("x-amz-content-sha256".into(), payload));
        out.headers
            .extend(signed.into_iter().map(|(k, v)| (k.to_string(), v)));
        Ok(())
    }

    /// The access key in the destination, else the AWS default chain: environment, web identity, container,
    /// EC2 instance role.
    fn aws_credentials(&self, dest: &Dest, region: &str) -> Result<sigv4::Credentials, String> {
        if !dest.option("access_key_id").is_empty() {
            return Ok(sigv4::Credentials {
                access_key_id: dest.option("access_key_id").to_string(),
                secret_access_key: dest.secret.clone(),
                session_token: None,
            });
        }
        if let (Some(id), Some(secret)) = (
            self.env("AWS_ACCESS_KEY_ID"),
            self.env("AWS_SECRET_ACCESS_KEY"),
        ) {
            return Ok(sigv4::Credentials {
                access_key_id: id,
                secret_access_key: secret,
                session_token: self.env("AWS_SESSION_TOKEN"),
            });
        }
        if let Some(Token::Aws(credentials)) = self.cached("aws") {
            return Ok(credentials);
        }
        let from = |v: &Value, token: &str| -> Option<sigv4::Credentials> {
            Some(sigv4::Credentials {
                access_key_id: v["AccessKeyId"].as_str()?.to_string(),
                secret_access_key: v["SecretAccessKey"].as_str()?.to_string(),
                session_token: v[token].as_str().map(str::to_string),
            })
        };
        let unreadable =
            || "the AWS credentials answer has no AccessKeyId and SecretAccessKey.".to_string();
        let credentials = if let (Some(file), Some(role)) = (
            self.env("AWS_WEB_IDENTITY_TOKEN_FILE"),
            self.env("AWS_ROLE_ARN"),
        ) {
            let token = std::fs::read_to_string(&file).map_err(|err| {
                format!("AWS_WEB_IDENTITY_TOKEN_FILE ({file}) cannot be read: {err}.")
            })?;
            let sts = self.env("AWS_ENDPOINT_URL_STS").unwrap_or_else(|| {
                format!(
                    "https://sts.{}.amazonaws.com",
                    self.env("AWS_REGION").unwrap_or_else(|| region.to_string())
                )
            });
            let query = [
                ("Action", "AssumeRoleWithWebIdentity"),
                ("RoleArn", role.as_str()),
                ("RoleSessionName", "gantry-audit-export"),
                ("Version", "2011-06-15"),
                ("WebIdentityToken", token.trim()),
            ]
            .iter()
            .map(|(k, v)| format!("{k}={}", sigv4::uri_encode(v, false)))
            .collect::<Vec<_>>()
            .join("&");
            let out = Out {
                method: "GET",
                url: format!("{}/?{query}", sts.trim_end_matches('/')),
                headers: vec![("accept".into(), "application/json".into())],
                body: Vec::new(),
            };
            let answer = self.json(&out, "AWS STS")?;
            from(
                &answer["AssumeRoleWithWebIdentityResponse"]["AssumeRoleWithWebIdentityResult"]
                    ["Credentials"],
                "SessionToken",
            )
            .ok_or_else(unreadable)?
        } else if let Some(url) = self.env("AWS_CONTAINER_CREDENTIALS_FULL_URI").or_else(|| {
            self.env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
                .map(|p| format!("http://169.254.170.2{p}"))
        }) {
            let mut out = Out {
                method: "GET",
                url,
                headers: Vec::new(),
                body: Vec::new(),
            };
            let token = match self.env("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE") {
                Some(file) => std::fs::read_to_string(file).ok(),
                None => self.env("AWS_CONTAINER_AUTHORIZATION_TOKEN"),
            };
            if let Some(token) = token {
                out.headers
                    .push(("authorization".into(), token.trim().to_string()));
            }
            from(
                &self.json(&out, "the container credentials endpoint")?,
                "Token",
            )
            .ok_or_else(unreadable)?
        } else if self.env("AWS_EC2_METADATA_DISABLED").as_deref() != Some("true") {
            let base = self
                .env("AWS_EC2_METADATA_SERVICE_ENDPOINT")
                .unwrap_or_else(|| "http://169.254.169.254".into());
            let base = base.trim_end_matches('/');
            let put = Out {
                method: "PUT",
                url: format!("{base}/latest/api/token"),
                headers: vec![(
                    "x-aws-ec2-metadata-token-ttl-seconds".into(),
                    "21600".into(),
                )],
                body: Vec::new(),
            };
            let none = || {
                "no AWS credentials: give an access key ID and secret on the destination, or run this replica with an IAM role (EC2 instance profile, ECS task role, EKS pod identity or IRSA) or AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.".to_string()
            };
            let (status, token) = self.call(&put).map_err(|_| none())?;
            if status != 200 {
                return Err(none());
            }
            let get = |path: &str| Out {
                method: "GET",
                url: format!("{base}/latest/meta-data/iam/security-credentials/{path}"),
                headers: vec![("x-aws-ec2-metadata-token".into(), token.trim().to_string())],
                body: Vec::new(),
            };
            let (status, role) = self.call(&get("")).map_err(|_| none())?;
            let role = role.lines().next().unwrap_or_default().trim().to_string();
            if status != 200 || role.is_empty() {
                return Err(none());
            }
            from(
                &self.json(&get(&role), "the EC2 instance metadata service")?,
                "Token",
            )
            .ok_or_else(unreadable)?
        } else {
            return Err("no AWS credentials: AWS_EC2_METADATA_DISABLED is true and no other source is set. Give an access key on the destination or run with an IAM role.".into());
        };
        self.keep("aws", Token::Aws(credentials.clone()), None);
        Ok(credentials)
    }

    // ------------------------------------------------------------------ Google

    /// A service account key in the destination's secret, else the metadata server (workload identity or the
    /// service account the replica runs as).
    fn gcs_token(&self, dest: &Dest) -> Result<String, String> {
        let key = format!("gcs:{}", sha256_hex(dest.secret.as_bytes()));
        if let Some(Token::Bearer(token)) = self.cached(&key) {
            return Ok(token);
        }
        let answer = if dest.secret.is_empty() {
            let host = self
                .env("GCE_METADATA_HOST")
                .unwrap_or_else(|| "metadata.google.internal".into());
            let out = Out {
                method: "GET",
                url: format!(
                    "http://{host}/computeMetadata/v1/instance/service-accounts/default/token"
                ),
                headers: vec![("metadata-flavor".into(), "Google".into())],
                body: Vec::new(),
            };
            self.json(&out, "the Google metadata server").map_err(|err| {
                format!("{err} Without a service account key on the destination, Gantry asks the metadata server (GKE workload identity, Cloud Run, Compute Engine).")
            })?
        } else {
            let account: Value = serde_json::from_str(&dest.secret).map_err(|_| {
                "the destination's secret is not a service account key. Paste the whole JSON key file, or leave it empty to use the identity this replica runs as.".to_string()
            })?;
            let assertion = service_account_jwt(&account)?;
            let token_uri = account["token_uri"]
                .as_str()
                .unwrap_or("https://oauth2.googleapis.com/token");
            let body = format!(
                "grant_type={}&assertion={assertion}",
                sigv4::uri_encode("urn:ietf:params:oauth:grant-type:jwt-bearer", false)
            );
            let out = Out::post(
                token_uri.to_string(),
                "application/x-www-form-urlencoded",
                body.into_bytes(),
            );
            self.json(&out, "Google's token endpoint")?
        };
        let token = answer["access_token"]
            .as_str()
            .ok_or("Google's answer has no access_token.")?
            .to_string();
        self.keep(
            &key,
            Token::Bearer(token.clone()),
            answer["expires_in"].as_u64(),
        );
        Ok(token)
    }

    // ------------------------------------------------------------------ Azure

    /// A token for `resource`: the destination's client secret (Sentinel), else workload identity
    /// (`AZURE_FEDERATED_TOKEN_FILE`), else managed identity (`IDENTITY_ENDPOINT`, or the instance metadata service).
    fn azure_token(&self, dest: &Dest, resource: &str) -> Result<String, String> {
        let client = match dest.option("client_id") {
            "" => self.env("AZURE_CLIENT_ID").unwrap_or_default(),
            id => id.to_string(),
        };
        let tenant = match dest.option("tenant") {
            "" => self.env("AZURE_TENANT_ID").unwrap_or_default(),
            t => t.to_string(),
        };
        let use_secret = dest.kind == Kind::Sentinel && !dest.secret.is_empty();
        let key = format!(
            "azure:{resource}:{client}:{}",
            sha256_hex(dest.secret.as_bytes())
        );
        if let Some(Token::Bearer(token)) = self.cached(&key) {
            return Ok(token);
        }
        let federated = self.env("AZURE_FEDERATED_TOKEN_FILE");
        let answer = if use_secret || federated.is_some() {
            if tenant.is_empty() || client.is_empty() {
                return Err("Microsoft Entra sign-in needs the tenant ID and the client ID on the destination (or AZURE_TENANT_ID and AZURE_CLIENT_ID).".into());
            }
            let authority = self
                .env("AZURE_AUTHORITY_HOST")
                .unwrap_or_else(|| "https://login.microsoftonline.com".into());
            let proof = if use_secret {
                format!("client_secret={}", sigv4::uri_encode(&dest.secret, false))
            } else {
                let file = federated.unwrap_or_default();
                let assertion = std::fs::read_to_string(&file).map_err(|err| {
                    format!("AZURE_FEDERATED_TOKEN_FILE ({file}) cannot be read: {err}.")
                })?;
                format!(
                    "client_assertion_type={}&client_assertion={}",
                    sigv4::uri_encode(
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                        false
                    ),
                    sigv4::uri_encode(assertion.trim(), false)
                )
            };
            let body = format!(
                "grant_type=client_credentials&client_id={}&scope={}&{proof}",
                sigv4::uri_encode(&client, false),
                sigv4::uri_encode(
                    &format!("{}/.default", resource.trim_end_matches('/')),
                    false
                )
            );
            let out = Out::post(
                format!(
                    "{}/{tenant}/oauth2/v2.0/token",
                    authority.trim_end_matches('/')
                ),
                "application/x-www-form-urlencoded",
                body.into_bytes(),
            );
            self.json(&out, "Microsoft Entra ID")?
        } else {
            let pick = if client.is_empty() {
                String::new()
            } else {
                format!("&client_id={}", sigv4::uri_encode(&client, false))
            };
            let out = match (self.env("IDENTITY_ENDPOINT"), self.env("IDENTITY_HEADER")) {
                (Some(endpoint), Some(secret)) => Out {
                    method: "GET",
                    url: format!(
                        "{endpoint}?api-version=2019-08-01&resource={}{pick}",
                        sigv4::uri_encode(resource, false)
                    ),
                    headers: vec![("x-identity-header".into(), secret)],
                    body: Vec::new(),
                },
                _ => Out {
                    method: "GET",
                    url: format!(
                        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource={}{pick}",
                        sigv4::uri_encode(resource, false)
                    ),
                    headers: vec![("metadata".into(), "true".into())],
                    body: Vec::new(),
                },
            };
            self.json(&out, "Azure managed identity").map_err(|err| {
                format!("{err} Without a secret on the destination, Gantry signs in as the replica's managed identity; give it the Storage Blob Data Contributor or Monitoring Metrics Publisher role.")
            })?
        };
        let token = answer["access_token"]
            .as_str()
            .ok_or("Azure's answer has no access_token.")?
            .to_string();
        // Managed identity gives expires_in as a string.
        let expires = answer["expires_in"]
            .as_u64()
            .or_else(|| answer["expires_in"].as_str().and_then(|s| s.parse().ok()));
        self.keep(&key, Token::Bearer(token.clone()), expires);
        Ok(token)
    }
}

fn host(url: &str) -> &str {
    let (origin, _) = split_url(url);
    origin.split("://").nth(1).unwrap_or(origin)
}

/// The signed JWT a Google service account trades for an access token (RS256 over its private key).
fn service_account_jwt(account: &Value) -> Result<String, String> {
    let (Some(email), Some(pem)) = (
        account["client_email"].as_str(),
        account["private_key"].as_str(),
    ) else {
        return Err("the service account key has no client_email or private_key.".into());
    };
    let der: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<String>();
    let der = base64::engine::general_purpose::STANDARD
        .decode(der.trim())
        .map_err(|_| "the service account's private_key is not PEM.".to_string())?;
    let key = ring::signature::RsaKeyPair::from_pkcs8(&der).map_err(|_| {
        "the service account's private_key is not an RSA key in PKCS #8.".to_string()
    })?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let b64 = |v: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
    let head = b64(json!({ "alg": "RS256", "typ": "JWT" })
        .to_string()
        .as_bytes());
    let claims = b64(json!({
        "iss": email,
        "scope": "https://www.googleapis.com/auth/devstorage.read_write",
        "aud": account["token_uri"].as_str().unwrap_or("https://oauth2.googleapis.com/token"),
        "iat": now,
        "exp": now + 3600,
    })
    .to_string()
    .as_bytes());
    let message = format!("{head}.{claims}");
    let mut signature = vec![0; key.public().modulus_len()];
    key.sign(
        &ring::signature::RSA_PKCS1_SHA256,
        &ring::rand::SystemRandom::new(),
        message.as_bytes(),
        &mut signature,
    )
    .map_err(|_| "the service account key could not sign.".to_string())?;
    Ok(format!("{message}.{}", b64(&signature)))
}
