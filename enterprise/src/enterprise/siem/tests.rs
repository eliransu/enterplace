//! The audit export and retention behaviour of the Cloudflare app (cloud/tests/test_siem.py and
//! test_siem_pull.py), against a real Postgres and local mock sinks, plus what the self-hosted port adds: every
//! destination's format and signature, cloud credentials without static keys, hash ranges, cursors that survive a
//! restart, retries, retention that `enterplace audit verify` still proves, and legal hold.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use enterplace_core::audit;
use serde_json::{Value, json};

use super::sinks::{Batch, Dest, Env, Kind, Sinks};
use super::*;
use crate::enterprise::testing::*;

/// The exporter each test gateway started, by its audit log's path.
pub(crate) fn registry() -> &'static Mutex<HashMap<PathBuf, Arc<Exporter>>> {
    static EXPORTERS: OnceLock<Mutex<HashMap<PathBuf, Arc<Exporter>>>> = OnceLock::new();
    EXPORTERS.get_or_init(|| Mutex::new(HashMap::new()))
}

const KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
/// A test-only RSA key, made for these tests, standing in for a Google service account's.
const TEST_RSA: &str = include_str!("test-service-account.pem");

/// A gateway whose exporter never runs on its own: the tests drive it.
pub(crate) fn quiet(
    test: &str,
    url: &str,
    features: &[&str],
) -> Result<(Gateway, Arc<Exporter>), Error> {
    quiet_policy(test, url, features, POLICY)
}

/// `quiet`, serving `policy`.
pub(crate) fn quiet_policy(
    test: &str,
    url: &str,
    features: &[&str],
    policy: &str,
) -> Result<(Gateway, Arc<Exporter>), Error> {
    let gw = gateway_policy(
        test,
        url,
        &licensed(features),
        &[
            (KEY_ENV, KEY),
            ("ENTERPLACE_EXPORT_TICK_MS", "3600000"),
            ("HOSTNAME", "pod-0"),
        ],
        policy,
    )?;
    let exporter = registry()
        .lock()
        .map_err(|_| "registry")?
        .get(&gw.audit)
        .cloned()
        .ok_or("no exporter registered")?;
    Ok((gw, exporter))
}

// ---------------------------------------------------------------- a mock of every receiving end

#[derive(Clone, Debug)]
pub(crate) struct Hit {
    pub method: String,
    pub uri: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl Hit {
    pub fn header(&self, name: &str) -> &str {
        self.headers.get(name).map_or("", String::as_str)
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

#[derive(Clone, Default)]
pub(crate) struct Sink {
    hits: Arc<Mutex<Vec<Hit>>>,
    /// The next this many deliveries (not credential calls) answer 503.
    fail: Arc<Mutex<usize>>,
    pub base: String,
}

impl Sink {
    pub async fn start() -> Result<Self, Error> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let sink = Self {
            base: format!("http://{}", listener.local_addr()?),
            ..Self::default()
        };
        let app = Router::new().fallback(answer).with_state(sink.clone());
        tokio::spawn(async move { axum::serve(listener, app).await });
        Ok(sink)
    }

    fn hits(&self) -> Vec<Hit> {
        self.hits.lock().map(|h| h.clone()).unwrap_or_default()
    }

    /// Deliveries only: no credential calls.
    pub fn deliveries(&self) -> Vec<Hit> {
        self.hits()
            .into_iter()
            .filter(|h| h.uri.starts_with("/in"))
            .collect()
    }

    pub fn fail_next(&self, n: usize) {
        if let Ok(mut f) = self.fail.lock() {
            *f = n;
        }
    }

    pub fn clear(&self) {
        if let Ok(mut h) = self.hits.lock() {
            h.clear();
        }
    }
}

const CREDS: &str = r#"{"AccessKeyId":"AKIDROLE","SecretAccessKey":"role-secret","Token":"role-token","Expiration":"2099-01-01T00:00:00Z"}"#;

async fn answer(
    State(sink): State<Sink>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let hit = Hit {
        method: method.to_string(),
        uri: uri.to_string(),
        headers: headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
            .collect(),
        body: body.to_vec(),
    };
    if let Ok(mut hits) = sink.hits.lock() {
        hits.push(hit.clone());
    }
    let path = uri.path();
    let json_answer =
        |v: Value| ([("content-type", "application/json")], v.to_string()).into_response();
    match path {
        "/latest/api/token" => "imds-token".into_response(),
        "/latest/meta-data/iam/security-credentials/" => "enterplace-role\n".into_response(),
        "/latest/meta-data/iam/security-credentials/enterplace-role" | "/container-creds" => {
            CREDS.into_response()
        }
        "/sts/" => json_answer(
            json!({ "AssumeRoleWithWebIdentityResponse": { "AssumeRoleWithWebIdentityResult": { "Credentials": {
            "AccessKeyId": "AKIDWEB", "SecretAccessKey": "web-secret", "SessionToken": "web-token" } } } }),
        ),
        "/computeMetadata/v1/instance/service-accounts/default/token" => {
            json_answer(json!({ "access_token": "gce-token", "expires_in": 3599 }))
        }
        "/google-token" => json_answer(json!({ "access_token": "sa-token", "expires_in": 3599 })),
        "/msi" => json_answer(json!({ "access_token": "msi-token", "expires_in": "3599" })),
        p if p.ends_with("/oauth2/v2.0/token") => {
            json_answer(json!({ "access_token": "entra-token", "expires_in": 3599 }))
        }
        _ => {
            let failing = sink.fail.lock().map(|mut f| {
                let now = *f > 0;
                *f = f.saturating_sub(1);
                now
            });
            if failing.unwrap_or(false) {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            if path.ends_with("/_bulk") {
                return json_answer(json!({ "errors": false, "items": [] }));
            }
            StatusCode::OK.into_response()
        }
    }
}

// ---------------------------------------------------------------- helpers

/// Request records written straight to the gateway's chain, as the gateway writes them. No prompt is ever in one;
/// the `prompt` field here is a canary that the audit writer would never have.
fn write_requests(gw: &Gateway, count: usize) -> Result<(), Error> {
    for i in 0..count {
        let mut record = audit::record(&audit::Entry {
            id: &format!("req-{i}"),
            person: Some("alice"),
            method: "POST",
            path: "/v1/chat/completions",
            model: Some("m"),
            allowed: true,
            ..Default::default()
        });
        record.insert("team".into(), "research".into());
        gw.log.append_record(&record)?;
    }
    Ok(())
}

/// Whether a line's hash is the SHA-256 of the line up to its `prev`, as `enterplace audit verify` checks.
fn hash_holds(line: &str) -> bool {
    let Some(at) = line.rfind(",\"hash\":\"") else {
        return false;
    };
    let hash = &line[at + 9..line.len() - 2];
    enterplace_core::id::sha256_hex(format!("{}}}", &line[..at]).as_bytes()) == hash
}

/// The chain's lines as the log holds them.
pub(crate) fn chain_lines(gw: &Gateway) -> Result<Vec<String>, Error> {
    use std::io::BufRead;
    gw.log.flush();
    Ok(audit::chain_reader(&gw.audit)?
        .lines()
        .collect::<Result<_, _>>()?)
}

fn env_of(pairs: &[(&str, String)]) -> Env {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect();
    Arc::new(move |name| map.get(name).cloned())
}

fn dest(kind: Kind, url: String, secret: &str, options: Value) -> Dest {
    Dest {
        id: 1,
        kind,
        url,
        secret: secret.into(),
        options,
    }
}

/// Two chained records, as the log writes them.
fn sample() -> Batch {
    let mut lines = Vec::new();
    let mut prev = "0".repeat(64);
    for n in 1..=2 {
        let body = format!(
            r#"{{"n":{n},"id":"r{n}","time":"2026-11-13T09:14:02.120Z","person":"alice","verdict":"allow","prev":"{prev}""#
        );
        let hash = enterplace_core::id::sha256_hex(format!("{body}}}").as_bytes());
        lines.push(format!(r#"{body},"hash":"{hash}"}}"#));
        prev = hash;
    }
    Batch::new("pod-0-abc".into(), lines)
}

fn sts_query(hit: &Hit, name: &str) -> String {
    hit.uri
        .split(['?', '&'])
        .find_map(|p| p.strip_prefix(&format!("{name}=")))
        .unwrap_or_default()
        .to_string()
}

/// The SigV4 authorization header S3 should have got for `hit`, from the same credentials.
fn s3_signature(hit: &Hit, sink: &Sink, id: &str, secret: &str, token: Option<&str>) -> String {
    let host = sink.base.trim_start_matches("http://").to_string();
    let signed = enterplace_core::sigv4::sign(
        &enterplace_core::sigv4::Credentials {
            access_key_id: id.into(),
            secret_access_key: secret.into(),
            session_token: token.map(str::to_string),
        },
        "eu-west-1",
        "s3",
        &enterplace_core::sigv4::Request {
            method: "PUT",
            path: &hit.uri,
            query: "",
            headers: &[
                ("host", &host),
                ("content-type", "application/x-ndjson"),
                ("x-amz-content-sha256", hit.header("x-amz-content-sha256")),
            ],
            payload: &hit.body,
        },
        hit.header("x-amz-date"),
    );
    signed
        .into_iter()
        .find(|(k, _)| *k == "authorization")
        .map(|(_, v)| v)
        .unwrap_or_default()
}

// ---------------------------------------------------------------- formats, without a database

#[tokio::test]
async fn every_destination_gets_its_documented_format_with_the_batch_hash_range()
-> Result<(), Error> {
    let sink = Sink::start().await?;
    let batch = sample();
    let (first, last) = (
        batch.records[0]["hash"].clone(),
        batch.records[1]["hash"].clone(),
    );
    let sinks = Arc::new(Sinks::new(env_of(&[])));
    let send = |d: Dest| {
        let (sinks, batch) = (sinks.clone(), batch.clone());
        async move {
            Ok::<(), Error>(tokio::task::spawn_blocking(move || sinks.deliver(&d, &batch)).await??)
        }
    };

    // Webhook: HMAC-SHA256 of the raw body, the range, and every line byte for byte, so each hash recomputes.
    send(dest(
        Kind::Webhook,
        format!("{}/in/hook", sink.base),
        "gsig_test",
        json!({}),
    ))
    .await?;
    let hit = sink.deliveries().pop().ok_or("no webhook")?;
    assert_eq!(
        hit.header("x-enterplace-signature"),
        format!("sha256={}", sinks::signature("gsig_test", &hit.body))
    );
    assert_ne!(
        hit.header("x-enterplace-signature"),
        format!("sha256={}", sinks::signature("gsig_wrong", &hit.body))
    );
    let body = hit.json();
    assert_eq!(
        (body["first_hash"].clone(), body["last_hash"].clone()),
        (first.clone(), last.clone())
    );
    assert_eq!(
        (
            body["first_n"].clone(),
            body["last_n"].clone(),
            body["replica"].clone()
        ),
        (json!(1), json!(2), json!("pod-0-abc"))
    );
    assert_eq!(body["prev"], json!("0".repeat(64)));
    for line in &batch.lines {
        assert!(
            hit.text().contains(line.as_str()),
            "the line is sent as written"
        );
        assert!(hash_holds(line));
    }

    // Splunk HEC: one event object per line, the token as `Splunk`, the range in indexed fields.
    send(dest(
        Kind::SplunkHec,
        format!("{}/in/services/collector/event", sink.base),
        "hec-token",
        json!({}),
    ))
    .await?;
    let hit = sink.deliveries().pop().ok_or("no splunk")?;
    assert_eq!(hit.header("authorization"), "Splunk hec-token");
    let events: Vec<Value> = hit
        .text()
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["sourcetype"], "enterplace:audit");
    assert_eq!(events[0]["event"]["hash"], first);
    assert_eq!(events[1]["fields"]["batch_last_hash"], last);
    assert!((events[0]["time"].as_f64().unwrap_or_default() - 1_794_561_242.12).abs() < 0.01);

    // Datadog: an array of logs, the API key header, each message the line itself.
    send(dest(
        Kind::Datadog,
        format!("{}/in/api/v2/logs", sink.base),
        "dd-key",
        json!({}),
    ))
    .await?;
    let hit = sink.deliveries().pop().ok_or("no datadog")?;
    assert_eq!(hit.header("dd-api-key"), "dd-key");
    let logs = hit.json();
    assert_eq!(logs[1]["message"], Value::from(batch.lines[1].clone()));
    assert!(
        logs[0]["ddtags"]
            .as_str()
            .unwrap_or_default()
            .contains(&format!(
                "batch_first_hash:{}",
                first.as_str().unwrap_or_default()
            ))
    );

    // Elasticsearch: bulk `create` with the replica and number as the ID, so a batch sent twice is stored once.
    send(dest(
        Kind::Elastic,
        format!("{}/in/enterplace-audit/", sink.base),
        "es-key",
        json!({}),
    ))
    .await?;
    let hit = sink.deliveries().pop().ok_or("no elastic")?;
    assert_eq!(hit.uri, "/in/enterplace-audit/_bulk");
    assert_eq!(
        (hit.header("authorization"), hit.header("content-type")),
        ("ApiKey es-key", "application/x-ndjson")
    );
    let lines: Vec<Value> = hit
        .text()
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(lines[0]["create"]["_id"], "pod-0-abc-1");
    assert_eq!(lines[3]["@timestamp"], "2026-11-13T09:14:02.120Z");
    assert_eq!(lines[3]["batch_last_hash"], last);

    // OTLP logs: one resource with the range, the line as the body, the secret in the header named.
    send(dest(
        Kind::Otlp,
        format!("{}/in/v1/logs", sink.base),
        "otlp-secret",
        json!({ "header": "X-Api-Key" }),
    ))
    .await?;
    let hit = sink.deliveries().pop().ok_or("no otlp")?;
    assert_eq!(hit.header("x-api-key"), "otlp-secret");
    let body = hit.json();
    let resource = &body["resourceLogs"][0];
    let attrs = resource["resource"]["attributes"].to_string();
    assert!(
        attrs.contains("enterplace.batch.first_hash")
            && attrs.contains(first.as_str().unwrap_or("x"))
    );
    let record = &resource["scopeLogs"][0]["logRecords"][1];
    assert_eq!(
        record["body"]["stringValue"],
        Value::from(batch.lines[1].clone())
    );
    assert_eq!(record["timeUnixNano"], "1794561242120000000");

    // Without a secret an OTLP collector gets no authorization at all; with one and no header, a bearer token.
    send(dest(
        Kind::Otlp,
        format!("{}/in/v1/logs", sink.base),
        "tok",
        json!({}),
    ))
    .await?;
    assert_eq!(
        sink.deliveries()
            .pop()
            .ok_or("no otlp")?
            .header("authorization"),
        "Bearer tok"
    );

    // Object storage names each object by its range and hashes.
    assert_eq!(
        batch.object_name(),
        format!(
            "pod-0-abc/{:020}-{:020}-{}-{}.ndjson",
            1,
            2,
            first.as_str().unwrap_or_default(),
            last.as_str().unwrap_or_default()
        )
    );
    Ok(())
}

#[tokio::test]
async fn object_stores_and_sentinel_sign_in_the_way_each_cloud_expects() -> Result<(), Error> {
    let sink = Sink::start().await?;
    let batch = sample();
    let host = sink.base.trim_start_matches("http://").to_string();
    let deliver = |env: Env, d: Dest| {
        let batch = batch.clone();
        async move {
            Ok::<(), Error>(
                tokio::task::spawn_blocking(move || Sinks::new(env).deliver(&d, &batch)).await??,
            )
        }
    };
    let s3 = |options: Value, secret: &str| {
        dest(
            Kind::S3,
            format!("{}/in/bucket/audit", sink.base),
            secret,
            options,
        )
    };

    // S3 with a static key: SigV4 over the exact body, the object named by its range, the NDJSON lines as written.
    deliver(
        env_of(&[]),
        s3(
            json!({ "region": "eu-west-1", "access_key_id": "AKIDSTATIC" }),
            "static-secret",
        ),
    )
    .await?;
    let hit = sink.deliveries().pop().ok_or("no s3")?;
    assert_eq!(hit.method, "PUT");
    assert_eq!(hit.uri, format!("/in/bucket/audit/{}", batch.object_name()));
    assert_eq!(hit.text(), batch.ndjson());
    assert_eq!(
        hit.header("x-amz-content-sha256"),
        enterplace_core::id::sha256_hex(&hit.body)
    );
    assert_eq!(
        hit.header("authorization"),
        s3_signature(&hit, &sink, "AKIDSTATIC", "static-secret", None)
    );
    assert!(
        hit.header("authorization")
            .contains("/eu-west-1/s3/aws4_request")
    );

    // No key: the EC2 instance role through IMDSv2 (a session token first, then the role, then its credentials).
    sink.clear();
    deliver(
        env_of(&[("AWS_EC2_METADATA_SERVICE_ENDPOINT", sink.base.clone())]),
        s3(json!({ "region": "eu-west-1" }), ""),
    )
    .await?;
    let hits = sink.hits();
    assert_eq!(
        (
            hits[0].method.as_str(),
            hits[0].header("x-aws-ec2-metadata-token-ttl-seconds")
        ),
        ("PUT", "21600")
    );
    assert_eq!(hits[1].header("x-aws-ec2-metadata-token"), "imds-token");
    let hit = sink.deliveries().pop().ok_or("no s3")?;
    assert_eq!(hit.header("x-amz-security-token"), "role-token");
    assert_eq!(
        hit.header("authorization"),
        s3_signature(&hit, &sink, "AKIDROLE", "role-secret", Some("role-token"))
    );

    // An ECS task role or EKS pod identity: the container endpoint, with its authorization token.
    sink.clear();
    deliver(
        env_of(&[
            (
                "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                format!("{}/container-creds", sink.base),
            ),
            ("AWS_CONTAINER_AUTHORIZATION_TOKEN", "pod-token".into()),
        ]),
        s3(json!({ "region": "eu-west-1" }), ""),
    )
    .await?;
    assert_eq!(sink.hits()[0].header("authorization"), "pod-token");
    assert!(
        sink.deliveries()
            .pop()
            .ok_or("no s3")?
            .header("authorization")
            .contains("Credential=AKIDROLE/")
    );

    // IRSA: the web identity token traded at STS.
    sink.clear();
    let token_file =
        std::env::temp_dir().join(format!("enterplace-web-identity-{}", std::process::id()));
    std::fs::write(&token_file, "web-identity-jwt\n")?;
    deliver(
        env_of(&[
            (
                "AWS_WEB_IDENTITY_TOKEN_FILE",
                token_file.display().to_string(),
            ),
            (
                "AWS_ROLE_ARN",
                "arn:aws:iam::123456789012:role/enterplace".into(),
            ),
            ("AWS_ENDPOINT_URL_STS", format!("{}/sts", sink.base)),
        ]),
        s3(json!({ "region": "eu-west-1" }), ""),
    )
    .await?;
    let sts = &sink.hits()[0];
    assert_eq!(sts_query(sts, "Action"), "AssumeRoleWithWebIdentity");
    assert_eq!(sts_query(sts, "WebIdentityToken"), "web-identity-jwt");
    assert_eq!(
        sts_query(sts, "RoleArn"),
        "arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Fenterplace"
    );
    let hit = sink.deliveries().pop().ok_or("no s3")?;
    assert_eq!(
        hit.header("authorization"),
        s3_signature(&hit, &sink, "AKIDWEB", "web-secret", Some("web-token"))
    );

    // GCS through the metadata server (GKE workload identity, Cloud Run): the JSON API's media upload.
    sink.clear();
    let gcs = |secret: &str| {
        dest(
            Kind::Gcs,
            format!("{}/bucket/audit", sink.base),
            secret,
            json!({}),
        )
    };
    deliver(env_of(&[("GCE_METADATA_HOST", host.clone())]), gcs("")).await?;
    let hits = sink.hits();
    assert_eq!(hits[0].header("metadata-flavor"), "Google");
    let upload = hits.last().ok_or("no upload")?;
    assert_eq!(upload.method, "POST");
    assert_eq!(
        upload.uri,
        format!(
            "/upload/storage/v1/b/bucket/o?uploadType=media&name={}",
            enterplace_core::sigv4::uri_encode(&format!("audit/{}", batch.object_name()), false)
        )
    );
    assert_eq!(
        (upload.header("authorization"), upload.text()),
        ("Bearer gce-token", batch.ndjson())
    );

    // GCS with a service account key: an RS256 JWT, checked here against the key's public half.
    sink.clear();
    let account = json!({
        "type": "service_account",
        "client_email": "enterplace@project.iam.gserviceaccount.com",
        "private_key": TEST_RSA,
        "token_uri": format!("{}/google-token", sink.base),
    });
    deliver(env_of(&[]), gcs(&account.to_string())).await?;
    let hits = sink.hits();
    let form = hits[0].text();
    assert!(form.starts_with(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion="
    ));
    let jwt = form.split("assertion=").nth(1).ok_or("no assertion")?;
    let parts: Vec<&str> = jwt.split('.').collect();
    let b64 =
        |s: &str| base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, s);
    let claims: Value = serde_json::from_slice(&b64(parts[1])?)?;
    assert_eq!(claims["iss"], "enterplace@project.iam.gserviceaccount.com");
    assert_eq!(
        claims["scope"],
        "https://www.googleapis.com/auth/devstorage.read_write"
    );
    let der: String = TEST_RSA
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    let pair = ring::signature::RsaKeyPair::from_pkcs8(&base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        der,
    )?)
    .map_err(|_| "test key")?;
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::RSA_PKCS1_2048_8192_SHA256,
        ring::signature::KeyPair::public_key(&pair).as_ref(),
    )
    .verify(
        format!("{}.{}", parts[0], parts[1]).as_bytes(),
        &b64(parts[2])?,
    )
    .map_err(|_| "the JWT signature does not verify")?;
    assert_eq!(
        hits.last().ok_or("no upload")?.header("authorization"),
        "Bearer sa-token"
    );

    // Azure Blob with a SAS token: a block blob PUT with the token as the query.
    sink.clear();
    let blob = |secret: &str| {
        dest(
            Kind::AzureBlob,
            format!("{}/in/container/audit", sink.base),
            secret,
            json!({}),
        )
    };
    deliver(env_of(&[]), blob("?sv=2022-11-02&sig=abc")).await?;
    let hit = sink.deliveries().pop().ok_or("no blob")?;
    assert_eq!(
        hit.uri,
        format!(
            "/in/container/audit/{}?sv=2022-11-02&sig=abc",
            batch.object_name()
        )
    );
    assert_eq!(
        (hit.method.as_str(), hit.header("x-ms-blob-type")),
        ("PUT", "BlockBlob")
    );
    assert!(hit.header("authorization").is_empty());

    // Azure Blob with managed identity (Container Apps, App Service): the identity endpoint, then a bearer token.
    sink.clear();
    deliver(
        env_of(&[
            ("IDENTITY_ENDPOINT", format!("{}/msi", sink.base)),
            ("IDENTITY_HEADER", "id-secret".into()),
        ]),
        blob(""),
    )
    .await?;
    let msi = &sink.hits()[0];
    assert_eq!(msi.header("x-identity-header"), "id-secret");
    assert!(
        msi.uri
            .contains("resource=https%3A%2F%2Fstorage.azure.com%2F"),
        "{}",
        msi.uri
    );
    let hit = sink.deliveries().pop().ok_or("no blob")?;
    assert_eq!(
        (hit.header("authorization"), hit.header("x-ms-version")),
        ("Bearer msi-token", "2021-08-06")
    );

    // Sentinel with an app registration's secret: Entra client credentials for Azure Monitor, then the rows.
    sink.clear();
    let sentinel = |secret: &str| {
        dest(
            Kind::Sentinel,
            format!(
                "{}/in/dataCollectionRules/dcr-1/streams/Custom-EnterplaceAudit_CL?api-version=2023-01-01",
                sink.base
            ),
            secret,
            json!({ "tenant": "tenant-1", "client_id": "app-1" }),
        )
    };
    let authority = env_of(&[("AZURE_AUTHORITY_HOST", sink.base.clone())]);
    deliver(authority, sentinel("app-secret")).await?;
    let hits = sink.hits();
    assert_eq!(hits[0].uri, "/tenant-1/oauth2/v2.0/token");
    let form = hits[0].text();
    assert!(
        form.contains("grant_type=client_credentials") && form.contains("client_secret=app-secret")
    );
    assert!(
        form.contains("scope=https%3A%2F%2Fmonitor.azure.com%2F.default"),
        "{form}"
    );
    let rows = hits.last().ok_or("no rows")?;
    assert_eq!(rows.header("authorization"), "Bearer entra-token");
    assert_eq!(rows.json()[1]["Hash"], batch.records[1]["hash"]);
    assert_eq!(rows.json()[0]["BatchLastHash"], batch.records[1]["hash"]);

    // Sentinel on AKS workload identity: the federated token as the client assertion, no secret anywhere.
    sink.clear();
    let federated =
        std::env::temp_dir().join(format!("enterplace-federated-{}", std::process::id()));
    std::fs::write(&federated, "federated-jwt")?;
    deliver(
        env_of(&[
            ("AZURE_AUTHORITY_HOST", sink.base.clone()),
            (
                "AZURE_FEDERATED_TOKEN_FILE",
                federated.display().to_string(),
            ),
        ]),
        sentinel(""),
    )
    .await?;
    let form = sink.hits()[0].text();
    assert!(
        form.contains("client_assertion=federated-jwt") && !form.contains("client_secret"),
        "{form}"
    );
    Ok(())
}

#[test]
fn destination_urls_are_https_or_this_machine() {
    for ok in [
        "https://splunk.example.com:8088/services/collector/event",
        "http://127.0.0.1:9000/x",
        "http://localhost/x",
        "http://[::1]:80/x",
    ] {
        assert!(sinks::url_ok(ok), "{ok}");
    }
    for bad in [
        "http://example.com/hook",
        "ftp://example.com",
        "https://",
        "http://127.0.0.1.evil.com/x",
        "http://user@example.com/x",
    ] {
        assert!(!sinks::url_ok(bad), "{bad}");
    }
}

#[test]
fn secrets_at_rest_open_only_with_the_same_key() -> Result<(), String> {
    let key = parse_key(KEY).ok_or("key")?;
    let sealed = seal_secret(&key, "hec-token")?;
    assert!(sealed.starts_with("v1:") && !sealed.contains("hec-token"));
    assert_eq!(open_secret(Some(&key), &sealed)?, "hec-token");
    let other = parse_key(&"ab".repeat(32)).ok_or("key")?;
    assert!(open_secret(Some(&other), &sealed).is_err_and(|e| e.contains("key changed")));
    assert!(open_secret(None, &sealed).is_err_and(|e| e.contains("ENTERPLACE_EXPORT_KEY")));
    Ok(())
}

// ---------------------------------------------------------------- the license

#[tokio::test]
async fn without_the_features_the_page_and_api_say_why_and_nothing_is_made() -> Result<(), Error> {
    for (name, status) in [
        ("siem_gate", unlicensed()),
        ("siem_gate_members", licensed(&["members"])),
        ("siem_gate_scim", licensed(&["members", "scim"])),
    ] {
        let Some(url) = database(name).await? else {
            return Ok(());
        };
        let gw = gateway(name, &url, &status)?;
        let mut owner = Browser::admin(&gw.app).await?;
        let page = owner.go(&gw.app, "GET", "/console/siem", &[]).await?;
        assert_eq!(page.status, StatusCode::FORBIDDEN);
        assert!(page.text.contains("license_required"), "{}", page.text);
        let api = Browser::default()
            .go(&gw.app, "GET", "/export/records", &[])
            .await?;
        assert_eq!(api.status, StatusCode::FORBIDDEN);
        assert!(api.text.contains("license_required"));
        let audit = owner.go(&gw.app, "GET", "/console/teams", &[]).await?;
        assert!(!audit.text.contains("/console/siem"), "no nav entry");
        // The gateway's own request index names its replica in the same `.replica` file the export uses, so that
        // file says nothing about the export: its tables, below, do.
        let (client, connection) = enterplace_server::store::tokio_postgres::connect(
            &url,
            enterplace_server::store::tokio_postgres::NoTls,
        )
        .await?;
        tokio::spawn(connection);
        let made: i64 = client
            .query_one(
                "SELECT count(*) FROM information_schema.tables WHERE table_name IN ('enterprise_audit', 'enterprise_replicas', 'enterprise_export_destinations')",
                &[],
            )
            .await?
            .try_get(0)?;
        // Each feature runs its own migrations: other features never make the export's tables.
        assert_eq!(made, 0, "{name}");
    }
    Ok(())
}

// ---------------------------------------------------------------- the Cloudflare app's checks

#[tokio::test]
async fn webhook_export_status_test_record_retention_hold_and_archive() -> Result<(), Error> {
    let Some(url) = database("siem_hook").await? else {
        return Ok(());
    };
    let sink = Sink::start().await?;
    let (gw, ex) = quiet("siem_hook", &url, &["siem", "retention"])?;
    let mut owner = Browser::admin(&gw.app).await?;

    let saved = owner
        .go(
            &gw.app,
            "POST",
            "/console/siem",
            &[
                ("action", "save"),
                ("kind", "webhook"),
                ("url", &format!("{}/in/hook", sink.base)),
                ("token", ""),
            ],
        )
        .await?;
    let secret = saved
        .text
        .split("gsig_")
        .nth(1)
        .map(|r| format!("gsig_{}", &r[..64]))
        .ok_or(format!("no secret: {}", saved.text))?;
    assert!(saved.text.contains("Saved destination 1"));
    let page = owner.go(&gw.app, "GET", "/console/siem", &[]).await?;
    assert!(!page.text.contains(&secret), "the secret is shown once");

    write_requests(&gw, 3)?;
    while ex.ingest().await? > 0 {}
    ex.ship().await?;
    let hit = sink.deliveries().pop().ok_or("nothing delivered")?;
    assert_eq!(
        hit.header("x-enterplace-signature"),
        format!("sha256={}", sinks::signature(&secret, &hit.body))
    );
    let body = hit.json();
    let records = body["records"].as_array().ok_or("no records")?;
    assert_eq!(
        records.len(),
        3,
        "only the records written after the destination was added"
    );
    assert!(records.iter().all(|r| r["person"] == "alice"
        && r.get("prompt").is_none()
        && r.get("messages").is_none()));
    let chain = chain_lines(&gw)?;
    let n = |v: &Value| v.as_u64().unwrap_or_default() as usize;
    assert_eq!(
        body["last_hash"],
        serde_json::from_str::<Value>(&chain[n(&body["last_n"]) - 1])?["hash"]
    );
    assert_eq!(
        body["prev"],
        serde_json::from_str::<Value>(&chain[n(&body["first_n"]) - 2])?["hash"]
    );

    let page = owner.go(&gw.app, "GET", "/console/siem", &[]).await?;
    assert!(
        page.text.contains(r#"id="delivered-1">3<"#),
        "{}",
        page.text
    );
    assert!(page.text.contains(r#"id="pending-1">0<"#));
    assert!(
        !page
            .text
            .contains(r#"Last success</dt><dd class="t-mono-sm">never"#),
        "last success is shown"
    );

    let tested = owner
        .go(
            &gw.app,
            "POST",
            "/console/siem",
            &[("action", "test"), ("id", "1")],
        )
        .await?;
    assert!(
        tested.text.contains("test record was delivered"),
        "{}",
        tested.text
    );
    assert_eq!(
        sink.deliveries().pop().ok_or("no test")?.json()["records"][0]["event"],
        "test"
    );

    let plain = owner
        .go(
            &gw.app,
            "POST",
            "/console/siem",
            &[
                ("action", "save"),
                ("kind", "webhook"),
                ("url", "http://example.com/hook"),
            ],
        )
        .await?;
    assert!(plain.text.contains("must use https"));
    let splunk = owner
        .go(
            &gw.app,
            "POST",
            "/console/siem",
            &[
                ("action", "save"),
                ("kind", "splunk_hec"),
                ("url", "https://splunk.example.com/x"),
            ],
        )
        .await?;
    assert!(splunk.text.contains("Enter the HEC token"));
    let low = owner
        .go(
            &gw.app,
            "POST",
            "/console/siem",
            &[("action", "retention"), ("retention_days", "10")],
        )
        .await?;
    assert!(low.text.contains("30 to 3650"));
    let set = owner
        .go(
            &gw.app,
            "POST",
            "/console/siem",
            &[("action", "retention"), ("retention_days", "90")],
        )
        .await?;
    assert!(
        set.text.contains("Retention is now 90 days")
            && set.text.contains(r#"id="retention-days">90<"#)
    );
    let empty = owner
        .go(
            &gw.app,
            "POST",
            "/console/siem",
            &[("action", "hold_on"), ("reason", "")],
        )
        .await?;
    assert!(empty.text.contains("Enter a reason"));
    let on = owner
        .go(
            &gw.app,
            "POST",
            "/console/siem",
            &[("action", "hold_on"), ("reason", "Case 42 discovery")],
        )
        .await?;
    assert!(
        on.text.contains("Legal hold is on")
            && on.text.contains("Case 42 discovery")
            && on.text.contains("noa")
    );
    let off = owner
        .go(
            &gw.app,
            "POST",
            "/console/siem",
            &[("action", "hold_off"), ("reason", "Case 42 closed")],
        )
        .await?;
    assert!(off.text.contains("Legal hold is off"));

    // Every change is an admin record in the chain, refusals with their code.
    let chain = chain_lines(&gw)?.join("\n");
    for action in [
        "export_destination_saved",
        "export_test_sent",
        "retention_set",
        "legal_hold_on",
        "legal_hold_off",
    ] {
        assert!(
            chain.contains(&format!("\"action\":\"{action}\"")),
            "{action}"
        );
    }
    assert!(
        chain.contains("\"code\":\"invalid_url\"") && chain.contains("\"code\":\"invalid_days\"")
    );
    assert!(!chain.contains(&secret), "the secret never reaches the log");

    // The archive: today's records, each line as the chain holds it.
    while ex.ingest().await? > 0 {}
    let today = audit::timestamp()[..10].to_string();
    let archive = owner
        .go(
            &gw.app,
            "GET",
            &format!("/console/siem/archive?from={today}&to={today}"),
            &[],
        )
        .await?;
    assert_eq!(archive.status, StatusCode::OK);
    let lines: Vec<&str> = archive.text.lines().collect();
    let chain = chain_lines(&gw)?;
    assert!(
        lines.len() + 2 >= chain.len()
            && lines
                .iter()
                .all(|l| chain.iter().any(|c| c == l) && hash_holds(l))
    );
    let bad = owner
        .go(
            &gw.app,
            "GET",
            "/console/siem/archive?from=2026-02-01&to=2026-01-01",
            &[],
        )
        .await?;
    assert!(bad.text.contains("from on or before to"));
    Ok(())
}

#[tokio::test]
async fn pull_api_pages_with_a_cursor_and_backfill_sends_contiguous_ranges() -> Result<(), Error> {
    let Some(url) = database("siem_pull").await? else {
        return Ok(());
    };
    let sink = Sink::start().await?;
    let (gw, ex) = quiet("siem_pull", &url, &["siem"])?;
    let mut owner = Browser::admin(&gw.app).await?;
    write_requests(&gw, 5)?;
    while ex.ingest().await? > 0 {}

    let made = owner
        .go(&gw.app, "POST", "/console/siem", &[("action", "pull_new")])
        .await?;
    let token = made
        .text
        .split("gpull_")
        .nth(1)
        .map(|r| format!("gpull_{}", &r[..64]))
        .ok_or("no token")?;
    assert!(
        !owner
            .go(&gw.app, "GET", "/console/siem", &[])
            .await?
            .text
            .contains(&token),
        "shown once"
    );

    let get = |path: String, token: String| {
        let app = gw.app.clone();
        async move {
            use tower::ServiceExt;
            let response = app
                .oneshot(
                    axum::http::Request::get(path)
                        .header("authorization", format!("Bearer {token}"))
                        .body(axum::body::Body::empty())?,
                )
                .await?;
            let status = response.status();
            let bytes = http_body_util::BodyExt::collect(response.into_body())
                .await?
                .to_bytes();
            Ok::<_, Error>((
                status,
                serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null),
            ))
        }
    };
    let (status, first) = get("/export/records?after=0&limit=2".into(), token.clone()).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["records"].as_array().map(Vec::len), Some(2));
    let total: usize = {
        let (_, all) = get("/export/records?after=0&limit=1000".into(), token.clone()).await?;
        all["records"].as_array().map_or(0, Vec::len)
    };
    let (_, rest) = get(
        format!("/export/records?after={}&limit=1000", first["next"]),
        token.clone(),
    )
    .await?;
    assert_eq!(rest["records"].as_array().map(Vec::len), Some(total - 2));
    let (_, end) = get(
        format!("/export/records?after={}&limit=10", rest["next"]),
        token.clone(),
    )
    .await?;
    assert_eq!(end, json!({ "records": [], "next": rest["next"] }));
    let record = &first["records"][0];
    assert!(hash_holds(record["line"].as_str().unwrap_or_default()));
    assert_eq!(record["replica"], Value::from(ex.replica.clone()));
    assert_eq!(
        get(
            "/export/records?after=0".into(),
            format!("gpull_{}", "0".repeat(64))
        )
        .await?
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        get("/export/records?limit=5000".into(), token.clone())
            .await?
            .0,
        StatusCode::BAD_REQUEST
    );

    owner
        .go(
            &gw.app,
            "POST",
            "/console/siem",
            &[
                ("action", "save"),
                ("kind", "webhook"),
                ("url", &format!("{}/in/hook", sink.base)),
            ],
        )
        .await?;
    let sent = owner
        .go(
            &gw.app,
            "POST",
            "/console/siem",
            &[("action", "backfill"), ("id", "1"), ("days", "7")],
        )
        .await?;
    assert!(
        sent.text.contains(&format!("Sent {total} records")),
        "{}",
        sent.text
    );
    assert!(sent.text.contains(&format!(r#"id="delivered-1">{total}<"#)));
    let batch = sink.deliveries().pop().ok_or("no backfill")?.json();
    let records = batch["records"].as_array().ok_or("records")?;
    for pair in records.windows(2) {
        assert_eq!(
            pair[1]["prev"], pair[0]["hash"],
            "a batch is a whole piece of the chain"
        );
    }
    assert_eq!(batch["first_n"], 1);
    let refused = owner
        .go(
            &gw.app,
            "POST",
            "/console/siem",
            &[("action", "backfill"), ("id", "1"), ("days", "500")],
        )
        .await?;
    assert!(refused.text.contains("1 to 90"));

    owner
        .go(&gw.app, "POST", "/console/siem", &[("action", "pull_off")])
        .await?;
    assert_eq!(
        get("/export/records?after=0".into(), token).await?.0,
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}

// ---------------------------------------------------------------- delivery

#[tokio::test]
async fn delivery_retries_with_backoff_and_resumes_from_the_cursor_after_a_restart()
-> Result<(), Error> {
    let Some(url) = database("siem_resume").await? else {
        return Ok(());
    };
    let sink = Sink::start().await?;
    let (gw, ex) = quiet("siem_resume", &url, &["siem"])?;
    let mut owner = Browser::admin(&gw.app).await?;
    owner
        .go(
            &gw.app,
            "POST",
            "/console/siem",
            &[
                ("action", "save"),
                ("kind", "splunk_hec"),
                ("url", &format!("{}/in/hec", sink.base)),
                ("token", "hec"),
            ],
        )
        .await?;
    write_requests(&gw, 4)?;
    while ex.ingest().await? > 0 {}

    // The destination is down: the error is shown, the cursor stays, and it is not called again until the backoff ends.
    sink.fail_next(1);
    ex.ship().await?;
    let page = owner.go(&gw.app, "GET", "/console/siem", &[]).await?;
    assert!(
        page.text.contains("HTTP 503 from the destination"),
        "{}",
        page.text
    );
    ex.ship().await?;
    assert_eq!(sink.deliveries().len(), 1, "backing off");
    ex.retry_now(1);
    ex.ship().await?;
    let first: Vec<Value> = sink
        .deliveries()
        .pop()
        .ok_or("none")?
        .text()
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert!(first.len() >= 4);
    let last_hash = first
        .last()
        .map(|e| e["event"]["hash"].clone())
        .ok_or("empty")?;

    // A restart: a new exporter on the same database and log, nothing in memory. It sends only what is new.
    write_requests(&gw, 2)?;
    let again = Exporter {
        db: ex.db.clone(),
        log: ex.log.clone(),
        path: ex.path.clone(),
        replica: ex.replica.clone(),
        siem: true,
        retention: false,
        read_through: ex.read_through.clone(),
        key: ex.key,
        sinks: Arc::new(Sinks::new(env_of(&[]))),
        captures: None,
        alerts: OnceLock::new(),
        alerts_on: false,
        hint: Mutex::new(None),
        backoff: Mutex::new(HashMap::new()),
        said: Mutex::new(String::new()),
    };
    while again.ingest().await? > 0 {}
    again.ship().await?;
    let next: Vec<Value> = sink
        .deliveries()
        .pop()
        .ok_or("none")?
        .text()
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(
        next[0]["event"]["prev"], last_hash,
        "the next batch starts where the last one ended"
    );
    assert_eq!(next.len(), 2);
    assert_eq!(
        next[0]["fields"]["batch_first_hash"],
        next[0]["event"]["hash"]
    );
    again.ship().await?;
    assert_eq!(
        sink.deliveries().len(),
        3,
        "nothing is sent twice once acknowledged"
    );

    // The loop runs on its own: a record written now arrives without anyone asking.
    let looped = Arc::new(again);
    tokio::spawn(looped.clone().run(Duration::from_millis(50)));
    write_requests(&gw, 1)?;
    for _ in 0..100 {
        if sink.deliveries().len() > 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        sink.deliveries().len(),
        4,
        "the exporter's loop ships new records"
    );
    Ok(())
}

// ---------------------------------------------------------------- retention

fn age(path: &std::path::Path, days: u64) -> Result<(), Error> {
    let file = std::fs::File::options().append(true).open(path)?;
    file.set_modified(SystemTime::now() - Duration::from_secs(days * 86_400))?;
    Ok(())
}

#[tokio::test]
async fn retention_retires_old_segments_verify_still_holds_and_legal_hold_stops_it()
-> Result<(), Error> {
    let Some(url) = database("siem_retain").await? else {
        return Ok(());
    };
    let sink = Sink::start().await?;
    let (gw, ex) = quiet("siem_retain", &url, &["siem", "retention"])?;
    let mut owner = Browser::admin(&gw.app).await?;
    owner
        .go(
            &gw.app,
            "POST",
            "/console/siem",
            &[
                ("action", "save"),
                ("kind", "webhook"),
                ("url", &format!("{}/in/hook", sink.base)),
            ],
        )
        .await?;
    write_requests(&gw, 3)?;
    let old = gw.log.seal()?.ok_or("nothing sealed")?;
    write_requests(&gw, 2)?;
    let newer = gw.log.seal()?.ok_or("nothing sealed")?;
    write_requests(&gw, 1)?;
    age(&old, 400)?;
    age(&newer, 400)?;
    while ex.ingest().await? > 0 {}

    // Under legal hold nothing goes.
    owner
        .go(
            &gw.app,
            "POST",
            "/console/siem",
            &[("action", "hold_on"), ("reason", "Case 7")],
        )
        .await?;
    assert!(ex.retain().await?.contains("Legal hold is on"));
    assert!(old.exists() && newer.exists());
    owner
        .go(
            &gw.app,
            "POST",
            "/console/siem",
            &[("action", "hold_off"), ("reason", "Case 7 closed")],
        )
        .await?;

    // A destination that has not taken the records holds them back.
    sink.fail_next(100);
    ex.ship().await?;
    let note = ex.retain().await?;
    assert!(note.contains("no sealed segment"), "{note}");
    assert!(old.exists());

    // Once delivered, both old segments are retired with one record that names them.
    sink.fail_next(0);
    ex.retry_now(1);
    while ex.ingest().await? > 0 {}
    ex.ship().await?;
    let segments = audit::segments(&gw.audit)?;
    let through = segments.last().map(|s| s.last).ok_or("no segments")?;
    let note = ex.retain().await?;
    assert!(
        note.contains(&format!("retired records 1 to {through} (2 segments)")),
        "{note}"
    );
    assert!(!old.exists() && !newer.exists());

    // `enterplace audit verify` still proves the rest, and says what was retired and by which record.
    gw.log.flush();
    let summary = audit::verify_full(&gw.audit, None)?;
    assert_eq!(summary.first, through + 1);
    let retired = summary
        .retired
        .ok_or("verify does not name the retirement")?;
    assert_eq!(retired.through, through);
    let lines = chain_lines(&gw)?;
    let record: Value = lines
        .iter()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find(|v| v["event"] == "audit_retired")
        .ok_or("no audit_retired record")?;
    assert_eq!(record["from_n"], 1);
    assert_eq!(record["through_n"], Value::from(through));
    assert_eq!(record["from_prev"], Value::from("0".repeat(64)));
    assert_eq!(record["segments"].as_array().map(Vec::len), Some(2));
    // The retirement record reaches the SIEM like any other, so the copy outside knows too.
    while ex.ingest().await? > 0 {}
    ex.ship().await?;
    let shipped = sink
        .deliveries()
        .into_iter()
        .map(|h| h.text())
        .collect::<String>();
    assert!(shipped.contains("audit_retired"));

    // A segment removed without a record is caught.
    write_requests(&gw, 1)?;
    let sneaky = gw.log.seal()?.ok_or("nothing sealed")?;
    write_requests(&gw, 1)?;
    gw.log.flush();
    std::fs::remove_file(&sneaky)?;
    assert!(audit::verify(&gw.audit).is_err());
    let page = owner.go(&gw.app, "GET", "/console/siem", &[]).await?;
    assert!(
        page.text.contains("retired records 1 to"),
        "the page shows the last run"
    );
    Ok(())
}

/// Invites `email` as `role` and has them accept: their browser, signed in.
async fn join(
    gw: &Gateway,
    owner: &mut Browser,
    role: &str,
    email: &str,
) -> Result<Browser, Error> {
    let made = owner
        .go(
            &gw.app,
            "POST",
            "/console/members/invite",
            &[("email", email), ("role", role), ("team", "ops")],
        )
        .await?;
    let token: String = made
        .text
        .split("/console/invite/")
        .nth(1)
        .ok_or("no invite")?
        .chars()
        .take_while(char::is_ascii_hexdigit)
        .collect();
    let mut person = Browser::default();
    person
        .go(
            &gw.app,
            "POST",
            &format!("/console/invite/{token}"),
            &[("name", "Sam"), ("password", "second-password-123")],
        )
        .await?;
    Ok(person)
}

#[tokio::test]
async fn an_admin_cannot_change_legal_hold_or_the_pull_token_and_a_viewer_changes_nothing()
-> Result<(), Error> {
    let Some(url) = database("siem_roles").await? else {
        return Ok(());
    };
    let (gw, _ex) = quiet("siem_roles", &url, &["members", "siem", "retention"])?;
    let mut owner = Browser::admin(&gw.app).await?;
    let mut admin = join(&gw, &mut owner, "admin", "admin@example.com").await?;
    let mut viewer = join(&gw, &mut owner, "viewer", "viewer@example.com").await?;

    let hold = admin
        .go(
            &gw.app,
            "POST",
            "/console/siem",
            &[("action", "hold_on"), ("reason", "x")],
        )
        .await?;
    assert!(hold.text.contains("Only an owner"), "{}", hold.text);
    let pull = admin
        .go(&gw.app, "POST", "/console/siem", &[("action", "pull_new")])
        .await?;
    assert!(pull.text.contains("Only an owner") && !pull.text.contains(r#"id="pull-token""#));
    let set = admin
        .go(
            &gw.app,
            "POST",
            "/console/siem",
            &[("action", "retention"), ("retention_days", "60")],
        )
        .await?;
    assert!(set.text.contains("Retention is now 60 days"));
    let looked = viewer
        .go(
            &gw.app,
            "POST",
            "/console/siem",
            &[("action", "retention"), ("retention_days", "31")],
        )
        .await?;
    assert!(looked.text.contains("Your role is viewer"));
    let archive = viewer
        .go(
            &gw.app,
            "GET",
            "/console/siem/archive?from=2026-01-01&to=2026-01-02",
            &[],
        )
        .await?;
    assert!(archive.text.contains("Your role is viewer"));
    let chain = chain_lines(&gw)?.join("\n");
    assert!(chain.contains("\"code\":\"owner_only\"") && chain.contains("\"code\":\"read_only\""));
    Ok(())
}

// ---------------------------------------------------------------- LLM observability destinations and captured text

/// A decision and its usage record, chained as the log writes them.
fn request_batch() -> Batch {
    let mut lines = Vec::new();
    let mut prev = "0".repeat(64);
    let bodies = [
        r#""id":"d1","time":"2026-11-13T09:14:02.120Z","person":"alice","team":"research","client":"10.0.0.1","key":"aaaa1111","path":"/v1/chat/completions","model":"m","verdict":"allow","rule":"all","provider":"openai""#,
        r#""event":"usage","id":"d1","time":"2026-11-13T09:14:03.620Z","person":"alice","team":"research","key":"aaaa1111","model":"m","provider":"openai","status":200,"ended":"complete","input_tokens":100,"output_tokens":20,"cache_read_tokens":5,"cache_write_tokens":0,"cost_usd":0.0012,"charged_usd":0.0012"#,
    ];
    for (i, fields) in bodies.iter().enumerate() {
        let body = format!(r#"{{"n":{},{fields},"prev":"{prev}""#, i + 1);
        let hash = enterplace_core::id::sha256_hex(format!("{body}}}").as_bytes());
        lines.push(format!(r#"{body},"hash":"{hash}"}}"#));
        prev = hash;
    }
    let mut batch = Batch::new("pod-0-abc".into(), lines);
    let decision = batch.records[0].clone();
    batch.joined.insert(
        "d1".into(),
        sinks::Joined {
            decision,
            text: None,
        },
    );
    batch
}

fn attribute<'a>(span: &'a Value, key: &str) -> &'a Value {
    span["attributes"]
        .as_array()
        .and_then(|a| a.iter().find(|x| x["key"] == key))
        .map_or(&Value::Null, |x| &x["value"])
}

#[test]
fn trace_destinations_get_genai_spans_with_cost_tokens_and_the_hash_range() -> Result<(), Error> {
    let batch = request_batch();
    let body = sinks::traces(&batch);
    let resource = &body["resourceSpans"][0]["resource"];
    let span = &body["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
    assert_eq!(
        body["resourceSpans"][0]["scopeSpans"][0]["spans"]
            .as_array()
            .map(Vec::len),
        Some(1),
        "one span per finished request"
    );
    assert_eq!(span["name"], "chat m");
    assert_eq!(
        attribute(span, "gen_ai.operation.name")["stringValue"],
        "chat"
    );
    assert_eq!(attribute(span, "gen_ai.request.model")["stringValue"], "m");
    assert_eq!(
        attribute(span, "gen_ai.usage.input_tokens")["intValue"],
        "100"
    );
    assert_eq!(
        attribute(span, "gen_ai.usage.output_tokens")["intValue"],
        "20"
    );
    assert_eq!(attribute(span, "gen_ai.usage.cost")["doubleValue"], 0.0012);
    assert_eq!(attribute(span, "llm.token_count.total")["intValue"], "120");
    assert_eq!(
        attribute(span, "langfuse.observation.type")["stringValue"],
        "generation"
    );
    assert_eq!(attribute(span, "user.id")["stringValue"], "alice");
    assert_eq!(
        attribute(span, "enterplace.client")["stringValue"],
        "10.0.0.1"
    );
    assert_eq!(
        attribute(span, "enterplace.hash"),
        &json!({ "stringValue": batch.records[1]["hash"] })
    );
    assert!(
        attribute(span, "gen_ai.input.messages").is_null(),
        "no text without the opt-in"
    );
    let nanos = |k: &str| {
        span[k]
            .as_str()
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(0)
    };
    assert_eq!(
        nanos("endTimeUnixNano") - nanos("startTimeUnixNano"),
        1_500_000_000,
        "from decision to answer's end"
    );
    let res = |k: &str| {
        resource["attributes"]
            .as_array()
            .and_then(|a| a.iter().find(|x| x["key"] == k))
            .map(|x| x["value"].clone())
            .unwrap_or(Value::Null)
    };
    assert_eq!(
        res("enterplace.batch.first_hash")["stringValue"],
        batch.records[0]["hash"]
    );
    assert_eq!(
        res("enterplace.batch.last_hash")["stringValue"],
        batch.records[1]["hash"]
    );
    assert_eq!(res("enterplace.batch.prev")["stringValue"], "0".repeat(64));

    // Langfuse: its OTLP endpoint, Basic auth of the key pair, and the real-time ingestion header.
    let out = sinks::request(
        &dest(
            Kind::Langfuse,
            "https://cloud.langfuse.com".into(),
            "sk-lf-1",
            json!({ "public_key": "pk-lf-1" }),
        ),
        &batch,
    );
    assert_eq!(
        out.url,
        "https://cloud.langfuse.com/api/public/otel/v1/traces"
    );
    use base64::Engine;
    let basic = base64::engine::general_purpose::STANDARD.encode("pk-lf-1:sk-lf-1");
    assert!(
        out.headers
            .contains(&("authorization".into(), format!("Basic {basic}")))
    );
    assert!(
        out.headers
            .contains(&("x-langfuse-ingestion-version".into(), "4".into()))
    );

    // The callback: one signed entry per request, with the batch's range.
    let out = sinks::request(
        &dest(
            Kind::Callback,
            "https://example.com/cb".into(),
            "gsig_cb",
            json!({}),
        ),
        &batch,
    );
    let sent: Value = serde_json::from_slice(&out.body)?;
    assert!(out.headers.contains(&(
        "x-enterplace-signature".into(),
        format!("sha256={}", sinks::signature("gsig_cb", &out.body))
    )));
    assert_eq!(sent["requests"][0]["decision"], "d1");
    assert_eq!(sent["requests"][0]["duration_ms"], 1500);
    assert_eq!(sent["requests"][0]["cost_usd"], 0.0012);
    assert_eq!(sent["last_hash"], batch.records[1]["hash"]);
    assert!(sent["requests"][0].get("prompt").is_none());
    Ok(())
}

#[test]
fn captured_text_is_redacted_by_the_secrets_and_pii_detectors() -> Result<(), Error> {
    let text = sinks::Text {
        prompt: vec![(
            "user".into(),
            "my key is AKIAIOSFODNN7EXAMPLE, mail me at dana@example.com".into(),
        )],
        answer: vec!["write to dana@example.com".into()],
    };
    let redacted = crate::enterprise::capture::redact(&text).ok_or("not checked")?;
    let joined = format!("{redacted:?}");
    assert!(
        !joined.contains("AKIAIOSFODNN7EXAMPLE") && !joined.contains("dana@example.com"),
        "{joined}"
    );
    assert!(
        redacted.prompt[0].1.contains("[MASKED aws_access_key]"),
        "{joined}"
    );
    assert!(
        redacted.answer[0].contains("[MASKED email_address]"),
        "{joined}"
    );
    assert_eq!(redacted.prompt[0].0, "user");
    Ok(())
}

#[tokio::test]
async fn text_goes_only_to_destinations_that_opt_in_redacted_encrypted_and_for_a_limited_time()
-> Result<(), Error> {
    let Some(url) = database("siem_text").await? else {
        return Ok(());
    };
    let sink = Sink::start().await?;
    let (gw, ex) = quiet("siem_text", &url, &["siem"])?;
    let mut owner = Browser::admin(&gw.app).await?;
    // Audit destinations cannot opt in: their records hold no text.
    let refused = owner
        .go(
            &gw.app,
            "POST",
            "/console/siem",
            &[
                ("action", "save"),
                ("kind", "datadog"),
                ("url", &format!("{}/in/dd", sink.base)),
                ("token", "k"),
                ("text", "on"),
            ],
        )
        .await?;
    assert!(
        refused
            .text
            .contains("can only go to a trace or callback destination"),
        "{}",
        refused.text
    );
    for (kind, path, text) in [
        ("otlp_traces", "/in/traces", true),
        ("callback", "/in/cb", false),
    ] {
        let mut form = vec![
            ("action", "save"),
            ("kind", kind),
            (
                "url",
                &*Box::leak(format!("{}{path}", sink.base).into_boxed_str()),
            ),
        ];
        if text {
            form.extend([("text", "on"), ("text_teams", "research")]);
        }
        let saved = owner.go(&gw.app, "POST", "/console/siem", &form).await?;
        assert!(saved.text.contains("Saved destination"), "{}", saved.text);
    }
    let captures = ex.captures.clone().ok_or("no capture hook")?;
    use enterplace_server::Capture;
    // Destinations are read on the next tick; until one opts in nothing is wanted.
    assert!(!captures.wanted("research"));
    ex.ship().await?;
    assert!(captures.wanted("research") && !captures.wanted("payments"));

    let id = "01TEXTDECISION";
    let mut record = audit::record(&audit::Entry {
        id,
        person: Some("alice"),
        team: Some("research"),
        method: "POST",
        path: "/v1/chat/completions",
        model: Some("m"),
        allowed: true,
        provider: "openai",
        ..Default::default()
    });
    record.insert("team".into(), "research".into());
    gw.log.append_record(&record)?;
    captures.take(enterplace_server::Captured {
        decision: id.into(),
        person: "alice".into(),
        team: "research".into(),
        model: "m".into(),
        provider: "openai".into(),
        route: "/v1/chat/completions".into(),
        request: r#"{"model":"m","messages":[{"role":"user","content":"secret AKIAIOSFODNN7EXAMPLE please"}]}"#.into(),
        answer: Some(r#"{"choices":[{"index":0,"message":{"role":"assistant","content":"done, dana@example.com"}}]}"#.into()),
        streamed: false,
    });
    let mut usage = serde_json::Map::new();
    for (k, v) in [
        ("event", json!("usage")),
        ("id", json!(id)),
        ("time", json!(audit::timestamp())),
        ("person", json!("alice")),
        ("team", json!("research")),
        ("model", json!("m")),
        ("provider", json!("openai")),
        ("status", json!(200)),
        ("input_tokens", json!(3)),
        ("output_tokens", json!(2)),
        ("cost_usd", json!(0.001)),
        ("charged_usd", json!(0.001)),
    ] {
        usage.insert(k.into(), v);
    }
    gw.log.append_record(&usage)?;
    while ex.ingest().await? > 0 {}
    ex.ship().await?;

    let hits = sink.deliveries();
    let traces = hits
        .iter()
        .find(|h| h.uri == "/in/traces")
        .ok_or("no traces")?
        .json();
    let span = &traces["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
    let input = attribute(span, "gen_ai.input.messages")["stringValue"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        input.contains("[MASKED aws_access_key]") && input.contains("please"),
        "{input}"
    );
    let output = attribute(span, "output.value")["stringValue"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert_eq!(output, "done, [MASKED email_address]");
    let callback = hits
        .iter()
        .find(|h| h.uri == "/in/cb")
        .ok_or("no callback")?;
    assert!(
        callback.json()["requests"][0].get("prompt").is_none(),
        "the callback did not opt in"
    );
    assert!(!callback.text().contains("please"));
    // Nothing of the text is in the chain or in the clear in the database.
    assert!(
        !chain_lines(&gw)?
            .iter()
            .any(|l| l.contains("please") || l.contains("AKIA"))
    );
    let (client, connection) = enterplace_server::store::tokio_postgres::connect(
        &url,
        enterplace_server::store::tokio_postgres::NoTls,
    )
    .await?;
    tokio::spawn(connection);
    let sealed: String = client
        .query_one(
            "SELECT sealed FROM enterprise_captures WHERE decision = $1",
            &[&id],
        )
        .await?
        .try_get(0)?;
    assert!(sealed.starts_with("v1:") && !sealed.contains("please"));
    let hours: f64 = client
        .query_one("SELECT extract(epoch FROM expires_at - captured_at)::float8 / 3600 FROM enterprise_captures WHERE decision = $1", &[&id])
        .await?
        .try_get(0)?;
    assert!(
        (hours - 24.0).abs() < 0.01,
        "kept 24 hours by default: {hours}"
    );
    // Past its expiry it is deleted on the next tick.
    client
        .execute(
            "UPDATE enterprise_captures SET expires_at = now() - interval '1 second'",
            &[],
        )
        .await?;
    ex.ship().await?;
    assert!(
        client
            .query_opt("SELECT 1 FROM enterprise_captures", &[])
            .await?
            .is_none()
    );
    let set = owner
        .go(
            &gw.app,
            "POST",
            "/console/siem",
            &[("action", "capture_hours"), ("hours", "200")],
        )
        .await?;
    assert!(set.text.contains("from 1 to 168"));
    assert!(chain_lines(&gw)?.iter().any(
        |l| l.contains("\"action\":\"export_destination_saved\"")
            && l.contains("\"text\":true")
            && l.contains("\"text_teams\":\"research\"")
    ));
    Ok(())
}

/// Request records of organization acme, which go to its own chain with `audit: { per_org: true }`.
fn write_acme(gw: &Gateway, from: usize, count: usize, code: Option<&str>) -> Result<(), Error> {
    for i in from..from + count {
        let mut record = audit::record(&audit::Entry {
            id: &format!("acme-{i}"),
            person: Some("alice"),
            method: "POST",
            path: "/v1/chat/completions",
            model: Some("m"),
            allowed: code.is_none(),
            code,
            ..Default::default()
        });
        record.insert("org".into(), "acme".into());
        gw.log.append_record(&record)?;
    }
    Ok(())
}

#[tokio::test]
async fn per_org_each_chain_is_exported_retained_held_and_alerted_on_its_own() -> Result<(), Error>
{
    let Some(url) = database("siem_per_org").await? else {
        return Ok(());
    };
    let sink = Sink::start().await?;
    let policy = format!("{POLICY}orgs: [acme]\naudit: {{ per_org: true }}\n");
    let (gw, ex) = quiet_policy(
        "siem_per_org",
        &url,
        &["siem", "retention", "alerts"],
        &policy,
    )?;
    let acme = audit::org_path(&gw.audit, "acme");
    let org = registry()
        .lock()
        .map_err(|_| "registry")?
        .get(&acme)
        .cloned()
        .ok_or("no exporter for acme's chain")?;
    assert_ne!(org.replica, ex.replica, "a replica of its own");
    let mut owner = Browser::admin(&gw.app).await?;
    owner
        .go(
            &gw.app,
            "POST",
            "/console/siem",
            &[
                ("action", "save"),
                ("kind", "webhook"),
                ("url", &format!("{}/in/hook", sink.base)),
            ],
        )
        .await?;

    // Export: acme's records are read from its chain under its replica, and sent; the install's has none of them.
    write_acme(&gw, 0, 3, None)?;
    let old = org.log.seal()?.ok_or("nothing sealed")?;
    write_acme(&gw, 3, 1, None)?;
    while org.ingest().await? > 0 {}
    while ex.ingest().await? > 0 {}
    let count = |replica: &str| {
        format!(
            "SELECT count(*) FROM enterprise_audit WHERE replica = '{replica}' AND line LIKE '%\"org\":\"acme\"%'"
        )
    };
    let n = |rows: Vec<enterplace_server::store::tokio_postgres::Row>| -> i64 {
        rows.first().and_then(|r| r.try_get(0).ok()).unwrap_or(-1)
    };
    let rows = crate::enterprise::alerts::tests::rows;
    assert_eq!(n(rows(&url, &count(&org.replica)).await?), 4);
    assert_eq!(n(rows(&url, &count(&ex.replica)).await?), 0);
    org.ship().await?;
    assert!(
        sink.deliveries()
            .iter()
            .any(|h| h.uri.starts_with("/in/hook") && h.text().contains("acme-0")),
        "acme's records reach the destination"
    );

    // Legal hold covers every chain; retention then retires acme's old segment in acme's chain.
    age(&old, 400)?;
    owner
        .go(
            &gw.app,
            "POST",
            "/console/siem",
            &[("action", "hold_on"), ("reason", "Case 9")],
        )
        .await?;
    assert!(org.retain().await?.contains("Legal hold is on"));
    assert!(old.exists());
    owner
        .go(
            &gw.app,
            "POST",
            "/console/siem",
            &[("action", "hold_off"), ("reason", "Case 9 closed")],
        )
        .await?;
    let note = org.retain().await?;
    assert!(note.contains("retired records 1 to 3"), "{note}");
    assert!(!old.exists());
    org.log.flush();
    let summary = audit::verify_full(&acme, None)?;
    assert_eq!(summary.first, 4, "verify proves the rest of acme's chain");
    audit::verify_full(&gw.audit, None)?;

    // Alerts: acme's guardrail block fires from acme's chain, and the alert is recorded there.
    owner
        .go(
            &gw.app,
            "POST",
            "/console/alerts",
            &[
                ("action", "channel_save"),
                ("kind", "webhook"),
                ("name", "ops"),
                ("url", &format!("{}/in/alerts", sink.base)),
            ],
        )
        .await?;
    owner
        .go(
            &gw.app,
            "POST",
            "/console/alerts",
            &[
                ("action", "rule_save"),
                ("kind", "guardrail_block"),
                ("name_rule", "Blocks"),
                ("count", "1"),
                ("channels", "1"),
                ("cooldown", "60"),
            ],
        )
        .await?;
    sink.clear();
    write_acme(&gw, 4, 1, Some("guardrail_blocked"))?;
    while org.ingest().await? > 0 {}
    org.alerts
        .get()
        .ok_or("no engine for acme")?
        .evaluate()
        .await?;
    let fired = sink.deliveries();
    assert!(
        fired
            .iter()
            .any(|h| h.uri.starts_with("/in/alerts") && h.json()["records"][0]["id"] == "acme-4"),
        "{:?}",
        fired.iter().map(Hit::text).collect::<Vec<_>>()
    );
    org.log.flush();
    let chain = std::fs::read_to_string(&acme)?;
    assert!(
        chain.contains("\"event\":\"alert\""),
        "the alert is in acme's chain"
    );
    Ok(())
}

#[tokio::test]
async fn an_org_added_by_a_reload_is_exported_retained_held_and_shipped_at_once()
-> Result<(), Error> {
    let Some(url) = database("siem_org_reload").await? else {
        return Ok(());
    };
    let (bucket, segments) = crate::enterprise::segments::tests::bucket().await?;
    let policy = format!("{POLICY}orgs: [acme]\naudit: {{ per_org: true }}\n");
    let gw = gateway_policy(
        "siem_org_reload",
        &url,
        &licensed(&["siem", "retention", "alerts"]),
        &[
            (KEY_ENV, KEY),
            ("ENTERPLACE_EXPORT_TICK_MS", "3600000"),
            ("HOSTNAME", "pod-0"),
            ("ENTERPLACE_AUDIT_SEGMENTS_URL", &segments),
        ],
        &policy,
    )?;
    let globex = audit::org_path(&gw.audit, "globex");
    let exporter = |path: &PathBuf| registry().lock().ok().and_then(|r| r.get(path).cloned());
    assert!(
        exporter(&globex).is_none(),
        "globex is not in the policy yet"
    );

    // The policy now names globex: the reload opens its chain and starts everything on it, with no restart.
    std::fs::write(
        gw.dir.join("enterplace.policy.yaml"),
        format!("{POLICY}orgs: [acme, globex]\naudit: {{ per_org: true }}\n"),
    )?;
    let reloader = gw.governed.reloader.clone();
    let reload =
        tokio::task::spawn_blocking(move || reloader.check(enterplace_server::Trigger::Signal))
            .await?;
    assert!(
        matches!(reload, enterplace_server::Reload::Loaded),
        "{reload:?}"
    );
    let org = exporter(&globex).ok_or("no exporter for globex's chain after the reload")?;

    // Export: globex's records are read from its own chain.
    let mut record = audit::record(&audit::Entry {
        id: "globex-0",
        person: Some("alice"),
        method: "POST",
        path: "/v1/chat/completions",
        model: Some("m"),
        allowed: true,
        ..Default::default()
    });
    record.insert("org".into(), "globex".into());
    gw.log.append_record(&record)?;
    org.log.flush();
    assert!(std::fs::read_to_string(&globex)?.contains("globex-0"));
    while org.ingest().await? > 0 {}
    let rows = crate::enterprise::alerts::tests::rows(
        &url,
        &format!(
            "SELECT count(*) FROM enterprise_audit WHERE replica = '{}' AND line LIKE '%globex-0%'",
            org.replica
        ),
    )
    .await?;
    assert_eq!(
        rows.first().and_then(|r| r.try_get::<_, i64>(0).ok()),
        Some(1)
    );

    // Retention and legal hold run on it.
    let mut owner = Browser::admin(&gw.app).await?;
    owner
        .go(
            &gw.app,
            "POST",
            "/console/siem",
            &[("action", "hold_on"), ("reason", "Case 10")],
        )
        .await?;
    assert!(org.retain().await?.contains("Legal hold is on"));

    // Segments: its shipper writes under orgs/globex in the bucket.
    let shipper = crate::enterprise::SHIPPERS
        .lock()
        .map_err(|_| "shippers")?
        .iter()
        .find(|s| s.path() == globex.as_path())
        .cloned()
        .ok_or("no segment shipper for globex's chain")?;
    tokio::task::spawn_blocking(move || shipper.pass(true)).await??;
    let keys: Vec<String> = bucket
        .lock()
        .map_err(|_| "bucket")?
        .keys()
        .cloned()
        .collect();
    assert!(keys.iter().any(|k| k.contains("orgs/globex/")), "{keys:?}");
    Ok(())
}
