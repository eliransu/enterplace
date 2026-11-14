//! Batch jobs at Amazon Bedrock and Vertex AI, behind the OpenAI-style `/v1/files` and `/v1/batches` routes.
//!
//! Gantry keeps the files itself, in the bucket the provider's `batch:` section names, and runs the provider's own
//! job on them. Each call is a documented HTTP API; no cloud SDK is linked. As documented on 2026-11-14:
//!
//! - Bedrock batch inference: `CreateModelInvocationJob` (`POST /model-invocation-job`), `GetModelInvocationJob`
//!   (`GET /model-invocation-job/{id}`) and `StopModelInvocationJob` (`POST .../stop`) on the Bedrock control plane
//!   (<https://docs.aws.amazon.com/bedrock/latest/APIReference/API_CreateModelInvocationJob.html>). Input lines are
//!   `{"recordId", "modelInput"}` with the InvokeModel body; Bedrock writes `<input file>.out` under
//!   `<output uri><job id>/`, each line `{"recordId", "modelInput", "modelOutput"}` or `"error"` in place of the output
//!   (<https://docs.aws.amazon.com/bedrock/latest/userguide/batch-inference-data.html>,
//!   <https://docs.aws.amazon.com/bedrock/latest/userguide/batch-inference-results.html>). Files are kept in S3
//!   (`PutObject`, `GetObject`, `DeleteObject`), signed with SigV4 for service `s3`.
//! - Vertex AI batch prediction: `POST .../locations/{l}/batchPredictionJobs`, `GET` and `:cancel` on the job's name
//!   (<https://cloud.google.com/vertex-ai/generative-ai/docs/multimodal/batch-prediction-from-cloud-storage>). Gemini
//!   input lines are `{"request": GenerateContentRequest}` and each output line echoes `request` beside `response`
//!   and `status`; Claude's are `{"custom_id", "request"}`
//!   (<https://cloud.google.com/vertex-ai/generative-ai/docs/partner-models/claude/batch>). Files are kept in Cloud
//!   Storage through its JSON API, with the provider's Google access token.

use axum::{
    body::{Body, Bytes},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, Version, header},
};
use gantry_core::{config::Kind, gemini, id::sha256_hex, sigv4, translate, usage::Usage};
use serde_json::{Map, Value, json};

use crate::{AppState, Refusal, Snapshot, Upstream};

/// The most bytes of one object read back from the bucket.
const MAX_OBJECT: usize = 256 * crate::MIB;

/// A provider that runs batch jobs on files Gantry keeps: Bedrock or Vertex AI, with a `batch:` section.
pub(crate) fn is_cloud(provider: &Upstream) -> bool {
    matches!(
        provider.kind,
        Kind::Bedrock | Kind::Vertex | Kind::VertexAnthropic
    )
}

/// Where a batch file's lines go: a provider by position, the model it knows them by, and the region its deployment
/// is labelled with.
pub(crate) struct Target {
    pub(crate) provider: usize,
    pub(crate) model: String,
    pub(crate) region: Option<String>,
}

/// The Bedrock or Vertex AI deployment that runs `model`'s batches, when one does: the first deployment of an alias
/// on such a provider (in one of `regions`, when the rule keeps requests there), or the provider that serves the
/// model. None when the model is served elsewhere. A rule with regions reaches only a labelled deployment.
pub(crate) fn target(
    version: &Snapshot,
    model: &str,
    regions: Option<&[String]>,
) -> Result<Option<Target>, Refusal> {
    let position = |name: &str| version.providers.iter().position(|p| p.name == name);
    if let Some(alias) = version.aliases.iter().find(|a| a.name == model) {
        let mut cloud = alias.deployments.iter().filter_map(|d| {
            let at = position(&d.provider)?;
            is_cloud(&version.providers[at]).then_some((at, d))
        });
        let Some(regions) = regions else {
            return Ok(cloud.next().map(|(provider, d)| Target {
                provider,
                model: d.model.clone(),
                region: d.region.clone(),
            }));
        };
        return cloud
            .find(|(_, d)| d.region.as_ref().is_some_and(|r| regions.contains(r)))
            .map(|(provider, d)| {
                Some(Target {
                    provider,
                    model: d.model.clone(),
                    region: d.region.clone(),
                })
            })
            .ok_or_else(|| outside(regions, model));
    }
    if let Some(regions) = regions {
        return Err(outside(regions, model));
    }
    Ok(version
        .providers
        .iter()
        .position(|p| is_cloud(p) && p.serves(model))
        .map(|provider| Target {
            provider,
            model: model.to_string(),
            region: None,
        }))
}

fn outside(regions: &[String], model: &str) -> Refusal {
    Refusal::new(
        StatusCode::FORBIDDEN,
        "region_not_allowed",
        format!(
            "Refused: your rule keeps requests in {}, and model \"{model}\" is not an alias with a Bedrock or Vertex AI deployment labelled with one of those regions, so where its batch would run cannot be shown. Use such an alias, or ask a Gantry admin to add region: to its deployment.",
            regions.join(", ")
        ),
    )
}

/// The provider's `batch:` section, or why it cannot run batches.
pub(crate) fn settings(
    provider: &Upstream,
) -> Result<&gantry_core::config::ProviderBatch, Refusal> {
    provider.batch.as_ref().ok_or_else(|| {
        Refusal::new(
            StatusCode::BAD_REQUEST,
            "batch_not_configured",
            format!(
                "Refused: model's batches go to provider \"{}\" of kind {}, which has no batch: section naming the bucket its batch jobs read and write. Ask a Gantry admin to add batch: {{ bucket: ... }} to the provider.",
                provider.name,
                provider.kind.word()
            ),
        )
    })
}

/// One line of a batch file as the provider's job reads it: the OpenAI chat completions body translated to the
/// provider's own. `model` is the model the provider knows (it goes in the job, not the line).
pub(crate) fn input_line(kind: Kind, custom_id: &str, body: &Value) -> Result<Value, String> {
    match kind {
        Kind::Bedrock | Kind::VertexAnthropic => {
            let mut message =
                translate::openai_to_anthropic_request(body).map_err(|e| e.to_string())?;
            if let Some(map) = message.as_object_mut() {
                map.remove("model");
                map.remove("stream");
                let version = if kind == Kind::Bedrock {
                    "bedrock-2023-05-31"
                } else {
                    "vertex-2023-10-16"
                };
                map.entry("anthropic_version").or_insert(version.into());
            }
            Ok(if kind == Kind::Bedrock {
                json!({ "recordId": custom_id, "modelInput": message })
            } else {
                json!({ "custom_id": custom_id, "request": message })
            })
        }
        _ => {
            let (request, _) = gemini::openai_to_gemini_request(body).map_err(|e| e.to_string())?;
            Ok(json!({ "request": request }))
        }
    }
}

/// A Gemini line's request, as a key that does not depend on the order of its fields: Vertex AI echoes the request
/// in each output line and the input lines carry no ID of their own.
pub(crate) fn request_key(request: &Value) -> String {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                Value::Object(
                    keys.into_iter()
                        .map(|k| (k.clone(), sorted(&map[k])))
                        .collect(),
                )
            }
            Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
            other => other.clone(),
        }
    }
    sha256_hex(sorted(request).to_string().as_bytes())
}

/// What went wrong talking to the provider or its bucket, for the admin's log and the caller's error.
pub(crate) struct Failed {
    pub(crate) status: Option<StatusCode>,
    pub(crate) detail: String,
}

impl Failed {
    /// The caller's error: the provider's own 4xx with its words (the caller can act on it), else a 502.
    pub(crate) fn refusal(&self, provider: &Upstream, what: &str) -> Refusal {
        let detail: String = self.detail.chars().take(500).collect();
        match self.status {
            Some(status) if status.is_client_error() => Refusal::new(
                status,
                "provider_refused",
                format!(
                    "Refused: provider \"{}\" refused {what} ({status}): {detail}",
                    provider.name
                ),
            ),
            _ => Refusal::new(
                StatusCode::BAD_GATEWAY,
                "upstream_failed",
                format!(
                    "Provider \"{}\" could not {what}. Try again. If it keeps happening, tell your Gantry admin.",
                    provider.name
                ),
            ),
        }
    }
}

async fn send(
    state: &AppState,
    provider: &Upstream,
    method: Method,
    url: &str,
    mut headers: HeaderMap,
    body: Bytes,
    service: &str,
) -> Result<Bytes, Failed> {
    let failed = |detail: String| Failed {
        status: None,
        detail,
    };
    let uri: Uri = url
        .parse()
        .map_err(|_| failed(format!("{url} is not a URL")))?;
    if provider.kind == Kind::Bedrock {
        sign(provider, &method, &uri, &body, service, &mut headers).map_err(failed)?;
    } else if let Some(token) = &provider.google {
        headers.insert(header::AUTHORIZATION, token.get());
    } else if let Some((name, value)) = &provider.key {
        headers.insert(name.clone(), value.clone());
    }
    let mut request = axum::http::Request::new(Body::from(body));
    *request.method_mut() = method;
    *request.uri_mut() = uri;
    *request.version_mut() = Version::HTTP_11;
    *request.headers_mut() = headers;
    let answer = crate::attempt(state, provider, request)
        .await
        .map_err(|r| failed(r.message))?;
    let status = answer.status();
    let bytes = http_body_util::Limited::new(answer.into_body(), MAX_OBJECT);
    let bytes = http_body_util::BodyExt::collect(bytes)
        .await
        .map(|b| b.to_bytes())
        .map_err(|err| failed(format!("the answer could not be read: {err}")))?;
    if !status.is_success() {
        return Err(Failed {
            status: Some(status),
            detail: String::from_utf8_lossy(&bytes).into_owned(),
        });
    }
    Ok(bytes)
}

/// Signs an AWS request with SigV4 for `service` (`bedrock` or `s3`), and sets the headers the signature covers.
fn sign(
    provider: &Upstream,
    method: &Method,
    uri: &Uri,
    body: &[u8],
    service: &str,
    headers: &mut HeaderMap,
) -> Result<(), String> {
    let (Some(credentials), Some(region), Some(host)) = (
        provider.aws.as_ref().map(crate::cloud::Live::get),
        &provider.region,
        uri.authority(),
    ) else {
        return Err("no AWS credentials, region or host to sign with".into());
    };
    let payload = sha256_hex(body);
    let mut signed: Vec<(&str, &str)> = vec![("host", host.as_str())];
    if service == "s3" {
        signed.push(("x-amz-content-sha256", &payload));
    } else if !body.is_empty() {
        signed.push(("content-type", "application/json"));
    }
    let query = canonical_query(uri.query().unwrap_or_default());
    let out = sigv4::sign(
        &credentials,
        region,
        service,
        &sigv4::Request {
            method: method.as_str(),
            path: uri.path(),
            query: &query,
            headers: &signed,
            payload: body,
        },
        &sigv4::amz_date_now(),
    );
    let bad = |_| "a signed header holds a character that cannot be sent".to_string();
    for (name, value) in signed {
        headers.insert(
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| "bad header".to_string())?,
            HeaderValue::from_str(value).map_err(bad)?,
        );
    }
    for (name, value) in out {
        let mut value = HeaderValue::from_str(&value).map_err(bad)?;
        value.set_sensitive(true);
        headers.insert(HeaderName::from_static(name), value);
    }
    Ok(())
}

/// A query as SigV4 signs it: pairs sorted by name. Gantry writes only plain, already-encoded values.
fn canonical_query(query: &str) -> String {
    let mut pairs: Vec<&str> = query.split('&').filter(|p| !p.is_empty()).collect();
    pairs.sort_unstable();
    pairs
        .into_iter()
        .map(|p| {
            if p.contains('=') {
                p.to_string()
            } else {
                format!("{p}=")
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// The URL of an object in the provider's bucket, for `op`: S3 by path under `storage_url`, else virtual-hosted;
/// Cloud Storage through its JSON API.
fn object_url(provider: &Upstream, key: &str, op: &Method) -> Result<String, Failed> {
    let batch = provider.batch.as_ref().ok_or(Failed {
        status: None,
        detail: "the provider has no batch: section".into(),
    })?;
    let (bucket, _) = batch.bucket_and_prefix();
    if provider.kind == Kind::Bedrock {
        let region = provider.region.as_deref().unwrap_or_default();
        return Ok(match &batch.storage_url {
            Some(base) => format!("{base}/{bucket}/{key}"),
            None => format!("https://{bucket}.s3.{region}.amazonaws.com/{key}"),
        });
    }
    let base = batch
        .storage_url
        .as_deref()
        .unwrap_or("https://storage.googleapis.com");
    let name = sigv4::uri_encode(key, false);
    Ok(if op == Method::POST {
        format!("{base}/upload/storage/v1/b/{bucket}/o?uploadType=media&name={name}")
    } else if op == Method::GET {
        format!("{base}/storage/v1/b/{bucket}/o/{name}?alt=media")
    } else {
        format!("{base}/storage/v1/b/{bucket}/o/{name}")
    })
}

/// The object key under the provider's prefix.
pub(crate) fn key(provider: &Upstream, rest: &str) -> String {
    let prefix = provider
        .batch
        .as_ref()
        .map_or("", |b| b.bucket_and_prefix().1);
    format!("{prefix}{rest}")
}

/// The bucket URI (`s3://` or `gs://`) of a key.
fn uri_of(provider: &Upstream, key: &str) -> String {
    let (scheme, bucket) = provider.batch.as_ref().map_or(("", ""), |b| {
        (
            b.bucket.split("://").next().unwrap_or_default(),
            b.bucket_and_prefix().0,
        )
    });
    format!("{scheme}://{bucket}/{key}")
}

pub(crate) async fn put(
    state: &AppState,
    provider: &Upstream,
    key: &str,
    body: Bytes,
) -> Result<(), Failed> {
    let method = if provider.kind == Kind::Bedrock {
        Method::PUT
    } else {
        Method::POST
    };
    let url = object_url(provider, key, &method)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/jsonl"),
    );
    send(state, provider, method, &url, headers, body, "s3")
        .await
        .map(|_| ())
}

pub(crate) async fn get(state: &AppState, provider: &Upstream, key: &str) -> Result<Bytes, Failed> {
    let url = object_url(provider, key, &Method::GET)?;
    send(
        state,
        provider,
        Method::GET,
        &url,
        HeaderMap::new(),
        Bytes::new(),
        "s3",
    )
    .await
}

pub(crate) async fn delete(state: &AppState, provider: &Upstream, key: &str) -> Result<(), Failed> {
    let url = object_url(provider, key, &Method::DELETE)?;
    match send(
        state,
        provider,
        Method::DELETE,
        &url,
        HeaderMap::new(),
        Bytes::new(),
        "s3",
    )
    .await
    {
        Ok(_) => Ok(()),
        Err(failed) if failed.status == Some(StatusCode::NOT_FOUND) => Ok(()),
        Err(failed) => Err(failed),
    }
}

/// The names of the Cloud Storage objects under `prefix`, every page of the listing.
async fn list(state: &AppState, provider: &Upstream, prefix: &str) -> Result<Vec<String>, Failed> {
    let batch = provider.batch.as_ref().ok_or(Failed {
        status: None,
        detail: "the provider has no batch: section".into(),
    })?;
    let base = batch
        .storage_url
        .as_deref()
        .unwrap_or("https://storage.googleapis.com");
    let (bucket, _) = batch.bucket_and_prefix();
    let mut names = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let mut url = format!(
            "{base}/storage/v1/b/{bucket}/o?prefix={}",
            sigv4::uri_encode(prefix, false)
        );
        if let Some(token) = &token {
            url.push_str(&format!("&pageToken={}", sigv4::uri_encode(token, false)));
        }
        let bytes = send(
            state,
            provider,
            Method::GET,
            &url,
            HeaderMap::new(),
            Bytes::new(),
            "s3",
        )
        .await?;
        let listing: Value = serde_json::from_slice(&bytes).unwrap_or_default();
        names.extend(
            listing["items"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|i| i["name"].as_str().map(String::from)),
        );
        // A token that does not move on would loop forever: the listing ends there.
        match listing["nextPageToken"].as_str() {
            Some(next) if !next.is_empty() && token.as_deref() != Some(next) => {
                token = Some(next.to_string());
            }
            _ => return Ok(names),
        }
    }
}

/// The base of the provider's batch API: Bedrock's control plane, or Vertex AI's location.
fn api_base(provider: &Upstream) -> String {
    if let Some(url) = provider.batch.as_ref().and_then(|b| b.url.clone()) {
        return url;
    }
    if provider.kind == Kind::Bedrock {
        return provider
            .url
            .replacen("://bedrock-runtime.", "://bedrock.", 1);
    }
    // .../v1/projects/P/locations/L/publishers/google: the jobs live under the location.
    provider
        .url
        .split_once("/publishers/")
        .map_or(provider.url.clone(), |(base, _)| base.to_string())
}

/// The root a Vertex AI job's name is read under: everything before `/v1/`, and `/v1`.
fn vertex_root(provider: &Upstream) -> String {
    let base = api_base(provider);
    base.split_once("/v1/")
        .map_or(base.clone(), |(root, _)| format!("{root}/v1"))
}

fn json_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers
}

/// Starts the provider's job on `input_key`, writing to `output_key`. Returns the job's ARN (Bedrock) or name
/// (Vertex AI).
pub(crate) async fn create_job(
    state: &AppState,
    provider: &Upstream,
    name: &str,
    model: &str,
    input_key: &str,
    output_key: &str,
) -> Result<String, Failed> {
    let batch = provider.batch.as_ref().ok_or(Failed {
        status: None,
        detail: "the provider has no batch: section".into(),
    })?;
    let (url, body) = if provider.kind == Kind::Bedrock {
        let model_id = provider
            .upstream_models
            .get(model)
            .map_or(model, String::as_str);
        (
            format!("{}/model-invocation-job", api_base(provider)),
            json!({
                "jobName": name,
                "clientRequestToken": name,
                "roleArn": batch.role_arn,
                "modelId": model_id,
                "inputDataConfig": { "s3InputDataConfig": { "s3Uri": uri_of(provider, input_key), "s3InputFormat": "JSONL" } },
                "outputDataConfig": { "s3OutputDataConfig": { "s3Uri": uri_of(provider, output_key) } },
            }),
        )
    } else {
        let publisher = if provider.kind == Kind::VertexAnthropic {
            "anthropic"
        } else {
            "google"
        };
        (
            format!("{}/batchPredictionJobs", api_base(provider)),
            json!({
                "displayName": name,
                "model": format!("publishers/{publisher}/models/{model}"),
                "inputConfig": { "instancesFormat": "jsonl", "gcsSource": { "uris": [uri_of(provider, input_key)] } },
                "outputConfig": { "predictionsFormat": "jsonl", "gcsDestination": { "outputUriPrefix": uri_of(provider, output_key) } },
            }),
        )
    };
    let answer = send(
        state,
        provider,
        Method::POST,
        &url,
        json_headers(),
        Bytes::from(body.to_string()),
        "bedrock",
    )
    .await?;
    let answer: Value = serde_json::from_slice(&answer).unwrap_or_default();
    let id = if provider.kind == Kind::Bedrock {
        &answer["jobArn"]
    } else {
        &answer["name"]
    };
    id.as_str().map(String::from).ok_or(Failed {
        status: None,
        detail: "the provider created a job and named no jobArn or name".into(),
    })
}

/// A job's path under the API: Bedrock's ARN encoded, Vertex AI's name as it is.
fn job_url(provider: &Upstream, job: &str) -> String {
    if provider.kind == Kind::Bedrock {
        format!(
            "{}/model-invocation-job/{}",
            api_base(provider),
            sigv4::uri_encode(job, false)
        )
    } else {
        format!("{}/{job}", vertex_root(provider))
    }
}

pub(crate) async fn job(state: &AppState, provider: &Upstream, job: &str) -> Result<Value, Failed> {
    let answer = send(
        state,
        provider,
        Method::GET,
        &job_url(provider, job),
        HeaderMap::new(),
        Bytes::new(),
        "bedrock",
    )
    .await?;
    Ok(serde_json::from_slice(&answer).unwrap_or_default())
}

pub(crate) async fn cancel(state: &AppState, provider: &Upstream, job: &str) -> Result<(), Failed> {
    let url = if provider.kind == Kind::Bedrock {
        format!("{}/stop", job_url(provider, job))
    } else {
        format!("{}:cancel", job_url(provider, job))
    };
    send(
        state,
        provider,
        Method::POST,
        &url,
        json_headers(),
        Bytes::from_static(b"{}"),
        "bedrock",
    )
    .await
    .map(|_| ())
}

/// A job's state as an OpenAI batch status.
pub(crate) fn status(kind: Kind, job: &Value) -> &'static str {
    if kind == Kind::Bedrock {
        return match job["status"].as_str().unwrap_or_default() {
            "InProgress" => "in_progress",
            "Completed" | "PartiallyCompleted" => "completed",
            "Failed" => "failed",
            "Stopping" => "cancelling",
            "Stopped" => "cancelled",
            "Expired" => "expired",
            _ => "validating",
        };
    }
    match job["state"].as_str().unwrap_or_default() {
        "JOB_STATE_RUNNING" | "JOB_STATE_UPDATING" | "JOB_STATE_PAUSED" => "in_progress",
        "JOB_STATE_SUCCEEDED" | "JOB_STATE_PARTIALLY_SUCCEEDED" => "completed",
        "JOB_STATE_FAILED" => "failed",
        "JOB_STATE_CANCELLING" => "cancelling",
        "JOB_STATE_CANCELLED" => "cancelled",
        "JOB_STATE_EXPIRED" => "expired",
        _ => "validating",
    }
}

/// One result line: its custom_id, whether it succeeded, its usage, and the line as OpenAI's output (or error) file
/// writes it.
pub(crate) struct Line {
    pub(crate) custom_id: String,
    pub(crate) ok: bool,
    pub(crate) usage: Option<Usage>,
    pub(crate) openai: Value,
}

/// Reads every result line the job wrote. `input_name` is the input file's name (Bedrock names its output after
/// it), `job` the job as the provider last described it. `ids` maps a Gemini request's key to its custom_id.
pub(crate) async fn results(
    state: &AppState,
    provider: &Upstream,
    job: &Value,
    output_key: &str,
    input_name: &str,
    ids: &Map<String, Value>,
    model: &str,
) -> Result<Vec<Line>, Failed> {
    let created = crate::batch::now_secs();
    let mut raw = Vec::new();
    if provider.kind == Kind::Bedrock {
        let arn = job["jobArn"].as_str().unwrap_or_default();
        let id = arn.rsplit('/').next().unwrap_or_default();
        raw.push(
            get(
                state,
                provider,
                &format!("{output_key}{id}/{input_name}.out"),
            )
            .await?,
        );
    } else {
        for name in list(state, provider, output_key).await? {
            if name.ends_with(".jsonl") {
                raw.push(get(state, provider, &name).await?);
            }
        }
    }
    let mut lines = Vec::new();
    for bytes in raw {
        for (n, line) in bytes
            .split(|b| *b == b'\n')
            .filter(|l| !l.iter().all(u8::is_ascii_whitespace))
            .enumerate()
        {
            let Ok(line) = serde_json::from_slice::<Value>(line) else {
                continue;
            };
            let n = lines.len() + n;
            lines.push(read_line(provider.kind, &line, ids, model, created, n));
        }
    }
    Ok(lines)
}

fn read_line(
    kind: Kind,
    line: &Value,
    ids: &Map<String, Value>,
    model: &str,
    created: u64,
    n: usize,
) -> Line {
    let (custom_id, answer, error) = match kind {
        Kind::Bedrock => (
            line["recordId"].as_str().unwrap_or_default().to_string(),
            line.get("modelOutput").filter(|v| v.is_object()),
            line.get("error").filter(|v| !v.is_null()).map(|e| {
                e["errorMessage"]
                    .as_str()
                    .map_or_else(|| e.to_string(), String::from)
            }),
        ),
        Kind::VertexAnthropic => (
            line["custom_id"].as_str().unwrap_or_default().to_string(),
            line.get("response").filter(|v| v.is_object()),
            vertex_error(line),
        ),
        _ => (
            ids.get(&request_key(&line["request"]))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            line.get("response")
                .filter(|v| v.as_object().is_some_and(|m| !m.is_empty())),
            vertex_error(line),
        ),
    };
    let translated = match (answer, &error) {
        (Some(answer), None) => {
            let out = if kind.google() {
                gemini::gemini_to_openai_response(answer, created)
            } else {
                translate::anthropic_to_openai_response(answer, created)
            };
            out.map_err(|e| e.to_string()).map(|mut body| {
                body["model"] = model.into();
                (body, Usage::from_body(answer.to_string().as_bytes()))
            })
        }
        (_, Some(error)) => Err(error.clone()),
        (None, None) => Err("the provider wrote no answer for this line".into()),
    };
    let id = format!("batch_req_{n}");
    match translated {
        Ok((body, usage)) => Line {
            custom_id: custom_id.clone(),
            ok: true,
            usage,
            openai: json!({ "id": id, "custom_id": custom_id, "response": { "status_code": 200, "request_id": "", "body": body }, "error": null }),
        },
        Err(message) => Line {
            custom_id: custom_id.clone(),
            ok: false,
            usage: None,
            openai: json!({ "id": id, "custom_id": custom_id, "response": null, "error": { "code": "provider_error", "message": message } }),
        },
    }
}

/// A Vertex AI output line's error: its `status`, when that is not empty.
fn vertex_error(line: &Value) -> Option<String> {
    match &line["status"] {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Object(_) => Some(line["status"].to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_gemini_request_key_ignores_the_order_of_fields() {
        let a = json!({"contents":[{"role":"user","parts":[{"text":"hi"}]}],"generationConfig":{"maxOutputTokens":5,"temperature":1}});
        let b = json!({"generationConfig":{"temperature":1,"maxOutputTokens":5},"contents":[{"parts":[{"text":"hi"}],"role":"user"}]});
        assert_eq!(request_key(&a), request_key(&b));
    }

    #[test]
    fn job_states_map_to_openai_statuses() {
        assert_eq!(
            status(Kind::Bedrock, &json!({"status":"PartiallyCompleted"})),
            "completed"
        );
        assert_eq!(
            status(Kind::Bedrock, &json!({"status":"Submitted"})),
            "validating"
        );
        assert_eq!(
            status(Kind::Vertex, &json!({"state":"JOB_STATE_CANCELLED"})),
            "cancelled"
        );
        assert_eq!(
            status(Kind::VertexAnthropic, &json!({"state":"JOB_STATE_RUNNING"})),
            "in_progress"
        );
    }
}
