//! Acceptance tests for Bedrock batch inference and Vertex AI batch prediction behind `/v1/files` and `/v1/batches`:
//! Enterplace translates and keeps the batch file in the provider's bucket, runs the provider's job, meters its results
//! per line at batch prices, and serves them as OpenAI output files, owned and governed as OpenAI batches are.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Request, State},
    http::{Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use enterplace_core::id::sha256_hex;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type Error = Box<dyn std::error::Error>;

const DANA: &str = "enterplace_cloudbatch_dana_key_000000";
const OMER: &str = "enterplace_cloudbatch_omer_key_000000";
const BOUNDARY: &str = "enterplaceboundary";
const ARN: &str = "arn:aws:bedrock:us-east-1:123456789012:model-invocation-job/job1";

/// The mock cloud: objects by bucket and key, the jobs created, and every request's method, path and headers.
#[derive(Default)]
struct Cloud {
    objects: HashMap<String, Vec<u8>>,
    jobs: Vec<Value>,
    seen: Vec<(String, String, Option<String>)>,
}

type Shared = Arc<Mutex<Cloud>>;

fn reply(status: StatusCode, body: Value) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

fn message(text: &str, input: u64, output: u64) -> Value {
    json!({"id":"m","type":"message","role":"assistant","model":"x","content":[{"type":"text","text":text}],"stop_reason":"end_turn","usage":{"input_tokens":input,"output_tokens":output}})
}

/// What the job writes for each input line: an answer with usage, and an error for the line whose custom_id is "bad".
fn run_job(cloud: &mut Cloud, job: &Value) {
    if let Some(input) = job["inputDataConfig"]["s3InputDataConfig"]["s3Uri"].as_str() {
        let input = input.trim_start_matches("s3://").to_string();
        let output = job["outputDataConfig"]["s3OutputDataConfig"]["s3Uri"]
            .as_str()
            .unwrap_or_default()
            .trim_start_matches("s3://")
            .to_string();
        let name = input.rsplit('/').next().unwrap_or_default().to_string();
        let lines =
            String::from_utf8_lossy(cloud.objects.get(&input).map_or(&[][..], |v| v)).into_owned();
        let mut out = String::new();
        for line in lines.lines() {
            let line: Value = serde_json::from_str(line).unwrap_or_default();
            let id = line["recordId"].clone();
            let row = if id == "bad" {
                json!({"recordId": id, "modelInput": line["modelInput"], "error": {"errorCode": 400, "errorMessage": "bad request"}})
            } else {
                json!({"recordId": id, "modelInput": line["modelInput"], "modelOutput": message("mail maya@example.com", 1000, 100)})
            };
            out.push_str(&row.to_string());
            out.push('\n');
        }
        cloud
            .objects
            .insert(format!("{output}job1/{name}.out"), out.into_bytes());
        return;
    }
    let input = job["inputConfig"]["gcsSource"]["uris"][0]
        .as_str()
        .unwrap_or_default()
        .trim_start_matches("gs://")
        .to_string();
    let output = job["outputConfig"]["gcsDestination"]["outputUriPrefix"]
        .as_str()
        .unwrap_or_default()
        .trim_start_matches("gs://")
        .to_string();
    let lines =
        String::from_utf8_lossy(cloud.objects.get(&input).map_or(&[][..], |v| v)).into_owned();
    // Vertex AI shards its output: here one file per line, so reading every line needs every page of the listing.
    for (n, line) in lines.lines().enumerate() {
        let line: Value = serde_json::from_str(line).unwrap_or_default();
        let row = if line.get("custom_id").is_some() {
            json!({"custom_id": line["custom_id"], "request": line["request"], "response": message("fine", 500, 50)})
        } else {
            // The request comes back with its fields in another order, as nothing promises the same order.
            let mut request = serde_json::Map::new();
            if let Some(map) = line["request"].as_object() {
                for (k, v) in map.iter().rev() {
                    request.insert(k.clone(), v.clone());
                }
            }
            json!({"status": "", "processed_time": "2026-11-14T00:00:00Z", "request": request, "response": {"candidates":[{"content":{"role":"model","parts":[{"text":"fine"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":200,"candidatesTokenCount":20,"totalTokenCount":220}}})
        };
        cloud.objects.insert(
            format!("{output}/prediction-model-1/predictions_{n:05}.jsonl"),
            format!("{row}\n").into_bytes(),
        );
    }
}

async fn handle(State(cloud): State<Shared>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let bytes = body
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    let path = parts.uri.path().to_string();
    let query = parts.uri.query().unwrap_or_default().to_string();
    let Ok(mut cloud) = cloud.lock() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let auth = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    cloud
        .seen
        .push((parts.method.to_string(), path.clone(), auth));
    let decode = |s: &str| s.replace("%2F", "/").replace("%3A", ":");
    let method = parts.method.clone();
    // Bedrock's control plane.
    if path == "/model-invocation-job" && method == Method::POST {
        let job: Value = serde_json::from_slice(&bytes).unwrap_or_default();
        cloud.jobs.push(job);
        return reply(StatusCode::OK, json!({ "jobArn": ARN }));
    }
    if let Some(rest) = path.strip_prefix("/model-invocation-job/") {
        if rest.ends_with("/stop") {
            return reply(StatusCode::OK, json!({}));
        }
        let Some(job) = cloud.jobs.last().cloned() else {
            return reply(StatusCode::NOT_FOUND, json!({"message": "no job"}));
        };
        run_job(&mut cloud, &job);
        return reply(
            StatusCode::OK,
            json!({ "jobArn": decode(rest), "status": "Completed" }),
        );
    }
    // Vertex AI.
    if path.ends_with("/batchPredictionJobs") && method == Method::POST {
        let job: Value = serde_json::from_slice(&bytes).unwrap_or_default();
        cloud.jobs.push(job);
        return reply(
            StatusCode::OK,
            json!({ "name": "projects/p/locations/l/batchPredictionJobs/77", "state": "JOB_STATE_PENDING" }),
        );
    }
    if path == "/v1/projects/p/locations/l/batchPredictionJobs/77" {
        let Some(job) = cloud.jobs.last().cloned() else {
            return reply(StatusCode::NOT_FOUND, json!({}));
        };
        run_job(&mut cloud, &job);
        return reply(
            StatusCode::OK,
            json!({ "name": "projects/p/locations/l/batchPredictionJobs/77", "state": "JOB_STATE_SUCCEEDED" }),
        );
    }
    // Cloud Storage's JSON API.
    let param = |name: &str| {
        query
            .split('&')
            .find_map(|p| p.strip_prefix(&format!("{name}=")))
            .map(decode)
    };
    if let Some(bucket) = path.strip_prefix("/upload/storage/v1/b/") {
        let bucket = bucket.trim_end_matches("/o");
        let key = format!("{bucket}/{}", param("name").unwrap_or_default());
        cloud.objects.insert(key, bytes.to_vec());
        return reply(StatusCode::OK, json!({}));
    }
    if let Some(rest) = path.strip_prefix("/storage/v1/b/") {
        let (bucket, object) = rest.split_once("/o").unwrap_or((rest, ""));
        let object = decode(object.trim_start_matches('/'));
        if object.is_empty() {
            // One object a page, so a reader that ignores nextPageToken misses the rest.
            let prefix = format!("{bucket}/{}", param("prefix").unwrap_or_default());
            let after = param("pageToken").unwrap_or_default();
            // In name order, as Cloud Storage lists, so a page token is a place in the listing.
            let mut names: Vec<&String> = cloud
                .objects
                .keys()
                .filter(|k| k.starts_with(&prefix) && k.as_str() > after.as_str())
                .collect();
            names.sort();
            let mut keys = names.into_iter();
            let Some(key) = keys.next() else {
                return reply(StatusCode::OK, json!({}));
            };
            let mut page =
                json!({ "items": [{ "name": key.trim_start_matches(&format!("{bucket}/")) }] });
            if keys.next().is_some() {
                page["nextPageToken"] = key.as_str().into();
            }
            return reply(StatusCode::OK, page);
        }
        let key = format!("{bucket}/{object}");
        if method == Method::DELETE {
            cloud.objects.remove(&key);
            return StatusCode::NO_CONTENT.into_response();
        }
        return match cloud.objects.get(&key) {
            Some(found) => (StatusCode::OK, found.clone()).into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    // S3, by path.
    let key = path.trim_start_matches('/').to_string();
    match method {
        Method::PUT => {
            if parts.headers.get("x-amz-content-sha256").is_none() {
                return StatusCode::FORBIDDEN.into_response();
            }
            cloud.objects.insert(key, bytes.to_vec());
            StatusCode::OK.into_response()
        }
        Method::DELETE => {
            cloud.objects.remove(&key);
            StatusCode::NO_CONTENT.into_response()
        }
        _ => match cloud.objects.get(&key) {
            Some(found) => (StatusCode::OK, found.clone()).into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        },
    }
}

async fn mock() -> Result<(u16, Shared), Error> {
    let cloud: Shared = Arc::default();
    let app = Router::new().fallback(handle).with_state(cloud.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((port, cloud))
}

fn setup(name: &str, port: u16, rule_extra: &str) -> Result<(PathBuf, PathBuf), Error> {
    let dir = std::env::temp_dir().join(format!(
        "enterplace-cloud-batches-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let policy = dir.join("enterplace.policy.yaml");
    std::fs::write(
        &policy,
        format!(
            "version: 1
providers:
  - name: bedrock
    kind: bedrock
    region: us-east-1
    url: http://127.0.0.1:{port}
    allow_private: true
    models: [claude-b]
    model_ids: {{ claude-b: anthropic.claude-b-v1:0 }}
    batch: {{ bucket: s3://bkt/enterplace/, role_arn: arn:aws:iam::123456789012:role/batch, url: http://127.0.0.1:{port}, storage_url: http://127.0.0.1:{port} }}
  - name: vertex
    kind: vertex
    url: http://127.0.0.1:{port}/v1/projects/p/locations/l/publishers/google
    allow_private: true
    key_env: VERTEX_TOKEN
    models: [gemini-v]
    batch: {{ bucket: gs://gbkt/enterplace, storage_url: http://127.0.0.1:{port} }}
  - name: vertex-claude
    kind: vertex_anthropic
    url: http://127.0.0.1:{port}/v1/projects/p/locations/l/publishers/anthropic
    allow_private: true
    key_env: VERTEX_TOKEN
    models: [claude-v]
    batch: {{ bucket: gs://gbkt/claude/, storage_url: http://127.0.0.1:{port} }}
aliases:
  - name: smart-eu
    deployments:
      - {{ provider: bedrock, model: claude-b, region: eu }}
prices:
  claude-b: {{ input: 1000, output: 2000, max_output: 100 }}
  gemini-v: {{ input: 1000, output: 2000, max_output: 100 }}
  claude-v: {{ input: 1000, output: 2000, max_output: 100 }}
guardrails:
  - name: answer-pii
    type: pii
    action: mask
    on: [answer]
rules:
  - name: data
    principals: {{ team: data }}
    models: [claude-b, gemini-v, claude-v, smart-eu]
    guardrails: [answer-pii]
    budget: {{ usd: 100, per: month }}
{rule_extra}"
        ),
    )?;
    std::fs::write(
        dir.join("enterplace.keys.yaml"),
        format!(
            "keys:\n  - name: dana\n    team: data\n    sha256: {}\n  - name: omer\n    team: data\n    sha256: {}\n",
            sha256_hex(DANA.as_bytes()),
            sha256_hex(OMER.as_bytes())
        ),
    )?;
    Ok((policy, dir.join("enterplace-audit.jsonl")))
}

fn env(variable: &str) -> Option<String> {
    match variable {
        "AWS_ACCESS_KEY_ID" => Some("AKIDEXAMPLE".into()),
        "AWS_SECRET_ACCESS_KEY" => Some("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into()),
        "AWS_EC2_METADATA_DISABLED" => Some("true".into()),
        "VERTEX_TOKEN" => Some("vertex-token".into()),
        _ => None,
    }
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    key: &str,
    content_type: &str,
    body: Vec<u8>,
) -> Result<(StatusCode, String), Error> {
    let response = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method(method)
                .uri(path)
                .header(header::AUTHORIZATION, format!("Bearer {key}"))
                .header(header::CONTENT_TYPE, content_type)
                .body(Body::from(body))?,
        )
        .await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, String::from_utf8(body.to_vec())?))
}

fn upload(lines: &[String]) -> Vec<u8> {
    let file: String = lines.iter().map(|l| format!("{l}\n")).collect();
    format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"purpose\"\r\n\r\nbatch\r\n--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"in.jsonl\"\r\nContent-Type: application/jsonl\r\n\r\n{file}\r\n--{BOUNDARY}--\r\n"
    )
    .into_bytes()
}

fn line(id: &str, model: &str, text: &str) -> String {
    format!(
        r#"{{"custom_id":"{id}","method":"POST","url":"/v1/chat/completions","body":{{"model":"{model}","max_tokens":100,"messages":[{{"role":"user","content":"{text}"}}]}}}}"#
    )
}

fn form() -> String {
    format!("multipart/form-data; boundary={BOUNDARY}")
}

fn records(path: &PathBuf) -> Result<Vec<Value>, Error> {
    std::fs::read_to_string(path)?
        .lines()
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn id_of(body: &str) -> Result<String, Error> {
    let value: Value = serde_json::from_str(body)?;
    Ok(value["id"].as_str().ok_or("no id")?.to_string())
}

fn create(file: &str) -> Vec<u8> {
    format!(r#"{{"input_file_id":"{file}","endpoint":"/v1/chat/completions","completion_window":"24h"}}"#).into_bytes()
}

#[tokio::test]
async fn a_bedrock_batch_runs_on_s3_is_metered_per_line_at_batch_price_and_owned()
-> Result<(), Error> {
    let (port, cloud) = mock().await?;
    let (policy, audit) = setup("bedrock", port, "")?;
    let gw = enterplace_server::governed(&policy, None, &env)?;
    let app = gw.router.clone();

    let (status, body) = call(
        &app,
        "POST",
        "/v1/files",
        DANA,
        &form(),
        upload(&[
            line("a", "claude-b", "hi"),
            line("bad", "claude-b", "there"),
        ]),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let file = id_of(&body)?;
    assert!(file.starts_with("file-enterplace-"), "{file}");
    {
        let cloud = cloud.lock().map_err(|_| "poisoned")?;
        let kept = cloud
            .objects
            .get(&format!("bkt/enterplace/input/{file}.jsonl"))
            .ok_or("the file is not in the bucket")?;
        let first: Value = serde_json::from_str(
            String::from_utf8_lossy(kept)
                .lines()
                .next()
                .ok_or("empty")?,
        )?;
        assert_eq!(first["recordId"], "a");
        assert_eq!(
            first["modelInput"]["anthropic_version"],
            "bedrock-2023-05-31"
        );
        assert!(
            first["modelInput"]["model"].is_null(),
            "the model goes in the job: {first}"
        );
        let put = cloud
            .seen
            .iter()
            .find(|(m, _, _)| m == "PUT")
            .ok_or("no PUT")?;
        assert!(
            put.2.as_deref().is_some_and(
                |a| a.starts_with("AWS4-HMAC-SHA256") && a.contains("/s3/aws4_request")
            ),
            "{put:?}"
        );
    }
    let (status, _) = call(
        &app,
        "GET",
        &format!("/v1/files/{file}"),
        OMER,
        "application/json",
        vec![],
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "another person cannot see the file"
    );
    let (status, body) = call(
        &app,
        "POST",
        "/v1/batches",
        OMER,
        "application/json",
        create(&file),
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    let (status, body) = call(
        &app,
        "POST",
        "/v1/batches",
        DANA,
        "application/json",
        create(&file),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let batch = id_of(&body)?;
    {
        let cloud = cloud.lock().map_err(|_| "poisoned")?;
        let job = cloud.jobs.last().ok_or("no job")?;
        assert_eq!(job["modelId"], "anthropic.claude-b-v1:0");
        assert_eq!(job["roleArn"], "arn:aws:iam::123456789012:role/batch");
        assert_eq!(
            job["inputDataConfig"]["s3InputDataConfig"]["s3Uri"],
            format!("s3://bkt/enterplace/input/{file}.jsonl")
        );
    }
    let (status, _) = call(
        &app,
        "GET",
        &format!("/v1/batches/{batch}"),
        OMER,
        "application/json",
        vec![],
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, body) = call(
        &app,
        "GET",
        &format!("/v1/batches/{batch}"),
        DANA,
        "application/json",
        vec![],
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let object: Value = serde_json::from_str(&body)?;
    assert_eq!(object["status"], "completed", "{object}");
    assert_eq!(object["request_counts"]["completed"], 1);
    assert_eq!(object["request_counts"]["failed"], 1);
    let output = object["output_file_id"]
        .as_str()
        .ok_or("no output file")?
        .to_string();
    assert!(object["error_file_id"].is_string(), "{object}");

    let usage: Vec<Value> = records(&audit)?
        .into_iter()
        .filter(|r| r["event"] == "usage" && r["batch"] == batch.as_str())
        .collect();
    assert_eq!(usage.len(), 2, "one usage record per line: {usage:?}");
    let a = usage.iter().find(|r| r["custom_id"] == "a").ok_or("no a")?;
    let charged = a["charged_usd"].as_f64().ok_or("no charge")?;
    assert!(
        (charged - 0.5 * (1000.0 * 1000.0 + 100.0 * 2000.0) / 1e6).abs() < 1e-9,
        "batch price: {charged}"
    );
    assert_eq!(a["provider"], "bedrock");
    let bad = usage
        .iter()
        .find(|r| r["custom_id"] == "bad")
        .ok_or("no bad")?;
    assert_eq!(bad["charged_usd"].as_f64(), Some(0.0));

    // The results are an OpenAI output file, the batch owner's, with the answer guardrails run on download.
    let (status, _) = call(
        &app,
        "GET",
        &format!("/v1/files/{output}/content"),
        OMER,
        "application/json",
        vec![],
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, content) = call(
        &app,
        "GET",
        &format!("/v1/files/{output}/content"),
        DANA,
        "application/json",
        vec![],
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{content}");
    let first: Value = serde_json::from_str(content.lines().next().ok_or("no line")?)?;
    assert_eq!(first["custom_id"], "a");
    assert_eq!(first["response"]["status_code"], 200);
    let said = first["response"]["body"]["choices"][0]["message"]["content"]
        .as_str()
        .ok_or("no content")?;
    assert!(
        said.starts_with("mail ") && !said.contains("maya@example.com"),
        "masked on download: {said}"
    );

    // A second read meters nothing more; the list shows the batch to its owner only.
    call(
        &app,
        "GET",
        &format!("/v1/batches/{batch}"),
        DANA,
        "application/json",
        vec![],
    )
    .await?;
    let again = records(&audit)?
        .into_iter()
        .filter(|r| r["event"] == "usage" && r["batch"] == batch.as_str())
        .count();
    assert_eq!(again, 2, "a batch is settled once");
    let (_, list) = call(&app, "GET", "/v1/batches", DANA, "application/json", vec![]).await?;
    assert!(list.contains(&batch), "{list}");
    let (_, list) = call(&app, "GET", "/v1/batches", OMER, "application/json", vec![]).await?;
    assert!(!list.contains(&batch), "{list}");

    let (status, body) = call(
        &app,
        "DELETE",
        &format!("/v1/files/{file}"),
        DANA,
        "application/json",
        vec![],
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        !cloud
            .lock()
            .map_err(|_| "poisoned")?
            .objects
            .contains_key(&format!("bkt/enterplace/input/{file}.jsonl"))
    );
    Ok(())
}

#[tokio::test]
async fn vertex_batches_run_for_gemini_and_claude_on_cloud_storage() -> Result<(), Error> {
    let (port, cloud) = mock().await?;
    let (policy, audit) = setup("vertex", port, "")?;
    let gw = enterplace_server::governed(&policy, None, &env)?;
    let app = gw.router.clone();
    for (model, prefix, input, output) in [
        ("gemini-v", "gbkt/enterplace/", 200.0, 20.0),
        ("claude-v", "gbkt/claude/", 500.0, 50.0),
    ] {
        let (status, body) = call(
            &app,
            "POST",
            "/v1/files",
            DANA,
            &form(),
            upload(&[line("x", model, "hi"), line("y", model, "there")]),
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        let file = id_of(&body)?;
        {
            let cloud = cloud.lock().map_err(|_| "poisoned")?;
            let kept = cloud
                .objects
                .get(&format!("{prefix}input/{file}.jsonl"))
                .ok_or("not in the bucket")?;
            let first: Value = serde_json::from_str(
                String::from_utf8_lossy(kept)
                    .lines()
                    .next()
                    .ok_or("empty")?,
            )?;
            if model == "gemini-v" {
                assert!(first["request"]["contents"].is_array(), "{first}");
            } else {
                assert_eq!(first["custom_id"], "x");
                assert_eq!(first["request"]["anthropic_version"], "vertex-2023-10-16");
            }
            let upload = cloud
                .seen
                .iter()
                .rev()
                .find(|(m, p, _)| m == "POST" && p.starts_with("/upload/"))
                .ok_or("no upload")?;
            assert_eq!(upload.2.as_deref(), Some("Bearer vertex-token"));
        }
        let (status, body) = call(
            &app,
            "POST",
            "/v1/batches",
            DANA,
            "application/json",
            create(&file),
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        let batch = id_of(&body)?;
        {
            let cloud = cloud.lock().map_err(|_| "poisoned")?;
            let job = cloud.jobs.last().ok_or("no job")?;
            let publisher = if model == "gemini-v" {
                "google"
            } else {
                "anthropic"
            };
            assert_eq!(
                job["model"],
                format!("publishers/{publisher}/models/{model}")
            );
        }
        let (status, body) = call(
            &app,
            "GET",
            &format!("/v1/batches/{batch}"),
            DANA,
            "application/json",
            vec![],
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        let object: Value = serde_json::from_str(&body)?;
        assert_eq!(object["status"], "completed", "{object}");
        let usage: Vec<Value> = records(&audit)?
            .into_iter()
            .filter(|r| r["event"] == "usage" && r["batch"] == batch.as_str())
            .collect();
        assert_eq!(usage.len(), 2, "{usage:?}");
        for id in ["x", "y"] {
            let one = usage
                .iter()
                .find(|r| r["custom_id"] == id)
                .ok_or("a line lost its custom_id")?;
            let charged = one["charged_usd"].as_f64().ok_or("no charge")?;
            assert!(
                (charged - 0.5 * (input * 1000.0 + output * 2000.0) / 1e6).abs() < 1e-9,
                "{model}: {charged}"
            );
        }
        let output_file = object["output_file_id"].as_str().ok_or("no output")?;
        let (status, content) = call(
            &app,
            "GET",
            &format!("/v1/files/{output_file}/content"),
            DANA,
            "application/json",
            vec![],
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{content}");
        assert!(
            content.contains("\"custom_id\":\"x\"") && content.contains("chat.completion"),
            "{content}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn residency_rpm_and_batch_limits_govern_cloud_batches() -> Result<(), Error> {
    let (port, _cloud) = mock().await?;
    let (policy, _) = setup(
        "residency",
        port,
        "    regions: [eu]\n    batch: { max_lines: 1 }\n",
    )?;
    let gw = enterplace_server::governed(&policy, None, &env)?;
    let app = gw.router.clone();
    // The model served directly shows no region: refused. The alias's eu deployment on Bedrock does.
    let (status, body) = call(
        &app,
        "POST",
        "/v1/files",
        DANA,
        &form(),
        upload(&[line("a", "claude-b", "hi")]),
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("region_not_allowed"), "{body}");
    let (status, body) = call(
        &app,
        "POST",
        "/v1/files",
        DANA,
        &form(),
        upload(&[line("a", "smart-eu", "hi"), line("b", "smart-eu", "hi")]),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("batch_too_many_lines"), "{body}");
    let (status, body) = call(
        &app,
        "POST",
        "/v1/files",
        DANA,
        &form(),
        upload(&[line("a", "smart-eu", "hi")]),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let file = id_of(&body)?;
    let (status, body) = call(
        &app,
        "POST",
        "/v1/batches",
        DANA,
        "application/json",
        create(&file),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = call(&app, "GET", "/v1/files", DANA, "application/json", vec![]).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains(&file), "{body}");

    let (policy, _) = setup("cloud-rpm", port, "    rate: { rpm: 1 }\n")?;
    let gw = enterplace_server::governed(&policy, None, &env)?;
    let app = gw.router.clone();
    let (status, body) = call(
        &app,
        "POST",
        "/v1/files",
        DANA,
        &form(),
        upload(&[line("a", "claude-b", "hi")]),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = call(
        &app,
        "POST",
        "/v1/batches",
        DANA,
        "application/json",
        create(&id_of(&body)?),
    )
    .await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");

    // Observe mode: residency records what it would refuse and lets the batch through.
    let (policy, audit) = setup("cloud-observe", port, "    regions: [eu]\n")?;
    let text = std::fs::read_to_string(&policy)?;
    std::fs::write(
        &policy,
        text.replacen("version: 1\n", "version: 1\nmode: observe\n", 1),
    )?;
    let gw = enterplace_server::governed(&policy, None, &env)?;
    let (status, body) = call(
        &gw.router,
        "POST",
        "/v1/files",
        DANA,
        &form(),
        upload(&[line("a", "claude-b", "hi")]),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let decided = records(&audit)?
        .into_iter()
        .find(|r| r["path"] == "/v1/files" && r["verdict"].is_string())
        .ok_or("no decision")?;
    assert!(
        decided.to_string().contains("region_not_allowed"),
        "{decided}"
    );
    let _ = Bytes::new();
    Ok(())
}
