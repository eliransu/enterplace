//! Acceptance tests for files, batches and fine-tuning jobs governed natively: each object is owned by the person who
//! created it, guardrails and the policy run on every batch line before the provider sees the file, a batch reserves
//! its estimate at batch prices, its results are metered per line, and the policy sets how long files are kept.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
    routing::{get, post},
};
use gantry_core::id::sha256_hex;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

type Error = Box<dyn std::error::Error>;

const DANA: &str = "gantry_batches_dana_key_000000000";
const OMER: &str = "gantry_batches_omer_key_000000000";
const ADMIN: &str = "gantry_batches_admin_key_00000000";
const BOUNDARY: &str = "gantryboundary";

/// What the provider saw: method, path, and body.
type Seen = Arc<Mutex<Vec<(String, String, Vec<u8>)>>>;

fn json(body: &'static str) -> ([(header::HeaderName, &'static str); 1], &'static str) {
    ([(header::CONTENT_TYPE, "application/json")], body)
}

async fn provider() -> Result<(u16, Seen), Error> {
    let seen: Seen = Arc::default();
    let note = seen.clone();
    let app = Router::new()
        .route("/v1/files", post(|| async { json(r#"{"id":"file-in","object":"file","purpose":"batch","bytes":10,"created_at":1,"filename":"in.jsonl"}"#) }))
        .route("/v1/files", get(|| async { json(r#"{"object":"list","data":[{"id":"file-in","object":"file"},{"id":"file-else","object":"file"}],"has_more":false}"#) }))
        .route("/v1/files/file-in", get(|| async { json(r#"{"id":"file-in","object":"file","purpose":"batch"}"#) }))
        .route("/v1/files/file-out/content", get(|| async {
            concat!(
                r#"{"id":"r1","custom_id":"a","response":{"status_code":200,"body":{"model":"model-a","usage":{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150}}},"error":null}"#, "\n",
                r#"{"id":"r2","custom_id":"b","response":{"status_code":200,"body":{"model":"model-a","usage":{"prompt_tokens":200,"completion_tokens":10,"total_tokens":210}}},"error":null}"#, "\n",
            )
        }))
        .route("/v1/batches", post(|| async { json(r#"{"id":"batch_1","object":"batch","status":"validating","input_file_id":"file-in","endpoint":"/v1/chat/completions"}"#) }))
        .route("/v1/batches/batch_1", get(|| async { json(r#"{"id":"batch_1","object":"batch","status":"completed","input_file_id":"file-in","output_file_id":"file-out","error_file_id":null}"#) }))
        .route("/v1/batches/batch_1/cancel", post(|| async { json(r#"{"id":"batch_1","object":"batch","status":"cancelling"}"#) }))
        .route("/v1/messages/batches", post(|| async { json(r#"{"id":"msgbatch_1","type":"message_batch","processing_status":"in_progress"}"#) }))
        .route("/v1/messages/batches/msgbatch_1", get(|| async { json(r#"{"id":"msgbatch_1","type":"message_batch","processing_status":"ended"}"#) }))
        .route("/v1/messages/batches/msgbatch_1/results", get(|| async {
            concat!(
                r#"{"custom_id":"x","result":{"type":"succeeded","message":{"id":"m","type":"message","role":"assistant","model":"claude-a","content":[],"usage":{"input_tokens":1000,"output_tokens":100}}}}"#, "\n",
                r#"{"custom_id":"y","result":{"type":"errored","error":{"type":"error","error":{"type":"invalid_request_error","message":"bad"}}}}"#, "\n",
            )
        }))
        .route("/v1/fine_tuning/jobs", post(|| async { json(r#"{"id":"ftjob-1","object":"fine_tuning.job","status":"queued","model":"model-a","training_file":"file-in"}"#) }))
        .route("/v1/chat/completions", post(|| async { json(r#"{"id":"c1","object":"chat.completion","model":"model-a","choices":[{"index":0,"message":{"role":"assistant","content":"Hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":1}}"#) }))
        .route("/v1/messages", post(|| async { json(r#"{"id":"msg_1","type":"message","role":"assistant","model":"claude-a","content":[{"type":"text","text":"Kept answer"}],"stop_reason":"end_turn","usage":{"input_tokens":5,"output_tokens":2}}"#) }))
        .route("/v1/responses", post(|| async { json(r#"{"id":"resp_bg","object":"response","status":"queued","background":true,"model":"model-a","output":[]}"#) }))
        .route("/v1/responses/resp_bg", get(|| async { json(r#"{"id":"resp_bg","object":"response","status":"completed","background":true,"model":"model-a","output":[],"usage":{"input_tokens":100,"output_tokens":10}}"#) }))
        .layer(axum::middleware::from_fn(move |request: Request<Body>, next: axum::middleware::Next| {
            let note = note.clone();
            async move {
                let (parts, body) = request.into_parts();
                let bytes = body.collect().await.map(|b| b.to_bytes()).unwrap_or_default();
                if let Ok(mut all) = note.lock() {
                    all.push((parts.method.to_string(), parts.uri.path().to_string(), bytes.to_vec()));
                }
                next.run(Request::from_parts(parts, Body::from(bytes))).await
            }
        }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((port, seen))
}

fn files(name: &str, port: u16, budget: &str) -> Result<(PathBuf, PathBuf), Error> {
    let dir = std::env::temp_dir().join(format!("gantry-batches-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let policy = dir.join("gantry.policy.yaml");
    std::fs::write(
        &policy,
        format!(
            "version: 1
providers:
  - name: mock
    kind: openai
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: MOCK_KEY
    models: [model-a]
  - name: claude
    kind: anthropic
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: MOCK_KEY
    models: [claude-a]
prices:
  model-a: {{ input: 1000, output: 2000, max_output: 100 }}
  claude-a: {{ input: 1000, output: 2000, max_output: 100 }}
guardrails:
  - name: no-secrets
    type: secrets
    action: block
rules:
  - name: data
    principals: {{ team: data }}
    models: [model-a, claude-a]
    guardrails: [no-secrets]
    file_retention_days: 2
{budget}"
        ),
    )?;
    let key = |name: &str, team: &str, key: &str, admin: bool| {
        format!(
            "  - name: {name}\n    team: {team}\n    sha256: {}\n{}",
            sha256_hex(key.as_bytes()),
            if admin { "    admin: true\n" } else { "" }
        )
    };
    std::fs::write(
        dir.join("gantry.keys.yaml"),
        format!(
            "keys:\n{}{}{}",
            key("dana", "data", DANA, false),
            key("omer", "data", OMER, false),
            key("ada", "data", ADMIN, true)
        ),
    )?;
    Ok((policy, dir.join("gantry-audit.jsonl")))
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
            Request::builder()
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

fn upload(lines: &[&str]) -> Vec<u8> {
    let mut file = String::new();
    for line in lines {
        file.push_str(line);
        file.push('\n');
    }
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

fn uploads(seen: &Seen) -> Result<Vec<Vec<u8>>, Error> {
    Ok(seen
        .lock()
        .map_err(|_| "poisoned")?
        .iter()
        .filter(|(m, p, _)| m == "POST" && p == "/v1/files")
        .map(|(_, _, b)| b.clone())
        .collect())
}

#[tokio::test]
async fn a_batch_file_with_a_blocked_or_refused_line_fails_naming_the_line() -> Result<(), Error> {
    let (port, seen) = provider().await?;
    let (policy, audit) = files("lines", port, "")?;
    let gw = gantry_server::governed(&policy, None, &|_| Some("provider-secret".into()))?;
    let app = gw.router.clone();

    let secret = "my key is AKIAIOSFODNN7EXAMPLE";
    let (status, body) = call(
        &app,
        "POST",
        "/v1/files",
        DANA,
        &form(),
        upload(&[&line("a", "model-a", "hi"), &line("b", "model-a", secret)]),
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body.contains("line 2"),
        "the refusal names the line: {body}"
    );

    let (status, body) = call(
        &app,
        "POST",
        "/v1/files",
        DANA,
        &form(),
        upload(&[&line("a", "model-a", "hi"), &line("b", "gpt-9", "hi")]),
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body.contains("line 2") && body.contains("gpt-9") && body.contains("model_not_allowed"),
        "{body}"
    );
    assert!(
        uploads(&seen)?.is_empty(),
        "the provider never saw a refused file"
    );
    let refused: Vec<Value> = records(&audit)?
        .into_iter()
        .filter(|r| r["path"] == "/v1/files" && r["verdict"] == "refused")
        .collect();
    assert_eq!(refused.len(), 2, "each refusal is recorded");
    Ok(())
}

#[tokio::test]
async fn files_and_batches_belong_to_their_creator_and_a_batch_is_metered_per_line()
-> Result<(), Error> {
    let (port, seen) = provider().await?;
    let (policy, audit) = files("owned", port, "    budget: { usd: 100, per: month }\n")?;
    let gw = gantry_server::governed(&policy, None, &|_| Some("provider-secret".into()))?;
    let app = gw.router.clone();

    let (status, body) = call(
        &app,
        "POST",
        "/v1/files",
        DANA,
        &form(),
        upload(&[&line("a", "model-a", "hi"), &line("b", "model-a", "there")]),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let sent = String::from_utf8(uploads(&seen)?.concat())?;
    assert!(
        sent.contains("name=\"expires_after[anchor]\"\r\n\r\ncreated_at")
            && sent.contains("name=\"expires_after[seconds]\"\r\n\r\n172800"),
        "the policy's retention (2 days) reaches the provider: {sent}"
    );

    // Someone else cannot read, list or use the file; an admin can read it.
    let (status, body) = call(
        &app,
        "GET",
        "/v1/files/file-in",
        OMER,
        "application/json",
        vec![],
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, _) = call(
        &app,
        "GET",
        "/v1/files/file-in",
        ADMIN,
        "application/json",
        vec![],
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = call(&app, "GET", "/v1/files", OMER, "application/json", vec![]).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        !body.contains("file-in"),
        "a list shows only your own: {body}"
    );
    let (_, body) = call(&app, "GET", "/v1/files", DANA, "application/json", vec![]).await?;
    assert!(
        body.contains("file-in") && !body.contains("file-else"),
        "{body}"
    );
    let create = br#"{"input_file_id":"file-in","endpoint":"/v1/chat/completions","completion_window":"24h"}"#;
    let (status, body) = call(
        &app,
        "POST",
        "/v1/batches",
        OMER,
        "application/json",
        create.to_vec(),
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    let (status, body) = call(
        &app,
        "POST",
        "/v1/batches",
        DANA,
        "application/json",
        create.to_vec(),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = call(
        &app,
        "POST",
        "/v1/batches/batch_1/cancel",
        OMER,
        "application/json",
        vec![],
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "another person cannot cancel it: {body}"
    );

    // Retrieving the finished batch settles it: one usage record per line, at half the model's price.
    let (status, body) = call(
        &app,
        "GET",
        "/v1/batches/batch_1",
        DANA,
        "application/json",
        vec![],
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mut lines = Vec::new();
    for _ in 0..50 {
        lines = records(&audit)?
            .into_iter()
            .filter(|r| r["event"] == "usage" && r["batch"] == "batch_1")
            .collect();
        if lines.len() == 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(lines.len(), 2, "one usage record per line");
    let first = lines
        .iter()
        .find(|r| r["custom_id"] == "a")
        .ok_or("no line a")?;
    let charged = first["charged_usd"].as_f64().ok_or("no charge")?;
    assert!(
        (charged - 0.5 * (100.0 * 1000.0 + 50.0 * 2000.0) / 1e6).abs() < 1e-9,
        "charged {charged}"
    );
    assert_eq!(first["person"], "dana");
    // The output file is the batch owner's.
    let (status, _) = call(
        &app,
        "GET",
        "/v1/files/file-out/content",
        DANA,
        "application/json",
        vec![],
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(
        &app,
        "GET",
        "/v1/files/file-out/content",
        OMER,
        "application/json",
        vec![],
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // A second retrieve charges nothing more.
    call(
        &app,
        "GET",
        "/v1/batches/batch_1",
        DANA,
        "application/json",
        vec![],
    )
    .await?;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let again = records(&audit)?
        .into_iter()
        .filter(|r| r["event"] == "usage" && r["batch"] == "batch_1")
        .count();
    assert_eq!(again, 2, "a batch is settled once");
    Ok(())
}

#[tokio::test]
async fn a_batch_reserves_its_estimate_at_batch_prices_against_the_budget() -> Result<(), Error> {
    let (port, seen) = provider().await?;
    // Each line could cost about (body/3 * 1000 + 100 * 2000) / 1e6 = $0.23 at full price: two lines are over
    // $0.50, and half of that fits in $0.40.
    let (policy, _) = files("budget", port, "    budget: { usd: 0.4, per: month }\n")?;
    let gw = gantry_server::governed(&policy, None, &|_| Some("provider-secret".into()))?;
    let app = gw.router.clone();
    let (status, body) = call(
        &app,
        "POST",
        "/v1/files",
        DANA,
        &form(),
        upload(&[&line("a", "model-a", "hi"), &line("b", "model-a", "there")]),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let create = br#"{"input_file_id":"file-in","endpoint":"/v1/chat/completions","completion_window":"24h"}"#;
    let (status, body) = call(
        &app,
        "POST",
        "/v1/batches",
        DANA,
        "application/json",
        create.to_vec(),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "half price fits: {body}");
    // The first batch's reservation is still held, so a second does not fit.
    let (status, body) = call(
        &app,
        "POST",
        "/v1/batches",
        DANA,
        "application/json",
        create.to_vec(),
    )
    .await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert!(
        body.contains("budget_exceeded") && body.contains("This batch"),
        "{body}"
    );
    let batches = seen
        .lock()
        .map_err(|_| "poisoned")?
        .iter()
        .filter(|(m, p, _)| m == "POST" && p == "/v1/batches")
        .count();
    assert_eq!(batches, 1, "the refused batch never reached the provider");
    Ok(())
}

#[tokio::test]
async fn an_anthropic_message_batch_is_checked_per_request_and_metered_per_result()
-> Result<(), Error> {
    let (port, _) = provider().await?;
    let (policy, audit) = files("messages", port, "")?;
    let gw = gantry_server::governed(&policy, None, &|_| Some("provider-secret".into()))?;
    let app = gw.router.clone();
    let request = |id: &str, text: &str| {
        format!(
            r#"{{"custom_id":"{id}","params":{{"model":"claude-a","max_tokens":100,"messages":[{{"role":"user","content":"{text}"}}]}}}}"#
        )
    };
    let blocked = format!(
        r#"{{"requests":[{},{}]}}"#,
        request("x", "hi"),
        request("y", "AKIAIOSFODNN7EXAMPLE")
    );
    let (status, body) = call(
        &app,
        "POST",
        "/v1/messages/batches",
        DANA,
        "application/json",
        blocked.into_bytes(),
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("request 2"), "{body}");

    let good = format!(
        r#"{{"requests":[{},{}]}}"#,
        request("x", "hi"),
        request("y", "there")
    );
    let (status, body) = call(
        &app,
        "POST",
        "/v1/messages/batches",
        DANA,
        "application/json",
        good.into_bytes(),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = call(
        &app,
        "GET",
        "/v1/messages/batches/msgbatch_1",
        OMER,
        "application/json",
        vec![],
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, body) = call(
        &app,
        "GET",
        "/v1/messages/batches/msgbatch_1",
        DANA,
        "application/json",
        vec![],
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mut lines = Vec::new();
    for _ in 0..50 {
        lines = records(&audit)?
            .into_iter()
            .filter(|r| r["event"] == "usage" && r["batch"] == "msgbatch_1")
            .collect();
        if lines.len() == 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(lines.len(), 2, "{lines:?}");
    let x = lines.iter().find(|r| r["custom_id"] == "x").ok_or("no x")?;
    let charged = x["charged_usd"].as_f64().ok_or("no charge")?;
    assert!(
        (charged - 0.5 * (1000.0 * 1000.0 + 100.0 * 2000.0) / 1e6).abs() < 1e-9,
        "{charged}"
    );
    let y = lines.iter().find(|r| r["custom_id"] == "y").ok_or("no y")?;
    assert_eq!(
        y["charged_usd"].as_f64(),
        Some(0.0),
        "an errored request costs nothing"
    );
    Ok(())
}

#[tokio::test]
async fn a_fine_tuning_job_needs_an_allowed_model_and_a_training_file_you_own() -> Result<(), Error>
{
    let (port, _) = provider().await?;
    let (policy, _) = files("tuning", port, "")?;
    let gw = gantry_server::governed(&policy, None, &|_| Some("provider-secret".into()))?;
    let app = gw.router.clone();
    let (status, body) = call(
        &app,
        "POST",
        "/v1/files",
        DANA,
        &form(),
        upload(&[&line("a", "model-a", "hi")]),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let job =
        |model: &str| format!(r#"{{"model":"{model}","training_file":"file-in"}}"#).into_bytes();
    let (status, body) = call(
        &app,
        "POST",
        "/v1/fine_tuning/jobs",
        DANA,
        "application/json",
        job("gpt-9"),
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = call(
        &app,
        "POST",
        "/v1/fine_tuning/jobs",
        OMER,
        "application/json",
        job("model-a"),
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, body) = call(
        &app,
        "POST",
        "/v1/fine_tuning/jobs",
        DANA,
        "application/json",
        job("model-a"),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let _ = Bytes::new();
    Ok(())
}

/// A fresh database for one test, as a connection string. `None` when GANTRY_TEST_DATABASE_URL is not set.
async fn database(test: &str) -> Result<Option<String>, Error> {
    let Ok(url) = std::env::var("GANTRY_TEST_DATABASE_URL") else {
        eprintln!("skipped {test}: GANTRY_TEST_DATABASE_URL is not set.");
        return Ok(None);
    };
    let config: tokio_postgres::Config = url.parse()?;
    let (client, connection) = config.connect(tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    let name = format!("gantry_{}_{test}", std::process::id());
    client
        .batch_execute(&format!("DROP DATABASE IF EXISTS {name}"))
        .await?;
    client
        .batch_execute(&format!("CREATE DATABASE {name}"))
        .await?;
    let host = match config.get_hosts().first() {
        Some(tokio_postgres::config::Host::Tcp(host)) => host.clone(),
        _ => "127.0.0.1".into(),
    };
    let password = config
        .get_password()
        .map(|p| String::from_utf8_lossy(p).to_string())
        .unwrap_or_default();
    Ok(Some(format!(
        "host={host} port={} user={} password='{password}' dbname={name} sslmode=disable",
        config.get_ports().first().copied().unwrap_or(5432),
        config.get_user().unwrap_or("postgres"),
    )))
}

#[tokio::test]
async fn with_a_store_every_replica_answers_for_a_file_and_a_batch_is_metered_once()
-> Result<(), Error> {
    let Some(url) = database("batches_shared").await? else {
        return Ok(());
    };
    let (port, _seen) = provider().await?;
    let gateway = |name: &str| -> Result<(gantry_server::Governed, PathBuf), Error> {
        let (policy, audit) = files(name, port, "    budget: { usd: 100, per: month }\n")?;
        let text = std::fs::read_to_string(&policy)?;
        std::fs::write(
            &policy,
            text.replacen(
                "version: 1\n",
                "version: 1\nstore: { postgres_url_env: GANTRY_STORE_URL }\n",
                1,
            ),
        )?;
        let url = url.clone();
        let gw = gantry_server::governed(&policy, None, &move |variable| match variable {
            "GANTRY_STORE_URL" => Some(url.clone()),
            "GANTRY_MASTER_KEY" | "GANTRY_MASTER_KEY_FILE" => None,
            _ => Some("provider-secret".into()),
        })?;
        Ok((gw, audit))
    };
    let (a, a_audit) = gateway("shared-a")?;
    let (b, b_audit) = gateway("shared-b")?;
    for (name, key) in [("dana", DANA), ("omer", OMER)] {
        gantry_core::keyfile::add_entry(name, "data", key, false, &a.loaded.keys_path)?;
    }
    // Each replica reads the keys from the store within 2 seconds, as any key issued on another.
    for gw in [&a, &b] {
        for _ in 0..50 {
            gw.reloader.check(gantry_server::Trigger::FileChange);
            let (status, _) = call(
                &gw.router,
                "GET",
                "/v1/files",
                OMER,
                "application/json",
                vec![],
            )
            .await?;
            if status != StatusCode::UNAUTHORIZED {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    let (status, body) = call(
        &a.router,
        "POST",
        "/v1/files",
        DANA,
        &form(),
        upload(&[&line("a", "model-a", "hi"), &line("b", "model-a", "there")]),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    // The other replica knows whose it is: its owner reads it, nobody else does.
    let (status, body) = call(
        &b.router,
        "GET",
        "/v1/files/file-in",
        DANA,
        "application/json",
        vec![],
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = call(
        &b.router,
        "GET",
        "/v1/files/file-in",
        OMER,
        "application/json",
        vec![],
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let create = br#"{"input_file_id":"file-in","endpoint":"/v1/chat/completions","completion_window":"24h"}"#;
    let (status, body) = call(
        &b.router,
        "POST",
        "/v1/batches",
        DANA,
        "application/json",
        create.to_vec(),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Both replicas see the batch end; it is metered once.
    for gw in [&a, &b, &a] {
        let (status, body) = call(
            &gw.router,
            "GET",
            "/v1/batches/batch_1",
            DANA,
            "application/json",
            vec![],
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let lines: usize = [a_audit, b_audit]
        .iter()
        .map(|audit| {
            records(audit).map(|all| {
                all.iter()
                    .filter(|r| r["event"] == "usage" && r["batch"] == "batch_1")
                    .count()
            })
        })
        .sum::<Result<usize, Error>>()?;
    assert_eq!(lines, 2, "one usage record per line, on one replica");
    Ok(())
}

/// Two replicas on one store, with a master key, and the keys both read.
async fn replicas(
    url: &str,
    port: u16,
    test: &str,
) -> Result<[(gantry_server::Governed, PathBuf); 2], Error> {
    let gateway = |name: String| -> Result<(gantry_server::Governed, PathBuf), Error> {
        let (policy, audit) = files(&name, port, "    budget: { usd: 100, per: month }\n")?;
        let text = std::fs::read_to_string(&policy)?;
        std::fs::write(
            &policy,
            text.replacen(
                "version: 1\n",
                "version: 1\nstore: { postgres_url_env: GANTRY_STORE_URL }\n",
                1,
            ),
        )?;
        let url = url.to_string();
        let gw = gantry_server::governed(&policy, None, &move |variable| match variable {
            "GANTRY_STORE_URL" => Some(url.clone()),
            "GANTRY_MASTER_KEY" => Some("ab".repeat(32)),
            "GANTRY_MASTER_KEY_FILE" => None,
            _ => Some("provider-secret".into()),
        })?;
        Ok((gw, audit))
    };
    let a = gateway(format!("{test}-a"))?;
    let b = gateway(format!("{test}-b"))?;
    for (name, key) in [("dana", DANA), ("omer", OMER)] {
        gantry_core::keyfile::add_entry(name, "data", key, false, &a.0.loaded.keys_path)?;
    }
    for gw in [&a.0, &b.0] {
        for _ in 0..50 {
            gw.reloader.check(gantry_server::Trigger::FileChange);
            let (status, _) = call(
                &gw.router,
                "GET",
                "/v1/files",
                OMER,
                "application/json",
                vec![],
            )
            .await?;
            if status != StatusCode::UNAUTHORIZED {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
    Ok([a, b])
}

/// Asks `path` until the answer is not `waiting`.
async fn until_not(
    app: &Router,
    path: &str,
    key: &str,
    waiting: &[StatusCode],
) -> Result<(StatusCode, String), Error> {
    let mut last = (StatusCode::NOT_FOUND, String::new());
    for _ in 0..100 {
        last = call(app, "GET", path, key, "application/json", vec![]).await?;
        if !waiting.contains(&last.0) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    }
    Ok(last)
}

#[tokio::test]
async fn with_a_store_any_replica_serves_held_answers_and_a_background_response_is_charged_once()
-> Result<(), Error> {
    let Some(url) = database("held_shared").await? else {
        return Ok(());
    };
    let (port, _seen) = provider().await?;
    let [(a, a_audit), (b, b_audit)] = replicas(&url, port, "held").await?;

    // An async job submitted to one replica is answered by the other, for its submitter alone.
    let chat =
        br#"{"model":"model-a","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}"#;
    let (status, body) = call(
        &a.router,
        "POST",
        "/v1/async/chat/completions",
        DANA,
        "application/json",
        chat.to_vec(),
    )
    .await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let job: Value = serde_json::from_str(&body)?;
    let path = format!(
        "/v1/async/chat/completions/{}",
        job["id"].as_str().ok_or("no id")?
    );
    let (status, body) = until_not(
        &b.router,
        &path,
        DANA,
        &[StatusCode::ACCEPTED, StatusCode::NOT_FOUND],
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let done: Value = serde_json::from_str(&body)?;
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(done["result"]["choices"][0]["message"]["content"], "Hi");
    let (status, _) = call(&b.router, "GET", &path, OMER, "application/json", vec![]).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A translated response kept with store: true is read on the other replica, and kept sealed.
    let kept = br#"{"model":"claude-a","input":"hello","max_output_tokens":10,"store":true}"#;
    let (status, body) = call(
        &a.router,
        "POST",
        "/v1/responses",
        DANA,
        "application/json",
        kept.to_vec(),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let made: Value = serde_json::from_str(&body)?;
    let path = format!("/v1/responses/{}", made["id"].as_str().ok_or("no id")?);
    let (status, body) = until_not(&b.router, &path, DANA, &[StatusCode::NOT_FOUND]).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(serde_json::from_str::<Value>(&body)?, made);
    let (status, _) = call(&b.router, "GET", &path, OMER, "application/json", vec![]).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    let rows = client
        .query("SELECT value, sealed FROM gantry_batches_held", &[])
        .await?;
    assert_eq!(
        rows.len(),
        2,
        "the job and the kept response are in the store"
    );
    for row in rows {
        let value: Vec<u8> = row.try_get(0)?;
        assert!(
            row.try_get::<_, bool>(1)?,
            "held answers are sealed under the master key"
        );
        assert!(!String::from_utf8_lossy(&value).contains("Kept answer"));
    }
    // Deleted on one replica, gone on the other.
    let (status, body) = call(&b.router, "DELETE", &path, DANA, "application/json", vec![]).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = call(&a.router, "GET", &path, DANA, "application/json", vec![]).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A background response: nothing charged when it is queued, its usage once when it is seen done.
    let background =
        br#"{"model":"model-a","input":"long job","max_output_tokens":100,"background":true}"#;
    let (status, body) = call(
        &a.router,
        "POST",
        "/v1/responses",
        DANA,
        "application/json",
        background.to_vec(),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = until_not(
        &b.router,
        "/v1/responses/resp_bg",
        DANA,
        &[StatusCode::NOT_FOUND],
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    for gw in [&a, &b, &a] {
        let (status, body) = call(
            &gw.router,
            "GET",
            "/v1/responses/resp_bg",
            DANA,
            "application/json",
            vec![],
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let mut all = records(&a_audit)?;
    all.extend(records(&b_audit)?);
    let queued = all
        .iter()
        .find(|r| r["event"] == "usage" && r["usage"] == "background")
        .ok_or("no usage record for the queued response")?;
    assert_eq!(queued["charged_usd"], 0.0);
    let settled: Vec<&Value> = all
        .iter()
        .filter(|r| r["event"] == "usage" && r["response"] == "resp_bg")
        .collect();
    assert_eq!(
        settled.len(),
        1,
        "charged once across replicas: {settled:?}"
    );
    assert_eq!(settled[0]["input_tokens"], 100);
    assert_eq!(settled[0]["output_tokens"], 10);
    let charged = settled[0]["charged_usd"].as_f64().ok_or("no charge")?;
    assert!((charged - 0.12).abs() < 1e-9, "{charged}");
    // Its reservation was given back: nothing stays reserved in the store.
    let mut reserved = f64::NAN;
    for _ in 0..50 {
        reserved = client
            .query_one(
                "SELECT COALESCE(SUM(reserved), 0)::float8 FROM gantry_spend",
                &[],
            )
            .await?
            .try_get(0)?;
        if reserved.abs() < 1e-9 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(reserved.abs() < 1e-9, "still reserved: {reserved}");
    Ok(())
}

#[tokio::test]
async fn residency_and_a_keys_routes_govern_the_batch_routes_too() -> Result<(), Error> {
    let (port, _seen) = provider().await?;
    let (policy, _) = files("residency", port, "    regions: [eu]\n")?;
    let gw = gantry_server::governed(&policy, None, &|_| Some("provider-secret".into()))?;
    let (status, body) = call(
        &gw.router,
        "GET",
        "/v1/files",
        DANA,
        "application/json",
        vec![],
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("region_not_allowed"), "{body}");

    let (policy, _) = files("routes", port, "")?;
    let keys = policy.with_file_name("gantry.keys.yaml");
    let text = std::fs::read_to_string(&keys)?;
    std::fs::write(
        &keys,
        text.replacen(
            "    team: data\n",
            "    team: data\n    routes: [/v1/chat/completions]\n",
            1,
        ),
    )?;
    let gw = gantry_server::governed(&policy, None, &|_| Some("provider-secret".into()))?;
    let (status, body) = call(
        &gw.router,
        "GET",
        "/v1/files",
        DANA,
        "application/json",
        vec![],
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("route_not_allowed"), "{body}");
    let (status, _) = call(
        &gw.router,
        "GET",
        "/v1/files",
        OMER,
        "application/json",
        vec![],
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    Ok(())
}
