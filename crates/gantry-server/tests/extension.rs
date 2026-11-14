//! What a binary that embeds the gateway adds to it: routes, /healthz fields, and tables of its own in the store's
//! database under a namespace of their own.
//!
//! The store tests need a real Postgres: set GANTRY_TEST_DATABASE_URL (CI runs a postgres:16 service). Without it
//! they print that they were skipped and pass.

use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::get,
};
use gantry_server::{Config, Extension};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type Error = Box<dyn std::error::Error>;
type TestResult = Result<(), Error>;

async fn get_json(app: &Router, path: &str) -> Result<(StatusCode, Value), Error> {
    let response = app
        .clone()
        .oneshot(Request::get(path).body(Body::empty())?)
        .await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, serde_json::from_slice(&body).unwrap_or(Value::Null)))
}

#[tokio::test]
async fn routes_and_health_fields_are_added_and_never_replace_the_gateways_own() -> TestResult {
    let extension = Extension {
        routes: Router::new().route("/extra/ping", get(|| async { "pong" })),
        health: Some(Arc::new(|| {
            let mut fields = serde_json::Map::new();
            fields.insert("license".into(), json!({ "customer": "Acme" }));
            fields.insert("status".into(), json!("overridden"));
            fields
        })),
        ..Extension::default()
    };
    let app = gantry_server::app(Config {
        extension,
        ..Config::default()
    })?;
    let response = app
        .clone()
        .oneshot(Request::get("/extra/ping").body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        &response.into_body().collect().await?.to_bytes()[..],
        b"pong"
    );
    let (status, health) = get_json(&app, "/healthz").await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(health["license"]["customer"], "Acme");
    assert_eq!(
        health["status"], "ok",
        "an extension replaced the gateway's own field"
    );
    // The open source gateway adds nothing.
    let (_, plain) = gantry_server::app(Config::default())
        .map(|app| async move { get_json(&app, "/healthz").await })?
        .await?;
    assert!(plain.get("license").is_none());
    Ok(())
}

#[tokio::test]
async fn an_embedder_check_that_says_not_ready_makes_readyz_503() -> TestResult {
    let ready = Arc::new(Mutex::new(true));
    let seen = ready.clone();
    let extension = Extension {
        health: Some(Arc::new(move || {
            let ok = seen.lock().map(|r| *r).unwrap_or(false);
            let mut fields = serde_json::Map::new();
            fields.insert(
                "license".into(),
                if ok {
                    json!({ "ready": true, "customer": "Acme" })
                } else {
                    json!({ "ready": false, "reason": "the license ended on 2026-11-01" })
                },
            );
            fields
        })),
        ..Extension::default()
    };
    let app = gantry_server::app(Config {
        extension,
        ..Config::default()
    })?;
    let (status, body) = get_json(&app, "/readyz").await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["checks"]["license"]["customer"], "Acme");
    *ready.lock().map_err(|_| "poisoned")? = false;
    let (status, body) = get_json(&app, "/readyz").await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body["checks"]["license"]["reason"],
        "the license ended on 2026-11-01"
    );
    // Liveness does not read readiness: the process is still alive.
    let (status, _) = get_json(&app, "/healthz").await?;
    assert_eq!(status, StatusCode::OK);
    Ok(())
}

/// A fresh database for one test, as a connection string. `None` when GANTRY_TEST_DATABASE_URL is not set.
async fn database(test: &str) -> Result<Option<String>, Error> {
    let Ok(url) = std::env::var("GANTRY_TEST_DATABASE_URL") else {
        eprintln!(
            "skipped {test}: GANTRY_TEST_DATABASE_URL is not set. Set it to a Postgres connection string to run the store tests."
        );
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
        "host={host} port={} user={} password='{}' dbname={name} sslmode=disable",
        config.get_ports().first().copied().unwrap_or(5432),
        config.get_user().unwrap_or("postgres"),
        password.replace('\\', "\\\\").replace('\'', "\\'"),
    )))
}

const ONE: &[&str] = &["CREATE TABLE ext_notes (id serial PRIMARY KEY, text text NOT NULL);"];
const TWO: &[&str] = &[
    "CREATE TABLE ext_notes (id serial PRIMARY KEY, text text NOT NULL);",
    "ALTER TABLE ext_notes ADD COLUMN author text;",
];

#[tokio::test]
async fn a_namespace_migrates_on_its_own_and_its_connection_holds_transactions() -> TestResult {
    let Some(url) = database("ext_migrate").await? else {
        return Ok(());
    };
    let dir = std::env::temp_dir().join(format!("gantry-ext-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let policy = dir.join("gantry.policy.yaml");
    std::fs::write(
        &policy,
        // An MCP server too, so every namespace of the gateway's own is created.
        "version: 1\nstore: { postgres_url_env: GANTRY_STORE_URL }\nproviders:\n  - name: mock\n    kind: openai\n    url: http://127.0.0.1:9\n    allow_private: true\n    key_env: MOCK_KEY\n    models: [m]\nmcp:\n  - name: docs\n    url: http://127.0.0.1:9/mcp\n    allow_private: true\nrules:\n  - name: all\n    principals: { any: true }\n    models: [m]\n",
    )?;
    let env = |variable: &str| match variable {
        "GANTRY_STORE_URL" => Some(url.clone()),
        // No master key: these gateways keep no provider credentials.
        "GANTRY_MASTER_KEY" | "GANTRY_MASTER_KEY_FILE" => None,
        _ => Some("provider-secret".into()),
    };
    // The extension gets the store at start, migrates its namespace, and keeps the store for its handlers.
    let kept = Arc::new(Mutex::new(None));
    let keep = kept.clone();
    let extend = move |host: gantry_server::Host<'_>| {
        let pg = host.postgres.ok_or("no store")?.clone();
        pg.migrate("demo", ONE)?;
        // Applied once: a second start, or a second replica, finds version 1 and does nothing.
        pg.migrate("demo", ONE)?;
        *keep.lock().map_err(|e| e.to_string())? = Some(pg);
        Ok(Extension::default())
    };
    let _gw = gantry_server::governed_with(&policy, None, &env, &extend)?;
    let pg = kept
        .lock()
        .map_err(|e| e.to_string())?
        .clone()
        .ok_or("extend did not run")?;

    let mut client = pg.connect().await?;
    let versions = client
        .query(
            "SELECT namespace, version FROM gantry_migrations ORDER BY namespace",
            &[],
        )
        .await?;
    let rows: Vec<(String, i32)> = versions
        .iter()
        .map(|r| Ok((r.try_get(0)?, r.try_get(1)?)))
        .collect::<Result<_, tokio_postgres::Error>>()?;
    // The gateway's own namespaces, beside the extension's: ownership of files and batches, policy versions, the
    // request index and the MCP gateway's state.
    assert_eq!(
        rows,
        vec![
            ("batches".to_string(), 2),
            ("demo".to_string(), 1),
            ("gantry_policy".to_string(), 1),
            ("insights".to_string(), 1),
            ("mcp".to_string(), 1),
        ]
    );
    // The gateway's own schema version is untouched by the namespace: its five migrations (keys, shared limits and
    // sessions, credentials, the hierarchy's key fields, key options).
    let core: i32 = client
        .query_one("SELECT max(version) FROM gantry_schema", &[])
        .await?
        .try_get(0)?;
    assert_eq!(core, 5);

    // Its own connection, so a transaction is safe on it.
    let tx = client.transaction().await?;
    tx.execute("INSERT INTO ext_notes (text) VALUES ('kept')", &[])
        .await?;
    tx.rollback().await?;
    let n: i64 = client
        .query_one("SELECT count(*) FROM ext_notes", &[])
        .await?
        .try_get(0)?;
    assert_eq!(n, 0);

    // A newer binary adds an entry: only that one runs.
    let migrate = pg.clone();
    tokio::task::spawn_blocking(move || migrate.migrate("demo", TWO)).await??;
    client
        .execute(
            "INSERT INTO ext_notes (text, author) VALUES ('x', 'ada')",
            &[],
        )
        .await?;
    // An older binary on a database a newer one wrote is refused, with the fix.
    let migrate = pg.clone();
    let err = tokio::task::spawn_blocking(move || migrate.migrate("demo", ONE))
        .await?
        .err()
        .ok_or("an older binary migrated a newer database")?;
    assert!(
        err.contains("demo") && err.contains("same version"),
        "{err}"
    );
    Ok(())
}

/// Takes what the gateway hands over, for teams in `teams`.
struct Keeper {
    teams: Vec<&'static str>,
    taken: Mutex<Vec<gantry_server::Captured>>,
    /// Whether the usage record was already in the log when the text was handed over (it must not be).
    audit: std::path::PathBuf,
    usage_before: Mutex<bool>,
}

impl gantry_server::Capture for Keeper {
    fn wanted(&self, team: &str) -> bool {
        self.teams.contains(&team)
    }
    fn take(&self, captured: gantry_server::Captured) {
        let written = std::fs::read_to_string(&self.audit).unwrap_or_default();
        if written.contains(&format!(
            "\"event\":\"usage\",\"id\":\"{}\"",
            captured.decision
        )) && let Ok(mut before) = self.usage_before.lock()
        {
            *before = true;
        }
        if let Ok(mut taken) = self.taken.lock() {
            taken.push(captured);
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_capture_gets_prompt_and_answer_text_only_for_teams_it_wants_and_before_the_usage_record()
-> TestResult {
    use axum::http::header;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let provider = Router::new().route(
        "/v1/chat/completions",
        axum::routing::post(|body: axum::body::Bytes| async move {
            let streamed = body.windows(13).any(|w| w == b"\"stream\":true");
            let (content_type, answer) = if streamed {
                (
                    "text/event-stream",
                    "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"stre\"}}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"amed\"}}]}\n\ndata: [DONE]\n\n",
                )
            } else {
                (
                    "application/json",
                    r#"{"id":"c1","choices":[{"index":0,"message":{"role":"assistant","content":"whole answer"}}],"usage":{"prompt_tokens":3,"completion_tokens":2}}"#,
                )
            };
            axum::response::Response::builder()
                .header(header::CONTENT_TYPE, content_type)
                .body(Body::from(answer))
                .unwrap_or_default()
        }),
    );
    tokio::spawn(async move { axum::serve(listener, provider).await });
    let dir = std::env::temp_dir().join(format!("gantry-capture-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let policy = dir.join("gantry.policy.yaml");
    std::fs::write(
        &policy,
        format!(
            "version: 1\nproviders:\n  - name: p\n    kind: openai\n    url: http://127.0.0.1:{port}\n    allow_private: true\n    key_env: MOCK_KEY\n    models: [m]\nrules:\n  - name: all\n    principals: {{ any: true }}\n    models: [m]\n"
        ),
    )?;
    let (pat, rita) = (
        "gantry_pat_0123456789abcdef0123456789ab",
        "gantry_rita_0123456789abcdef0123456789a",
    );
    let entry = |name: &str, team: &str, key: &str| {
        format!(
            "  - name: {name}\n    team: {team}\n    sha256: {}\n",
            gantry_core::id::sha256_hex(key.as_bytes())
        )
    };
    std::fs::write(
        dir.join("gantry.keys.yaml"),
        format!(
            "keys:\n{}{}",
            entry("pat", "payments", pat),
            entry("rita", "ops", rita)
        ),
    )?;
    let keeper = Arc::new(Keeper {
        teams: vec!["payments"],
        taken: Mutex::new(Vec::new()),
        audit: dir.join("gantry-audit.jsonl"),
        usage_before: Mutex::new(false),
    });
    let kept = keeper.clone();
    let gw = gantry_server::governed_with(&policy, None, &|_| Some("secret".into()), &move |_| {
        Ok(Extension {
            capture: Some(kept.clone()),
            ..Extension::default()
        })
    })?;
    let send = |key: &str, body: &str| {
        Request::post("/v1/chat/completions")
            .header(header::AUTHORIZATION, format!("Bearer {key}"))
            .body(Body::from(body.to_string()))
    };
    for (key, body) in [
        (
            pat,
            r#"{"model":"m","messages":[{"role":"user","content":"hello whole"}]}"#,
        ),
        (
            pat,
            r#"{"model":"m","stream":true,"messages":[{"role":"user","content":"hello stream"}]}"#,
        ),
        (
            rita,
            r#"{"model":"m","messages":[{"role":"user","content":"not mine"}]}"#,
        ),
    ] {
        let response = gw.router.clone().oneshot(send(key, body)?).await?;
        assert_eq!(response.status(), StatusCode::OK);
        response.into_body().collect().await?;
    }
    let start = std::time::Instant::now();
    while keeper.taken.lock().map(|t| t.len()).unwrap_or(0) < 2
        && start.elapsed() < std::time::Duration::from_secs(3)
    {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    gw.log.flush();
    let taken = keeper.taken.lock().map(|t| t.clone()).unwrap_or_default();
    assert_eq!(taken.len(), 2, "only the payments team's two requests");
    let whole = taken
        .iter()
        .find(|c| !c.streamed)
        .ok_or("no whole answer")?;
    assert_eq!(
        whole.prompt(),
        vec![("user".to_string(), "hello whole".to_string())]
    );
    assert_eq!(whole.answer_text(), vec!["whole answer".to_string()]);
    assert_eq!(
        (whole.person.as_str(), whole.team.as_str()),
        ("pat", "payments")
    );
    let stream = taken.iter().find(|c| c.streamed).ok_or("no stream")?;
    assert_eq!(stream.prompt()[0].1, "hello stream");
    assert_eq!(stream.answer_text(), vec!["streamed".to_string()]);
    assert!(
        !*keeper.usage_before.lock().map_err(|_| "lock")?,
        "the text is handed over before the usage record is written"
    );
    let log = std::fs::read_to_string(dir.join("gantry-audit.jsonl"))?;
    assert!(log.contains(&format!(
        "\"event\":\"usage\",\"id\":\"{}\"",
        whole.decision
    )));
    assert!(
        !log.contains("hello whole") && !log.contains("whole answer"),
        "no text in the log"
    );
    Ok(())
}
