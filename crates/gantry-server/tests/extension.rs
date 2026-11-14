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
        "version: 1\nstore: { postgres_url_env: GANTRY_STORE_URL }\nproviders:\n  - name: mock\n    kind: openai\n    url: http://127.0.0.1:9\n    allow_private: true\n    key_env: MOCK_KEY\n    models: [m]\nrules:\n  - name: all\n    principals: { any: true }\n    models: [m]\n",
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
    // The gateway's own namespaces, beside the extension's: policy versions and the request index.
    assert_eq!(
        rows,
        vec![
            ("demo".to_string(), 1),
            ("gantry_policy".to_string(), 1),
            ("insights".to_string(), 1)
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
