//! Acceptance tests for the store (slice 7): gateways pointed at one Postgres database act as one gateway. A key
//! issued on one is accepted by the other within 2 seconds and a revoked one refused by both within 2 seconds, a
//! kill switch stops the other within 1 second, one budget holds across both, and a database that goes away keeps
//! known keys working while budgeted requests are refused.
//!
//! Each gateway here has its own directory, audit chain, connection, poll and reloader, as a separate process has:
//! they share nothing but the database. The two-process version, with `gantry serve` binaries, is in the CLI tests.
//!
//! They need a real Postgres. Set GANTRY_TEST_DATABASE_URL to a connection string whose user may create databases
//! (CI runs a postgres:16 service). Without it each test prints that it was skipped and passes.

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
    routing::post,
};
use gantry_server::Governed;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Error = Box<dyn std::error::Error>;

const ADMIN: &str = "gantry_admin_0123456789abcdef012345678";
const MAYA: &str = "gantry_maya_0123456789abcdef0123456789";
const PAT: &str = "gantry_pat_0123456789abcdef01234567890";
const LEE: &str = "gantry_lee_0123456789abcdef01234567890";

/// A fresh database for one test, on the server GANTRY_TEST_DATABASE_URL names. `None` when it is not set.
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
    // One statement each: several in one string run as a transaction, where these are refused.
    client
        .batch_execute(&format!("DROP DATABASE IF EXISTS {name}"))
        .await?;
    client
        .batch_execute(&format!("CREATE DATABASE {name}"))
        .await?;
    Ok(Some(key_value(&config, None, &name)))
}

/// A connection string in key=value form, so a password needs no URL encoding. `port` replaces the server's.
fn key_value(config: &tokio_postgres::Config, port: Option<u16>, database: &str) -> String {
    let quote = |s: &str| format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"));
    let host = match config.get_hosts().first() {
        Some(tokio_postgres::config::Host::Tcp(host)) => host.clone(),
        _ => "127.0.0.1".into(),
    };
    let password = config
        .get_password()
        .map(|p| String::from_utf8_lossy(p).to_string())
        .unwrap_or_default();
    format!(
        "host={} port={} user={} password={} dbname={} sslmode=disable",
        quote(if port.is_some() { "127.0.0.1" } else { &host }),
        port.unwrap_or_else(|| config.get_ports().first().copied().unwrap_or(5432)),
        quote(config.get_user().unwrap_or("postgres")),
        quote(&password),
        quote(database)
    )
}

/// A provider whose every answer used 3 output tokens. Model `slow` answers after a second, `lag`
/// after 150 ms.
async fn provider() -> Result<u16, Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let app = Router::new().route(
        "/v1/chat/completions",
        post(|body: Bytes| async move {
            if body.windows(6).any(|w| w == b"\"slow\"") {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            if body.windows(5).any(|w| w == b"\"lag\"") {
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
            axum::response::Response::builder()
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"id":"c","choices":[],"usage":{"prompt_tokens":0,"completion_tokens":3}}"#,
                ))
                .unwrap_or_default()
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

/// Model m costs $0.001 an output token: a request with max_tokens 3 reserves, and costs, $0.003. Team payments
/// may spend $0.01 a day on it: three requests fit, a fourth would pass the budget. Team rated may send 30
/// requests a minute, team tokens 300 tokens a minute, and team paired sends to an alias whose first deployment
/// is on a provider that refuses every connection.
fn policy(port: u16) -> String {
    format!(
        "version: 1
store: {{ postgres_url_env: GANTRY_STORE_URL }}
providers:
  - name: mock
    kind: openai
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: MOCK_KEY
    models: [m, free, slow, lag]
  - name: mock2
    kind: openai
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: MOCK_KEY
    models: [fast]
  - name: dead
    kind: openai
    url: http://127.0.0.1:{dead}
    allow_private: true
    key_env: MOCK_KEY
    models: [gone]
aliases:
  - name: pair
    cooldown_seconds: 30
    deployments:
      - {{ provider: dead, model: gone }}
      - {{ provider: mock, model: free }}
  - name: sticky
    session_affinity: true
    deployments:
      - {{ provider: mock, model: free }}
      - {{ provider: mock2, model: fast }}
  - name: quick
    balance: lowest_latency
    deployments:
      - {{ provider: mock, model: lag }}
      - {{ provider: mock2, model: fast }}
  - name: capped
    deployments:
      - {{ provider: mock, model: free, rpm: 2 }}
  - name: single
    deployments:
      - {{ provider: mock, model: slow, max_parallel: 1 }}
prices:
  m: {{ input: 0, output: 1000 }}
rules:
  - name: budgeted
    principals: {{ team: payments }}
    models: [m]
    budget: {{ usd: 0.01, per: day }}
  - name: open
    principals: {{ team: ops }}
    models: [free]
  - name: roomy
    principals: {{ team: roomy }}
    models: [m]
    budget: {{ usd: 1000, per: day }}
  - name: rated
    principals: {{ team: rated }}
    models: [free]
    rate: {{ rpm: 30 }}
  - name: tokens
    principals: {{ team: tokens }}
    models: [slow]
    rate: {{ tpm: 300 }}
  - name: paired
    principals: {{ team: paired }}
    models: [pair, sticky, quick, capped, single]
  - name: shop
    principals: {{ team: shop }}
    models: [m]
    customers: [\"*\"]
  - name: held
    principals: {{ team: held }}
    models: [slow]
  - name: slid
    principals: {{ team: slid }}
    models: [m]
    budget: {{ usd: 0.01, per: {{ sliding: 24h }} }}
limits:
  - {{ customer: \"*\", budget: {{ usd: 0.006, per: day, tz: America/New_York }} }}
  - {{ team: held, parallel: 2 }}
",
        dead = DEAD.get_or_init(closed_port)
    )
}

/// A port nothing listens on, so a connection to it is refused at once.
static DEAD: std::sync::OnceLock<u16> = std::sync::OnceLock::new();

fn closed_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .and_then(|l| l.local_addr())
        .map_or(9, |a| a.port())
}

fn dir(name: &str) -> Result<PathBuf, Error> {
    let dir = std::env::temp_dir().join(format!("gantry-store-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// A gateway serving the policy in its own directory, watching for changes as `gantry serve` does.
fn gateway(dir: &Path, url: &str, port: u16) -> Result<Governed, Error> {
    let policy = dir.join("gantry.policy.yaml");
    std::fs::write(&policy, self::policy(port))?;
    let url = url.to_string();
    let gw = gantry_server::governed(&policy, None, &|variable| match variable {
        "GANTRY_STORE_URL" => Some(url.clone()),
        // No master key: these gateways keep no provider credentials.
        "GANTRY_MASTER_KEY" | "GANTRY_MASTER_KEY_FILE" => None,
        _ => Some("provider-secret".into()),
    })?;
    gw.reloader.watch();
    Ok(gw)
}

/// Puts a key in the store through the keys path of `gw`, as `gantry key new` does, and has `gw` apply it now
/// rather than at its next check.
fn add_key(gw: &Governed, name: &str, team: &str, key: &str, admin: bool) -> Result<(), Error> {
    gantry_core::keyfile::add_entry(name, team, key, admin, &gw.loaded.keys_path)?;
    gw.reloader.check(gantry_server::Trigger::FileChange);
    Ok(())
}

fn request(method: &str, path: &str, key: &str, body: &str) -> Result<Request<Body>, Error> {
    Ok(Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {key}"))
        .body(Body::from(body.to_string()))?)
}

async fn answer(app: &Router, request: Request<Body>) -> Result<(StatusCode, Value), Error> {
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, serde_json::from_slice(&body).unwrap_or(Value::Null)))
}

fn code(body: &Value) -> &str {
    body["error"]["code"].as_str().unwrap_or_default()
}

const FREE: &str = r#"{"model":"free","messages":[]}"#;
const BUDGETED: &str = r#"{"model":"m","max_tokens":3,"messages":[]}"#;

/// How long it took until `app` answered `key` as `wanted` says, or an error once `within` has passed.
async fn until(
    app: &Router,
    key: &str,
    within: Duration,
    wanted: impl Fn(StatusCode, &Value) -> bool,
) -> Result<Duration, Error> {
    let start = Instant::now();
    loop {
        let (status, body) =
            answer(app, request("POST", "/v1/chat/completions", key, FREE)?).await?;
        if wanted(status, &body) {
            return Ok(start.elapsed());
        }
        if start.elapsed() > within {
            return Err(format!("not within {within:?}: {status} {body}").into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_issued_on_one_gateway_works_on_the_other_and_a_revoke_stops_both() -> TestResult {
    let Some(url) = database("keys").await? else {
        return Ok(());
    };
    let port = provider().await?;
    let (a_dir, b_dir) = (dir("keys-a")?, dir("keys-b")?);
    let a = gateway(&a_dir, &url, port)?;
    add_key(&a, "ops", "ops", ADMIN, true)?;
    let b = gateway(&b_dir, &url, port)?;
    // The admin key went in before b started: b read it at start.
    let (status, _) = answer(&b.router, request("GET", "/admin/keys", ADMIN, "")?).await?;
    assert_eq!(status, StatusCode::OK);

    let (status, issued) = answer(
        &a.router,
        request(
            "POST",
            "/admin/keys",
            ADMIN,
            r#"{"name":"maya","team":"ops"}"#,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED, "{issued}");
    let key = issued["key"].as_str().ok_or("no key")?.to_string();
    let prefix = issued["sha256_prefix"]
        .as_str()
        .ok_or("no prefix")?
        .to_string();
    let took = until(&b.router, &key, Duration::from_secs(2), |s, _| {
        s == StatusCode::OK
    })
    .await?;
    eprintln!("a key issued on a was accepted by b after {took:?}");
    // Each gateway records the change in its own audit chain.
    let log = std::fs::read_to_string(b_dir.join("gantry-audit.jsonl"))?;
    assert!(
        log.contains(&format!("\"sha256_prefix\":\"{prefix}\"")),
        "{log}"
    );

    let (status, body) = answer(
        &a.router,
        request("DELETE", &format!("/admin/keys/{prefix}"), ADMIN, "")?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    for gw in [&a, &b] {
        let took = until(&gw.router, &key, Duration::from_secs(2), |s, body| {
            s == StatusCode::UNAUTHORIZED && code(body) == "unknown_key"
        })
        .await?;
        eprintln!("the revoked key was refused after {took:?}");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_kill_switch_set_on_one_gateway_stops_the_other_within_a_second() -> TestResult {
    let Some(url) = database("kills").await? else {
        return Ok(());
    };
    let port = provider().await?;
    let (a_dir, b_dir) = (dir("kills-a")?, dir("kills-b")?);
    let a = gateway(&a_dir, &url, port)?;
    add_key(&a, "ops", "ops", ADMIN, true)?;
    add_key(&a, "maya", "ops", MAYA, false)?;
    let b = gateway(&b_dir, &url, port)?;
    until(&b.router, MAYA, Duration::from_secs(2), |s, _| {
        s == StatusCode::OK
    })
    .await?;

    let (status, body) = answer(
        &a.router,
        request(
            "POST",
            "/admin/kills",
            ADMIN,
            r#"{"scope":"person","value":"maya","reason":"looping on one ticket"}"#,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let took = until(&b.router, MAYA, Duration::from_secs(1), |s, body| {
        s == StatusCode::FORBIDDEN
            && code(body) == "killed"
            && body.to_string().contains("looping on one ticket")
    })
    .await?;
    eprintln!("a switch set on a stopped b after {took:?}");
    // b lists it too, and a third gateway started now reads it at start.
    let (_, listed) = answer(&b.router, request("GET", "/admin/kills", ADMIN, "")?).await?;
    assert_eq!(listed["kills"][0]["value"], "maya", "{listed}");

    let (status, body) = answer(
        &b.router,
        request(
            "DELETE",
            "/admin/kills",
            ADMIN,
            r#"{"scope":"person","value":"maya"}"#,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    until(&a.router, MAYA, Duration::from_secs(1), |s, _| {
        s == StatusCode::OK
    })
    .await?;
    Ok(())
}

/// What the usage records of a gateway charged, in all.
fn charged(dir: &Path) -> Result<f64, Error> {
    let mut total = 0.0;
    for line in std::fs::read_to_string(dir.join("gantry-audit.jsonl"))?.lines() {
        let record: Value = serde_json::from_str(line)?;
        if record["event"] == "usage" {
            total += record["charged_usd"].as_f64().unwrap_or_default();
        }
    }
    Ok(total)
}

#[tokio::test(flavor = "multi_thread")]
async fn two_gateways_sending_at_once_never_pass_one_budget() -> TestResult {
    let Some(url) = database("budget").await? else {
        return Ok(());
    };
    let port = provider().await?;
    let (a_dir, b_dir) = (dir("budget-a")?, dir("budget-b")?);
    let a = gateway(&a_dir, &url, port)?;
    add_key(&a, "pat", "payments", PAT, false)?;
    add_key(&a, "lee", "payments", LEE, false)?;
    let b = gateway(&b_dir, &url, port)?;
    until(&b.router, PAT, Duration::from_secs(2), |s, _| {
        s != StatusCode::UNAUTHORIZED
    })
    .await?;

    // Twenty requests at once, half through each gateway, from two members of the team.
    let mut tasks = Vec::new();
    for i in 0..20 {
        let app = if i % 2 == 0 {
            a.router.clone()
        } else {
            b.router.clone()
        };
        let key = if i % 3 == 0 { PAT } else { LEE };
        tasks.push(tokio::spawn(async move {
            let request = request("POST", "/v1/chat/completions", key, BUDGETED)
                .map_err(|e| e.to_string())?;
            answer(&app, request).await.map_err(|e| e.to_string())
        }));
    }
    let mut admitted = 0;
    for task in tasks {
        let (status, body) = task.await??;
        match status {
            StatusCode::OK => admitted += 1,
            StatusCode::TOO_MANY_REQUESTS => assert_eq!(code(&body), "budget_exceeded", "{body}"),
            other => return Err(format!("unexpected {other}: {body}").into()),
        }
    }
    assert_eq!(
        admitted, 3,
        "three requests of $0.003 fit in $0.01, across both gateways"
    );
    // The usage records are written when each answer ends.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let total = charged(&a_dir)? + charged(&b_dir)?;
    assert!(
        total <= 0.01 + 0.003 + 1e-9,
        "charged {total}: more than one request's estimate over the budget"
    );
    for gw in [&a, &b] {
        let (status, body) = answer(
            &gw.router,
            request("POST", "/v1/chat/completions", PAT, BUDGETED)?,
        )
        .await?;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
        assert_eq!(code(&body), "budget_exceeded", "{body}");
    }
    Ok(())
}

/// What the store's sliding counter of team slid holds, by slot.
async fn slots(url: &str) -> Result<Vec<(String, f64)>, Error> {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    Ok(client
        .query(
            "SELECT period, spent FROM gantry_spend WHERE scope = 'team:slid' AND per = 'sliding:24h' ORDER BY period",
            &[],
        )
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sliding_budget_counts_the_last_24_hours_exactly_across_two_gateways() -> TestResult {
    let Some(url) = database("sliding").await? else {
        return Ok(());
    };
    let port = provider().await?;
    let (a_dir, b_dir) = (dir("slide-a")?, dir("slide-b")?);
    let a = gateway(&a_dir, &url, port)?;
    add_key(&a, "pat", "slid", PAT, false)?;
    let b = gateway(&b_dir, &url, port)?;
    until(&b.router, PAT, Duration::from_secs(2), |s, _| {
        s != StatusCode::UNAUTHORIZED
    })
    .await?;
    // Spent 25 hours ago: out of the window. Spent 2 hours ago: in it, leaving $0.006 of the $0.01.
    let per = gantry_core::policy::Period::parse("sliding 24h", None)?;
    let ago = |hours: u64| {
        per.label(&gantry_core::audit::rfc3339(
            std::time::SystemTime::now() - Duration::from_secs(hours * 3600),
        ))
    };
    let (old, recent) = (ago(25), ago(2));
    {
        let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
        tokio::spawn(connection);
        client
            .execute(
                "INSERT INTO gantry_spend (scope, per, period, spent) VALUES ('team:slid', 'sliding:24h', $1, 100), ('team:slid', 'sliding:24h', $2, 0.004)",
                &[&old, &recent],
            )
            .await?;
    }
    let mut tasks = Vec::new();
    for i in 0..20 {
        let app = if i % 2 == 0 {
            a.router.clone()
        } else {
            b.router.clone()
        };
        tasks.push(tokio::spawn(async move {
            let request = request("POST", "/v1/chat/completions", PAT, BUDGETED)
                .map_err(|e| e.to_string())?;
            answer(&app, request).await.map_err(|e| e.to_string())
        }));
    }
    let mut admitted = 0;
    let mut refusal = String::new();
    for task in tasks {
        let (status, body) = task.await??;
        match status {
            StatusCode::OK => admitted += 1,
            StatusCode::TOO_MANY_REQUESTS => {
                assert_eq!(code(&body), "budget_exceeded", "{body}");
                refusal = body["error"]["message"].as_str().unwrap_or_default().into();
            }
            other => return Err(format!("unexpected {other}: {body}").into()),
        }
    }
    assert_eq!(
        admitted, 2,
        "two requests of $0.003 fit in what the last 24 hours left, across both gateways"
    );
    assert!(refusal.contains("The budget slides"), "{refusal}");
    assert!(refusal.contains("any 24 hours"), "{refusal}");
    // The settled costs are in the current slot; the slot older than the window, holding nothing, is gone.
    let start = Instant::now();
    loop {
        let held = slots(&url).await?;
        let now: f64 = held
            .iter()
            .filter(|(p, _)| *p > recent)
            .map(|(_, s)| s)
            .sum();
        if (now - 0.006).abs() < 1e-9 {
            assert!(!held.iter().any(|(p, _)| *p == old), "{held:?}");
            assert!(held.iter().any(|(p, _)| *p == recent), "{held:?}");
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(5), "{held:?}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_customer_budget_and_a_parallel_limit_hold_across_two_gateways() -> TestResult {
    let Some(url) = database("hierarchy").await? else {
        return Ok(());
    };
    let port = provider().await?;
    let (a_dir, b_dir) = (dir("hier-a")?, dir("hier-b")?);
    let a = gateway(&a_dir, &url, port)?;
    add_key(&a, "shop", "shop", PAT, false)?;
    add_key(&a, "held", "held", LEE, false)?;
    let b = gateway(&b_dir, &url, port)?;
    until(&b.router, LEE, Duration::from_secs(2), |s, _| {
        s != StatusCode::UNAUTHORIZED
    })
    .await?;
    // Twenty at once for one customer, half through each gateway: two of $0.003 fit in its $0.006.
    let mut tasks = Vec::new();
    for i in 0..20 {
        let app = if i % 2 == 0 {
            a.router.clone()
        } else {
            b.router.clone()
        };
        tasks.push(tokio::spawn(async move {
            let mut request = request("POST", "/v1/chat/completions", PAT, BUDGETED)
                .map_err(|e| e.to_string())?;
            request.headers_mut().insert(
                "x-gantry-customer",
                header::HeaderValue::from_static("globex"),
            );
            answer(&app, request).await.map_err(|e| e.to_string())
        }));
    }
    let mut admitted = 0;
    for task in tasks {
        let (status, body) = task.await??;
        match status {
            StatusCode::OK => admitted += 1,
            StatusCode::TOO_MANY_REQUESTS => assert_eq!(code(&body), "budget_exceeded", "{body}"),
            other => return Err(format!("unexpected {other}: {body}").into()),
        }
    }
    assert_eq!(
        admitted, 2,
        "two requests of $0.003 fit in the customer's $0.006, across both gateways"
    );
    // Six slow requests at once, three through each gateway: two may be in flight for the team.
    let slow = r#"{"model":"slow","messages":[]}"#;
    let mut tasks = Vec::new();
    for i in 0..6 {
        let app = if i % 2 == 0 {
            a.router.clone()
        } else {
            b.router.clone()
        };
        tasks.push(tokio::spawn(async move {
            let request =
                request("POST", "/v1/chat/completions", LEE, slow).map_err(|e| e.to_string())?;
            answer(&app, request).await.map_err(|e| e.to_string())
        }));
    }
    let mut admitted = 0;
    for task in tasks {
        let (status, body) = task.await??;
        match status {
            StatusCode::OK => admitted += 1,
            StatusCode::TOO_MANY_REQUESTS => assert_eq!(code(&body), "parallel_limited", "{body}"),
            other => return Err(format!("unexpected {other}: {body}").into()),
        }
    }
    assert_eq!(
        admitted, 2,
        "two in flight at once for the team, across both gateways"
    );
    // The places are given back when the answers end: the store settles twice a second.
    let start = Instant::now();
    loop {
        let (status, body) = answer(
            &b.router,
            request("POST", "/v1/chat/completions", LEE, slow)?,
        )
        .await?;
        if status == StatusCode::OK {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(5), "{body}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

/// A TCP relay to Postgres that the test can cut, as a database that goes away looks to Gantry.
struct Relay {
    port: u16,
    down: Arc<AtomicBool>,
}

async fn relay(to: (String, u16)) -> Result<Relay, Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let down = Arc::new(AtomicBool::new(false));
    let cut = down.clone();
    tokio::spawn(async move {
        while let Ok((mut inbound, _)) = listener.accept().await {
            if cut.load(Ordering::SeqCst) {
                continue;
            }
            let (to, cut) = (to.clone(), cut.clone());
            tokio::spawn(async move {
                let Ok(mut outbound) = tokio::net::TcpStream::connect(to).await else {
                    return;
                };
                let copy = tokio::io::copy_bidirectional(&mut inbound, &mut outbound);
                let watch = async {
                    while !cut.load(Ordering::SeqCst) {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                };
                // Either side closing ends it; so does the cut, which drops both sockets.
                tokio::select! {
                    _ = copy => {}
                    () = watch => {}
                }
            });
        }
    });
    Ok(Relay { port, down })
}

#[tokio::test(flavor = "multi_thread")]
async fn with_postgres_down_known_keys_work_and_budgeted_requests_are_refused() -> TestResult {
    let Some(url) = database("down").await? else {
        return Ok(());
    };
    let config: tokio_postgres::Config = url.parse()?;
    let host = match config.get_hosts().first() {
        Some(tokio_postgres::config::Host::Tcp(host)) => host.clone(),
        _ => "127.0.0.1".into(),
    };
    let relay = relay((host, config.get_ports().first().copied().unwrap_or(5432))).await?;
    let through = key_value(
        &config,
        Some(relay.port),
        config.get_dbname().unwrap_or("postgres"),
    );
    let port = provider().await?;
    let a_dir = dir("down-a")?;
    let a = gateway(&a_dir, &through, port)?;
    add_key(&a, "ops", "ops", ADMIN, true)?;
    add_key(&a, "maya", "ops", MAYA, false)?;
    add_key(&a, "pat", "payments", PAT, false)?;
    add_key(&a, "lee", "rated", LEE, false)?;
    let (status, body) = answer(
        &a.router,
        request(
            "POST",
            "/admin/kills",
            ADMIN,
            r#"{"scope":"person","value":"maya","reason":"paused"}"#,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = answer(
        &a.router,
        request("POST", "/v1/chat/completions", PAT, BUDGETED)?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = answer(&a.router, request("GET", "/readyz", ADMIN, "")?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["checks"]["store"]["ready"], true);

    relay.down.store(true, Ordering::SeqCst);
    let start = Instant::now();
    loop {
        let (status, body) = answer(
            &a.router,
            request("POST", "/v1/chat/completions", PAT, BUDGETED)?,
        )
        .await?;
        if status == StatusCode::SERVICE_UNAVAILABLE {
            assert_eq!(code(&body), "store_unavailable", "{body}");
            let message = body["error"]["message"].as_str().unwrap_or_default();
            assert!(
                message.contains("Postgres"),
                "the refusal names the fix: {message}"
            );
            break;
        }
        // Until the cut is noticed a request may still be served: it is never let through unreserved.
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "the outage was never noticed"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Readiness says so: an orchestrator stops sending here while the store is away.
    let (status, body) = answer(&a.router, request("GET", "/readyz", ADMIN, "")?).await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["checks"]["store"]["ready"], false);
    // Known keys keep working from memory, and the kill switch keeps its last state.
    tokio::time::sleep(Duration::from_secs(1)).await;
    // A request under a rate limit every replica shares cannot be counted, so it is refused as a budgeted one is.
    let (status, body) = answer(
        &a.router,
        request("POST", "/v1/chat/completions", LEE, FREE)?,
    )
    .await?;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::SERVICE_UNAVAILABLE, "store_unavailable"),
        "{body}"
    );
    let (status, body) = answer(
        &a.router,
        request("POST", "/v1/chat/completions", ADMIN, FREE)?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = answer(
        &a.router,
        request("POST", "/v1/chat/completions", MAYA, FREE)?,
    )
    .await?;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::FORBIDDEN, "killed"),
        "{body}"
    );
    // A change cannot be made, and says why.
    let (status, body) = answer(
        &a.router,
        request(
            "POST",
            "/admin/keys",
            ADMIN,
            r#"{"name":"new","team":"ops"}"#,
        )?,
    )
    .await?;
    assert!(!status.is_success(), "{body}");

    // Back again: budgeted requests are served once the poll has reconnected.
    relay.down.store(false, Ordering::SeqCst);
    let start = Instant::now();
    loop {
        let (status, body) = answer(
            &a.router,
            request("POST", "/v1/chat/completions", PAT, BUDGETED)?,
        )
        .await?;
        if status == StatusCode::OK {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "never served again: {body}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (status, body) = answer(&a.router, request("GET", "/readyz", ADMIN, "")?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_changed_or_rotated_on_one_gateway_is_in_force_on_the_other_with_shared_spend()
-> TestResult {
    let Some(url) = database("keyops").await? else {
        return Ok(());
    };
    let port = provider().await?;
    let (a_dir, b_dir) = (dir("keyops-a")?, dir("keyops-b")?);
    let a = gateway(&a_dir, &url, port)?;
    add_key(&a, "ops", "ops", ADMIN, true)?;
    add_key(&a, "pat", "payments", PAT, false)?;
    let b = gateway(&b_dir, &url, port)?;
    let prefix = &gantry_core::id::sha256_hex(PAT.as_bytes())[..8];
    let path = format!("/admin/keys/{prefix}");
    let (status, body) = answer(
        &a.router,
        request("PATCH", &path, ADMIN, r#"{"rpm": 1, "tags": ["eval"], "routes": ["/v1/chat/completions"], "metadata": {"owner": "pat"}}"#)?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    // b reads the change from the store.
    let start = Instant::now();
    loop {
        let (_, info) = answer(&b.router, request("GET", &path, ADMIN, "")?).await?;
        if info["key"]["rpm"] == 1 {
            assert_eq!(info["key"]["tags"], serde_json::json!(["eval"]));
            assert_eq!(info["spend_counted_by"], "store");
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "b never saw the change: {info}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // One rpm across both gateways: the key's own limit is shared through the store.
    let (status, body) = answer(
        &a.router,
        request("POST", "/v1/chat/completions", PAT, BUDGETED)?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let (status, body) = answer(
        &b.router,
        request("POST", "/v1/chat/completions", PAT, BUDGETED)?,
    )
    .await?;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
        "{body}"
    );
    // The key's spend is the store's, the same on both.
    let (_, info) = answer(&b.router, request("GET", &path, ADMIN, "")?).await?;
    let spent: f64 = info["spend"].as_array().map_or(0.0, |rows| {
        rows.iter().filter_map(|r| r["spent_usd"].as_f64()).sum()
    });
    assert!(spent > 0.0, "{info}");
    // A rotation on a: b accepts the new key, and records the old one's use as in its grace.
    let (status, rotated) = answer(
        &a.router,
        request("PATCH", &path, ADMIN, r#"{"rpm": null}"#)?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{rotated}");
    let (status, rotated) = answer(
        &a.router,
        request(
            "POST",
            &format!("{path}/rotate"),
            ADMIN,
            r#"{"grace": "2h"}"#,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED, "{rotated}");
    let new_key = rotated["key"].as_str().ok_or("no key")?.to_string();
    let start = Instant::now();
    loop {
        let (status, body) = answer(
            &b.router,
            request("POST", "/v1/chat/completions", &new_key, BUDGETED)?,
        )
        .await?;
        if status == StatusCode::OK {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "b never took the new key: {body}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (status, body) = answer(
        &b.router,
        request("POST", "/v1/chat/completions", PAT, BUDGETED)?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let log = std::fs::read_to_string(b_dir.join("gantry-audit.jsonl"))?;
    assert!(log.contains("\"key_rotated\""), "{log}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn serve_refuses_to_start_without_its_store_or_on_a_newer_schema() -> TestResult {
    let Some(url) = database("start").await? else {
        return Ok(());
    };
    let port = provider().await?;
    let d = dir("start")?;
    let policy = d.join("gantry.policy.yaml");
    std::fs::write(&policy, self::policy(port))?;
    let unset = gantry_server::governed(&policy, None, &|variable| {
        (variable != "GANTRY_STORE_URL").then(|| "provider-secret".to_string())
    })
    .err()
    .unwrap_or_default();
    assert!(
        unset.contains("GANTRY_STORE_URL") && unset.contains("is not set"),
        "{unset}"
    );
    let closed = gantry_server::governed(&policy, None, &|variable| match variable {
        "GANTRY_STORE_URL" => Some("host=127.0.0.1 port=9 user=x dbname=x sslmode=disable".into()),
        // No master key: these gateways keep no provider credentials.
        "GANTRY_MASTER_KEY" | "GANTRY_MASTER_KEY_FILE" => None,
        _ => Some("provider-secret".into()),
    })
    .err()
    .unwrap_or_default();
    assert!(closed.contains("cannot be reached"), "{closed}");

    // A gateway creates the tables; a database a newer Gantry wrote is refused.
    drop(gateway(&d, &url, port)?);
    let config: tokio_postgres::Config = url.parse()?;
    let (client, connection) = config.connect(tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    client
        .batch_execute("INSERT INTO gantry_schema VALUES (999)")
        .await?;
    let newer = gateway(&dir("start-newer")?, &url, port)
        .err()
        .map(|e| e.to_string());
    let newer = newer.unwrap_or_default();
    assert!(newer.contains("newer Gantry"), "{newer}");

    // A rolling upgrade: a schema moved ahead by the next minor version is used; two minor versions ahead is refused,
    // naming both versions.
    let mut parts = gantry_core::VERSION.split('.').map(str::parse::<u64>);
    let (Some(Ok(major)), Some(Ok(minor))) = (parts.next(), parts.next()) else {
        return Err("the workspace version is not X.Y.Z".into());
    };
    let next = format!("{major}.{}.0", minor + 1);
    client
        .execute("UPDATE gantry_writer SET version = $1", &[&next])
        .await?;
    drop(gateway(&dir("start-next")?, &url, port)?);
    let writer: String = client
        .query_one("SELECT version FROM gantry_writer", &[])
        .await?
        .try_get(0)?;
    assert_eq!(writer, next, "an older Gantry lowered the recorded version");
    let two = format!("{major}.{}.0", minor + 2);
    client
        .execute("UPDATE gantry_writer SET version = $1", &[&two])
        .await?;
    let refused = gateway(&dir("start-two")?, &url, port)
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(
        refused.contains(&two)
            && refused.contains(gantry_core::VERSION)
            && refused.contains("one minor version apart"),
        "{refused}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_budgeted_request_with_the_store_costs_one_round_trip() -> TestResult {
    let Some(url) = database("latency").await? else {
        return Ok(());
    };
    let port = provider().await?;
    let a_dir = dir("latency")?;
    let a = gateway(&a_dir, &url, port)?;
    add_key(&a, "pat", "roomy", PAT, false)?;
    add_key(&a, "maya", "ops", MAYA, false)?;
    let request_of = |key: &str, body: &str| request("POST", "/v1/chat/completions", key, body);
    let times = |samples: &mut Vec<Duration>| {
        samples.sort();
        let at = |q: f64| samples[((samples.len() as f64 - 1.0) * q) as usize];
        (at(0.5), at(0.99))
    };
    // The same request with and without a budget (roomy has $1000 a day), so the difference is the reservation
    // and the settlement in the store.
    let mut budgeted = Vec::new();
    let mut unbudgeted = Vec::new();
    for _ in 0..200 {
        let start = Instant::now();
        let (status, _) = answer(&a.router, request_of(MAYA, FREE)?).await?;
        unbudgeted.push(start.elapsed());
        assert_eq!(status, StatusCode::OK);
        let start = Instant::now();
        let (status, body) = answer(&a.router, request_of(PAT, BUDGETED)?).await?;
        budgeted.push(start.elapsed());
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let (b50, b99) = times(&mut budgeted);
    let (u50, u99) = times(&mut unbudgeted);
    eprintln!(
        "through a gateway with a mock provider: without a budget p50 {u50:?} p99 {u99:?}; with a budget in the store p50 {b50:?} p99 {b99:?}"
    );
    assert!(
        b50 < Duration::from_millis(100),
        "a budgeted request took {b50:?}"
    );
    Ok(())
}

/// A Postgres that speaks TLS, as a managed database does: the test CA's certificate for 127.0.0.1
/// (tests/tls) in front of the plain test server. It answers the client's SSLRequest, then relays.
async fn tls_relay(to: (String, u16)) -> Result<u16, Error> {
    let fixture = |name: &str| {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/tls")
            .join(name)
    };
    let acceptor = gantry_server::tls_acceptor(&fixture("cert.pem"), &fixture("key.pem"))?;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        while let Ok((mut inbound, _)) = listener.accept().await {
            let (acceptor, to) = (acceptor.clone(), to.clone());
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut request = [0u8; 8];
                if inbound.read_exact(&mut request).await.is_err()
                    || inbound.write_all(b"S").await.is_err()
                {
                    return;
                }
                let Ok(mut tls) = acceptor.accept(inbound).await else {
                    return;
                };
                let Ok(mut outbound) = tokio::net::TcpStream::connect(to).await else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut tls, &mut outbound).await;
            });
        }
    });
    Ok(port)
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_to_the_store_does_what_sslmode_and_sslrootcert_say() -> TestResult {
    let Some(url) = database("tls").await? else {
        return Ok(());
    };
    let config: tokio_postgres::Config = url.parse()?;
    let host = match config.get_hosts().first() {
        Some(tokio_postgres::config::Host::Tcp(host)) => host.clone(),
        _ => "127.0.0.1".into(),
    };
    let relay = tls_relay((host, config.get_ports().first().copied().unwrap_or(5432))).await?;
    // The plain string of this test's database, less its sslmode, pointed at the relay.
    let plain = key_value(
        &config,
        Some(relay),
        config.get_dbname().unwrap_or("postgres"),
    );
    let plain = plain.replace(" sslmode=disable", "");
    let ca = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/tls/ca.pem")
        .display()
        .to_string();
    let port = provider().await?;
    let start = |name: &str, url: String| -> Result<(), String> {
        let d = dir(name).map_err(|e| e.to_string())?;
        gateway(&d, &url, port).map(drop).map_err(|e| e.to_string())
    };

    // verify-full, the default, against a private CA named by sslrootcert.
    start(
        "tls-full",
        format!("{plain} sslmode=verify-full sslrootcert='{ca}'"),
    )?;
    start("tls-default", format!("{plain} sslrootcert='{ca}'"))?;
    // Without it, the certificate is not trusted, and the refusal names sslrootcert as the fix.
    let untrusted = start("tls-untrusted", plain.clone())
        .err()
        .unwrap_or_default();
    assert!(
        untrusted.contains("not signed by a certificate Gantry trusts")
            && untrusted.contains("sslrootcert=")
            && untrusted.contains("global-bundle.pem"),
        "{untrusted}"
    );
    // A certificate for 127.0.0.1 reached as localhost: verify-full refuses the name, verify-ca checks the signer.
    let by_name = plain.replace("host='127.0.0.1'", "host='localhost' hostaddr=127.0.0.1");
    assert_ne!(by_name, plain, "the host is named in the string");
    let wrong_name = start("tls-name", format!("{by_name} sslrootcert='{ca}'"))
        .err()
        .unwrap_or_default();
    assert!(
        wrong_name.contains("does not name the host"),
        "{wrong_name}"
    );
    start(
        "tls-ca",
        format!("{by_name} sslmode=verify-ca sslrootcert='{ca}'"),
    )?;
    let other_ca = start("tls-ca-mozilla", format!("{by_name} sslmode=verify-ca"))
        .err()
        .unwrap_or_default();
    assert!(other_ca.contains("sslrootcert="), "{other_ca}");
    // require: encrypted, not checked, as libpq does.
    start("tls-require", format!("{by_name} sslmode=require"))?;
    // A server without TLS is refused unless the string says sslmode=disable.
    let no_tls = key_value(&config, None, config.get_dbname().unwrap_or("postgres"))
        .replace(" sslmode=disable", "");
    let refused = start("tls-none", no_tls.clone()).err().unwrap_or_default();
    assert!(refused.contains("sslmode=disable"), "{refused}");
    for message in [&untrusted, &wrong_name, &refused] {
        eprintln!("{message}");
    }
    start("tls-disabled", format!("{no_tls} sslmode=disable"))?;
    Ok(())
}

/// A Unix socket in front of the test Postgres, as the Cloud SQL connector gives one at /cloudsql/...: plain
/// bytes both ways, and the server behind it offers no TLS.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_unix_socket_connects_without_tls_whatever_sslmode_says() -> TestResult {
    let Some(url) = database("socket").await? else {
        return Ok(());
    };
    let config: tokio_postgres::Config = url.parse()?;
    let host = match config.get_hosts().first() {
        Some(tokio_postgres::config::Host::Tcp(host)) => host.clone(),
        _ => "127.0.0.1".into(),
    };
    let to = (host, config.get_ports().first().copied().unwrap_or(5432));
    // Short and under /tmp: a socket path is limited to about 100 bytes.
    let folder = PathBuf::from(format!("/tmp/gantry-sock-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&folder);
    std::fs::create_dir_all(&folder)?;
    let port = 5432;
    let listener = tokio::net::UnixListener::bind(folder.join(format!(".s.PGSQL.{port}")))?;
    tokio::spawn(async move {
        while let Ok((mut inbound, _)) = listener.accept().await {
            let to = to.clone();
            tokio::spawn(async move {
                if let Ok(mut outbound) = tokio::net::TcpStream::connect(to).await {
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                }
            });
        }
    });
    let password = config
        .get_password()
        .map(|p| String::from_utf8_lossy(p).to_string())
        .unwrap_or_default();
    let socket = format!(
        "host='{}' port={port} user='{}' password='{password}' dbname='{}'",
        folder.display(),
        config.get_user().unwrap_or("postgres"),
        config.get_dbname().unwrap_or("postgres")
    );
    let provider = provider().await?;
    for (name, tail) in [("sock-default", ""), ("sock-full", " sslmode=verify-full")] {
        let a = gateway(&dir(name)?, &format!("{socket}{tail}"), provider)?;
        // The second gateway reads the key the first wrote, at start.
        if name == "sock-default" {
            add_key(&a, "maya", "ops", MAYA, false)?;
        }
        let (status, body) = answer(
            &a.router,
            request("POST", "/v1/chat/completions", MAYA, FREE)?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{name}: {body}");
    }
    let _ = std::fs::remove_dir_all(&folder);
    Ok(())
}

/// Sends `n` requests at once, spread over `gateways` in turn, and counts those admitted. Every other answer must
/// be a `rate_limited` refusal with a Retry-After.
async fn burst(gateways: &[&Governed], key: &str, body: &str, n: usize) -> Result<usize, Error> {
    let mut tasks = Vec::new();
    for i in 0..n {
        let app = gateways[i % gateways.len()].router.clone();
        let request = request("POST", "/v1/chat/completions", key, body)?;
        tasks.push(tokio::spawn(async move {
            let response = app.oneshot(request).await.map_err(|e| e.to_string())?;
            let status = response.status();
            let retry = response.headers().contains_key(header::RETRY_AFTER);
            let body = response
                .into_body()
                .collect()
                .await
                .map_err(|e| e.to_string())?
                .to_bytes();
            Ok::<_, String>((
                status,
                retry,
                serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null),
            ))
        }));
    }
    let mut admitted = 0;
    for task in tasks {
        let (status, retry, body) = task.await??;
        match status {
            StatusCode::OK => admitted += 1,
            StatusCode::TOO_MANY_REQUESTS => {
                assert_eq!(code(&body), "rate_limited", "{body}");
                assert!(retry, "a refusal that would fit later says when: {body}");
            }
            other => return Err(format!("unexpected {other}: {body}").into()),
        }
    }
    Ok(admitted)
}

/// Three gateways on one database, each with the person's key.
fn three(
    test: &str,
    url: &str,
    port: u16,
    keys: &[(&str, &str, &str)],
) -> Result<[Governed; 3], Error> {
    let a = gateway(&dir(&format!("{test}-a"))?, url, port)?;
    for (name, team, key) in keys {
        add_key(&a, name, team, key, false)?;
    }
    let b = gateway(&dir(&format!("{test}-b"))?, url, port)?;
    let c = gateway(&dir(&format!("{test}-c"))?, url, port)?;
    Ok([a, b, c])
}

#[tokio::test(flavor = "multi_thread")]
async fn three_gateways_never_admit_more_than_one_rpm_between_them() -> TestResult {
    let Some(url) = database("rpm").await? else {
        return Ok(());
    };
    let port = provider().await?;
    let [a, b, c] = three("rpm", &url, port, &[("pat", "rated", PAT)])?;
    // 90 requests at once from one person, 30 through each gateway, under an rpm of 30. Counted per gateway, each
    // would admit 30: 90 in all.
    let admitted = burst(&[&a, &b, &c], PAT, FREE, 90).await?;
    eprintln!("three gateways admitted {admitted} of 90 under rpm 30");
    assert!(
        admitted <= 30,
        "{admitted} admitted: more than the rpm of 30"
    );
    // A slice a gateway leased and has not used yet waits for its lease to end before another gateway may have it.
    assert!(
        admitted >= 27,
        "only {admitted} admitted: the leases held back too much"
    );
    // A second burst inside the same minute is refused on every gateway.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let later = burst(&[&a, &b, &c], PAT, FREE, 9).await?;
    assert!(
        admitted + later <= 30,
        "{admitted} then {later}: more than 30 in one minute"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn three_gateways_never_admit_more_than_one_tpm_between_them() -> TestResult {
    let Some(url) = database("tpm").await? else {
        return Ok(());
    };
    let port = provider().await?;
    let [a, b, c] = three("tpm", &url, port, &[("lee", "tokens", LEE)])?;
    // Each request could use 46 / 3 rounded up, 16, plus its max_tokens of 20: 36 tokens. 300 a minute fit 8 of
    // them. The answers take a second, so none gives back what it did not use during the burst.
    let body = r#"{"model":"slow","max_tokens":20,"messages":[]}"#;
    let admitted = burst(&[&a, &b, &c], LEE, body, 30).await?;
    eprintln!("three gateways admitted {admitted} of 30 under tpm 300");
    assert!(admitted <= 8, "{admitted} admitted: more than 300 tokens");
    assert!(
        admitted >= 7,
        "only {admitted} admitted: the leases held back too much"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_deployment_that_failed_on_one_gateway_is_passed_over_by_the_others() -> TestResult {
    let Some(url) = database("cooldown").await? else {
        return Ok(());
    };
    let port = provider().await?;
    let [a, b, _c] = three("cooldown", &url, port, &[("maya", "paired", MAYA)])?;
    // Round robin over two deployments: one of two requests through a goes to the dead one first, which fails it.
    for _ in 0..2 {
        let (status, body) = answer(
            &a.router,
            request(
                "POST",
                "/v1/chat/completions",
                MAYA,
                r#"{"model":"pair","messages":[]}"#,
            )?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    // b never failed it itself, and still passes it over: each of its requests goes to the live one first.
    for _ in 0..4 {
        let (status, body) = answer(
            &b.router,
            request(
                "POST",
                "/v1/chat/completions",
                MAYA,
                r#"{"model":"pair","messages":[]}"#,
            )?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let log = std::fs::read_to_string(dir_of(&b).join("gantry-audit.jsonl"))?;
    let decisions = log.lines().filter(|l| l.contains("\"deployment\"")).count();
    assert_eq!(decisions, 4, "{log}");
    assert!(
        !log.contains("dead/gone"),
        "b sent to the deployment a found dead: {log}"
    );
    Ok(())
}

/// The deployment and the reason of each routed request in `gw`'s audit log, oldest first.
fn routes(gw: &Governed) -> Result<Vec<(String, String)>, Error> {
    let log = std::fs::read_to_string(dir_of(gw).join("gantry-audit.jsonl"))?;
    Ok(log
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|r| r["routing"]["deployment"].is_string())
        .map(|r| {
            (
                r["routing"]["deployment"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                r["routing"]["reason"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            )
        })
        .collect())
}

async fn send(gw: &Governed, body: &str, session: Option<&str>) -> Result<(), Error> {
    let mut request = request("POST", "/v1/chat/completions", MAYA, body)?;
    if let Some(session) = session {
        request
            .headers_mut()
            .insert("x-claude-code-session-id", session.parse()?);
    }
    let (status, body) = answer(&gw.router, request).await?;
    if status != StatusCode::OK {
        return Err(format!("{status} {body}").into());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_pinned_on_one_gateway_goes_to_the_same_deployment_on_the_other() -> TestResult {
    let Some(url) = database("affinity").await? else {
        return Ok(());
    };
    let port = provider().await?;
    let [a, b, _c] = three("affinity", &url, port, &[("maya", "paired", MAYA)])?;
    let sticky = r#"{"model":"sticky","messages":[]}"#;
    // Moves b's round robin on, so its own turn would differ from a's for the session.
    send(&b, sticky, None).await?;
    send(&a, sticky, Some("s1")).await?;
    let pinned = routes(&a)?.last().map(|r| r.0.clone()).unwrap_or_default();
    assert!(!pinned.is_empty());
    tokio::time::sleep(Duration::from_millis(1500)).await;
    for _ in 0..4 {
        send(&b, sticky, Some("s1")).await?;
    }
    let seen = routes(&b)?;
    for (deployment, reason) in &seen[1..] {
        assert_eq!(deployment, &pinned, "b moved the session: {seen:?}");
        assert!(reason.starts_with("session: pinned"), "{reason}");
    }
    assert_eq!(seen.len(), 5, "{seen:?}");
    // Another session is still balanced as usual on b.
    send(&b, sticky, Some("s2")).await?;
    let last = routes(&b)?.last().map(|r| r.1.clone()).unwrap_or_default();
    assert!(last.starts_with("round_robin"), "{last}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn lowest_latency_ranks_deployments_on_what_every_gateway_measured() -> TestResult {
    let Some(url) = database("ttfb").await? else {
        return Ok(());
    };
    let port = provider().await?;
    let [a, b, _c] = three("ttfb", &url, port, &[("maya", "paired", MAYA)])?;
    let quick = r#"{"model":"quick","messages":[]}"#;
    // a measures both, a poll apart: the first deployment answers after 150 ms, the second at once. Each gateway
    // ranks on the shared numbers only, so a too waits for its own samples to come back from the store.
    for _ in 0..3 {
        send(&a, quick, None).await?;
        tokio::time::sleep(Duration::from_millis(1200)).await;
    }
    let on_a = routes(&a)?;
    assert_eq!(
        on_a.last().map(|r| r.0.as_str()),
        Some("mock2/fast"),
        "{on_a:?}"
    );
    // b sent nothing to either, and still goes to the fast one first, on the numbers a measured.
    send(&b, quick, None).await?;
    let on_b = routes(&b)?;
    let (deployment, reason) = on_b.first().cloned().unwrap_or_default();
    assert_eq!(deployment, "mock2/fast", "{on_b:?}");
    assert!(reason.contains("p90 time to first byte"), "{reason}");
    Ok(())
}

/// A deployment's rpm and max_parallel count every gateway's requests: what a sent is seen by b within a poll.
#[tokio::test(flavor = "multi_thread")]
async fn a_deployment_s_rpm_and_max_parallel_hold_across_gateways() -> TestResult {
    let Some(url) = database("deployment_load").await? else {
        return Ok(());
    };
    let port = provider().await?;
    let [a, b, _c] = three("deployment_load", &url, port, &[("maya", "paired", MAYA)])?;
    // The rpm window is the wall-clock minute: start well inside one.
    let second = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        % 60;
    if second > 45 {
        tokio::time::sleep(Duration::from_secs(61 - second)).await;
    }
    let capped = r#"{"model":"capped","messages":[]}"#;
    send(&a, capped, None).await?;
    send(&a, capped, None).await?;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let (status, body) = answer(
        &b.router,
        request("POST", "/v1/chat/completions", MAYA, capped)?,
    )
    .await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(code(&body), "deployment_limit", "{body}");

    // One slow request in flight on a: b's is refused while it runs, and taken once it answered.
    let slow = r#"{"model":"single","messages":[]}"#;
    let (first, second) = tokio::join!(
        answer(
            &a.router,
            request("POST", "/v1/chat/completions", MAYA, slow)?
        ),
        async {
            tokio::time::sleep(Duration::from_millis(700)).await;
            answer(
                &b.router,
                request("POST", "/v1/chat/completions", MAYA, slow)?,
            )
            .await
        }
    );
    assert_eq!(first?.0, StatusCode::OK);
    let (status, body) = second?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    tokio::time::sleep(Duration::from_millis(1200)).await;
    send(&b, slow, None).await?;
    Ok(())
}

fn dir_of(gw: &Governed) -> PathBuf {
    gw.loaded
        .audit_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default()
}

/// The console session cookie a response sets, as `gantry_console=<id>`.
fn session_cookie(response: &axum::response::Response) -> Option<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with("gantry_console=") && !v.starts_with("gantry_console=;"))
        .and_then(|v| v.split(';').next())
        .map(str::to_string)
}

async fn console_page(gw: &Governed, cookie: &str) -> Result<StatusCode, Error> {
    let response = gw
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/console/audit")
                .header(header::HOST, "gantry.test")
                .header(header::COOKIE, cookie)
                .body(Body::empty())?,
        )
        .await?;
    Ok(response.status())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_console_sign_in_on_one_gateway_is_good_on_all_and_a_sign_out_ends_it_everywhere()
-> TestResult {
    let Some(url) = database("sessions").await? else {
        return Ok(());
    };
    let port = provider().await?;
    let a = gateway(&dir("sessions-a")?, &url, port)?;
    add_key(&a, "ops", "ops", ADMIN, true)?;
    let b = gateway(&dir("sessions-b")?, &url, port)?;
    let response = a
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/console/sign-in")
                .header(header::HOST, "gantry.test")
                .header(header::ORIGIN, "http://gantry.test")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("key={ADMIN}")))?,
        )
        .await?;
    let cookie = session_cookie(&response).ok_or("the sign-in set no session cookie")?;
    assert_eq!(console_page(&a, &cookie).await?, StatusCode::OK);
    assert_eq!(
        console_page(&b, &cookie).await?,
        StatusCode::OK,
        "b does not know a's session"
    );
    assert_ne!(
        console_page(&b, "gantry_console=00ff").await?,
        StatusCode::OK,
        "a made-up session is refused"
    );

    let response = a
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/console/sign-out")
                .header(header::HOST, "gantry.test")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())?,
        )
        .await?;
    assert!(response.status().is_redirection());
    let start = Instant::now();
    while console_page(&b, &cookie).await? == StatusCode::OK {
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "b still serves a session signed out on a"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_ne!(console_page(&a, &cookie).await?, StatusCode::OK);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn one_gateway_at_a_time_holds_a_deployment_s_probe() -> TestResult {
    use gantry_core::store::Store;
    let Some(url) = database("probe_lease").await? else {
        return Ok(());
    };
    let a = gantry_server::store::open("GANTRY_TEST_DATABASE_URL", &url)?;
    let b = gantry_server::store::open("GANTRY_TEST_DATABASE_URL", &url)?;
    let ttl = Duration::from_secs(1);
    assert!(a.probe_lease("p/m".into(), ttl).await?);
    assert!(!b.probe_lease("p/m".into(), ttl).await?, "a holds it");
    assert!(
        b.probe_lease("q/m".into(), ttl).await?,
        "each deployment has its own"
    );
    assert!(
        a.probe_lease("p/m".into(), ttl).await?,
        "the holder keeps it"
    );
    tokio::time::sleep(Duration::from_millis(1300)).await;
    assert!(
        b.probe_lease("p/m".into(), ttl).await?,
        "taken over once a stopped probing"
    );
    assert!(!a.probe_lease("p/m".into(), ttl).await?);
    Ok(())
}
