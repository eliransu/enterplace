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

/// A provider whose every answer used 3 output tokens.
async fn provider() -> Result<u16, Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let app = Router::new().route(
        "/v1/chat/completions",
        post(|_: Bytes| async move {
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
/// may spend $0.01 a day on it: three requests fit, a fourth would pass the budget.
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
    models: [m, free]
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
"
    )
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
    // Known keys keep working from memory, and the kill switch keeps its last state.
    tokio::time::sleep(Duration::from_secs(1)).await;
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
