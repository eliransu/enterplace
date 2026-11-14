//! Acceptance tests for slice 1: a request is identified, decided and recorded before it is forwarded,
//! with the files read the same way `gantry serve` reads them.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::post,
};
use gantry_core::{
    audit::{self, AuditLog},
    id::sha256_hex,
};
use gantry_server::{Audit, Config, Secret};
use http_body_util::BodyExt;
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const PROVIDER_KEY: &str = "provider-secret-9f3b";
const MAYA: &str = "gantry_maya";
const OMER: &str = "gantry_omer";
const DANA: &str = "gantry_dana";
// Two keys in the real format: the prefix and 64 hex characters.
const LIOR: &str = "gantry_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const GAL: &str = "gantry_fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

/// What the mock provider saw.
#[derive(Default)]
struct Provider {
    hits: AtomicUsize,
    authorization: Mutex<Vec<String>>,
}

async fn provider() -> Result<(SocketAddr, Arc<Provider>), Box<dyn std::error::Error>> {
    let seen = Arc::new(Provider::default());
    let record = seen.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move |request: Request<Body>| {
            record.hits.fetch_add(1, Ordering::SeqCst);
            let sent = request
                .headers()
                .get_all(header::AUTHORIZATION)
                .iter()
                .filter_map(|v| v.to_str().ok().map(String::from));
            if let Ok(mut all) = record.authorization.lock() {
                all.extend(sent);
            }
            async move { request.into_body() }
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((addr, seen))
}

struct Gateway {
    app: Router,
    provider: Arc<Provider>,
    audit: PathBuf,
}

fn files(name: &str, upstream: SocketAddr) -> std::io::Result<PathBuf> {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "gantry-governed-{}-{}-{name}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        dir.join("gantry.policy.yaml"),
        format!(
            "version: 1
providers:
  - name: mock
    kind: openai
    url: http://{upstream}
    allow_private: true
    key_env: UNUSED_IN_TESTS
    models: [model-a]
rules:
  - name: maya-only
    principals: {{ name: maya.cohen }}
    models: [model-a]
  - name: payments-team
    principals: {{ team: payments }}
    models: [\"*\"]
"
        ),
    )?;
    let key = |name: &str, team: &str, key: &str| {
        format!(
            "  - name: {name}\n    team: {team}\n    sha256: {}\n",
            sha256_hex(key.as_bytes())
        )
    };
    std::fs::write(
        dir.join("gantry.keys.yaml"),
        format!(
            "keys:\n{}{}{}",
            key("maya.cohen", "payments", MAYA),
            key("omer.katz", "payments", OMER),
            key("dana.levi", "interns", DANA)
        ) + &key("lior.amit", "payments", LIOR)
            + &key("gal.peretz", "payments", GAL),
    )?;
    Ok(dir)
}

fn start(dir: &Path, log: AuditLog) -> Result<Router, Box<dyn std::error::Error>> {
    start_with(dir, log, None)
}

fn start_with(
    dir: &Path,
    log: AuditLog,
    max_buffered_bytes: Option<usize>,
) -> Result<Router, Box<dyn std::error::Error>> {
    let loaded = gantry_core::config::load(&dir.join("gantry.policy.yaml"), None)
        .map_err(|e| e.join("\n"))?;
    Ok(gantry_server::app(Config {
        // One upstream that serves every model, so the tests below can use any model name.
        upstream: Some(loaded.providers[0].url.clone()),
        provider_key: Some(Secret::new(PROVIDER_KEY)),
        audit: Some(Audit {
            log: Arc::new(log),
            provider: loaded.providers[0].name.clone(),
            policy_sha256: loaded.policy_sha256.clone(),
            keys_sha256: loaded.keys_sha256.clone(),
        }),
        policy: Some(loaded.policy),
        max_buffered_bytes,
        ..Config::default()
    })?)
}

async fn gateway(name: &str) -> Result<Gateway, Box<dyn std::error::Error>> {
    let (upstream, provider) = provider().await?;
    let dir = files(name, upstream)?;
    let audit = dir.join("gantry-audit.jsonl");
    let app = start(&dir, AuditLog::open(&audit)?)?;
    Ok(Gateway {
        app,
        provider,
        audit,
    })
}

fn chat(key: &str, model: &str) -> Result<Request<Body>, axum::http::Error> {
    Request::post("/v1/chat/completions")
        .header(header::AUTHORIZATION, format!("Bearer {key}"))
        .body(Body::from(format!(
            r#"{{"model":"{model}","messages":[]}}"#
        )))
}

/// Status, the decision header, and the body as text.
async fn answer(
    app: &Router,
    request: Request<Body>,
) -> Result<(StatusCode, String, String), Box<dyn std::error::Error>> {
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    let decision = response
        .headers()
        .get("x-gantry-decision")
        .ok_or("the response carries no decision ID")?
        .to_str()?
        .to_string();
    let body = String::from_utf8(response.into_body().collect().await?.to_bytes().to_vec())?;
    Ok((status, decision, body))
}

fn records(path: &Path) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    std::fs::read_to_string(path)?
        .lines()
        // Decision records. Each forwarded request also gets a usage record when its answer ends: tests/spend.rs.
        .filter(|line| !line.contains("\"event\":\"usage\""))
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

#[tokio::test]
async fn an_allowed_request_is_recorded_then_forwarded_with_the_provider_key() -> TestResult {
    let gw = gateway("allowed").await?;
    let (status, decision, body) = answer(&gw.app, chat(OMER, "any-model")?).await?;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(decision.len(), 26);
    assert_eq!(body, r#"{"model":"any-model","messages":[]}"#);
    let sent = gw
        .provider
        .authorization
        .lock()
        .map_err(|_| "lock")?
        .clone();
    assert_eq!(
        sent,
        [format!("Bearer {PROVIDER_KEY}")],
        "the provider must get its own key and never the caller's"
    );

    let records = records(&gw.audit)?;
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record["id"], decision.as_str());
    assert_eq!(record["person"], "omer.katz");
    assert_eq!(record["team"], "payments");
    assert_eq!(record["model"], "any-model");
    assert_eq!(record["verdict"], "allow");
    assert_eq!(record["rule"], "payments-team");
    assert_eq!(record["rule_line"], 13);
    assert_eq!(record["provider"], "mock");
    assert_eq!(record["policy_sha256"].as_str().map(str::len), Some(64));
    Ok(())
}

#[tokio::test]
async fn every_refusal_has_its_code_its_decision_id_and_a_record_and_nothing_is_forwarded()
-> TestResult {
    let gw = gateway("refusals").await?;
    let no_key = Request::post("/v1/chat/completions").body(Body::from("{}"))?;
    let two_keys = Request::post("/v1/chat/completions")
        .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
        .header(header::AUTHORIZATION, format!("Bearer {OMER}"))
        .body(Body::from("{}"))?;
    let other_route = Request::get("/v1/files")
        .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
        .body(Body::empty())?;
    let stranger_elsewhere = Request::get("/admin").body(Body::empty())?;
    let second_spelling = Request::post("/v1/chat/completions")
        .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
        .body(Body::from(r#"{"model":"model-a","MODEL":"model-b"}"#))?;
    let cases = [
        (no_key, StatusCode::UNAUTHORIZED, "no_key", "unknown"),
        (
            two_keys,
            StatusCode::BAD_REQUEST,
            "ambiguous_key",
            "unknown",
        ),
        (
            chat("gantry_nobody", "model-a")?,
            StatusCode::UNAUTHORIZED,
            "unknown_key",
            "unknown",
        ),
        (
            stranger_elsewhere,
            StatusCode::UNAUTHORIZED,
            "no_key",
            "unknown",
        ),
        (
            other_route,
            StatusCode::NOT_FOUND,
            "unknown_route",
            "maya.cohen",
        ),
        // The team rule below would allow model-b, but the rule that names maya comes first.
        (
            chat(MAYA, "model-b")?,
            StatusCode::FORBIDDEN,
            "model_not_allowed",
            "maya.cohen",
        ),
        (
            chat(DANA, "model-a")?,
            StatusCode::FORBIDDEN,
            "no_rule",
            "dana.levi",
        ),
        (
            second_spelling,
            StatusCode::BAD_REQUEST,
            "unreadable_request",
            "maya.cohen",
        ),
    ];
    let count = cases.len();
    let mut expected = Vec::new();
    for (request, status, code, person) in cases {
        expected.push((code, person));
        let (got, decision, body) = answer(&gw.app, request).await?;
        assert_eq!(got, status, "{code}: {body}");
        let json: serde_json::Value = serde_json::from_str(&body)?;
        assert_eq!(json["error"]["code"], code);
        assert_eq!(json["error"]["type"], "gantry_error");
        assert_eq!(json["error"]["decision"], decision.as_str());
        let message = json["error"]["message"].as_str().ok_or("no message")?;
        assert!(
            message.starts_with("Refused (") && message.ends_with(&format!("Decision {decision}.")),
            "{message}"
        );
        assert!(
            !body.contains(PROVIDER_KEY) && !body.contains("127.0.0.1"),
            "{body}"
        );
    }
    assert_eq!(gw.provider.hits.load(Ordering::SeqCst), 0);

    let records = records(&gw.audit)?;
    assert_eq!(
        records.len(),
        count,
        "one record per request, refused or not"
    );
    for (record, (code, person)) in records.iter().zip(&expected) {
        assert_eq!(record["verdict"], "refused");
        assert_eq!(record["code"], *code);
        assert_eq!(record["person"], *person);
    }
    assert_eq!(
        records[2]["key"].as_str().map(str::len),
        Some(8),
        "an unknown key leaves 8 characters of its hash"
    );
    assert_eq!(records[5]["rule"], "maya-only");
    assert_eq!(records[5]["rule_line"], 10);
    let log = std::fs::read_to_string(&gw.audit)?;
    for secret in [PROVIDER_KEY, MAYA, OMER, DANA, "gantry_nobody"] {
        assert!(!log.contains(secret), "the audit log holds a key");
    }
    assert_eq!(audit::verify_full(&gw.audit, None)?.requests, count as u64);
    Ok(())
}

#[tokio::test]
async fn the_chain_continues_after_a_restart_and_a_changed_record_is_found() -> TestResult {
    let (upstream, _provider) = provider().await?;
    let dir = files("restart", upstream)?;
    let log = dir.join("gantry-audit.jsonl");
    let first = start(&dir, AuditLog::open(&log)?)?;
    for model in ["a", "b", "c"] {
        answer(&first, chat(OMER, model)?).await?;
    }
    // A usage record is written as its answer ends. Opening the log again before the last one is on file would
    // start a second writer on the same chain, which a real restart (a new process) never does.
    for _ in 0..100 {
        if std::fs::read_to_string(&log)?
            .matches("\"event\":\"usage\"")
            .count()
            == 3
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    drop(first);
    let second = start(&dir, AuditLog::open(&log)?)?;
    answer(&second, chat(OMER, "d")?).await?;
    assert_eq!(audit::verify_full(&log, None)?.requests, 4);

    let text = std::fs::read_to_string(&log)?;
    // The decision record of model b, which comes before its usage record.
    let b = 1 + text
        .lines()
        .position(|line| line.contains("\"model\":\"b\""))
        .ok_or("no record of model b")?;
    std::fs::write(&log, text.replacen("\"model\":\"b\"", "\"model\":\"x\"", 1))?;
    let err = audit::verify(&log).err().ok_or("a changed record passed")?;
    assert!(err.contains(&format!("record {b} ")), "{err}");
    Ok(())
}

#[tokio::test]
async fn a_request_that_cannot_be_recorded_is_not_forwarded() -> TestResult {
    let (upstream, provider) = provider().await?;
    let dir = files("unwritable", upstream)?;
    let path = dir.join("read-only.jsonl");
    std::fs::write(&path, "")?;
    // A file opened for reading cannot be written, which is what a full or revoked disk looks like to the gateway.
    let app = start(&dir, AuditLog::from_file(std::fs::File::open(&path)?)?)?;
    let (status, decision, body) = answer(&app, chat(OMER, "any-model")?).await?;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let json: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(json["error"]["code"], "audit_unavailable");
    assert_eq!(json["error"]["decision"], decision.as_str());
    assert_eq!(provider.hits.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn many_requests_at_once_each_get_exactly_one_record() -> TestResult {
    let gw = gateway("concurrent").await?;
    let mut tasks = Vec::new();
    for i in 0..300 {
        let app = gw.app.clone();
        let request = if i % 3 == 0 {
            chat("gantry_nobody", "m")?
        } else {
            chat(OMER, "m")?
        };
        tasks.push(tokio::spawn(async move {
            app.oneshot(request).await.map(|r| r.status())
        }));
    }
    let mut ok = 0;
    for task in tasks {
        ok += usize::from(task.await?? == StatusCode::OK);
    }
    // 300 requests in flight at once is more than the old one-MiB-per-request budget could hold.
    assert_eq!(ok, 200);
    assert_eq!(audit::verify_full(&gw.audit, None)?.requests, 300);
    Ok(())
}

/// An upstream that keeps what it was sent and answers after a pause.
async fn watching_upstream(
    pause: std::time::Duration,
) -> Result<
    (SocketAddr, Arc<Mutex<Vec<(String, axum::http::HeaderMap)>>>),
    Box<dyn std::error::Error>,
> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = Router::new().fallback(move |request: Request<Body>| {
        if let Ok(mut all) = record.lock() {
            all.push((request.uri().to_string(), request.headers().clone()));
        }
        async move {
            tokio::time::sleep(pause).await;
            "{}"
        }
    });
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((addr, seen))
}

#[tokio::test]
async fn a_gantry_key_or_an_account_choice_reaches_the_provider_in_no_header_and_no_query()
-> TestResult {
    let (upstream, seen) = watching_upstream(std::time::Duration::ZERO).await?;
    let dir = files("headers", upstream)?;
    let app = start(&dir, AuditLog::open(&dir.join("gantry-audit.jsonl"))?)?;
    // A key in the query is refused by name, never forwarded and never dropped in silence.
    let in_query = Request::post(format!("/v1/chat/completions?api_key={LIOR}&x=1"))
        .header(header::AUTHORIZATION, format!("Bearer {LIOR}"))
        .body(Body::from(r#"{"model":"m","messages":[]}"#))?;
    let (status, _, body) = answer(&app, in_query).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body.contains("unknown_query") && body.contains("api_key"),
        "{body}"
    );
    assert!(!body.contains(LIOR), "the refusal repeats the key: {body}");
    assert!(seen.lock().map_err(|_| "lock")?.is_empty());

    let request = Request::post("/v1/chat/completions")
        .header(header::AUTHORIZATION, format!("Bearer {LIOR}"))
        .header("x-api-key", LIOR)
        .header("api-key", LIOR)
        .header("x-goog-api-key", LIOR)
        .header("x-auth-token", LIOR)
        .header("ocp-apim-subscription-key", LIOR)
        .header("api_key", LIOR)
        .header("x-innocent-name", format!("prefix {LIOR} suffix"))
        .header("idempotency-key", "retry-7")
        .header("x-upstream-api-key", "someone-elses-credential-1")
        .header("x-session-token", "someone-elses-credential-2")
        .header("x-client-secret", "someone-elses-credential-3")
        .header("openai-organization", "org-of-the-callers-choice")
        .header("openai-project", "proj-of-the-callers-choice")
        .header("x-request-id", "kept-1")
        // Proxy and CDN headers carry the caller's address and loop markers: a provider has no use for either, and
        // one behind Cloudflare refuses a request that carries Cloudflare's own (error 1000).
        .header("x-forwarded-for", "203.0.113.7")
        .header("x-forwarded-proto", "https")
        .header("x-real-ip", "203.0.113.7")
        .header("true-client-ip", "203.0.113.7")
        .header("forwarded", "for=203.0.113.7")
        .header("via", "1.1 edge")
        .header("cf-connecting-ip", "203.0.113.7")
        .header("cf-ray", "8a1b2c3d4e5f")
        .header("cdn-loop", "cloudflare")
        // What Fastly, Azure Front Door, Envoy, App Engine and Akamai-style proxies add.
        .header("x-client-ip", "203.0.113.7")
        .header("client-ip", "203.0.113.7")
        .header("x-true-client-ip", "203.0.113.7")
        .header("fastly-client-ip", "203.0.113.7")
        .header("x-cluster-client-ip", "203.0.113.7")
        .header("x-original-forwarded-for", "203.0.113.7")
        .header("x-envoy-external-address", "203.0.113.7")
        .header("x-azure-clientip", "203.0.113.7")
        .header("x-appengine-user-ip", "203.0.113.7")
        .header("x-originating-ip", "203.0.113.7")
        .header("x-remote-addr", "203.0.113.7")
        .header("x-remote-ip", "203.0.113.7")
        // Gantry reads every answer (usage, guardrails, translation), so it asks the provider for plain bytes.
        .header("accept-encoding", "gzip, br")
        .body(Body::from(r#"{"model":"m","messages":[]}"#))?;
    let (status, _, _) = answer(&app, request).await?;
    assert_eq!(status, StatusCode::OK);

    let seen = seen.lock().map_err(|_| "lock")?;
    let (uri, headers) = seen.first().ok_or("nothing reached the provider")?;
    assert_eq!(uri, "/v1/chat/completions", "the query must stay behind");
    let sent = format!("{headers:?}");
    assert!(
        !sent.contains(LIOR),
        "a Gantry key reached the provider: {sent}"
    );
    assert!(
        !sent.contains("callers-choice"),
        "the caller chose the provider account: {sent}"
    );
    assert_eq!(
        headers.get("x-request-id").and_then(|v| v.to_str().ok()),
        Some("kept-1")
    );
    assert_eq!(headers.get_all(header::AUTHORIZATION).iter().count(), 1);
    assert!(
        !sent.contains("someone-elses-credential"),
        "a header named for a credential reached the provider: {sent}"
    );
    assert_eq!(
        headers.get("idempotency-key").and_then(|v| v.to_str().ok()),
        Some("retry-7")
    );
    for name in [
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-real-ip",
        "true-client-ip",
        "forwarded",
        "via",
        "cf-connecting-ip",
        "cf-ray",
        "cdn-loop",
        "x-client-ip",
        "client-ip",
        "x-true-client-ip",
        "fastly-client-ip",
        "x-cluster-client-ip",
        "x-original-forwarded-for",
        "x-envoy-external-address",
        "x-azure-clientip",
        "x-appengine-user-ip",
        "x-originating-ip",
        "x-remote-addr",
        "x-remote-ip",
        "accept-encoding",
    ] {
        assert!(
            headers.get(name).is_none(),
            "{name} reached the provider: {sent}"
        );
    }
    assert!(
        !sent.contains("203.0.113.7"),
        "the caller's address reached the provider: {sent}"
    );
    Ok(())
}

#[tokio::test]
async fn one_caller_has_a_share_of_the_memory_and_all_callers_together_have_a_limit() -> TestResult
{
    let (upstream, _seen) = watching_upstream(std::time::Duration::from_secs(2)).await?;
    let dir = files("share", upstream)?;
    // A budget of 64 KiB, so one caller's share is 16 KiB. Each body here is 5 KiB.
    let app = start_with(
        &dir,
        AuditLog::open(&dir.join("gantry-audit.jsonl"))?,
        Some(64 * 1024),
    )?;
    let body_of = |key: &'static str, model: &'static str| {
        let body = format!(r#"{{"model":"{model}","pad":"{}"}}"#, "x".repeat(4_900));
        Request::post("/v1/chat/completions")
            .header(header::AUTHORIZATION, format!("Bearer {key}"))
            .body(Body::from(body))
    };
    let mut held = Vec::new();
    let mut hold = |key: &'static str, model: &'static str| -> TestResult {
        let (app, request) = (app.clone(), body_of(key, model)?);
        held.push(tokio::spawn(async move {
            app.oneshot(request).await.map(|r| r.status())
        }));
        Ok(())
    };
    // Three bodies in flight from one caller hold 15 KiB of its 16.
    for _ in 0..3 {
        hold(OMER, "m")?;
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let (status, _, body) = answer(&app, body_of(OMER, "m")?).await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert!(
        body.contains("\"busy\"") && body.contains("one caller"),
        "{body}"
    );

    // Three more callers do the same: 60 KiB of the 64 are held. None of them is refused for another's use.
    for (key, model) in [(MAYA, "model-a"), (LIOR, "m"), (GAL, "m")] {
        for _ in 0..3 {
            hold(key, model)?;
        }
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    // A fifth caller is inside its own share, and the whole budget has no room for 5 KiB more.
    let (status, _, body) = answer(&app, body_of(DANA, "m")?).await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(body.contains("\"busy\""), "{body}");

    for task in held {
        assert_eq!(task.await??, StatusCode::OK);
    }
    // Once the requests have finished, the memory is free again.
    let (status, _, _) = answer(&app, body_of(OMER, "m")?).await?;
    assert_eq!(status, StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn a_body_sent_a_byte_at_a_time_is_charged_for_its_bytes_not_its_frames() -> TestResult {
    let (upstream, _seen) = watching_upstream(std::time::Duration::from_millis(600)).await?;
    let dir = files("drip", upstream)?;
    let app = start(&dir, AuditLog::open(&dir.join("gantry-audit.jsonl"))?)?;
    // 40 requests in flight, each a body of 4,000 one-byte frames. Charged per frame that would be
    // 40 * 4,000 KiB = 156 MiB, far over one caller's 64 MiB. Charged per byte it is 160 KiB.
    let mut tasks = Vec::new();
    for _ in 0..40 {
        let app = app.clone();
        let body = format!(r#"{{"model":"m","pad":"{}"}}"#, "x".repeat(3_980));
        let frames = body
            .into_bytes()
            .into_iter()
            .map(|b| Ok::<_, std::io::Error>(vec![b]));
        let request = Request::post("/v1/chat/completions")
            .header(header::AUTHORIZATION, format!("Bearer {OMER}"))
            .body(Body::from_stream(Frames(frames)))?;
        tasks.push(tokio::spawn(async move {
            app.oneshot(request).await.map(|r| r.status())
        }));
    }
    for task in tasks {
        assert_eq!(task.await??, StatusCode::OK);
    }
    Ok(())
}

/// A stream over an iterator, without pulling in a stream library for one test.
struct Frames<I>(I);

impl<I: Iterator + Unpin> futures_core::Stream for Frames<I> {
    type Item = I::Item;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<I::Item>> {
        std::task::Poll::Ready(self.0.next())
    }
}

#[tokio::test]
async fn readiness_says_why_the_gateway_would_refuse_and_liveness_stays_up() -> TestResult {
    let (upstream, _provider) = provider().await?;
    let dir = files("ready", upstream)?;
    let log = dir.join("gantry-audit.jsonl");
    let app = start(&dir, AuditLog::open(&log)?)?;
    let ready = || Request::get("/readyz").body(Body::empty());
    let response = app.clone().oneshot(ready()?).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    assert_eq!(body["status"], "ready");
    assert_eq!(body["checks"]["audit"]["ready"], true);
    assert_eq!(body["checks"]["policy"]["ready"], true);
    if cfg!(windows) {
        return Ok(());
    }
    // The audit log is lost: every request would be refused, so the orchestrator must stop routing here.
    std::fs::remove_file(&log)?;
    let response = app.clone().oneshot(ready()?).await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    assert_eq!(body["status"], "not_ready");
    assert_eq!(body["checks"]["audit"]["ready"], false);
    assert!(
        body["checks"]["audit"]["reason"]
            .as_str()
            .is_some_and(|r| r.contains("audit_unavailable")),
        "{body}"
    );

    // A policy with no key and no identity provider refuses everything: not ready either.
    let empty = files("ready-empty", upstream)?;
    std::fs::write(empty.join("gantry.keys.yaml"), "keys: []\n")?;
    let app = start(&empty, AuditLog::open(&empty.join("gantry-audit.jsonl"))?)?;
    let response = app.clone().oneshot(ready()?).await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    assert_eq!(body["checks"]["policy"]["ready"], false, "{body}");
    // Liveness is a different question: the process is up and answering.
    let live = app
        .clone()
        .oneshot(Request::get("/healthz").body(Body::empty())?)
        .await?;
    assert_eq!(live.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn the_health_check_fails_once_the_audit_log_is_lost() -> TestResult {
    let (upstream, provider) = provider().await?;
    let dir = files("health", upstream)?;
    let log = dir.join("gantry-audit.jsonl");
    let app = start(&dir, AuditLog::open(&log)?)?;
    let health = || Request::get("/healthz").body(Body::empty());
    assert_eq!(
        app.clone().oneshot(health()?).await?.status(),
        StatusCode::OK
    );

    if cfg!(windows) {
        // Windows: a held log cannot be deleted, so it is never lost and the check stays healthy.
        assert!(
            std::fs::remove_file(&log).is_err(),
            "a held audit log was deleted"
        );
        assert_eq!(
            app.clone().oneshot(health()?).await?.status(),
            StatusCode::OK
        );
        return Ok(());
    }
    std::fs::remove_file(&log)?;
    // Before any request has been refused: the check looks at the log itself.
    assert_eq!(
        app.clone().oneshot(health()?).await?.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let (status, _, body) = answer(&app, chat(OMER, "m")?).await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(provider.hits.load(Ordering::SeqCst), 0);
    assert_eq!(
        app.clone().oneshot(health()?).await?.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    Ok(())
}

#[tokio::test]
async fn a_key_in_upper_case_without_its_prefix_or_as_a_header_name_does_not_reach_the_provider()
-> TestResult {
    let (upstream, seen) = watching_upstream(std::time::Duration::ZERO).await?;
    let dir = files("forms", upstream)?;
    let app = start(&dir, AuditLog::open(&dir.join("gantry-audit.jsonl"))?)?;
    let random = LIOR.trim_start_matches("gantry_");
    let request = Request::post("/v1/chat/completions")
        .header(header::AUTHORIZATION, format!("Bearer {LIOR}"))
        .header("x-note-a", LIOR.to_uppercase())
        .header("x-note-b", format!("see {random} here"))
        .header(LIOR, "1")
        .header("x-note-c", "harmless")
        .body(Body::from(r#"{"model":"m","messages":[]}"#))?;
    let (status, _, _) = answer(&app, request).await?;
    assert_eq!(status, StatusCode::OK);

    let seen = seen.lock().map_err(|_| "lock")?;
    let (_, headers) = seen.first().ok_or("nothing reached the provider")?;
    let sent = format!("{headers:?}").to_lowercase();
    assert!(
        !sent.contains(random),
        "the key reached the provider: {sent}"
    );
    assert_eq!(
        headers.get("x-note-c").and_then(|v| v.to_str().ok()),
        Some("harmless")
    );
    Ok(())
}

#[tokio::test]
async fn the_record_says_where_the_request_came_from() -> TestResult {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (upstream, _provider) = provider().await?;
    let dir = files("client", upstream)?;
    let log = dir.join("gantry-audit.jsonl");
    let app = start(&dir, AuditLog::open(&log)?)?;
    // Through a real socket, with the accept loop the binary uses: only that knows the client's address.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(gantry_server::serve_on(
        listener,
        app,
        gantry_server::Timeouts::default(),
        std::future::pending(),
    ));
    let mut socket = tokio::net::TcpStream::connect(addr).await?;
    let body = r#"{"model":"m","messages":[]}"#;
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: gantry\r\nAuthorization: Bearer {OMER}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    socket.write_all(request.as_bytes()).await?;
    let mut answer = String::new();
    socket.read_to_string(&mut answer).await?;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");

    let records = records(&log)?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["client"], "127.0.0.1");
    assert_eq!(records[0]["person"], "omer.katz");
    Ok(())
}

#[test]
fn a_provider_key_cannot_be_printed() {
    let config = Config {
        provider_key: Some(Secret::new("sk-must-never-be-printed")),
        ..Config::default()
    };
    let printed = format!("{config:?} {:?}", Secret::new("sk-must-never-be-printed"));
    assert!(!printed.contains("sk-must-never-be-printed"), "{printed}");
}

#[tokio::test]
async fn a_short_hand_made_key_does_not_strip_ordinary_headers() -> TestResult {
    let (upstream, seen) = watching_upstream(std::time::Duration::ZERO).await?;
    let dir = files("short", upstream)?;
    // A key someone wrote by hand, which happens to be a word that ordinary headers contain.
    let keys = dir.join("gantry.keys.yaml");
    let short = "json";
    let mut text = std::fs::read_to_string(&keys)?;
    text.push_str(&format!(
        "  - name: tal.ron\n    team: payments\n    sha256: {}\n",
        sha256_hex(short.as_bytes())
    ));
    std::fs::write(&keys, text)?;
    let app = start(&dir, AuditLog::open(&dir.join("gantry-audit.jsonl"))?)?;
    let request = Request::post("/v1/chat/completions")
        .header(header::AUTHORIZATION, format!("Bearer {short}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        // The short key standing as a word of its own is still the key, and must not reach the provider.
        .header("x-token", format!("Bearer {short}"))
        .header("x-note", short)
        .body(Body::from(r#"{"model":"m","messages":[]}"#))?;
    let (status, _, _) = answer(&app, request).await?;
    assert_eq!(status, StatusCode::OK);
    let seen = seen.lock().map_err(|_| "lock")?;
    let (_, headers) = seen.first().ok_or("nothing reached the provider")?;
    assert_eq!(
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
    assert_eq!(
        headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
    assert!(
        !headers.contains_key("x-token") && !headers.contains_key("x-note"),
        "{headers:?}"
    );
    Ok(())
}

#[tokio::test]
async fn a_body_larger_than_one_callers_share_is_refused_for_good() -> TestResult {
    let (upstream, _seen) = watching_upstream(std::time::Duration::ZERO).await?;
    let dir = files("oversize", upstream)?;
    // A budget of 64 KiB gives one caller 16 KiB. A body of 20 KiB can never fit, so the answer must not say "try again".
    let app = start_with(
        &dir,
        AuditLog::open(&dir.join("gantry-audit.jsonl"))?,
        Some(64 * 1024),
    )?;
    let body = format!(r#"{{"model":"m","pad":"{}"}}"#, "x".repeat(20 * 1024));
    let response = app
        .clone()
        .oneshot(
            Request::post("/v1/chat/completions")
                .header(header::AUTHORIZATION, format!("Bearer {OMER}"))
                .body(Body::from(body))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(!response.headers().contains_key(header::RETRY_AFTER));
    Ok(())
}

/// A full disk: on Linux `/dev/full` takes the open and fails every write with "no space left on device".
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_full_disk_refuses_every_request_and_forwards_nothing() -> TestResult {
    let (upstream, provider) = provider().await?;
    let dir = files("disk-full", upstream)?;
    let full = std::fs::OpenOptions::new().write(true).open("/dev/full")?;
    let app = start(&dir, AuditLog::from_file(full)?)?;
    for _ in 0..2 {
        let (status, _, body) = answer(&app, chat(OMER, "any-model")?).await?;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        let json: serde_json::Value = serde_json::from_str(&body)?;
        assert_eq!(json["error"]["code"], "audit_unavailable");
    }
    assert_eq!(provider.hits.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn removing_the_audit_folder_while_running_refuses_every_request() -> TestResult {
    let (upstream, provider) = provider().await?;
    let dir = files("folder-gone", upstream)?;
    let log = dir.join("audit").join("gantry-audit.jsonl");
    std::fs::create_dir_all(log.parent().ok_or("no folder")?)?;
    let app = start(&dir, AuditLog::open(&log)?)?;
    assert_eq!(
        answer(&app, chat(OMER, "any-model")?).await?.0,
        StatusCode::OK
    );

    if cfg!(windows) {
        // Windows: a held log cannot be deleted, so its folder cannot be removed and records keep reaching it.
        assert!(
            std::fs::remove_dir_all(log.parent().ok_or("no folder")?).is_err() && log.exists(),
            "the folder of a held audit log was removed"
        );
        assert_eq!(
            answer(&app, chat(OMER, "any-model")?).await?.0,
            StatusCode::OK
        );
        assert_eq!(provider.hits.load(Ordering::SeqCst), 2);
        gantry_core::audit::verify(&log)?;
        return Ok(());
    }
    std::fs::remove_dir_all(log.parent().ok_or("no folder")?)?;
    for _ in 0..2 {
        let (status, _, body) = answer(&app, chat(OMER, "any-model")?).await?;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        let json: serde_json::Value = serde_json::from_str(&body)?;
        assert_eq!(json["error"]["code"], "audit_unavailable");
    }
    // Only the request made before the folder went.
    assert_eq!(provider.hits.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn an_unreachable_provider_is_a_whole_refusal_with_a_record_and_no_usage() -> TestResult {
    // A port that was just free and is closed again refuses connections.
    let down = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await?
        .local_addr()?;
    let dir = files("provider-down", down)?;
    let audit = dir.join("gantry-audit.jsonl");
    let app = start(&dir, AuditLog::open(&audit)?)?;
    let (status, decision, body) = answer(&app, chat(OMER, "any-model")?).await?;

    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    // The whole body is one refusal: nothing of an answer came before it.
    let json: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(json["error"]["code"], "upstream_unreachable");
    assert!(!body.contains(&down.to_string()), "{body}");
    let text = std::fs::read_to_string(&audit)?;
    let decided: Vec<serde_json::Value> = text
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    let request = decided
        .iter()
        .find(|r| r["id"] == decision.as_str() && r.get("event").is_none())
        .ok_or("no request record")?;
    assert_eq!(request["verdict"], "allow");
    assert!(
        !decided.iter().any(|r| r["event"] == "usage"),
        "a request that got no answer has no usage record: {text}"
    );
    Ok(())
}
