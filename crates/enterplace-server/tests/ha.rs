//! Acceptance tests for what two gateways on one Postgres share beyond `store.rs`: the answer cache
//! (`store.answer_cache: true`), budgets leased ahead of requests, hourly and daily request counts, budget raises
//! and each gateway's heartbeat. Each gateway has its own directory, audit chain and connection, as a separate
//! process has.
//!
//! They need a real Postgres: set ENTERPLACE_TEST_DATABASE_URL (see `store.rs`). Without it each test says it was
//! skipped and passes.

use enterplace_server::store::TestStore;
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::post,
};
use enterplace_core::store::CachedAnswer;
use enterplace_server::Governed;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Error = Box<dyn std::error::Error>;

const ADMIN: &str = "enterplace_admin_0123456789abcdef012345678";
const PAT: &str = "enterplace_pat_0123456789abcdef01234567890";
const LEE: &str = "enterplace_lee_0123456789abcdef01234567890";

async fn database(test: &str) -> Result<Option<enterplace_server::store::TestStore>, Error> {
    enterplace_server::store::TestStore::create(&format!(
        "enterplace_ha_{}_{test}",
        std::process::id()
    ))
    .await
}

/// Every answer used 3 output tokens ($0.003 on model m) and says which call of the provider's it was.
async fn provider() -> Result<(u16, Arc<AtomicUsize>), Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let app = Router::new()
        .route(
            "/v1/embeddings",
            // Two wordings of one question land close together, anything else far away.
            post(|body: String| async move {
                let vector = if body.contains("France") { "[1.0, 0.05]" } else { "[0.0, 1.0]" };
                axum::response::Response::builder()
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"object":"list","data":[{{"object":"embedding","index":0,"embedding":{vector}}}],"model":"emb","usage":{{"prompt_tokens":1,"total_tokens":1}}}}"#
                    )))
                    .unwrap_or_default()
            }),
        )
        .route(
        "/v1/chat/completions",
        post(move || {
            let seen = seen.clone();
            async move {
                let n = seen.fetch_add(1, Ordering::SeqCst) + 1;
                axum::response::Response::builder()
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"id":"call-{n}","choices":[],"usage":{{"prompt_tokens":0,"completion_tokens":3}}}}"#
                    )))
                    .unwrap_or_default()
            }
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((port, calls))
}

fn policy(port: u16) -> String {
    TestStore::policy(&format!(
        "version: 1
store: {{ postgres_url_env: ENTERPLACE_STORE_URL, answer_cache: true }}
providers:
  - name: mock
    kind: openai
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: MOCK_KEY
    models: [m, free, emb]
prices:
  m: {{ input: 0, output: 1000 }}
rules:
  - name: cached
    principals: {{ team: cached }}
    models: [free]
    cache: {{ ttl_seconds: 60 }}
  - name: semantic
    principals: {{ team: semantic }}
    models: [free, emb]
    cache: {{ ttl_seconds: 60, semantic: {{ model: emb, threshold: 0.9 }} }}
  - name: leased
    principals: {{ team: leased }}
    models: [m]
    budget: {{ usd: 0.9005, per: day }}
  - name: daily
    principals: {{ team: daily }}
    models: [free]
    rate: {{ rpd: 5 }}
  - name: tight
    principals: {{ team: tight }}
    models: [m]
    budget: {{ usd: 0.003, per: day }}
  - name: admins
    principals: {{ any: true }}
    models: []
"
    ))
}

fn dir(name: &str) -> Result<PathBuf, Error> {
    let dir = std::env::temp_dir().join(format!("enterplace-ha-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn gateway(dir: &Path, url: &str, port: u16) -> Result<Governed, Error> {
    let policy = dir.join("enterplace.policy.yaml");
    std::fs::write(&policy, self::policy(port))?;
    let url = url.to_string();
    let gw = enterplace_server::governed(&policy, None, &|variable| match variable {
        _ if TestStore::env(variable, &url).is_some() => TestStore::env(variable, &url),
        "ENTERPLACE_MASTER_KEY" | "ENTERPLACE_MASTER_KEY_FILE" => None,
        _ => Some("provider-secret".into()),
    })?;
    gw.reloader.watch();
    Ok(gw)
}

fn add_key(gw: &Governed, name: &str, team: &str, key: &str, admin: bool) -> Result<(), Error> {
    enterplace_core::keyfile::add_entry(name, team, key, admin, &gw.loaded.keys_path)?;
    gw.reloader.check(enterplace_server::Trigger::FileChange);
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

fn chat(key: &str, body: &str) -> Result<Request<Body>, Error> {
    request("POST", "/v1/chat/completions", key, body)
}

/// The status, the body and whether the answer came from the cache.
async fn answer(app: &Router, request: Request<Body>) -> Result<(StatusCode, Value, bool), Error> {
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    let hit = response
        .headers()
        .get("x-enterplace-cache")
        .is_some_and(|v| v == "hit");
    let body = response.into_body().collect().await?.to_bytes();
    Ok((
        status,
        serde_json::from_slice(&body).unwrap_or(Value::Null),
        hit,
    ))
}

fn code(body: &Value) -> &str {
    body["error"]["code"].as_str().unwrap_or_default()
}

/// Two gateways on one database, each knowing every key.
async fn pair(
    test: &str,
    url: &str,
    port: u16,
    keys: &[(&str, &str, &str, bool)],
) -> Result<(Governed, Governed), Error> {
    let a = gateway(&dir(&format!("{test}-a"))?, url, port)?;
    for (name, team, key, admin) in keys {
        add_key(&a, name, team, key, *admin)?;
    }
    let b = gateway(&dir(&format!("{test}-b"))?, url, port)?;
    Ok((a, b))
}

/// Tries `check` until it holds, or fails once `within` has passed.
async fn eventually<F, Fut>(within: Duration, what: &str, check: F) -> TestResult
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<bool, Error>>,
{
    let start = Instant::now();
    loop {
        if check().await? {
            return Ok(());
        }
        if start.elapsed() > within {
            return Err(format!("not within {within:?}: {what}").into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

const FREE: &str = r#"{"model":"free","messages":[{"role":"user","content":"hello"}]}"#;
const PRICED: &str = r#"{"model":"m","max_tokens":3,"messages":[]}"#;

#[tokio::test(flavor = "multi_thread")]
async fn an_answer_cached_on_one_gateway_is_served_by_the_other_in_its_scope_only() -> TestResult {
    let Some(url) = database("cache").await? else {
        return Ok(());
    };
    let (port, calls) = provider().await?;
    let (a, b) = pair(
        "cache",
        &url,
        port,
        &[("pat", "cached", PAT, false), ("lee", "cached", LEE, false)],
    )
    .await?;
    let (status, first, hit) = answer(&a.router, chat(PAT, FREE)?).await?;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert!(!hit);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // The answer is written to the store without the request waiting for it. Counted with SQL, so on Postgres; b
    // serving it below shows it on either store.
    if !TestStore::cloudflare() {
        let reader = enterplace_server::store::open("ENTERPLACE_STORE_URL", &url)?;
        let connection = reader.connect().await?;
        eventually(
            Duration::from_secs(3),
            "the answer is in the store",
            || async {
                let row = connection
                    .query_one("SELECT count(*) FROM enterplace_answer_cache", &[])
                    .await?;
                Ok(row.try_get::<_, i64>(0)? == 1)
            },
        )
        .await?;
        reader.close();
    }
    // Gateway b never saw the request: it reads the answer from the store, and the provider is not asked again.
    let app = b.router.clone();
    eventually(
        Duration::from_secs(3),
        "b serves a's answer from the cache",
        || async {
            let (status, body, hit) = answer(&app, chat(PAT, FREE)?).await?;
            Ok(status == StatusCode::OK && hit && body["id"] == "call-1")
        },
    )
    .await?;
    let asked = calls.load(Ordering::SeqCst);
    // The second read on b comes from its own memory.
    let (_, body, hit) = answer(&b.router, chat(PAT, FREE)?).await?;
    assert!(hit && body["id"] == "call-1", "{body}");
    assert_eq!(calls.load(Ordering::SeqCst), asked);

    // The cache is scoped to the person: lee's identical request is not served pat's answer, on either gateway.
    let (status, body, hit) = answer(&b.router, chat(LEE, FREE)?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!hit, "another person's answer was served: {body}");
    assert_ne!(body["id"], "call-1");

    // The hit is recorded as one, naming the decision that made the answer.
    let log = std::fs::read_to_string(b.loaded.keys_path.with_file_name("enterplace-audit.jsonl"))?;
    assert!(log.contains("\"cache_match\":\"exact\""), "{log}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_question_in_other_words_is_served_on_the_other_gateway_from_the_semantic_cache()
-> TestResult {
    let Some(url) = database("semantic").await? else {
        return Ok(());
    };
    let (port, calls) = provider().await?;
    let (a, b) = pair(
        "semantic",
        &url,
        port,
        &[
            ("pat", "semantic", PAT, false),
            ("lee", "semantic", LEE, false),
        ],
    )
    .await?;
    let ask = |words: &str| {
        format!(r#"{{"model":"free","messages":[{{"role":"user","content":"{words}"}}]}}"#)
    };
    let (status, first, hit) = answer(
        &a.router,
        chat(PAT, &ask("What is the capital of France?"))?,
    )
    .await?;
    assert_eq!((status, hit), (StatusCode::OK, false), "{first}");
    let app = b.router.clone();
    eventually(
        Duration::from_secs(3),
        "b serves a's answer to the reworded question",
        || async {
            let (status, body, hit) =
                answer(&app, chat(PAT, &ask("Tell me France's capital"))?).await?;
            Ok(status == StatusCode::OK && hit && body["id"] == first["id"])
        },
    )
    .await?;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the provider was asked again"
    );
    // Scoped to the person on every gateway: lee's close question is not served pat's answer.
    let (_, body, hit) = answer(&b.router, chat(LEE, &ask("Tell me France's capital"))?).await?;
    assert!(!hit && body["id"] != first["id"], "{body}");
    let log = std::fs::read_to_string(b.loaded.keys_path.with_file_name("enterplace-audit.jsonl"))?;
    assert!(log.contains("\"cache_match\":\"semantic\""), "{log}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn the_store_keeps_answers_and_embeddings_by_scope_until_they_run_out() -> TestResult {
    let Some(url) = database("vectors").await? else {
        return Ok(());
    };
    let a = TestStore::open(&url)?;
    let b = TestStore::open(&url)?;
    let entry = |key: u8, scope: &str, ttl: u64, vector: Option<Vec<f32>>| CachedAnswer {
        key: [key; 32],
        scope: scope.to_string(),
        status: 200,
        content_type: Some("application/json".into()),
        body: b"{\"ok\":true}".to_vec(),
        origin: format!("decision-{key}"),
        cost: 0.25,
        ttl: Duration::from_secs(ttl),
        vector: vector.map(|v| ([9; 32], v)),
    };
    a.cache_put(entry(1, "rule\0person:pat", 60, Some(vec![1.0, 0.0])));
    a.cache_put(entry(2, "rule\0person:pat", 60, Some(vec![0.0, 1.0])));
    a.cache_put(entry(3, "rule\0person:pat", 0, Some(vec![1.0, 1.0])));
    let read = b.clone();
    eventually(
        Duration::from_secs(3),
        "the other gateway reads the answer",
        || async {
            Ok(read
                .cache_get([2; 32], "rule\0person:pat".into())
                .await?
                .is_some())
        },
    )
    .await?;
    let found = b
        .cache_get([1; 32], "rule\0person:pat".into())
        .await?
        .ok_or("no answer")?;
    assert_eq!(found.body, b"{\"ok\":true}");
    assert_eq!((found.origin.as_str(), found.cost), ("decision-1", 0.25));
    assert!(found.ttl <= Duration::from_secs(60) && found.ttl > Duration::from_secs(50));
    // Never in another scope, and never past its time.
    assert!(
        b.cache_get([1; 32], "rule\0person:lee".into())
            .await?
            .is_none()
    );
    assert!(
        b.cache_get([3; 32], "rule\0person:pat".into())
            .await?
            .is_none()
    );
    // The embeddings of a partition, without the answer that ran out; another partition has none.
    let mut keys: Vec<u8> = b
        .cache_vectors([9; 32])
        .await?
        .iter()
        .map(|(k, _)| k[0])
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, [1, 2]);
    assert!(b.cache_vectors([8; 32]).await?.is_empty());
    drop((a, b));
    Ok(())
}

/// Sends `n` budgeted requests, alternating gateways, and returns how many were admitted.
async fn spend_some(gateways: [&Governed; 2], key: &'static str, n: usize) -> Result<usize, Error> {
    let mut tasks = Vec::new();
    for i in 0..n {
        let app = gateways[i % 2].router.clone();
        tasks.push(tokio::spawn(async move {
            let request = chat(key, PRICED).map_err(|e| e.to_string())?;
            answer(&app, request).await.map_err(|e| e.to_string())
        }));
    }
    let mut admitted = 0;
    for task in tasks {
        let (status, body, _) = task.await??;
        match status {
            StatusCode::OK => admitted += 1,
            StatusCode::TOO_MANY_REQUESTS => assert_eq!(code(&body), "budget_exceeded", "{body}"),
            other => return Err(format!("unexpected {other}: {body}").into()),
        }
    }
    Ok(admitted)
}

#[tokio::test(flavor = "multi_thread")]
async fn two_gateways_leasing_one_budget_never_pass_it_and_leave_none_of_it_unused() -> TestResult {
    let Some(url) = database("lease").await? else {
        return Ok(());
    };
    let (port, _) = provider().await?;
    let (a, b) = pair("lease", &url, port, &[("pat", "leased", PAT, false)]).await?;
    let app = b.router.clone();
    eventually(Duration::from_secs(3), "b knows the key", || async {
        Ok(answer(&app, request("GET", "/v1/models", PAT, "")?)
            .await?
            .0
            == StatusCode::OK)
    })
    .await?;
    // $0.9005 a day and $0.003 a request: 300 fit, with half a cent's twentieth to spare for rounding. Each gateway leases a hundredth of the budget (three requests)
    // at a time, so 340 sent at once through both must admit no more than 300.
    let mut admitted = spend_some([&a, &b], PAT, 340).await?;
    assert!(
        admitted <= 300,
        "{admitted} admitted: the budget was passed"
    );
    assert!(
        admitted >= 290,
        "{admitted} admitted: more than two leases were held back"
    );
    // What a gateway leased and did not use goes back within a second: the rest of the budget is then spent to
    // the last request, and not one more.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    for _ in 0..3 {
        admitted += spend_some([&a, &b], PAT, 20).await?;
        tokio::time::sleep(Duration::from_millis(1200)).await;
    }
    assert_eq!(admitted, 300, "the whole budget, and no more");
    let client = TestStore::open(&url)?;
    let day = client
        .spend("team:leased".into())
        .await?
        .into_iter()
        .find(|(per, ..)| per == "day")
        .ok_or("no spend for the day")?;
    let (spent, reserved) = (day.2, day.3);
    assert!((spent - 0.9).abs() < 1e-6, "spent {spent}");
    assert!(reserved.abs() < 1e-6, "{reserved} is still held");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_daily_request_limit_and_a_budget_raise_hold_on_every_gateway() -> TestResult {
    let Some(url) = database("daily").await? else {
        return Ok(());
    };
    let (port, _) = provider().await?;
    let (a, b) = pair(
        "daily",
        &url,
        port,
        &[
            ("pat", "daily", PAT, false),
            ("lee", "tight", LEE, false),
            ("ops", "ops", ADMIN, true),
        ],
    )
    .await?;
    let app = b.router.clone();
    eventually(Duration::from_secs(3), "b knows the keys", || async {
        Ok(answer(&app, request("GET", "/v1/models", LEE, "")?)
            .await?
            .0
            == StatusCode::OK)
    })
    .await?;
    // rpd: 5, counted in the store: five between the two gateways, a sixth on neither.
    let mut admitted = 0;
    for i in 0..8 {
        let gw = if i % 2 == 0 { &a } else { &b };
        let (status, body, _) = answer(&gw.router, chat(PAT, FREE)?).await?;
        match status {
            StatusCode::OK => admitted += 1,
            _ => assert_eq!(code(&body), "rate_limited", "{body}"),
        }
    }
    assert_eq!(admitted, 5);

    // Team tight may spend one request a day. A raise approved on gateway a makes room on gateway b.
    let (status, body, _) = answer(&a.router, chat(LEE, PRICED)?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, body, _) = answer(&b.router, chat(LEE, PRICED)?).await?;
    assert_eq!(code(&body), "budget_exceeded", "{body}");
    let asked = r#"{"usd":0.003,"until":"2099-01-01","reason":"one more"}"#;
    let (status, raise, _) =
        answer(&b.router, request("POST", "/v1/budget/raises", LEE, asked)?).await?;
    assert_eq!(status, StatusCode::CREATED, "{raise}");
    let id = raise["id"].as_str().ok_or("no id")?.to_string();
    // Asked for on b, listed and approved on a.
    let app = a.router.clone();
    let path = format!("/admin/budget/raises/{id}/approve");
    eventually(
        Duration::from_secs(3),
        "a sees the raise b took",
        || async {
            Ok(answer(&app, request("POST", &path, ADMIN, "")?).await?.0 == StatusCode::OK)
        },
    )
    .await?;
    let app = b.router.clone();
    eventually(
        Duration::from_secs(3),
        "b applies the raise a approved",
        || async { Ok(answer(&app, chat(LEE, PRICED)?).await?.0 == StatusCode::OK) },
    )
    .await?;
    let (_, body, _) = answer(&a.router, chat(LEE, PRICED)?).await?;
    assert_eq!(code(&body), "budget_exceeded", "{body}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn every_gateway_on_the_store_is_listed_with_its_version_and_health() -> TestResult {
    let Some(url) = database("replicas").await? else {
        return Ok(());
    };
    let a = TestStore::open(&url)?;
    let b = TestStore::open(&url)?;
    let read = a.clone();
    eventually(
        Duration::from_secs(6),
        "both gateways wrote a heartbeat",
        || async { Ok(read.replicas().await?.len() == 2) },
    )
    .await?;
    let listed = a.replicas().await?;
    assert_ne!(listed[0].gateway, listed[1].gateway);
    for replica in &listed {
        assert!(replica.healthy, "{replica:?}");
        assert_eq!(replica.version, enterplace_core::VERSION);
        assert!(
            TestStore::cloudflare()
                || (replica.schema.contains("core ") && replica.schema.contains("enterplace_ha 1")),
            "{}",
            replica.schema
        );
        assert!(replica.started.ends_with('Z') && replica.seen >= replica.started);
    }
    // A gateway that stopped stays listed, and is no longer healthy once its heartbeat is 10 seconds old.
    let gone = b.replicas().await?;
    drop(b);
    assert_eq!(gone.len(), 2);
    let read = a.clone();
    eventually(
        Duration::from_secs(15),
        "the stopped gateway is listed as not healthy",
        || async {
            let now = read.replicas().await?;
            Ok(now.len() == 2 && now.iter().filter(|r| r.healthy).count() == 1)
        },
    )
    .await?;
    drop(a);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn the_admin_api_lists_every_gateway_on_the_store() -> TestResult {
    let Some(url) = database("replicas_api").await? else {
        return Ok(());
    };
    let (port, _) = provider().await?;
    let (a, b) = pair(
        "replicas_api",
        &url,
        port,
        &[("ops", "ops", ADMIN, true), ("pat", "daily", PAT, false)],
    )
    .await?;
    let app = b.router.clone();
    eventually(Duration::from_secs(6), "b lists both gateways", || async {
        let (status, body, _) = answer(&app, request("GET", "/admin/replicas", ADMIN, "")?).await?;
        Ok(status == StatusCode::OK
            && body["store"] == true
            && body["replicas"].as_array().is_some_and(|l| {
                l.len() == 2
                    && l.iter()
                        .all(|r| r["healthy"] == true && r["version"] == enterplace_core::VERSION)
            }))
    })
    .await?;
    // A caller without the right to see records is refused.
    let (status, body, _) = answer(&a.router, request("GET", "/admin/replicas", PAT, "")?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    // The console's policy page lists them too.
    let signed_in = a
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/console/sign-in")
                .header(header::HOST, "enterplace.test")
                .header(header::ORIGIN, "http://enterplace.test")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("key={ADMIN}")))?,
        )
        .await?;
    let cookie = signed_in
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with("enterplace_console=") && !v.starts_with("enterplace_console=;"))
        .and_then(|v| v.split(';').next())
        .ok_or("the sign-in set no session cookie")?
        .to_string();
    let page = a
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/console/api/policy/raw")
                .header(header::HOST, "enterplace.test")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())?,
        )
        .await?;
    let body = String::from_utf8(page.into_body().collect().await?.to_bytes().to_vec())?;
    let raw: serde_json::Value = serde_json::from_str(&body)?;
    let replicas = raw["replicas"].as_array().ok_or(body.clone())?;
    assert_eq!(
        replicas.iter().filter(|r| r["healthy"] == true).count(),
        2,
        "{body}"
    );
    Ok(())
}
