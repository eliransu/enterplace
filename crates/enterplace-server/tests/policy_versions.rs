//! The policy kept in the store as versions (`store.policy_from: store`): the console and the admin API save a new
//! version, checked as `enterplace check` checks a file, and every gateway on the database uses it within 2 seconds
//! without a restart. Optional approval by a second admin, a dry run against recent requests, rollback, export and
//! import, each change in the audit chain. A gateway whose policy stays in the file refuses every change.
//!
//! Needs ENTERPLACE_TEST_DATABASE_URL, as the store tests do; without it each test says it was skipped and passes.

use enterplace_server::store::TestStore;
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
    routing::post,
};
use enterplace_server::Governed;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Error = Box<dyn std::error::Error>;

const ADMIN: &str = "enterplace_admin_0123456789abcdef012345678";
const SECOND: &str = "enterplace_second_0123456789abcdef01234567";
const MAYA: &str = "enterplace_maya_0123456789abcdef0123456789";
const HOST: &str = "enterplace.test";

async fn database(test: &str) -> Result<Option<enterplace_server::store::TestStore>, Error> {
    enterplace_server::store::TestStore::create(&format!(
        "enterplace_{}_{test}",
        std::process::id()
    ))
    .await
}

/// A model server that answers every chat request.
async fn provider() -> Result<u16, Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let app = Router::new().route(
        "/v1/chat/completions",
        post(|| async { r#"{"id":"c","object":"chat.completion","choices":[]}"# }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

fn policy(port: u16, from: &str) -> String {
    TestStore::policy(&format!(
        "version: 1
store: {{ postgres_url_env: ENTERPLACE_STORE_URL, policy_from: {from} }}
providers:
  - name: mock
    kind: openai
    url: http://127.0.0.1:{port}
    allow_private: true
    models: [m]
rules:
  - name: everyone
    principals: {{ any: true }}
    models: [m]
"
    ))
}

fn dir(name: &str) -> Result<PathBuf, Error> {
    let dir =
        std::env::temp_dir().join(format!("enterplace-versions-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn gateway(dir: &Path, url: &str, text: &str) -> Result<Governed, String> {
    let policy = dir.join("enterplace.policy.yaml");
    std::fs::write(&policy, text).map_err(|e| e.to_string())?;
    let url = url.to_string();
    let gw = enterplace_server::governed(&policy, None, &|variable| match variable {
        _ if TestStore::env(variable, &url).is_some() => TestStore::env(variable, &url),
        _ => None,
    })?;
    gw.reloader.watch();
    Ok(gw)
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    key: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Result<(StatusCode, HeaderMap, String), Error> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {key}"));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string()))?)
        .await?;
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await?.to_bytes();
    Ok((
        parts.status,
        parts.headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    ))
}

async fn chat(app: &Router, model: &str) -> Result<StatusCode, Error> {
    let body = json!({"model": model, "messages": []}).to_string();
    Ok(call(
        app,
        "POST",
        "/v1/chat/completions",
        MAYA,
        &[("content-type", "application/json")],
        &body,
    )
    .await?
    .0)
}

/// Waits until `model` gets `wanted` on `app`, for at most 2 seconds: how long a change takes to reach a gateway.
async fn within_two_seconds(app: &Router, model: &str, wanted: StatusCode) -> TestResult {
    let start = Instant::now();
    loop {
        let got = chat(app, model).await?;
        if got == wanted {
            return Ok(());
        }
        if start.elapsed() > Duration::from_secs(2) {
            return Err(format!("{model} got {got}, not {wanted}, after 2 seconds").into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn put(
    app: &Router,
    key: &str,
    base: &str,
    text: &str,
) -> Result<(StatusCode, Value), Error> {
    let (status, _, body) = call(
        app,
        "PUT",
        "/admin/policy",
        key,
        &[("if-match", base), ("x-enterplace-note", "test change")],
        text,
    )
    .await?;
    Ok((
        status,
        serde_json::from_str(&body).unwrap_or(Value::String(body)),
    ))
}

async fn post_json(
    app: &Router,
    key: &str,
    path: &str,
    body: &str,
) -> Result<(StatusCode, Value), Error> {
    let (status, _, body) = call(app, "POST", path, key, &[], body).await?;
    Ok((
        status,
        serde_json::from_str(&body).unwrap_or(Value::String(body)),
    ))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_version_saved_on_one_gateway_is_live_on_another_within_two_seconds() -> TestResult {
    let Some(url) = database("policy_versions").await? else {
        return Ok(());
    };
    let (port, other_port) = (provider().await?, provider().await?);
    let (one_dir, two_dir) = (dir("one")?, dir("two")?);
    let first = policy(port, "store");
    let one = gateway(&one_dir, &url, &first)?;
    for (name, key, admin) in [
        ("admin", ADMIN, true),
        ("second.admin", SECOND, true),
        ("maya.cohen", MAYA, false),
    ] {
        enterplace_core::keyfile::add_entry(name, "ops", key, admin, &one.loaded.keys_path)?;
    }
    one.reloader.check(enterplace_server::Trigger::FileChange);
    // The second gateway's file is stale: the store's version 1, imported by the first, wins and it says so.
    let two = gateway(
        &two_dir,
        &url,
        &first.replace("models: [m]\nrules", "models: [m, stale]\nrules"),
    )?;
    assert_eq!(
        enterplace_core::versions::file_differs(&two_dir.join("enterplace.policy.yaml")),
        Some(1)
    );

    // Export: the live version as YAML, its number in the ETag.
    let (status, headers, body) = call(&two.router, "GET", "/admin/policy", ADMIN, &[], "").await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, first);
    assert_eq!(
        headers.get(header::ETAG).and_then(|v| v.to_str().ok()),
        Some("\"1\"")
    );
    assert_eq!(chat(&two.router, "m2").await?, StatusCode::FORBIDDEN);

    // Import a new version on the first gateway: a model and a new provider, with no restart anywhere.
    let second = first
        .replace("    models: [m]\nrules", &format!("    models: [m, m2]\n  - name: other\n    kind: openai\n    url: http://127.0.0.1:{other_port}\n    allow_private: true\n    models: [m3]\nrules"))
        .replace("    models: [m]\n", "    models: [m, m2, m3]\n");
    let (status, body) = put(&one.router, ADMIN, "\"1\"", &second).await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(
        (body["version"].clone(), body["state"].clone()),
        (json!(2), json!("live"))
    );
    assert_eq!(body["in_effect"], true);
    within_two_seconds(&two.router, "m2", StatusCode::OK).await?;
    within_two_seconds(&two.router, "m3", StatusCode::OK).await?;

    // A stale base, a missing If-Match, and a draft `enterplace check` refuses are refused, and change nothing.
    let (status, body) = put(&two.router, ADMIN, "\"1\"", &first).await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.to_string().contains("version 2 is live now"), "{body}");
    let (status, _, _) = call(&two.router, "PUT", "/admin/policy", ADMIN, &[], &first).await?;
    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED);
    let broken = second.replace("principals: { any: true }", "principals: { anyone: true }");
    let (status, body) = put(&two.router, ADMIN, "2", &broken).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let expected = enterplace_core::config::load_texts(
        &two_dir.join("enterplace.policy.yaml"),
        &broken,
        &two.loaded.keys_path,
        "",
    )
    .err()
    .unwrap_or_default();
    assert!(!expected.is_empty());
    assert!(
        body.to_string().contains("invalid_policy") && body.to_string().contains("anyone"),
        "{body}"
    );
    // A change that needs a restart is refused before it is saved.
    let moved = second
        .replace("ENTERPLACE_STORE_URL", "OTHER_URL")
        .replace("cloudflare: true", "postgres_url_env: OTHER_URL");
    let (status, body) = put(&two.router, ADMIN, "2", &moved).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.to_string().contains("restart"), "{body}");

    // Approval on. That version goes live without one (the live version did not ask); the next waits.
    let approving = second.replace(
        "policy_from: store }",
        "policy_from: store, approval: true }",
    );
    let (status, body) = put(&two.router, ADMIN, "2", &approving).await?;
    assert_eq!(
        (status, body["state"].clone()),
        (StatusCode::CREATED, json!("live")),
        "{body}"
    );
    let narrower = approving.replace("    models: [m, m2, m3]\n", "    models: [m, m3]\n");
    let (status, body) = put(&two.router, ADMIN, "3", &narrower).await?;
    assert_eq!(
        (status, body["state"].clone()),
        (StatusCode::CREATED, json!("pending")),
        "{body}"
    );
    assert_eq!(
        chat(&one.router, "m2").await?,
        StatusCode::OK,
        "a pending version decided a request"
    );

    // Dry run of the pending draft against what happened: maya's m2 requests would now be refused.
    let (status, body) = post_json(
        &one.router,
        ADMIN,
        "/admin/policy/dry-run?hours=1",
        &narrower,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let refused = body["dry_run"]["now_refused"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(!refused.is_empty(), "{body}");
    assert!(
        refused
            .iter()
            .all(|r| r["model"] == "m2" && r["person"] == "maya.cohen"),
        "{body}"
    );
    assert!(
        body["dry_run"]["replayed"].as_u64().unwrap_or(0) >= 1,
        "{body}"
    );

    // Nobody approves their own version. The second admin does, and it is live everywhere within 2 seconds.
    let (status, body) =
        post_json(&one.router, ADMIN, "/admin/policy/versions/4/approve", "").await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) =
        post_json(&one.router, SECOND, "/admin/policy/versions/4/approve", "").await?;
    assert_eq!(
        (status, body["state"].clone()),
        (StatusCode::OK, json!("live")),
        "{body}"
    );
    within_two_seconds(&two.router, "m2", StatusCode::FORBIDDEN).await?;

    // One-click rollback to version 2 waits for approval too, then brings m2 back.
    let (status, body) =
        post_json(&two.router, SECOND, "/admin/policy/versions/2/rollback", "").await?;
    assert_eq!(
        (status, body["state"].clone()),
        (StatusCode::CREATED, json!("pending")),
        "{body}"
    );
    let rollback = body["version"].as_i64().unwrap_or_default();
    let (status, body) = post_json(
        &two.router,
        ADMIN,
        &format!("/admin/policy/versions/{rollback}/approve"),
        "",
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    within_two_seconds(&one.router, "m2", StatusCode::OK).await?;

    // The history and one version's diff.
    let (status, _, body) =
        call(&one.router, "GET", "/admin/policy/versions", ADMIN, &[], "").await?;
    assert_eq!(status, StatusCode::OK);
    let list: Value = serde_json::from_str(&body)?;
    let states: Vec<String> = list["versions"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|v| {
            format!(
                "{}:{}",
                v["version"],
                v["state"].as_str().unwrap_or_default()
            )
        })
        .collect();
    assert_eq!(
        states,
        ["5:live", "4:retired", "3:retired", "2:retired", "1:retired"],
        "{body}"
    );
    let (_, _, body) = call(
        &one.router,
        "GET",
        "/admin/policy/versions/4",
        ADMIN,
        &[],
        "",
    )
    .await?;
    let shown: Value = serde_json::from_str(&body)?;
    assert!(
        shown["diff"]
            .as_str()
            .unwrap_or_default()
            .contains("-     models: [m, m2, m3]"),
        "{body}"
    );
    assert_eq!(shown["decided_by"], "second.admin");

    // Every change is in the audit chain, and each version the gateway loaded names its number.
    let log = std::fs::read_to_string(one_dir.join("enterplace-audit.jsonl"))?
        + &std::fs::read_to_string(two_dir.join("enterplace-audit.jsonl"))?;
    for action in [
        "propose_policy",
        "approve_policy",
        "rollback_policy",
        "dry_run_policy",
    ] {
        assert!(
            log.contains(&format!("\"action\":\"{action}\"")),
            "no {action} record"
        );
    }
    assert!(
        log.lines()
            .any(|l| l.contains("\"event\":\"config_loaded\"")
                && l.contains("\"policy_version\":4")
                && l.contains("\"trigger\":\"store\""))
    );
    assert!(log.lines().any(|l| l.contains("\"code\":\"own_version\"")));

    // A non-admin key may not read or change the policy.
    let (status, _, _) = call(&one.router, "GET", "/admin/policy", MAYA, &[], "").await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_policy_kept_in_the_file_is_read_only_through_enterplace() -> TestResult {
    let Some(url) = database("policy_file").await? else {
        return Ok(());
    };
    let port = provider().await?;
    let gw_dir = dir("file")?;
    let text = policy(port, "file");
    let gw = gateway(&gw_dir, &url, &text)?;
    enterplace_core::keyfile::add_entry("admin", "ops", ADMIN, true, &gw.loaded.keys_path)?;
    gw.reloader.check(enterplace_server::Trigger::FileChange);
    let (status, headers, body) = call(&gw.router, "GET", "/admin/policy", ADMIN, &[], "").await?;
    assert_eq!((status, body.as_str()), (StatusCode::OK, text.as_str()));
    assert_eq!(
        headers
            .get("x-enterplace-policy-source")
            .and_then(|v| v.to_str().ok()),
        Some("file")
    );
    let (status, body) = put(&gw.router, ADMIN, "none", &text.replace("[m]", "[m, m2]")).await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(
        body.to_string().contains("policy_in_file")
            && body.to_string().contains("policy_from: store"),
        "{body}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn the_console_adds_a_model_edits_a_key_and_shows_teams_and_versions() -> TestResult {
    let Some(url) = database("policy_console").await? else {
        return Ok(());
    };
    let port = provider().await?;
    let gw_dir = dir("console")?;
    let gw = gateway(&gw_dir, &url, &policy(port, "store"))?;
    enterplace_core::keyfile::add_entry("admin", "ops", ADMIN, true, &gw.loaded.keys_path)?;
    enterplace_core::keyfile::add_entry(
        "maya.cohen",
        "payments",
        MAYA,
        false,
        &gw.loaded.keys_path,
    )?;
    gw.reloader.check(enterplace_server::Trigger::FileChange);

    let form = |method: &str, path: &str, cookie: &str, body: &str| {
        Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, HOST)
            .header(header::ORIGIN, format!("http://{HOST}"))
            .header(header::COOKIE, cookie)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body.to_string()))
    };
    let send = |request: Request<Body>| {
        let app = gw.router.clone();
        async move {
            let response = app.oneshot(request).await?;
            let (parts, body) = response.into_parts();
            let bytes = body.collect().await?.to_bytes();
            Ok::<_, Error>((
                parts.status,
                parts.headers,
                String::from_utf8_lossy(&bytes).into_owned(),
            ))
        }
    };
    let (_, headers, _) = send(form(
        "POST",
        "/console/sign-in",
        "",
        &format!("key={ADMIN}"),
    )?)
    .await?;
    let cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|c| c.split(';').next())
        .ok_or("no cookie")?
        .to_string();

    // Prices: add a model to the provider with a price and an alias. It is a new live version.
    let (status, _, page) = send(form("GET", "/console/api/prices", &cookie, "")?).await?;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(
        page.contains("mock") && page.contains(r#""editable":true"#),
        "{page}"
    );
    let (status, _, page) = send(form(
        "POST",
        "/console/api/prices/add",
        &cookie,
        "provider=mock&model=m9&input=1.5&output=6&aliases=fast&base=1",
    )?)
    .await?;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(page.contains(r#""version":2"#), "{page}");
    let live = enterplace_core::config::policy_text(&gw_dir.join("enterplace.policy.yaml"))?;
    assert!(
        live.contains("m9") && live.contains("fast") && live.contains("input: 1.5"),
        "{live}"
    );
    let (_, _, page) = send(form("GET", "/console/api/prices", &cookie, "")?).await?;
    assert!(
        page.contains("m9") && page.contains("fast") && page.contains("1.50"),
        "{page}"
    );

    // Keys: edit maya's fields in place. The key stays the same; its tokens per minute change.
    let maya = enterplace_core::id::sha256_hex(MAYA.as_bytes());
    let (status, _, page) = send(form(
        "POST",
        "/console/api/people/edit",
        &cookie,
        &format!("sha256={maya}&tpm=5000&models=m&budget=&per=month&expires="),
    )?)
    .await?;
    assert_eq!(status, StatusCode::OK, "{page}");
    let keys = enterplace_core::store::attached(&gw.loaded.keys_path)
        .ok_or("no store")?
        .keys_text();
    assert!(keys.contains("tpm: 5000") && keys.contains(&maya), "{keys}");

    // Teams and people, with their roles.
    let (status, _, page) = send(form("GET", "/console/api/teams", &cookie, "")?).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains(r#""name":"payments""#)
            && page.contains(r#""name":"maya.cohen""#)
            && page.contains(r#""name":"ops""#)
            && page.contains(r#""admin":true"#),
        "{page}"
    );

    // Policy versions: the history, a diff, a dry run, and an edit saved from the editor. The old addresses point
    // at the app.
    let (status, headers, _) = send(form(
        "GET",
        "/console/policy/versions?version=2",
        &cookie,
        "",
    )?)
    .await?;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        headers.get(header::LOCATION).and_then(|v| v.to_str().ok()),
        Some("/console/app/#/policy/versions?version=2")
    );
    let (status, _, page) = send(form(
        "GET",
        "/console/api/policy/versions?version=2",
        &cookie,
        "",
    )?)
    .await?;
    assert_eq!(status, StatusCode::OK, "{page}");
    let versions: serde_json::Value = serde_json::from_str(&page)?;
    let detail = &versions["detail"];
    assert!(
        detail["id"] == 2
            && detail["diff"]
                .as_array()
                .is_some_and(|d| d.iter().any(|l| l["kind"] == "add"))
            && detail["actions"]
                .as_array()
                .is_some_and(|a| a.iter().any(|a| a == "dry_run")),
        "{versions}"
    );
    // The live version has nothing to roll back to; an earlier one does.
    assert!(
        !detail["actions"].to_string().contains("rollback"),
        "{versions}"
    );
    let (_, _, page) = send(form(
        "GET",
        "/console/api/policy/versions?version=1",
        &cookie,
        "",
    )?)
    .await?;
    assert!(page.contains(r#""rollback""#), "{page}");
    let (status, _, page) = send(form("GET", "/console/api/policy/editor", &cookie, "")?).await?;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(page.contains(r#""base":2"#), "{page}");
    let edited = live.replace("models: [m, m9]", "models: [m]");
    let body = format!(
        "text={}&base=2&note=narrow",
        enterplace_console::html::enc(&edited)
    );
    let (status, _, page) =
        send(form("POST", "/console/api/policy/dry-run", &cookie, &body)?).await?;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(
        page.contains("Dry run done") && page.contains("Now refused"),
        "{page}"
    );
    let (status, _, page) = send(form("POST", "/console/api/policy/save", &cookie, &body)?).await?;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(page.contains(r#""version":3"#), "{page}");
    // Saved again on the same base: the version it started from is no longer live.
    let (status, _, page) = send(form("POST", "/console/api/policy/save", &cookie, &body)?).await?;
    assert_eq!(status, StatusCode::CONFLICT, "{page}");
    let (status, _, page) = send(form(
        "POST",
        "/console/api/policy/versions/1/rollback",
        &cookie,
        "",
    )?)
    .await?;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(page.contains("is live"), "{page}");
    let live = enterplace_core::config::policy_text(&gw_dir.join("enterplace.policy.yaml"))?;
    assert_eq!(live, policy(port, "store"));
    let (_, headers, export) = send(form("GET", "/console/policy/export", &cookie, "")?).await?;
    assert_eq!(export, live);
    assert!(headers.get(header::CONTENT_DISPOSITION).is_some());
    Ok(())
}

/// Each policy field the other branches added, in one version: organizations, profiles, scoped limits, roles,
/// JWT issuers, trusted proxies, CORS origins, residency, capture, the semantic and prompt caches, file retention, parallel.
fn every_field(port: u16) -> String {
    TestStore::policy(&format!(
        "version: 1
store: {{ postgres_url_env: ENTERPLACE_STORE_URL, policy_from: store }}
providers:
  - name: mock
    kind: openai
    url: http://127.0.0.1:{port}
    allow_private: true
    models: [m, e]
prices:
  m: {{ input: 0, output: 1000 }}
orgs: [acme]
jwt:
  - issuer: https://login.example.com
    audience: enterplace
    jwks_url: https://login.example.com/jwks
    team: ops
trusted_proxies: [10.0.0.0/8]
cors:
  allowed_origins: [https://pivot.claude.ai]
profiles:
  - name: standard
    models: [m]
    rate: {{ rpm: 60 }}
rules:
  - name: everyone
    principals: {{ any: true }}
    profiles: [standard]
    models: [m, e]
    from: [0.0.0.0/0]
    regions: [eu]
    parallel: 4
    cache: {{ ttl_seconds: 300, semantic: {{ model: e, threshold: 0.95 }} }}
    prompt_cache: auto
    capture: {{ to: console, days: 7, viewers: [admin] }}
    file_retention_days: 7
limits:
  - {{ org: acme, budget: {{ usd: 100, per: week, tz: Europe/Berlin }}, parallel: 20 }}
roles:
  - name: finance
    permissions: [see_spend]
    org: acme
"
    ))
}

#[tokio::test(flavor = "multi_thread")]
async fn every_policy_field_survives_a_saved_version_and_none_needs_a_restart() -> TestResult {
    let Some(url) = database("policy_every_field").await? else {
        return Ok(());
    };
    let port = provider().await?;
    let dir = dir("every-field")?;
    let path = dir.join("enterplace.policy.yaml");
    let first = policy(port, "store");
    std::fs::write(&path, &first)?;
    let store_url = url.clone();
    // A master key, so capture can seal what it keeps.
    let gw = enterplace_server::governed(&path, None, &|variable| match variable {
        _ if TestStore::env(variable, &store_url).is_some() => TestStore::env(variable, &store_url),
        "ENTERPLACE_MASTER_KEY" => {
            Some("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".into())
        }
        _ => None,
    })?;
    enterplace_core::keyfile::add_entry("admin", "ops", ADMIN, true, &gw.loaded.keys_path)?;
    gw.reloader.check(enterplace_server::Trigger::FileChange);

    let text = every_field(port);
    let (status, body) = put(&gw.router, ADMIN, "\"1\"", &text).await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["state"], "live", "{body}");
    // Applied by the reload: no field of them needs a restart.
    assert_eq!(body["in_effect"], true, "{body}");
    let (status, _, live) = call(&gw.router, "GET", "/admin/policy", ADMIN, &[], "").await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(live, text, "the store keeps the whole text of the version");

    // Read back through the store, every field loads as written.
    let loaded = enterplace_core::config::load_texts(&path, &live, &gw.loaded.keys_path, "")
        .map_err(|e| e.join("\n"))?;
    let policy = &loaded.policy;
    assert_eq!(policy.orgs(), ["acme"]);
    assert_eq!(policy.roles().len(), 1);
    assert_eq!(policy.scope_limits().len(), 1);
    assert_eq!(policy.jwt().len(), 1);
    assert_eq!(
        policy.cors().map(|c| c.allowed_origins.clone()),
        Some(vec!["https://pivot.claude.ai".to_string()])
    );
    assert_eq!(
        policy.client_ip("10.0.0.1".parse()?, &["198.51.100.4"]),
        "198.51.100.4".parse::<std::net::IpAddr>()?
    );
    let rule = &policy.rule_list()[0];
    assert_eq!(rule.profiles, ["standard"]);
    assert_eq!(rule.limits.rpm, Some(60));
    assert_eq!(rule.limits.parallel, Some(4));
    assert_eq!(rule.limits.regions, Some(vec!["eu".to_string()]));
    assert_eq!(rule.limits.from.len(), 1);
    assert!(rule.limits.semantic.is_some() && rule.limits.prompt_cache);
    assert_eq!(rule.limits.capture.as_ref().map(|c| c.days), Some(7));
    assert_eq!(rule.limits.file_retention_days, Some(7));
    let start = enterplace_core::config::load_texts(&path, &first, &gw.loaded.keys_path, "")
        .map_err(|e| e.join("\n"))?;
    assert!(enterplace_core::config::needs_restart(&start, &loaded).is_empty());
    assert!(enterplace_core::config::needs_restart(&loaded, &start).is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dry_run_replays_the_requests_of_every_gateway_on_the_store() -> TestResult {
    if TestStore::cloudflare() {
        return Ok(()); // The request log every gateway shares is kept in Postgres alone.
    }
    let Some(url) = database("dry_run_shared").await? else {
        return Ok(());
    };
    let port = provider().await?;
    let text = policy(port, "file");
    let one = gateway(&dir("dry-one")?, &url, &text)?;
    for (name, key, admin) in [("admin", ADMIN, true), ("maya.cohen", MAYA, false)] {
        enterplace_core::keyfile::add_entry(name, "ops", key, admin, &one.loaded.keys_path)?;
    }
    one.reloader.check(enterplace_server::Trigger::FileChange);
    let two = gateway(&dir("dry-two")?, &url, &text)?;
    // Maya's requests all go through the second gateway.
    within_two_seconds(&two.router, "m", StatusCode::OK).await?;
    for _ in 0..2 {
        assert_eq!(chat(&two.router, "m").await?, StatusCode::OK);
    }
    let draft = text.replace("principals: { any: true }", "principals: { team: nobody }");
    // The first gateway saw none of them, and its dry run still finds them, once the index has copied them.
    let start = Instant::now();
    let body = loop {
        let (status, body) =
            post_json(&one.router, ADMIN, "/admin/policy/dry-run?hours=1", &draft).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        if body["dry_run"]["now_refused"]
            .as_array()
            .map_or(0, Vec::len)
            >= 3
        {
            break body;
        }
        if start.elapsed() > Duration::from_secs(10) {
            return Err(format!("the other gateway's requests were not replayed: {body}").into());
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    };
    assert_eq!(body["dry_run"]["source"], "store", "{body}");
    assert!(
        body["dry_run"]["now_refused"]
            .as_array()
            .is_some_and(|r| r.iter().all(|r| r["person"] == "maya.cohen")),
        "{body}"
    );
    assert_eq!(
        body["dry_run"]["now_refused"].as_array().map(Vec::len),
        Some(3),
        "{body}"
    );
    // The second gateway has them in its own log and in the index: each is replayed once.
    let (_, body) = post_json(&two.router, ADMIN, "/admin/policy/dry-run?hours=1", &draft).await?;
    assert_eq!(
        body["dry_run"]["now_refused"].as_array().map(Vec::len),
        Some(3),
        "{body}"
    );
    let own = std::fs::read_to_string(&one.loaded.audit_path)?;
    assert!(
        !own.contains("/v1/chat/completions"),
        "the first gateway served a request itself"
    );

    // Without a store, the dry run replays this gateway's own log, and says so.
    let alone_dir = dir("dry-alone")?;
    let alone_text = text.replace(
        &TestStore::policy(
            "store: { postgres_url_env: ENTERPLACE_STORE_URL, policy_from: file }\n",
        ),
        "",
    );
    let alone = gateway(&alone_dir, &url, &alone_text)?;
    enterplace_core::keyfile::add_entry("admin", "ops", ADMIN, true, &alone.loaded.keys_path)?;
    alone.reloader.check(enterplace_server::Trigger::FileChange);
    let draft = alone_text.replace("principals: { any: true }", "principals: { team: nobody }");
    let (status, body) = post_json(
        &alone.router,
        ADMIN,
        "/admin/policy/dry-run?hours=1",
        &draft,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["dry_run"]["source"], "audit_log", "{body}");
    assert!(
        body["dry_run"]["note"]
            .as_str()
            .unwrap_or_default()
            .contains("does not name"),
        "{body}"
    );
    Ok(())
}
