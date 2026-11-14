//! The policy kept in the store as versions (`store.policy_from: store`): the console and the admin API save a new
//! version, checked as `gantry check` checks a file, and every gateway on the database uses it within 2 seconds
//! without a restart. Optional approval by a second admin, a dry run against recent requests, rollback, export and
//! import, each change in the audit chain. A gateway whose policy stays in the file refuses every change.
//!
//! Needs GANTRY_TEST_DATABASE_URL, as the store tests do; without it each test says it was skipped and passes.

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
use gantry_server::Governed;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Error = Box<dyn std::error::Error>;

const ADMIN: &str = "gantry_admin_0123456789abcdef012345678";
const SECOND: &str = "gantry_second_0123456789abcdef01234567";
const MAYA: &str = "gantry_maya_0123456789abcdef0123456789";
const HOST: &str = "gantry.test";

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
    let quote = |s: &str| format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"));
    let host = match config.get_hosts().first() {
        Some(tokio_postgres::config::Host::Tcp(host)) => host.clone(),
        _ => "127.0.0.1".into(),
    };
    let password = config
        .get_password()
        .map(|p| String::from_utf8_lossy(p).to_string())
        .unwrap_or_default();
    Ok(Some(format!(
        "host={} port={} user={} password={} dbname={} sslmode=disable",
        quote(&host),
        config.get_ports().first().copied().unwrap_or(5432),
        quote(config.get_user().unwrap_or("postgres")),
        quote(&password),
        quote(&name)
    )))
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
    format!(
        "version: 1
store: {{ postgres_url_env: GANTRY_STORE_URL, policy_from: {from} }}
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
    )
}

fn dir(name: &str) -> Result<PathBuf, Error> {
    let dir = std::env::temp_dir().join(format!("gantry-versions-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn gateway(dir: &Path, url: &str, text: &str) -> Result<Governed, String> {
    let policy = dir.join("gantry.policy.yaml");
    std::fs::write(&policy, text).map_err(|e| e.to_string())?;
    let url = url.to_string();
    let gw = gantry_server::governed(&policy, None, &|variable| match variable {
        "GANTRY_STORE_URL" => Some(url.clone()),
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
        &[("if-match", base), ("x-gantry-note", "test change")],
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
        gantry_core::keyfile::add_entry(name, "ops", key, admin, &one.loaded.keys_path)?;
    }
    one.reloader.check(gantry_server::Trigger::FileChange);
    // The second gateway's file is stale: the store's version 1, imported by the first, wins and it says so.
    let two = gateway(
        &two_dir,
        &url,
        &first.replace("models: [m]\nrules", "models: [m, stale]\nrules"),
    )?;
    assert_eq!(
        gantry_core::versions::file_differs(&two_dir.join("gantry.policy.yaml")),
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

    // A stale base, a missing If-Match, and a draft `gantry check` refuses are refused, and change nothing.
    let (status, body) = put(&two.router, ADMIN, "\"1\"", &first).await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.to_string().contains("version 2 is live now"), "{body}");
    let (status, _, _) = call(&two.router, "PUT", "/admin/policy", ADMIN, &[], &first).await?;
    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED);
    let broken = second.replace("principals: { any: true }", "principals: { anyone: true }");
    let (status, body) = put(&two.router, ADMIN, "2", &broken).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let expected = gantry_core::config::load_texts(
        &two_dir.join("gantry.policy.yaml"),
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
    let moved = second.replace("GANTRY_STORE_URL", "OTHER_URL");
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
    let log = std::fs::read_to_string(one_dir.join("gantry-audit.jsonl"))?
        + &std::fs::read_to_string(two_dir.join("gantry-audit.jsonl"))?;
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
async fn a_policy_kept_in_the_file_is_read_only_through_gantry() -> TestResult {
    let Some(url) = database("policy_file").await? else {
        return Ok(());
    };
    let port = provider().await?;
    let gw_dir = dir("file")?;
    let text = policy(port, "file");
    let gw = gateway(&gw_dir, &url, &text)?;
    gantry_core::keyfile::add_entry("admin", "ops", ADMIN, true, &gw.loaded.keys_path)?;
    gw.reloader.check(gantry_server::Trigger::FileChange);
    let (status, headers, body) = call(&gw.router, "GET", "/admin/policy", ADMIN, &[], "").await?;
    assert_eq!((status, body.as_str()), (StatusCode::OK, text.as_str()));
    assert_eq!(
        headers
            .get("x-gantry-policy-source")
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
    gantry_core::keyfile::add_entry("admin", "ops", ADMIN, true, &gw.loaded.keys_path)?;
    gantry_core::keyfile::add_entry("maya.cohen", "payments", MAYA, false, &gw.loaded.keys_path)?;
    gw.reloader.check(gantry_server::Trigger::FileChange);

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

    // Models: add one to the provider with a price and an alias. It is a new live version.
    let (status, _, page) = send(form("GET", "/console/models", &cookie, "")?).await?;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(
        page.contains("mock") && page.contains("Add a model"),
        "{page}"
    );
    let (status, headers, page) = send(form(
        "POST",
        "/console/models/add",
        &cookie,
        "provider=mock&model=m9&input=1.5&output=6&aliases=fast&base=1",
    )?)
    .await?;
    assert!(status.is_redirection(), "{status}: {page}");
    assert!(
        headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .contains("version=2")
    );
    let live = gantry_core::config::policy_text(&gw_dir.join("gantry.policy.yaml"))?;
    assert!(
        live.contains("m9") && live.contains("fast") && live.contains("input: 1.5"),
        "{live}"
    );
    let (_, _, page) = send(form("GET", "/console/models", &cookie, "")?).await?;
    assert!(
        page.contains("m9") && page.contains("fast") && page.contains("1.50"),
        "{page}"
    );

    // Keys: edit maya's fields in place. The key stays the same; its tokens per minute change.
    let maya = gantry_core::id::sha256_hex(MAYA.as_bytes());
    let (status, _, page) = send(form(
        "POST",
        "/console/people/edit",
        &cookie,
        &format!("sha256={maya}&tpm=5000&models=m&budget=&per=month&expires="),
    )?)
    .await?;
    assert!(status.is_redirection(), "{status}: {page}");
    let keys = gantry_core::store::attached(&gw.loaded.keys_path)
        .ok_or("no store")?
        .keys_text();
    assert!(keys.contains("tpm: 5000") && keys.contains(&maya), "{keys}");

    // Teams and people, with their roles.
    let (status, _, page) = send(form("GET", "/console/teams", &cookie, "")?).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains("payments")
            && page.contains("maya.cohen")
            && page.contains("ops")
            && page.contains("Admin"),
        "{page}"
    );

    // Policy versions: the history, a diff, a dry run, and an edit saved from the editor.
    let (status, _, page) = send(form(
        "GET",
        "/console/policy/versions?version=2",
        &cookie,
        "",
    )?)
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains("Version 2")
            && page.contains("g-code__line--add")
            && page.contains("Dry run"),
        "{page}"
    );
    // The live version has nothing to roll back to; an earlier one does.
    assert!(!page.contains("Roll back to this version"), "{page}");
    let (_, _, page) = send(form(
        "GET",
        "/console/policy/versions?version=1",
        &cookie,
        "",
    )?)
    .await?;
    assert!(page.contains("Roll back to this version"), "{page}");
    let edited = live.replace("models: [m, m9]", "models: [m]");
    let body = format!(
        "text={}&base=2&note=narrow",
        gantry_console::html::enc(&edited)
    );
    let (status, _, page) = send(form("POST", "/console/policy/dry-run", &cookie, &body)?).await?;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(page.contains("Dry run"), "{page}");
    let (status, _, page) = send(form("POST", "/console/policy/save", &cookie, &body)?).await?;
    assert!(status.is_redirection(), "{status}: {page}");
    let (status, _, page) = send(form(
        "POST",
        "/console/policy/versions/1/rollback",
        &cookie,
        "",
    )?)
    .await?;
    assert!(status.is_redirection(), "{status}: {page}");
    let live = gantry_core::config::policy_text(&gw_dir.join("gantry.policy.yaml"))?;
    assert_eq!(live, policy(port, "store"));
    let (_, headers, export) = send(form("GET", "/console/policy/export", &cookie, "")?).await?;
    assert_eq!(export, live);
    assert!(headers.get(header::CONTENT_DISPOSITION).is_some());
    Ok(())
}
