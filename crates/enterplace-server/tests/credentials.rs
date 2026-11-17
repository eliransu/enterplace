//! Provider credentials kept in the store: an admin adds, rotates and removes them in the console or through the
//! admin API, sealed with AES-256-GCM under ENTERPLACE_MASTER_KEY. A policy provider names one with `credential:`.
//! A rotation reaches every gateway on the database without a restart. The value is never shown again, never in an
//! API answer, a page or an audit record.
//!
//! The Postgres tests need ENTERPLACE_TEST_DATABASE_URL, as the store tests do; without it they print that they were
//! skipped and pass.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
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
const MAYA: &str = "enterplace_maya_0123456789abcdef0123456789";
const MASTER: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f000112233445566778899aabbccddeeff";
const OTHER_MASTER: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
const FIRST: &str = "sk-live-first-value-a1b2c3d4-1111";
const SECOND: &str = "sk-live-second-value-e5f6a7b8-2222";
const SPARE: &str = "sk-spare-value-0a9b8c7d-3333";
const HOST: &str = "enterplace.test";

async fn database(test: &str) -> Result<Option<enterplace_server::store::TestDatabase>, Error> {
    enterplace_server::store::TestDatabase::create(&format!(
        "enterplace_{}_{test}",
        std::process::id()
    ))
    .await
}

/// A provider that keeps the Authorization header of every request it gets.
async fn provider() -> Result<(Arc<Mutex<Vec<String>>>, u16), Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let app = Router::new()
        .route(
            "/v1/chat/completions",
            post(
                |State(seen): State<Arc<Mutex<Vec<String>>>>, headers: HeaderMap, _: Bytes| async move {
                    let auth = headers
                        .get(header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_string();
                    if let Ok(mut all) = seen.lock() {
                        all.push(auth);
                    }
                    r#"{"id":"c","object":"chat.completion","choices":[]}"#
                },
            ),
        )
        .with_state(seen.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((seen, port))
}

/// The policy of a gateway whose provider key is `key`: `key_env: MOCK_KEY` or `credential: openai-prod`.
fn policy(port: u16, key: &str) -> String {
    format!(
        "version: 1
store: {{ postgres_url_env: ENTERPLACE_STORE_URL }}
providers:
  - name: mock
    kind: openai
    url: http://127.0.0.1:{port}
    allow_private: true
    {key}
    models: [m]
rules:
  - name: everyone
    principals: {{ any: true }}
    models: [m]
"
    )
}

fn dir(name: &str) -> Result<PathBuf, Error> {
    let dir = std::env::temp_dir().join(format!("enterplace-cred-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn gateway(dir: &Path, url: &str, text: &str, master: Option<&str>) -> Result<Governed, String> {
    let policy = dir.join("enterplace.policy.yaml");
    std::fs::write(&policy, text).map_err(|e| e.to_string())?;
    let (url, master) = (url.to_string(), master.map(str::to_string));
    let gw = enterplace_server::governed(&policy, None, &|variable| match variable {
        "ENTERPLACE_STORE_URL" => Some(url.clone()),
        "ENTERPLACE_MASTER_KEY" => master.clone(),
        "ENTERPLACE_MASTER_KEY_FILE" => None,
        _ => Some("env-provider-key".into()),
    })?;
    gw.reloader.watch();
    Ok(gw)
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    key: &str,
    body: Option<Value>,
) -> Result<(StatusCode, String), Error> {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {key}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))?;
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    let bytes = response.into_body().collect().await?.to_bytes();
    Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
}

async fn console(
    app: &Router,
    method: &str,
    path: &str,
    cookie: &str,
    form: &str,
) -> Result<(StatusCode, HeaderMap, String), Error> {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, HOST)
        .header(header::ORIGIN, format!("http://{HOST}"))
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(form.to_string()))?;
    let response = app.clone().oneshot(request).await?;
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await?.to_bytes();
    Ok((
        parts.status,
        parts.headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    ))
}

async fn sign_in(app: &Router) -> Result<String, Error> {
    let (status, headers, _) =
        console(app, "POST", "/console/sign-in", "", &format!("key={ADMIN}")).await?;
    assert_eq!(status, StatusCode::SEE_OTHER);
    Ok(headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|c| c.split(';').next())
        .ok_or("no cookie was set")?
        .to_string())
}

fn chat() -> Value {
    json!({"model": "m", "messages": []})
}

fn last(seen: &Arc<Mutex<Vec<String>>>) -> String {
    seen.lock()
        .ok()
        .and_then(|all| all.last().cloned())
        .unwrap_or_default()
}

fn no_secret(text: &str, what: &str) {
    for secret in [FIRST, SECOND, SPARE, MASTER] {
        assert!(
            !text.contains(secret),
            "{what} holds a secret value: {text}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_credential_added_on_one_gateway_is_used_rotated_and_removed_on_another() -> TestResult {
    let Some(url) = database("credentials").await? else {
        return Ok(());
    };
    let (seen, port) = provider().await?;
    let (one_dir, two_dir) = (dir("one")?, dir("two")?);
    let named = policy(port, "credential: openai-prod");

    // The first gateway keeps its own key in the environment; the store holds the admin and the caller.
    let one = gateway(
        &one_dir,
        &url,
        &policy(port, "key_env: MOCK_KEY"),
        Some(MASTER),
    )?;
    enterplace_core::keyfile::add_entry("admin", "ops", ADMIN, true, &one.loaded.keys_path)?;
    enterplace_core::keyfile::add_entry(
        "maya.cohen",
        "payments",
        MAYA,
        false,
        &one.loaded.keys_path,
    )?;
    one.reloader.check(enterplace_server::Trigger::FileChange);

    // A policy that names a credential the store does not hold: `enterplace check` and the start both say so.
    std::fs::write(two_dir.join("enterplace.policy.yaml"), &named)?;
    let loaded = enterplace_core::config::load(&two_dir.join("enterplace.policy.yaml"), None)
        .map_err(|e| e.join("\n"))?;
    let env = |variable: &str| match variable {
        "ENTERPLACE_STORE_URL" => Some(url.clone()),
        "ENTERPLACE_MASTER_KEY" => Some(MASTER.to_string()),
        _ => None,
    };
    let problems = enterplace_server::credential_problems(
        &two_dir.join("enterplace.policy.yaml"),
        &loaded,
        &env,
    )?;
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(
        problems[0].contains("\"openai-prod\"") && problems[0].contains("POST /admin/credentials"),
        "{problems:?}"
    );
    let refused = gateway(&two_dir, &url, &named, Some(MASTER))
        .err()
        .unwrap_or_default();
    assert!(refused.contains("\"openai-prod\""), "{refused}");

    // Added through the admin API of the first gateway. The answer names it and never holds the value.
    let (status, body) = call(
        &one.router,
        "POST",
        "/admin/credentials",
        ADMIN,
        Some(json!({"name": "openai-prod", "provider": "openai", "value": FIRST})),
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    no_secret(&body, "the add answer");
    let added: Value = serde_json::from_str(&body)?;
    assert_eq!(added["credential"]["name"], "openai-prod");
    assert_eq!(added["credential"]["fingerprint"], "...1111");
    assert_eq!(added["credential"]["created_by"], "admin");
    assert!(
        enterplace_server::credential_problems(
            &two_dir.join("enterplace.policy.yaml"),
            &loaded,
            &env
        )?
        .is_empty()
    );

    // A second gateway on the same database starts with it and sends it.
    let two = gateway(&two_dir, &url, &named, Some(MASTER))?;
    let (status, body) = call(
        &two.router,
        "POST",
        "/v1/chat/completions",
        MAYA,
        Some(chat()),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(last(&seen), format!("Bearer {FIRST}"));

    // Rotated on the first gateway, the second sends the new value within 2 seconds, with no restart.
    let (status, body) = call(
        &one.router,
        "PUT",
        "/admin/credentials/openai-prod",
        ADMIN,
        Some(json!({"value": SECOND})),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    no_secret(&body, "the rotate answer");
    let start = Instant::now();
    loop {
        call(
            &two.router,
            "POST",
            "/v1/chat/completions",
            MAYA,
            Some(chat()),
        )
        .await?;
        if last(&seen) == format!("Bearer {SECOND}") {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "the rotation did not reach the other gateway: {}",
            last(&seen)
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let (status, body) = call(&two.router, "GET", "/admin/credentials", ADMIN, None).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    no_secret(&body, "the list");
    let list: Value = serde_json::from_str(&body)?;
    assert_eq!(list["credentials"][0]["fingerprint"], "...2222", "{body}");
    assert_eq!(list["credentials"][0]["rotated_by"], "admin", "{body}");

    // A credential the policy in use names is not removed from under it.
    let (status, body) = call(
        &two.router,
        "DELETE",
        "/admin/credentials/openai-prod",
        ADMIN,
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.contains("credential_in_use"), "{body}");

    // Added and removed in the console of the second gateway.
    let cookie = sign_in(&two.router).await?;
    let (status, _, page) = console(
        &two.router,
        "POST",
        "/console/credentials/add",
        &cookie,
        &format!("name=spare&provider=anthropic&value={SPARE}"),
    )
    .await?;
    assert!(status.is_success() || status.is_redirection(), "{page}");
    no_secret(&page, "the page after adding");
    let (status, _, page) =
        console(&two.router, "GET", "/console/credentials", &cookie, "").await?;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("openai-prod") && page.contains("spare") && page.contains("...3333"));
    no_secret(&page, "the credentials page");
    let (status, _, page) = console(
        &two.router,
        "POST",
        "/console/credentials/remove",
        &cookie,
        "name=spare&confirm=spare",
    )
    .await?;
    assert!(status.is_success() || status.is_redirection(), "{page}");
    let (_, body) = call(&one.router, "GET", "/admin/credentials", ADMIN, None).await?;
    let names: Vec<Value> = serde_json::from_str::<Value>(&body)?["credentials"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|c| c["name"].clone())
        .collect();
    assert_eq!(names, vec![json!("openai-prod")], "{body}");

    // Each change is recorded, never with the value.
    for gw_dir in [&one_dir, &two_dir] {
        let log = std::fs::read_to_string(gw_dir.join("enterplace-audit.jsonl"))?;
        no_secret(&log, "the audit log");
    }
    let log = std::fs::read_to_string(one_dir.join("enterplace-audit.jsonl"))?
        + &std::fs::read_to_string(two_dir.join("enterplace-audit.jsonl"))?;
    for action in ["add_credential", "rotate_credential", "remove_credential"] {
        assert!(
            log.lines()
                .any(|l| l.contains(&format!("\"action\":\"{action}\""))),
            "no {action} record"
        );
    }

    // The wrong master key is refused at start, with the fix.
    let three = dir("three")?;
    let refused = gateway(
        &three,
        &url,
        &policy(port, "key_env: MOCK_KEY"),
        Some(OTHER_MASTER),
    )
    .err()
    .unwrap_or_default();
    assert!(
        refused.contains("ENTERPLACE_MASTER_KEY") && refused.contains("not the key"),
        "{refused}"
    );
    // Without a master key a gateway still starts on key_env, and says how to turn credentials on.
    let four = gateway(
        &dir("four")?,
        &url,
        &policy(port, "key_env: MOCK_KEY"),
        None,
    )?;
    let (status, body) = call(&four.router, "GET", "/admin/credentials", ADMIN, None).await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(
        body.contains("no_master_key") && body.contains("ENTERPLACE_MASTER_KEY"),
        "{body}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_store_the_console_points_to_key_env() -> TestResult {
    let (_, port) = provider().await?;
    let dir = dir("no-store")?;
    let policy = dir.join("enterplace.policy.yaml");
    std::fs::write(&policy, policy_without_store(port))?;
    std::fs::write(
        dir.join("enterplace.keys.yaml"),
        format!(
            "keys:\n  - name: admin\n    team: ops\n    admin: true\n    sha256: {}\n",
            enterplace_core::id::sha256_hex(ADMIN.as_bytes())
        ),
    )?;
    let gw = enterplace_server::governed(&policy, None, &|_| Some("env-provider-key".into()))?;
    let cookie = sign_in(&gw.router).await?;
    let (status, _, page) = console(&gw.router, "GET", "/console/credentials", &cookie, "").await?;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("store") && page.contains("key_env"), "{page}");
    let (status, body) = call(&gw.router, "GET", "/admin/credentials", ADMIN, None).await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(
        body.contains("credentials_need_store") && body.contains("key_env"),
        "{body}"
    );
    Ok(())
}

fn policy_without_store(port: u16) -> String {
    policy(port, "key_env: MOCK_KEY")
        .replace("store: { postgres_url_env: ENTERPLACE_STORE_URL }\n", "")
}
