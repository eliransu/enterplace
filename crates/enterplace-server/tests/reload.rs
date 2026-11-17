//! Acceptance tests for slice 3: the policy and keys files change while Enterplace serves, and the admin API for keys.
//! Each test's mock provider listens on a port of 127.0.0.1 the system picks.

use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
    routing::post,
};
use enterplace_core::id::sha256_hex;
use enterplace_server::{Governed, Reload, Trigger};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Error = Box<dyn std::error::Error>;

const MAYA: &str = "enterplace_maya_0123456789abcdef0123456789";
const OMER: &str = "enterplace_omer_0123456789abcdef0123456789";
const ADMIN: &str = "enterplace_admin_0123456789abcdef012345678";

/// A stream of events sent one every 100 ms, so a stream can be in flight while the files change.
struct Slow(tokio::sync::mpsc::Receiver<Bytes>);

impl futures_core::Stream for Slow {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.0.poll_recv(cx).map(|item| item.map(Ok))
    }
}

/// A provider that answers at once, or streams 20 events over two seconds when asked to stream. Returns its port.
async fn provider() -> Result<u16, Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let app = Router::new().route(
        "/v1/chat/completions",
        post(|body: Bytes| async move {
            if body.windows(13).any(|w| w == b"\"stream\":true") {
                let (tx, rx) = tokio::sync::mpsc::channel(4);
                tokio::spawn(async move {
                    for i in 0..20 {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        let _ = tx
                            .send(Bytes::from(format!("data: {{\"n\":{i}}}\n\n")))
                            .await;
                    }
                    let _ = tx.send(Bytes::from_static(b"data: [DONE]\n\n")).await;
                });
                axum::response::Response::builder()
                    .header(header::CONTENT_TYPE, "text/event-stream")
                    .body(Body::from_stream(Slow(rx)))
                    .unwrap_or_default()
            } else {
                axum::response::Response::new(Body::from(r#"{"choices":[]}"#))
            }
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

fn policy(port: u16) -> String {
    format!(
        "version: 1
providers:
  - name: mock
    kind: openai
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: MOCK_PROVIDER_KEY
    models: [model-a, model-b]
rules:
  - name: payments-team
    principals: {{ team: payments }}
    models: [model-a, model-b]
"
    )
}

fn entry(name: &str, team: &str, key: &str) -> String {
    format!(
        "  - name: {name}\n    team: {team}\n    sha256: {}\n",
        sha256_hex(key.as_bytes())
    )
}

fn keys() -> String {
    format!(
        "keys:\n{}{}{}    admin: true\n",
        entry("maya.cohen", "payments", MAYA),
        entry("omer.katz", "payments", OMER),
        entry("ops.admin", "ops", ADMIN)
    )
}

fn dir(name: &str) -> std::io::Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!("enterplace-reload-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

struct Setup {
    port: u16,
    dir: PathBuf,
    policy: PathBuf,
    keys: PathBuf,
    audit: PathBuf,
    gw: Governed,
}

async fn setup(name: &str) -> Result<Setup, Error> {
    let port = provider().await?;
    let dir = dir(name)?;
    let (policy, keys_path) = (
        dir.join("enterplace.policy.yaml"),
        dir.join("enterplace.keys.yaml"),
    );
    std::fs::write(&policy, self::policy(port))?;
    std::fs::write(&keys_path, keys())?;
    let gw = start(&policy)?;
    Ok(Setup {
        port,
        audit: dir.join("enterplace-audit.jsonl"),
        dir,
        policy,
        keys: keys_path,
        gw,
    })
}

fn start(policy: &Path) -> Result<Governed, Error> {
    Ok(enterplace_server::governed(policy, None, &|_| {
        Some("provider-secret".into())
    })?)
}

fn chat(key: &str, model: &str, stream: bool) -> Result<Request<Body>, axum::http::Error> {
    Request::post("/v1/chat/completions")
        .header(header::AUTHORIZATION, format!("Bearer {key}"))
        .body(Body::from(format!(
            r#"{{"model":"{model}","stream":{stream},"messages":[]}}"#
        )))
}

async fn answer(app: &Router, request: Request<Body>) -> Result<(StatusCode, String), Error> {
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, String::from_utf8(body.to_vec())?))
}

/// The `code` of a refusal in OpenAI's shape.
fn code(body: &str) -> String {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v["error"]["code"].as_str().map(String::from))
        .unwrap_or_default()
}

fn records(path: &Path) -> Result<Vec<Value>, Error> {
    std::fs::read_to_string(path)?
        .lines()
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn events<'a>(records: &'a [Value], event: &str) -> Vec<&'a Value> {
    records.iter().filter(|r| r["event"] == event).collect()
}

/// Sends the request every 50 ms until its status is `want`, for at most `limit`. Returns how long it took.
async fn until_status(
    app: &Router,
    limit: Duration,
    want: StatusCode,
    request: impl Fn() -> Result<Request<Body>, axum::http::Error>,
) -> Result<(Duration, String), Error> {
    let start = Instant::now();
    loop {
        let (status, body) = answer(app, request()?).await?;
        if status == want {
            return Ok((start.elapsed(), body));
        }
        if start.elapsed() > limit {
            return Err(format!("still {status} after {limit:?}: {body}").into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Saves a file the way most editors do: write a new file beside it, then rename it over the old one.
fn save(path: &Path, text: &str) -> std::io::Result<()> {
    let temporary = path.with_extension("swp");
    std::fs::write(&temporary, text)?;
    std::fs::rename(&temporary, path)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_removed_key_is_refused_within_two_seconds_and_a_stream_already_started_finishes()
-> TestResult {
    let s = setup("revoke").await?;
    s.gw.reloader.watch();
    let app = s.gw.router.clone();
    let response = app.clone().oneshot(chat(MAYA, "model-a", true)?).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let stream = tokio::spawn(async move {
        let body = response.into_body().collect().await.map(|b| b.to_bytes());
        (body, Instant::now())
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    std::fs::write(
        &s.keys,
        keys().replace(&entry("maya.cohen", "payments", MAYA), ""),
    )?;
    let (took, body) = until_status(
        &app,
        Duration::from_secs(2),
        StatusCode::UNAUTHORIZED,
        || chat(MAYA, "model-a", false),
    )
    .await?;
    assert_eq!(code(&body), "unknown_key", "{body}");
    assert!(took <= Duration::from_secs(2), "{took:?}");
    assert!(!body.contains("restart"), "{body}");
    let refused_at = Instant::now();
    // Everyone else is untouched.
    assert_eq!(
        answer(&app, chat(OMER, "model-a", false)?).await?.0,
        StatusCode::OK
    );

    let (body, ended) = stream.await?;
    let text = String::from_utf8(body?.to_vec())?;
    assert!(
        text.contains("\"n\":19") && text.ends_with("data: [DONE]\n\n"),
        "{text}"
    );
    assert!(
        ended > refused_at,
        "the stream ended before the key was refused"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_model_removed_from_a_rule_is_refused_within_two_seconds_with_the_new_policy_hash()
-> TestResult {
    let s = setup("model").await?;
    s.gw.reloader.watch();
    let changed = policy(s.port).replacen(
        "principals: { team: payments }\n    models: [model-a, model-b]",
        "principals: { team: payments }\n    models: [model-a]",
        1,
    );
    std::fs::write(&s.policy, &changed)?;
    let (took, body) = until_status(
        &s.gw.router,
        Duration::from_secs(2),
        StatusCode::FORBIDDEN,
        || chat(MAYA, "model-b", false),
    )
    .await?;
    assert_eq!(code(&body), "model_not_allowed", "{body}");
    assert!(took <= Duration::from_secs(2), "{took:?}");
    let all = records(&s.audit)?;
    let last = all.last().ok_or("no records")?;
    assert_eq!(last["code"], "model_not_allowed");
    assert_eq!(last["policy_sha256"], sha256_hex(changed.as_bytes()));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_save_with_a_mistake_is_not_used_is_recorded_once_and_the_next_correct_save_is_used()
-> TestResult {
    let s = setup("mistake").await?;
    s.gw.reloader.watch();
    let broken = policy(s.port).replacen(
        "principals: { team: payments }\n    models:",
        "principals: { team: payments }\n    modles:",
        1,
    );
    std::fs::write(&s.policy, &broken)?;
    // Three checks of the files see the same mistake.
    tokio::time::sleep(Duration::from_millis(3200)).await;
    let all = records(&s.audit)?;
    let rejected = events(&all, "config_rejected");
    assert_eq!(rejected.len(), 1, "{rejected:?}");
    let problems = rejected[0]["problems"].to_string();
    assert!(
        problems.contains("enterplace.policy.yaml:") && problems.contains("modles"),
        "{problems}"
    );
    assert_eq!(rejected[0]["problem_count"], 1);
    assert_eq!(rejected[0]["policy_sha256"], sha256_hex(broken.as_bytes()));
    // The old version keeps deciding.
    assert_eq!(
        answer(&s.gw.router, chat(MAYA, "model-b", false)?).await?.0,
        StatusCode::OK
    );

    let fixed = policy(s.port).replacen(
        "principals: { team: payments }\n    models: [model-a, model-b]",
        "principals: { team: payments }\n    models: [model-a]",
        1,
    );
    std::fs::write(&s.policy, &fixed)?;
    until_status(
        &s.gw.router,
        Duration::from_secs(2),
        StatusCode::FORBIDDEN,
        || chat(MAYA, "model-b", false),
    )
    .await?;
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_file_replaced_by_rename_or_a_symlink_switched_to_another_file_is_noticed() -> TestResult
{
    let port = provider().await?;
    let dir = dir("rename")?;
    let (first, second) = (dir.join("policy-1.yaml"), dir.join("policy-2.yaml"));
    std::fs::write(&first, policy(port))?;
    let link = dir.join("enterplace.policy.yaml");
    std::os::unix::fs::symlink(&first, &link)?;
    let keys_path = dir.join("enterplace.keys.yaml");
    std::fs::write(&keys_path, keys())?;
    let gw = start(&link)?;
    gw.reloader.watch();

    save(
        &keys_path,
        &keys().replace(&entry("omer.katz", "payments", OMER), ""),
    )?;
    until_status(
        &gw.router,
        Duration::from_secs(2),
        StatusCode::UNAUTHORIZED,
        || chat(OMER, "model-a", false),
    )
    .await?;

    std::fs::write(
        &second,
        policy(port).replacen(
            "principals: { team: payments }\n    models: [model-a, model-b]",
            "principals: { team: payments }\n    models: [model-a]",
            1,
        ),
    )?;
    let switched = dir.join("switch.link");
    std::os::unix::fs::symlink(&second, &switched)?;
    std::fs::rename(&switched, &link)?;
    until_status(
        &gw.router,
        Duration::from_secs(2),
        StatusCode::FORBIDDEN,
        || chat(MAYA, "model-b", false),
    )
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_file_a_changed_audit_path_or_an_unusable_provider_is_rejected_and_the_old_version_kept()
-> TestResult {
    let s = setup("restart-only").await?;
    let check = || s.gw.reloader.check(Trigger::FileChange);

    std::fs::remove_file(&s.keys)?;
    let Reload::Rejected(problems) = check() else {
        return Err("a missing keys file was accepted".into());
    };
    assert!(problems.join("\n").contains("missing"), "{problems:?}");
    std::fs::write(&s.keys, keys())?;
    assert!(matches!(check(), Reload::Unchanged));

    // The audit log path needs a restart. A provider whose key cannot be read is not used: its route would
    // have no key.
    for (changed, reason, fix) in [
        (
            policy(s.port) + "audit: { path: elsewhere.jsonl }\n",
            "audit log path",
            "restart",
        ),
        (
            policy(s.port).replace("MOCK_PROVIDER_KEY", "ENTERPLACE_TEST_UNSET_KEY"),
            "ENTERPLACE_TEST_UNSET_KEY",
            "export",
        ),
        (
            policy(s.port).replace(
                "rules:\n",
                "  - name: other\n    kind: openai\n    url: https://api.openai.com\n    key_env: ENTERPLACE_TEST_OTHER_KEY\n    models: [gpt-4o]\nrules:\n",
            ),
            "ENTERPLACE_TEST_OTHER_KEY",
            "export",
        ),
    ] {
        std::fs::write(&s.policy, &changed)?;
        let Reload::Rejected(problems) = check() else {
            return Err(format!("a change of the {reason} was accepted").into());
        };
        let text = problems.join("\n");
        assert!(text.contains(reason), "{reason}: {text}");
        assert!(text.contains(fix), "{reason}: {text}");
        assert_eq!(
            answer(&s.gw.router, chat(MAYA, "model-b", false)?).await?.0,
            StatusCode::OK,
            "{reason}"
        );
    }
    let all = records(&s.audit)?;
    let rejected = events(&all, "config_rejected");
    assert_eq!(rejected.len(), 4, "one per distinct pair of files");
    assert!(rejected[0]["problems"].to_string().contains("missing"));

    // A provider's models list may change without a restart.
    std::fs::write(
        &s.policy,
        policy(s.port).replace(
            "models: [model-a, model-b]\nrules",
            "models: [model-a, model-b, model-c]\nrules",
        ),
    )?;
    assert!(
        matches!(check(), Reload::Loaded),
        "a models change was refused"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_provider_added_or_moved_is_used_at_the_next_reload_without_a_restart() -> TestResult {
    let s = setup("provider-change").await?;
    let check = || s.gw.reloader.check(Trigger::FileChange);
    // A model server on this machine needs no key, so its route can be built from the file alone.
    let local = |port: u16| {
        policy(s.port)
            .replace(
                "rules:\n",
                &format!("  - name: local\n    kind: openai\n    url: http://127.0.0.1:{port}\n    allow_private: true\n    models: [model-z]\nrules:\n"),
            )
            + "  - name: everyone\n    principals: { any: true }\n    models: [model-z]\n"
    };
    assert_ne!(
        answer(&s.gw.router, chat(ADMIN, "model-z", false)?)
            .await?
            .0,
        StatusCode::OK
    );
    std::fs::write(&s.policy, local(s.port))?;
    assert!(
        matches!(check(), Reload::Loaded),
        "a new provider was refused"
    );
    // The admin's team has no rule of its own, so the new `everyone` rule lets it use the new provider.
    assert_eq!(
        answer(&s.gw.router, chat(ADMIN, "model-z", false)?)
            .await?
            .0,
        StatusCode::OK
    );
    // Moved to a port nobody listens on: the next request goes there and fails, with no restart.
    std::fs::write(&s.policy, local(1))?;
    assert!(
        matches!(check(), Reload::Loaded),
        "a moved provider was refused"
    );
    assert_ne!(
        answer(&s.gw.router, chat(ADMIN, "model-z", false)?)
            .await?
            .0,
        StatusCode::OK
    );
    // Removed: its model is no longer served.
    std::fs::write(&s.policy, policy(s.port))?;
    assert!(
        matches!(check(), Reload::Loaded),
        "removing a provider was refused"
    );
    assert_ne!(
        answer(&s.gw.router, chat(ADMIN, "model-z", false)?)
            .await?
            .0,
        StatusCode::OK
    );
    assert_eq!(
        answer(&s.gw.router, chat(MAYA, "model-b", false)?).await?.0,
        StatusCode::OK
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn each_version_is_in_the_chain_with_what_changed_and_a_restart_continues_from_the_last()
-> TestResult {
    let s = setup("records").await?;
    let first_policy = sha256_hex(policy(s.port).as_bytes());
    let first_keys = sha256_hex(keys().as_bytes());
    let all = records(&s.audit)?;
    let loaded = events(&all, "config_loaded");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0]["trigger"], "start");
    assert_eq!(loaded[0]["policy_sha256_before"], Value::Null);
    assert_eq!(loaded[0]["policy_sha256"], first_policy);
    assert_eq!(loaded[0]["keys_sha256"], first_keys);
    assert_eq!(loaded[0]["policy"], policy(s.port));
    assert_eq!(loaded[0]["keys_added"].as_array().map(Vec::len), Some(3));

    answer(&s.gw.router, chat(MAYA, "model-a", false)?).await?;
    let new_keys = keys().replace(&entry("omer.katz", "payments", OMER), "")
        + &entry(
            "lior.amit",
            "payments",
            "enterplace_lior_0123456789abcdef0123456789",
        );
    std::fs::write(&s.keys, &new_keys)?;
    assert!(matches!(
        s.gw.reloader.check(Trigger::FileChange),
        Reload::Loaded
    ));
    let all = records(&s.audit)?;
    let change = *events(&all, "config_loaded").last().ok_or("no record")?;
    assert_eq!(change["trigger"], "file_change");
    assert_eq!(change["policy_sha256_before"], first_policy);
    assert_eq!(change["policy_sha256"], first_policy);
    assert_eq!(change["keys_sha256_before"], first_keys);
    assert_eq!(change["keys_sha256"], sha256_hex(new_keys.as_bytes()));
    let omer_hash = sha256_hex(OMER.as_bytes());
    assert_eq!(
        change["keys_removed"],
        serde_json::json!([{ "name": "omer.katz", "team": "payments", "sha256_prefix": &omer_hash[..8] }])
    );
    assert_eq!(change["keys_added"][0]["name"], "lior.amit");
    let text = change.to_string();
    assert!(
        !text.contains(&omer_hash),
        "a whole key hash is in the record"
    );

    // Enterplace stops, the policy changes, Enterplace starts again: the start record shows the change made meanwhile.
    drop(s.gw);
    let edited = policy(s.port).replace(
        "[model-a, model-b]\nrules",
        "[model-a, model-b, model-c]\nrules",
    );
    std::fs::write(&s.policy, &edited)?;
    let _again = start(&s.policy)?;
    let all = records(&s.audit)?;
    let restart = *events(&all, "config_loaded").last().ok_or("no record")?;
    assert_eq!(restart["trigger"], "start");
    assert_eq!(restart["policy_sha256_before"], first_policy);
    assert_eq!(restart["policy_sha256"], sha256_hex(edited.as_bytes()));
    assert_eq!(restart["keys_sha256_before"], change["keys_sha256"]);
    assert_eq!(restart["keys_added"], serde_json::json!([]));

    let summary = enterplace_core::audit::verify_full(&s.audit, None)?;
    assert_eq!(summary.records, 5);
    assert_eq!(summary.configuration, 3);
    assert_eq!(summary.requests, 1);
    assert_eq!(summary.usage, 1);
    let _ = std::fs::remove_dir_all(&s.dir);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn no_request_is_decided_by_one_versions_policy_and_anothers_keys() -> TestResult {
    let s = setup("atomic").await?;
    let reloader = s.gw.reloader.clone();
    let (policy_path, keys_path) = (s.policy.clone(), s.keys.clone());
    let changes = tokio::task::spawn_blocking(move || -> Result<(), String> {
        for i in 0..10 {
            std::thread::sleep(Duration::from_millis(30));
            let result = if i % 2 == 0 {
                std::fs::write(&policy_path, format!("{}# change {i}\n", policy(s.port)))
            } else {
                std::fs::write(
                    &keys_path,
                    format!(
                        "{}{}",
                        keys(),
                        entry(&format!("extra{i}"), "t", &format!("k{i}"))
                    ),
                )
            };
            result.map_err(|e| e.to_string())?;
            if !matches!(reloader.check(Trigger::Signal), Reload::Loaded) {
                return Err(format!("change {i} was not loaded"));
            }
        }
        Ok(())
    });
    let mut tasks = Vec::new();
    for _ in 0..30 {
        for _ in 0..20 {
            let app = s.gw.router.clone();
            let request = chat(MAYA, "model-a", false)?;
            tasks.push(tokio::spawn(async move {
                app.oneshot(request).await.map(|r| r.status())
            }));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    for task in tasks {
        assert_eq!(task.await??, StatusCode::OK);
    }
    changes.await??;

    let all = records(&s.audit)?;
    let mut versions = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for record in &all {
        let pair = (
            record["policy_sha256"].to_string(),
            record["keys_sha256"].to_string(),
        );
        if record["event"] == "config_loaded" {
            versions.push(pair);
        } else {
            seen.insert(pair.clone());
            assert!(
                versions.contains(&pair),
                "a request record has hashes no version before it has: {record}"
            );
        }
    }
    assert_eq!(versions.len(), 11);
    assert!(seen.len() > 1, "the requests did not span a change");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn healthz_names_the_hashes_in_use_and_a_rejected_files_hashes() -> TestResult {
    let s = setup("health").await?;
    let health = || Request::get("/healthz").body(Body::empty());
    let (status, body) = answer(&s.gw.router, health()?).await?;
    assert_eq!(status, StatusCode::OK);
    let json: Value = serde_json::from_str(&body)?;
    assert_eq!(json["policy_sha256"], sha256_hex(policy(s.port).as_bytes()));
    assert_eq!(json["keys_sha256"], sha256_hex(keys().as_bytes()));
    assert_eq!(json["rejected"], Value::Null);

    let broken = policy(s.port) + "bogus: 1\n";
    std::fs::write(&s.policy, &broken)?;
    assert!(matches!(
        s.gw.reloader.check(Trigger::FileChange),
        Reload::Rejected(_)
    ));
    let (status, body) = answer(&s.gw.router, health()?).await?;
    assert_eq!(status, StatusCode::OK);
    let json: Value = serde_json::from_str(&body)?;
    assert_eq!(json["policy_sha256"], sha256_hex(policy(s.port).as_bytes()));
    assert_eq!(
        json["rejected"]["policy_sha256"],
        sha256_hex(broken.as_bytes())
    );
    assert_eq!(
        json["rejected"]["keys_sha256"],
        sha256_hex(keys().as_bytes())
    );
    Ok(())
}

fn admin(
    method: &str,
    path: &str,
    key: Option<&str>,
    body: &str,
) -> Result<Request<Body>, axum::http::Error> {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    let request = match key {
        Some(key) => request.header(header::AUTHORIZATION, format!("Bearer {key}")),
        None => request,
    };
    request.body(Body::from(body.to_string()))
}

#[tokio::test(flavor = "multi_thread")]
async fn an_admin_issues_lists_and_revokes_keys_at_runtime() -> TestResult {
    let s = setup("admin").await?;
    let app = &s.gw.router;
    let (status, body) = answer(
        app,
        admin(
            "POST",
            "/admin/keys",
            Some(ADMIN),
            r#"{"name":"new.person","team":"payments"}"#,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let issued: Value = serde_json::from_str(&body)?;
    let key = issued["key"]
        .as_str()
        .ok_or("no key in the answer")?
        .to_string();
    assert!(key.starts_with("enterplace_") && key.len() == 75, "{key}");
    let hash = sha256_hex(key.as_bytes());
    assert_eq!(issued["sha256_prefix"], &hash[..8]);
    let saved = std::fs::read_to_string(&s.keys)?;
    assert!(saved.contains(&hash) && !saved.contains(&key));
    assert!(
        saved.starts_with(&keys()),
        "the file was rewritten, not appended to"
    );
    assert_eq!(
        answer(app, chat(&key, "model-a", false)?).await?.0,
        StatusCode::OK
    );

    let (status, body) = answer(app, admin("GET", "/admin/keys", Some(ADMIN), "")?).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.contains(&key) && !body.contains(&hash), "{body}");
    let list: Value = serde_json::from_str(&body)?;
    let listed = list["keys"].as_array().ok_or("no list")?;
    assert_eq!(listed.len(), 4);
    assert!(listed.iter().any(|k| k["name"] == "new.person"
        && k["team"] == "payments"
        && k["sha256_prefix"] == hash[..8]));

    let (status, body) = answer(
        app,
        admin(
            "DELETE",
            &format!("/admin/keys/{}", &hash[..8]),
            Some(ADMIN),
            "",
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (took, _) = until_status(
        app,
        Duration::from_secs(2),
        StatusCode::UNAUTHORIZED,
        || chat(&key, "model-a", false),
    )
    .await?;
    assert!(took <= Duration::from_secs(2));
    assert_eq!(
        std::fs::read_to_string(&s.keys)?,
        keys(),
        "other entries were changed"
    );
    assert_eq!(
        answer(app, chat(MAYA, "model-a", false)?).await?.0,
        StatusCode::OK
    );

    let (status, body) = answer(
        app,
        admin(
            "DELETE",
            &format!("/admin/keys/{}", &hash[..8]),
            Some(ADMIN),
            "",
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(code(&body), "no_such_key");

    let all = records(&s.audit)?;
    let done: Vec<&str> = events(&all, "admin")
        .iter()
        .filter_map(|r| r["action"].as_str())
        .collect();
    assert_eq!(done, ["issue_key", "list_keys", "revoke_key", "revoke_key"]);
    let first = events(&all, "admin")[0];
    assert_eq!(first["person"], "ops.admin");
    assert_eq!(first["target"]["name"], "new.person");
    assert_eq!(first["verdict"], "allow");
    assert!(enterplace_core::audit::verify(&s.audit).is_ok());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn only_an_admin_key_may_use_the_admin_routes() -> TestResult {
    let s = setup("not-admin").await?;
    let app = &s.gw.router;
    let issue = r#"{"name":"sneaky","team":"payments"}"#;
    for (key, status, expected) in [
        (Some(MAYA), StatusCode::FORBIDDEN, "not_admin"),
        (None, StatusCode::UNAUTHORIZED, "no_key"),
        (
            Some("enterplace_nobody_0123456789abcdef"),
            StatusCode::UNAUTHORIZED,
            "unknown_key",
        ),
    ] {
        for (method, path, body) in [
            ("POST", "/admin/keys", issue),
            ("GET", "/admin/keys", ""),
            ("DELETE", "/admin/keys/0123abcd", ""),
        ] {
            let (got, text) = answer(app, admin(method, path, key, body)?).await?;
            assert_eq!(got, status, "{method} {path}: {text}");
            assert_eq!(code(&text), expected, "{text}");
        }
    }
    let (status, text) = answer(
        app,
        admin(
            "POST",
            "/admin/keys",
            Some(ADMIN),
            r#"{"name":"bad name","team":"t"}"#,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    let (status, _) = answer(
        app,
        admin(
            "POST",
            "/admin/keys",
            Some(ADMIN),
            r#"{"name":"x","team":"t","admin":true}"#,
        )?,
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an unknown field was dropped silently"
    );
    assert_eq!(std::fs::read_to_string(&s.keys)?, keys());
    let all = records(&s.audit)?;
    let refused = events(&all, "admin");
    assert_eq!(refused.len(), 11);
    assert!(refused.iter().take(9).all(|r| r["verdict"] == "refused"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn an_admin_issues_a_key_with_an_expiry_and_a_budget() -> TestResult {
    let s = setup("admin-attrs").await?;
    let app = &s.gw.router;
    let (status, body) = answer(
        app,
        admin(
            "POST",
            "/admin/keys",
            Some(ADMIN),
            r#"{"name":"ci.bot","team":"payments","expires":"2099-01-01","budget":{"usd":20,"per":"month"}}"#,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let saved = std::fs::read_to_string(&s.keys)?;
    assert!(
        saved.contains("    expires: 2099-01-01\n    budget: { usd: 20, per: month }\n"),
        "{saved}"
    );
    let (_, body) = answer(app, admin("GET", "/admin/keys", Some(ADMIN), "")?).await?;
    let list: Value = serde_json::from_str(&body)?;
    let bot = list["keys"]
        .as_array()
        .and_then(|keys| keys.iter().find(|k| k["name"] == "ci.bot"))
        .ok_or("ci.bot is not listed")?;
    assert_eq!(bot["expires"], "2099-01-01");
    assert_eq!(bot["budget"]["usd"], 20.0);
    assert_eq!(bot["budget"]["per"], "month");

    // PM13 MIN-1: the model list and the TPM limit of a key, as LiteLLM's key API takes them.
    let (status, body) = answer(
        app,
        admin(
            "POST",
            "/admin/keys",
            Some(ADMIN),
            r#"{"name":"agent","team":"payments","models":["model-a"],"tpm":5000}"#,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let saved = std::fs::read_to_string(&s.keys)?;
    assert!(
        saved.contains("    models: [\"model-a\"]\n    tpm: 5000\n"),
        "{saved}"
    );
    let (_, body) = answer(app, admin("GET", "/admin/keys", Some(ADMIN), "")?).await?;
    let list: Value = serde_json::from_str(&body)?;
    let agent = list["keys"]
        .as_array()
        .and_then(|keys| keys.iter().find(|k| k["name"] == "agent"))
        .ok_or("agent is not listed")?;
    assert_eq!(
        (&agent["models"], &agent["tpm"]),
        (&serde_json::json!(["model-a"]), &serde_json::json!(5000))
    );
    assert_eq!(bot["models"], Value::Null);
    for bad in [
        r#"{"name":"x","team":"t","expires":"next week"}"#,
        r#"{"name":"x","team":"t","expires":"2020-01-01"}"#,
        r#"{"name":"x","team":"t","expires":"2026-04-31"}"#,
        r#"{"name":"x","team":"t","budget":{"usd":-1,"per":"day"}}"#,
        r#"{"name":"x","team":"t","budget":{"usd":1,"per":"fortnight"}}"#,
        r#"{"name":"x","team":"t","budget":{"usd":1,"per":"day","tz":"Mars/Olympus"}}"#,
        r#"{"name":"x","team":"t","models":[]}"#,
        r#"{"name":"x","team":"t","models":["no-such-model"]}"#,
        r#"{"name":"x","team":"t","tpm":0}"#,
    ] {
        let (status, body) = answer(app, admin("POST", "/admin/keys", Some(ADMIN), bad)?).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {body}");
    }
    Ok(())
}

/// A provider that answers with the Authorization header it was sent, so a test sees which key Enterplace used.
async fn echo_provider() -> Result<u16, Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let app = Router::new().route(
        "/v1/chat/completions",
        post(|headers: axum::http::HeaderMap| async move {
            let auth = headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            axum::response::Response::new(Body::from(auth))
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_file_is_read_at_start_and_a_new_key_in_it_is_used_within_two_seconds() -> TestResult
{
    let port = echo_provider().await?;
    let dir = dir("key-file")?;
    let (policy, keys_path, key) = (
        dir.join("enterplace.policy.yaml"),
        dir.join("enterplace.keys.yaml"),
        dir.join("provider.key"),
    );
    let text = self::policy(port).replace(
        "key_env: MOCK_PROVIDER_KEY",
        &format!("key_file: {}", key.display()),
    );
    std::fs::write(&policy, &text)?;
    std::fs::write(&keys_path, keys())?;

    // A key file that is missing or empty stops the start, and the message names the file.
    for content in [None, Some("  \n")] {
        if let Some(content) = content {
            std::fs::write(&key, content)?;
        }
        let err = match enterplace_server::governed(&policy, None, &|_| None) {
            Ok(_) => return Err("started without a provider key".into()),
            Err(err) => err,
        };
        assert!(
            err.contains(&key.display().to_string()) && err.contains("provider \"mock\""),
            "{err}"
        );
    }

    save(&key, "key-one\n")?;
    let gw = enterplace_server::governed(&policy, None, &|_| None)?;
    gw.reloader.watch();
    let (status, body) = answer(&gw.router, chat(MAYA, "model-a", false)?).await?;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "Bearer key-one"));

    // A new key in the file is used without a restart, while the policy and keys files stay as they are.
    let policy_before = sha256_hex(&std::fs::read(&policy)?);
    save(&key, "key-two\n")?;
    let start = Instant::now();
    loop {
        let (status, body) = answer(&gw.router, chat(MAYA, "model-a", false)?).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        if body == "Bearer key-two" {
            break;
        }
        assert_eq!(body, "Bearer key-one");
        if start.elapsed() > Duration::from_secs(2) {
            return Err("the new key was not used within 2 seconds".into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(policy_before, sha256_hex(&std::fs::read(&policy)?));

    // An emptied key file is not used: Enterplace keeps the key it has and says why.
    save(&key, "")?;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let (status, body) = answer(&gw.router, chat(MAYA, "model-a", false)?).await?;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "Bearer key-two"));
    // The key is never written to the audit log.
    let log = std::fs::read_to_string(dir.join("enterplace-audit.jsonl"))?;
    assert!(!log.contains("key-one") && !log.contains("key-two"));
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn an_unreadable_keys_file_or_a_policy_that_is_not_yaml_keeps_the_last_good_version()
-> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let s = setup("last-good").await?;
    let check = || s.gw.reloader.check(Trigger::FileChange);
    let ok = |model: &'static str| chat(MAYA, model, false);

    // Without the keys file, every key would be unknown: the keys in use stay.
    std::fs::set_permissions(&s.keys, std::fs::Permissions::from_mode(0o000))?;
    // Root reads any file, so the check only means something when the mode keeps this process out.
    if std::fs::read(&s.keys).is_err() {
        let Reload::Rejected(problems) = check() else {
            return Err("an unreadable keys file was accepted".into());
        };
        assert!(
            problems.join("\n").contains("enterplace.keys.yaml"),
            "{problems:?}"
        );
        assert_eq!(
            answer(&s.gw.router, ok("model-b")?).await?.0,
            StatusCode::OK
        );
    }
    std::fs::set_permissions(&s.keys, std::fs::Permissions::from_mode(0o600))?;

    let not_yaml = "version: 1\nproviders: [\n  - name: {\n";
    std::fs::write(&s.policy, not_yaml)?;
    let Reload::Rejected(problems) = check() else {
        return Err("a policy that is not YAML was accepted".into());
    };
    assert!(
        problems.join("\n").contains("enterplace.policy.yaml"),
        "{problems:?}"
    );
    assert_eq!(
        answer(&s.gw.router, ok("model-b")?).await?.0,
        StatusCode::OK
    );
    let all = records(&s.audit)?;
    let rejected = events(&all, "config_rejected");
    assert!(
        rejected
            .iter()
            .any(|r| r["policy_sha256"] == sha256_hex(not_yaml.as_bytes())),
        "{rejected:?}"
    );
    Ok(())
}
