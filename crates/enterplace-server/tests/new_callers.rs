//! New callers (`new_callers:` in the policy): what happens the first time a key, a person token or a JWT names a
//! caller nobody has reviewed. `allow` lets it through and flags its records, `hold` refuses it as
//! `awaiting_approval` until an admin allows it, `block` refuses it as `caller_blocked`. A name on `allowed:` passes
//! in every mode, a name on `blocked:` is refused in every mode, and an admin key is never held. Without the
//! setting nothing changes. Each refusal names the console page that fixes it, and a change to the lists is in force
//! within 2 seconds.

use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
    routing::post,
};
use enterplace_core::id::sha256_hex;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Error = Box<dyn std::error::Error>;

const MAYA: &str = "enterplace_maya_0123456789abcdef0123456789";
const BOT: &str = "enterplace_bot_00123456789abcdef0123456789";
const ADMIN: &str = "enterplace_admin_0123456789abcdef012345678";
const PAGE: &str = "/console/app/#/apps/new";

async fn provider() -> Result<u16, Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let app = Router::new().route(
        "/v1/chat/completions",
        post(|_: Bytes| async move {
            axum::response::Response::builder()
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"choices":[]}"#))
                .unwrap_or_default()
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

struct Setup {
    dir: PathBuf,
    port: u16,
}

impl Setup {
    fn policy_path(&self) -> PathBuf {
        self.dir.join("enterplace.policy.yaml")
    }

    fn write(&self, new_callers: &str) -> Result<(), Error> {
        let port = self.port;
        std::fs::write(
            self.policy_path(),
            format!(
                "version: 1
providers:
  - name: mock
    kind: openai
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: MOCK_PROVIDER_KEY
    models: [model-a]
rules:
  - name: everyone
    principals: {{ any: true }}
    models: [\"*\"]
{new_callers}"
            ),
        )?;
        Ok(())
    }

    fn records(&self) -> Result<Vec<Value>, Error> {
        Ok(
            std::fs::read_to_string(self.dir.join("enterplace-audit.jsonl"))?
                .lines()
                .filter_map(|l| serde_json::from_str::<Value>(l).ok())
                .filter(|r| r.get("verdict").is_some())
                .collect(),
        )
    }
}

async fn setup(name: &str, new_callers: &str) -> Result<Setup, Error> {
    let port = provider().await?;
    let dir = std::env::temp_dir().join(format!(
        "enterplace-new-callers-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let entry = |name: &str, team: &str, key: &str| {
        format!(
            "  - name: {name}\n    team: {team}\n    sha256: {}\n",
            sha256_hex(key.as_bytes())
        )
    };
    std::fs::write(
        dir.join("enterplace.keys.yaml"),
        format!(
            "keys:\n{}{}{}    admin: true\n",
            entry("maya.cohen", "payments", MAYA),
            entry("billing-bot", "apps", BOT),
            entry("ops.admin", "ops", ADMIN)
        ),
    )?;
    let s = Setup { dir, port };
    s.write(new_callers)?;
    Ok(s)
}

fn node(s: &Setup) -> Result<enterplace_server::Governed, Error> {
    Ok(enterplace_server::governed(
        &s.policy_path(),
        None,
        &|_| Some("provider-secret".into()),
    )?)
}

fn chat(key: &str, model: &str) -> Result<Request<Body>, axum::http::Error> {
    Request::post("/v1/chat/completions")
        .header(header::AUTHORIZATION, format!("Bearer {key}"))
        .body(Body::from(format!(
            r#"{{"model":"{model}","messages":[]}}"#
        )))
}

async fn answer(app: &Router, request: Request<Body>) -> Result<(StatusCode, Value), Error> {
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, serde_json::from_slice(&body).unwrap_or(Value::Null)))
}

fn message(body: &Value) -> &str {
    body["error"]["message"].as_str().unwrap_or("")
}

/// Waits until `app` answers `want`, for at most `limit`.
async fn until(
    app: &Router,
    limit: Duration,
    want: StatusCode,
    request: impl Fn() -> Result<Request<Body>, axum::http::Error>,
) -> Result<Value, Error> {
    let start = Instant::now();
    loop {
        let (status, body) = answer(app, request()?).await?;
        if status == want {
            return Ok(body);
        }
        if start.elapsed() > limit {
            return Err(format!("still {status} after {limit:?}: {body}").into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn without_the_setting_nothing_changes() -> TestResult {
    let s = setup("none", "").await?;
    let gw = node(&s)?;
    assert_eq!(
        answer(&gw.router, chat(BOT, "model-a")?).await?.0,
        StatusCode::OK
    );
    let records = s.records()?;
    assert!(
        records.iter().all(|r| r.get("new_caller").is_none()),
        "{records:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn allow_lets_a_new_caller_through_and_flags_its_records() -> TestResult {
    let s = setup(
        "allow",
        "new_callers:\n  mode: allow\n  allowed: [maya.cohen]\n",
    )
    .await?;
    let gw = node(&s)?;
    assert_eq!(
        answer(&gw.router, chat(BOT, "model-a")?).await?.0,
        StatusCode::OK
    );
    assert_eq!(
        answer(&gw.router, chat(MAYA, "model-a")?).await?.0,
        StatusCode::OK
    );
    assert_eq!(
        answer(&gw.router, chat(ADMIN, "model-a")?).await?.0,
        StatusCode::OK
    );
    let records = s.records()?;
    let flagged: Vec<&str> = records
        .iter()
        .filter(|r| r["new_caller"] == true)
        .filter_map(|r| r["person"].as_str())
        .collect();
    assert_eq!(flagged, ["billing-bot"], "{records:?}");
    // A model no provider serves is still refused, and the refusal says where an admin adds it.
    let (status, body) = answer(&gw.router, chat(BOT, "openai/gpt-4o")?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], "unknown_model");
    assert!(message(&body).contains(PAGE), "{body}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn hold_refuses_a_new_caller_until_it_is_allowed_within_two_seconds() -> TestResult {
    let s = setup("hold", "new_callers:\n  mode: hold\n").await?;
    let gw = node(&s)?;
    gw.reloader.watch();
    let (status, body) = answer(&gw.router, chat(BOT, "model-a")?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], "awaiting_approval");
    let text = message(&body);
    assert!(
        text.contains("billing-bot") && text.contains(PAGE),
        "{text}"
    );
    // An admin key is never held, or nobody could approve anything.
    assert_eq!(
        answer(&gw.router, chat(ADMIN, "model-a")?).await?.0,
        StatusCode::OK
    );
    let records = s.records()?;
    let last_bot = records
        .iter()
        .rev()
        .find(|r| r["person"] == "billing-bot")
        .ok_or("no record of billing-bot")?;
    assert_eq!(last_bot["code"], "awaiting_approval", "{last_bot}");

    s.write("new_callers:\n  mode: hold\n  allowed: [billing-bot]\n")?;
    until(&gw.router, Duration::from_secs(2), StatusCode::OK, || {
        chat(BOT, "model-a")
    })
    .await?;
    // Others are still held.
    let (status, body) = answer(&gw.router, chat(MAYA, "model-a")?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], "awaiting_approval");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn block_refuses_new_callers_and_a_blocked_name_is_refused_in_every_mode() -> TestResult {
    let s = setup("block", "new_callers:\n  mode: block\n").await?;
    let gw = node(&s)?;
    gw.reloader.watch();
    let (status, body) = answer(&gw.router, chat(BOT, "model-a")?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], "caller_blocked");
    assert!(message(&body).contains(PAGE), "{body}");

    s.write("new_callers:\n  mode: allow\n  blocked: [billing-bot]\n")?;
    until(&gw.router, Duration::from_secs(2), StatusCode::OK, || {
        chat(MAYA, "model-a")
    })
    .await?;
    let (status, body) = answer(&gw.router, chat(BOT, "model-a")?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], "caller_blocked");
    assert!(message(&body).contains("blocked"), "{body}");

    s.write("new_callers:\n  mode: block\n  allowed: [billing-bot]\n")?;
    until(&gw.router, Duration::from_secs(2), StatusCode::OK, || {
        chat(BOT, "model-a")
    })
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_mistake_in_the_setting_is_refused_with_its_line_and_fix() -> TestResult {
    let s = setup("mistake", "new_callers:\n  mode: maybe\n").await?;
    let err = match node(&s) {
        Ok(_) => return Err("a policy with mode: maybe was loaded".into()),
        Err(err) => err.to_string(),
    };
    assert!(
        err.contains("new_callers") && err.contains("allow") && err.contains("hold"),
        "{err}"
    );
    s.write("new_callers:\n  mode: hold\n  allowed: [billing-bot]\n  blocked: [billing-bot]\n")?;
    let err = match node(&s) {
        Ok(_) => return Err("a name both allowed and blocked was loaded".into()),
        Err(err) => err.to_string(),
    };
    assert!(err.contains("billing-bot"), "{err}");
    Ok(())
}
