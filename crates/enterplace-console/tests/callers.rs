//! Access requests: the console lists the callers no admin has reviewed and the models no provider serves, from
//! the request log, and Allow, Block and the mode change the policy's `new_callers:` like any other policy edit.

use std::{path::PathBuf, sync::Arc};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use enterplace_console::{ConsoleConfig, router};
use enterplace_core::{
    audit::{AuditLog, Entry},
    id::sha256_hex,
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type Error = Box<dyn std::error::Error>;
type TestResult = Result<(), Error>;

const NOA: &str = "enterplace_noa_admin_key_for_callers";
const HOST: &str = "127.0.0.1:19853";

const POLICY: &str = "\
version: 1
providers:
  - name: claude
    kind: anthropic
    url: https://api.anthropic.com
    auth: passthrough
    models: [\"claude-*\"]
rules:
  - name: everyone
    principals: { any: true }
    models: [\"*\"]
";

struct Setup {
    app: Router,
    dir: PathBuf,
}

fn setup(name: &str, policy: &str) -> Result<Setup, Error> {
    let dir = std::env::temp_dir().join(format!(
        "enterplace-console-callers-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("enterplace.policy.yaml"), policy)?;
    std::fs::write(
        dir.join("enterplace.keys.yaml"),
        format!(
            "keys:\n  - name: noa.bar\n    team: platform\n    sha256: {}\n    admin: true\n  - name: billing-bot\n    team: apps\n    sha256: {}\n    metadata: {{\"kind\":\"workload\"}}\n",
            sha256_hex(NOA.as_bytes()),
            sha256_hex(b"enterplace_billing_bot_key")
        ),
    )?;
    let audit = dir.join("enterplace-audit.jsonl");
    let log = AuditLog::open(&audit)?;
    let request = |person: &'static str, model: &'static str, code: Option<&'static str>| {
        enterplace_core::audit::record(&Entry {
            id: "01CALLERS000000000000000001",
            person: Some(person),
            team: Some("apps"),
            method: "POST",
            path: "/v1/chat/completions",
            model: Some(model),
            allowed: code.is_none(),
            code,
            ..Entry::default()
        })
    };
    // The product owner's morning: a service key sends OpenRouter-style names and is refused, and an admin works.
    log.append_record(&request(
        "billing-bot",
        "openai/gpt-4o",
        Some("unknown_model"),
    ))?;
    log.append_record(&request(
        "billing-bot",
        "claude-sonnet-4-5",
        Some("login_needed"),
    ))?;
    log.append_record(&request("noa.bar", "claude-sonnet-4-5", None))?;
    log.flush();
    let config = ConsoleConfig {
        policy: dir.join("enterplace.policy.yaml"),
        keys: dir.join("enterplace.keys.yaml"),
        audit,
        log: Some(Arc::new(log)),
    };
    Ok(Setup {
        app: Router::new().nest("/console", router(config)),
        dir,
    })
}

/// The policy file as written, and as the gateway loads it.
fn read_policy(s: &Setup) -> Result<(String, enterplace_core::config::Loaded), Error> {
    let path = s.dir.join("enterplace.policy.yaml");
    let loaded = enterplace_core::config::load(&path, Some(&s.dir.join("enterplace.keys.yaml")))
        .map_err(|problems| problems.join(" "))?;
    Ok((std::fs::read_to_string(&path)?, loaded))
}

async fn sign_in(s: &Setup) -> Result<String, Error> {
    let request = Request::post("/console/sign-in")
        .header(header::HOST, HOST)
        .header(header::ORIGIN, format!("http://{HOST}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("key={NOA}")))?;
    let response = s.app.clone().oneshot(request).await?;
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .ok_or("no cookie was set")?;
    Ok(cookie.split(';').next().unwrap_or("").to_string())
}

async fn call(
    s: &Setup,
    method: &str,
    path: &str,
    cookie: &str,
    body: Option<Value>,
) -> Result<(StatusCode, Value), Error> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, HOST)
        .header(header::ORIGIN, format!("http://{HOST}"))
        .header(header::COOKIE, cookie);
    if body.is_some() {
        request = request.header(header::CONTENT_TYPE, "application/json");
    }
    let request = request.body(Body::from(body.map(|b| b.to_string()).unwrap_or_default()))?;
    let response = s.app.clone().oneshot(request).await?;
    let status = response.status();
    let bytes = response.into_body().collect().await?.to_bytes();
    Ok((
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    ))
}

#[tokio::test]
async fn new_callers_and_unserved_models_are_listed_and_allowed_with_one_call() -> TestResult {
    let s = setup("list", &format!("{POLICY}new_callers:\n  mode: hold\n"))?;
    let cookie = sign_in(&s).await?;
    let (status, data) = call(&s, "GET", "/console/api/callers", &cookie, None).await?;
    assert_eq!(status, StatusCode::OK, "{data}");
    assert_eq!(data["mode"], "hold");
    let callers = data["callers"].as_array().ok_or("no callers")?;
    // The admin is never listed: an admin key is never held.
    assert_eq!(callers.len(), 1, "{data}");
    let bot = &callers[0];
    assert_eq!(bot["name"], "billing-bot");
    assert_eq!(bot["kind"], "service key");
    assert_eq!(bot["state"], "pending");
    assert_eq!(
        (bot["requests"].as_u64(), bot["refused"].as_u64()),
        (Some(2), Some(2))
    );
    assert_eq!(
        bot["refusal"]["code"], "login_needed",
        "the newest refusal: {bot}"
    );
    assert_eq!(bot["refusal"]["fix"], "provider");
    // Both models are listed with the step that fixes them; the one a request got through with is not.
    let models: Vec<(&str, &str)> = data["models"]
        .as_array()
        .ok_or("no models")?
        .iter()
        .map(|m| {
            (
                m["model"].as_str().unwrap_or(""),
                m["refusal"]["code"].as_str().unwrap_or(""),
            )
        })
        .collect();
    assert_eq!(models, [("openai/gpt-4o", "unknown_model")], "{data}");
    assert_eq!(data["waiting"], 2);

    let (status, done) = call(
        &s,
        "POST",
        "/console/api/callers",
        &cookie,
        Some(json!({ "name": "billing-bot", "decision": "allow" })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    let (policy, loaded) = read_policy(&s)?;
    let setting = loaded.policy.new_callers().ok_or("no new_callers")?;
    assert!(setting.allowed.contains("billing-bot"), "{policy}");
    let (_, data) = call(&s, "GET", "/console/api/callers", &cookie, None).await?;
    assert_eq!(data["callers"].as_array().map(Vec::len), Some(0), "{data}");

    // Block moves it to the other list; the change is recorded with who made it.
    let (status, _) = call(
        &s,
        "POST",
        "/console/api/callers",
        &cookie,
        Some(json!({ "name": "billing-bot", "decision": "block" })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let (policy, loaded) = read_policy(&s)?;
    let setting = loaded.policy.new_callers().ok_or("no new_callers")?;
    assert!(
        setting.blocked.contains("billing-bot") && !setting.allowed.contains("billing-bot"),
        "{policy}"
    );
    let audit = std::fs::read_to_string(s.dir.join("enterplace-audit.jsonl"))?;
    assert!(
        audit.contains("\"decide_new_caller\"") && audit.contains("noa.bar"),
        "{audit}"
    );
    Ok(())
}

#[tokio::test]
async fn the_mode_is_set_without_yaml_and_can_keep_the_callers_already_working() -> TestResult {
    let s = setup("mode", POLICY)?;
    let cookie = sign_in(&s).await?;
    let (_, data) = call(&s, "GET", "/console/api/callers", &cookie, None).await?;
    assert_eq!(data["set"], false, "{data}");
    let (status, refused) = call(
        &s,
        "PUT",
        "/console/api/callers/mode",
        &cookie,
        Some(json!({ "mode": "maybe" })),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        refused["error"].as_str().unwrap_or("").contains("hold"),
        "{refused}"
    );
    let (status, done) = call(
        &s,
        "PUT",
        "/console/api/callers/mode",
        &cookie,
        Some(json!({ "mode": "block", "allow": ["billing-bot"] })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    let (policy, loaded) = read_policy(&s)?;
    let setting = loaded.policy.new_callers().ok_or("no new_callers")?;
    assert_eq!(setting.mode.word(), "block");
    assert!(setting.allowed.contains("billing-bot"), "{policy}");
    Ok(())
}
