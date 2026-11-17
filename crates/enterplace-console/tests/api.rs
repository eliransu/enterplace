//! The console app's JSON API: each editor (providers and models, MCP servers, the policy's basics) reads, adds,
//! edits and removes through the policy file, refuses what `enterplace check` refuses with a message that names the
//! fix, refuses a role without `edit_policy`, and records every change with who made it.

use std::{path::PathBuf, sync::Arc};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use enterplace_console::{ConsoleConfig, router};
use enterplace_core::store::Store as _;
use enterplace_core::{audit::AuditLog, id::sha256_hex};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const ADMIN_KEY: &str = "enterplace_admin_key_for_api";
const VIEWER_KEY: &str = "enterplace_viewer_key_for_api";
const HOST: &str = "127.0.0.1:19852";

const POLICY: &str = "\
version: 1
providers:
  - name: openai
    kind: openai
    url: https://api.openai.com
    key_env: OPENAI_API_KEY
    models: [gpt-4o-mini, gpt-4o]
rules:
  - name: everyone
    principals: { any: true }
    models: [\"*\"]
guardrails:
  - name: no-secrets
    type: secrets
    action: block
roles:
  - name: viewer
    permissions: [see_keys, see_records, see_spend]
";

struct Setup {
    app: Router,
    dir: PathBuf,
}

impl Setup {
    fn policy(&self) -> Result<String, std::io::Error> {
        std::fs::read_to_string(self.dir.join("enterplace.policy.yaml"))
    }
    fn audit(&self) -> Result<String, std::io::Error> {
        std::fs::read_to_string(self.dir.join("enterplace-audit.jsonl"))
    }
}

fn setup(name: &str) -> Result<Setup, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!("enterplace-api-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("enterplace.policy.yaml"), POLICY)?;
    std::fs::write(
        dir.join("enterplace.keys.yaml"),
        format!(
            "keys:\n  - name: noa.bar\n    team: platform\n    sha256: {}\n    admin: true\n  - name: vic.viewer\n    team: platform\n    sha256: {}\n    admin: true\n    role: viewer\n",
            sha256_hex(ADMIN_KEY.as_bytes()),
            sha256_hex(VIEWER_KEY.as_bytes())
        ),
    )?;
    let log = Arc::new(AuditLog::open(&dir.join("enterplace-audit.jsonl"))?);
    let config = ConsoleConfig {
        policy: dir.join("enterplace.policy.yaml"),
        keys: dir.join("enterplace.keys.yaml"),
        audit: dir.join("enterplace-audit.jsonl"),
        log: Some(log),
    };
    Ok(Setup {
        app: Router::new().nest("/console", router(config)),
        dir,
    })
}

async fn call(
    s: &Setup,
    method: &str,
    path: &str,
    cookie: &str,
    body: Option<Value>,
) -> Result<(StatusCode, Value), Box<dyn std::error::Error>> {
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
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Ok((status, value))
}

async fn sign_in(s: &Setup, key: &str) -> Result<String, Box<dyn std::error::Error>> {
    let request = Request::post("/console/sign-in")
        .header(header::HOST, HOST)
        .header(header::ORIGIN, format!("http://{HOST}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("key={key}")))?;
    let response = s.app.clone().oneshot(request).await?;
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .ok_or("no cookie was set")?;
    Ok(cookie.split(';').next().unwrap_or("").to_string())
}

fn error(value: &Value) -> &str {
    value["error"].as_str().unwrap_or("")
}

#[tokio::test]
async fn the_app_is_served_to_a_signed_in_admin_only() -> TestResult {
    let s = setup("app")?;
    let request = Request::get("/console/app/")
        .header(header::HOST, HOST)
        .body(Body::empty())?;
    let response = s.app.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let cookie = sign_in(&s, ADMIN_KEY).await?;
    let request = Request::get("/console/app/")
        .header(header::HOST, HOST)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())?;
    let response = s.app.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let page = String::from_utf8(response.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(page.contains("/console/app/app.js"), "{page}");
    let (status, me) = call(&s, "GET", "/console/api/me", &cookie, None).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(me["edit_policy"], true);
    assert_eq!(me["source"], "file");
    let (status, _) = call(&s, "GET", "/console/api/me", "", None).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn providers_are_listed_added_edited_and_removed() -> TestResult {
    let s = setup("providers")?;
    let cookie = sign_in(&s, ADMIN_KEY).await?;
    let (status, list) = call(&s, "GET", "/console/api/providers", &cookie, None).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["providers"][0]["name"], "openai");
    assert_eq!(
        list["providers"][0]["models"],
        json!(["gpt-4o-mini", "gpt-4o"])
    );
    assert_eq!(
        list["providers"][0]["key"],
        "environment variable OPENAI_API_KEY"
    );
    assert!(
        list["catalog"]
            .as_array()
            .is_some_and(|c| c.iter().any(|p| p["id"] == "anthropic"))
    );

    // Add, from the catalog, with the key in an environment variable.
    let (status, done) = call(
        &s,
        "POST",
        "/console/api/providers",
        &cookie,
        Some(json!({ "preset": "groq", "key_env": "GROQ_API_KEY", "models": "llama-3.3-70b, llama-3.1-8b" })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert!(
        done["message"]
            .as_str()
            .unwrap_or("")
            .contains("within 2 seconds")
    );
    let policy = s.policy()?;
    assert!(
        policy.contains("name: groq")
            && policy.contains("preset: groq")
            && policy.contains("key_env: GROQ_API_KEY"),
        "{policy}"
    );

    // Edit the models served, retries and the fallback.
    let (status, done) = call(
        &s,
        "PUT",
        "/console/api/providers/openai",
        &cookie,
        Some(json!({ "models": ["gpt-4o-mini"], "retries": 2, "fallback": "groq" })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    let (_, list) = call(&s, "GET", "/console/api/providers", &cookie, None).await?;
    assert_eq!(list["providers"][0]["models"], json!(["gpt-4o-mini"]));
    assert_eq!(list["providers"][0]["retries"], 2);
    assert_eq!(list["providers"][0]["fallback"], "groq");

    // A name already taken and a fallback that names no provider are refused, with the fix, and nothing changes.
    let before = s.policy()?;
    let (status, refused) = call(
        &s,
        "POST",
        "/console/api/providers",
        &cookie,
        Some(json!({ "preset": "groq", "key_env": "X", "models": ["m"] })),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        error(&refused).contains("already") && error(&refused).contains("another name"),
        "{refused}"
    );
    let (status, refused) = call(
        &s,
        "PUT",
        "/console/api/providers/openai",
        &cookie,
        Some(json!({ "models": ["gpt-4o-mini"], "fallback": "nobody" })),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(error(&refused).contains("enterplace check"), "{refused}");
    let (status, refused) = call(
        &s,
        "POST",
        "/console/api/providers",
        &cookie,
        Some(json!({ "preset": "openai", "name": "openai-2", "models": ["gpt-4o"] })),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        error(&refused).contains("environment variable"),
        "{refused}"
    );
    assert_eq!(s.policy()?, before);

    // A pasted key needs a place to seal it: the message says how to get one.
    let (status, refused) = call(
        &s,
        "POST",
        "/console/api/providers",
        &cookie,
        Some(json!({ "preset": "gemini", "key": "AIza-test-1234567890", "models": ["gemini-2.5-flash"] })),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        error(&refused).contains("ENTERPLACE_MASTER_KEY"),
        "{refused}"
    );

    // Remove: the fallback that named it goes first, or the check refuses it.
    let (status, refused) =
        call(&s, "DELETE", "/console/api/providers/groq", &cookie, None).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    call(
        &s,
        "PUT",
        "/console/api/providers/openai",
        &cookie,
        Some(json!({ "models": ["gpt-4o-mini"], "fallback": "" })),
    )
    .await?;
    let (status, done) = call(&s, "DELETE", "/console/api/providers/groq", &cookie, None).await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert!(!s.policy()?.contains("groq"));

    let audit = s.audit()?;
    for action in ["connect_provider", "change_provider", "remove_provider"] {
        assert!(
            audit.contains(&format!(r#""action":"{action}""#)),
            "{action}: {audit}"
        );
    }
    assert!(audit.contains("noa.bar"), "who made the change: {audit}");
    Ok(())
}

#[tokio::test]
async fn mcp_servers_are_added_edited_given_tool_access_and_removed() -> TestResult {
    let s = setup("mcp")?;
    let cookie = sign_in(&s, ADMIN_KEY).await?;
    let (status, list) = call(&s, "GET", "/console/api/mcp", &cookie, None).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["servers"], json!([]));

    let (status, done) = call(
        &s,
        "POST",
        "/console/api/mcp",
        &cookie,
        Some(json!({ "name": "github", "transport": "http", "url": "https://mcp.example.com/github", "auth": "header", "auth_header": "Authorization", "auth_env": "GITHUB_MCP_TOKEN" })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    let policy = s.policy()?;
    assert!(
        policy.contains("name: github") && policy.contains("GITHUB_MCP_TOKEN"),
        "{policy}"
    );

    // Per tool: the rule allows every tool of the server but one.
    let (status, done) = call(
        &s,
        "PUT",
        "/console/api/mcp/github/tools",
        &cookie,
        Some(json!({ "rules": [{ "rule": "everyone", "allow": ["*"], "deny": ["delete_repo"] }] })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    let (_, list) = call(&s, "GET", "/console/api/mcp", &cookie, None).await?;
    let server = &list["servers"][0];
    assert_eq!(server["auth"], "header");
    assert_eq!(server["access"][0]["allow"], json!(["*"]));
    assert_eq!(server["access"][0]["deny"], json!(["delete_repo"]));
    assert!(s.policy()?.contains("!github.delete_repo"));

    // Edit: another URL, and each person signs in themselves.
    let (status, done) = call(
        &s,
        "PUT",
        "/console/api/mcp/github",
        &cookie,
        Some(json!({ "transport": "http", "url": "https://mcp.example.com/gh", "auth": "oauth" })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    let policy = s.policy()?;
    assert!(
        policy.contains("https://mcp.example.com/gh")
            && policy.contains("user_auth: oauth")
            && !policy.contains("GITHUB_MCP_TOKEN"),
        "{policy}"
    );

    // Invalid: no URL, a dotted name, a secret where the variable's name goes.
    for body in [
        json!({ "name": "docs", "transport": "http", "url": "" }),
        json!({ "name": "git.hub", "url": "https://mcp.example.com" }),
        json!({ "name": "docs", "url": "https://mcp.example.com", "auth": "header", "auth_env": "Bearer abc" }),
    ] {
        let (status, refused) = call(&s, "POST", "/console/api/mcp", &cookie, Some(body)).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(error(&refused).contains("for example"), "{refused}");
    }

    // Remove: what the rules said of its tools goes with it.
    let (status, done) = call(&s, "DELETE", "/console/api/mcp/github", &cookie, None).await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    let policy = s.policy()?;
    assert!(!policy.contains("github"), "{policy}");
    let audit = s.audit()?;
    for action in [
        "add_mcp_server",
        "change_mcp_tools",
        "change_mcp_server",
        "remove_mcp_server",
    ] {
        assert!(
            audit.contains(&format!(r#""action":"{action}""#)),
            "{action}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn policy_basics_change_rules_limits_guardrails_aliases_and_mode() -> TestResult {
    let s = setup("basics")?;
    let cookie = sign_in(&s, ADMIN_KEY).await?;
    let (status, policy) = call(&s, "GET", "/console/api/policy", &cookie, None).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(policy["mode"], "enforce");
    assert_eq!(policy["rules"][0]["who"]["kind"], "any");
    assert_eq!(policy["guardrails"][0]["on"], false);

    // A rule for a team goes before the one for everyone, so it decides for that team.
    let (status, done) = call(
        &s,
        "POST",
        "/console/api/policy/rules",
        &cookie,
        Some(json!({ "name": "payments", "who": { "kind": "team", "value": "payments" }, "models": ["gpt-4o-mini"], "guardrails": ["no-secrets"] })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    let (_, policy) = call(&s, "GET", "/console/api/policy", &cookie, None).await?;
    assert_eq!(policy["rules"][0]["name"], "payments");
    assert_eq!(policy["rules"][1]["name"], "everyone");
    let (status, done) = call(
        &s,
        "PUT",
        "/console/api/policy/rules/payments",
        &cookie,
        Some(json!({ "who": { "kind": "team", "value": "payments" }, "models": ["gpt-4o"] })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    // A guardrail the policy does not define is refused by the check, naming it.
    let (status, refused) = call(
        &s,
        "PUT",
        "/console/api/policy/rules/payments",
        &cookie,
        Some(json!({ "who": { "kind": "team", "value": "payments" }, "models": ["gpt-4o"], "guardrails": ["nope"] })),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(error(&refused).contains("nope"), "{refused}");
    let (status, done) = call(
        &s,
        "DELETE",
        "/console/api/policy/rules/payments",
        &cookie,
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");

    // Limits: budgets per team and per person, tokens per key, a cap on one model.
    for body in [
        json!({ "scope": "team", "value": "payments", "usd": 500, "per": "month" }),
        json!({ "scope": "person", "value": "maya.cohen", "usd": "20", "per": "day" }),
        json!({ "scope": "key", "value": "1a2b3c4d", "tpm": "100000", "parallel": 4 }),
        json!({ "scope": "model", "value": "gpt-4o", "usd": 1000, "per": "month", "parallel": 20 }),
    ] {
        let (status, done) = call(
            &s,
            "POST",
            "/console/api/policy/limits",
            &cookie,
            Some(body),
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{done}");
    }
    let (_, policy) = call(&s, "GET", "/console/api/policy", &cookie, None).await?;
    let limits = policy["limits"].as_array().cloned().unwrap_or_default();
    assert_eq!(limits.len(), 4, "{policy}");
    assert_eq!(
        limits[2]["entry"],
        json!({ "key": "1a2b3c4d", "rate": { "tpm": 100000 }, "parallel": 4 })
    );
    assert_eq!(limits[3]["entry"]["model"], "gpt-4o");
    // Edit: names the limit as it was read.
    let was = limits[0]["entry"].clone();
    let (status, done) = call(
        &s,
        "PUT",
        "/console/api/policy/limits/0",
        &cookie,
        Some(json!({ "was": was, "scope": "team", "value": "payments", "usd": 800, "per": "month", "rpd": 5000 })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    let (_, policy) = call(&s, "GET", "/console/api/policy", &cookie, None).await?;
    assert_eq!(policy["limits"][0]["entry"]["budget"]["usd"], 800);
    assert_eq!(policy["limits"][0]["entry"]["rate"]["rpd"], 5000);
    // The same edit again names a limit that is no longer there as read: refused, nothing changed.
    let (status, refused) = call(
        &s,
        "PUT",
        "/console/api/policy/limits/0",
        &cookie,
        Some(
            json!({ "was": was, "scope": "team", "value": "payments", "usd": 900, "per": "month" }),
        ),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(error(&refused).contains("Reload"), "{refused}");
    for (body, says) in [
        (
            json!({ "scope": "team", "value": "payments", "usd": -1, "per": "month" }),
            "above 0",
        ),
        (
            json!({ "scope": "team", "value": "payments" }),
            "limits nothing",
        ),
        (
            json!({ "scope": "team", "value": "payments", "rpm": 1.5 }),
            "whole number",
        ),
    ] {
        let (status, refused) = call(
            &s,
            "POST",
            "/console/api/policy/limits",
            &cookie,
            Some(body),
        )
        .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(error(&refused).contains(says), "{says}: {refused}");
    }
    let was = policy["limits"][1]["entry"].clone();
    let (status, done) = call(
        &s,
        "DELETE",
        "/console/api/policy/limits/1",
        &cookie,
        Some(json!({ "was": was })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert!(!s.policy()?.contains("maya.cohen"));

    // Guardrail definitions: add one, change it, and the check refuses a type that does not exist.
    let (status, done) = call(
        &s,
        "POST",
        "/console/api/policy/guardrails",
        &cookie,
        Some(json!({ "name": "card-numbers", "type": "regex", "action": "mask", "on": ["request", "answer"], "patterns": "card: \\b\\d{16}\\b" })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    let (status, done) = call(
        &s,
        "PUT",
        "/console/api/policy/guardrails/card-numbers",
        &cookie,
        Some(json!({ "type": "regex", "action": "block", "patterns": "card: \\b\\d{16}\\b\niban: \\bIL\\d{21}\\b" })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    let (_, policy) = call(&s, "GET", "/console/api/policy", &cookie, None).await?;
    let guard = policy["guardrails"]
        .as_array()
        .and_then(|g| g.iter().find(|g| g["name"] == "card-numbers").cloned())
        .ok_or("no guardrail")?;
    assert_eq!(guard["entry"]["action"], "block");
    assert!(guard["entry"]["patterns"]["iban"].is_string(), "{guard}");
    let (status, refused) = call(
        &s,
        "POST",
        "/console/api/policy/guardrails",
        &cookie,
        Some(json!({ "name": "odd", "type": "telepathy" })),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(error(&refused).contains("enterplace check"), "{refused}");
    // A rule uses it; removing it takes it out of the rule too.
    call(
        &s,
        "POST",
        "/console/api/policy/rules",
        &cookie,
        Some(json!({ "name": "cards", "who": { "kind": "team", "value": "payments" }, "models": ["gpt-4o"], "guardrails": ["card-numbers"] })),
    )
    .await?;
    let (status, done) = call(
        &s,
        "DELETE",
        "/console/api/policy/guardrails/card-numbers",
        &cookie,
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert!(!s.policy()?.contains("card-numbers"), "{}", s.policy()?);

    // Guardrails on and off for every request.
    let (status, done) = call(
        &s,
        "PUT",
        "/console/api/policy/guardrails/no-secrets/on",
        &cookie,
        Some(json!({ "on": true })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert!(
        s.policy()?.contains("default_guardrails: [no-secrets]"),
        "{}",
        s.policy()?
    );
    call(
        &s,
        "PUT",
        "/console/api/policy/guardrails/no-secrets/on",
        &cookie,
        Some(json!({ "on": false })),
    )
    .await?;
    assert!(!s.policy()?.contains("default_guardrails"));

    // Routing: an alias with a fallback.
    let (status, done) = call(
        &s,
        "POST",
        "/console/api/policy/aliases",
        &cookie,
        Some(json!({ "name": "smart", "deployments": ["openai/gpt-4o"], "fallbacks": ["gpt-4o-mini"] })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    let (status, done) = call(
        &s,
        "PUT",
        "/console/api/policy/aliases/smart",
        &cookie,
        Some(json!({ "deployments": "openai/gpt-4o, openai/gpt-4o-mini" })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    let (status, refused) = call(
        &s,
        "POST",
        "/console/api/policy/aliases",
        &cookie,
        Some(json!({ "name": "broken", "deployments": ["gpt-4o"] })),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(error(&refused).contains("provider/model"), "{refused}");
    let (status, done) = call(
        &s,
        "DELETE",
        "/console/api/policy/aliases/smart",
        &cookie,
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");

    // Mode.
    let (status, done) = call(
        &s,
        "PUT",
        "/console/api/policy/mode",
        &cookie,
        Some(json!({ "mode": "observe" })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert!(s.policy()?.contains("mode: observe"));
    let (status, refused) = call(
        &s,
        "PUT",
        "/console/api/policy/mode",
        &cookie,
        Some(json!({ "mode": "loud" })),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(error(&refused).contains("enforce"), "{refused}");
    Ok(())
}

#[tokio::test]
async fn a_role_without_edit_policy_and_a_foreign_form_change_nothing() -> TestResult {
    let s = setup("roles")?;
    let viewer = sign_in(&s, VIEWER_KEY).await?;
    let (status, me) = call(&s, "GET", "/console/api/me", &viewer, None).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(me["edit_policy"], false);
    let (status, _) = call(&s, "GET", "/console/api/providers", &viewer, None).await?;
    assert_eq!(status, StatusCode::OK, "reading is allowed");
    let changes = [
        (
            "POST",
            "/console/api/providers",
            json!({ "preset": "anthropic", "key_env": "K", "models": ["m"] }),
        ),
        ("DELETE", "/console/api/providers/openai", Value::Null),
        (
            "POST",
            "/console/api/mcp",
            json!({ "name": "docs", "url": "https://mcp.example.com" }),
        ),
        (
            "PUT",
            "/console/api/policy/mode",
            json!({ "mode": "observe" }),
        ),
        (
            "POST",
            "/console/api/policy/limits",
            json!({ "scope": "team", "value": "x", "usd": 1, "per": "day" }),
        ),
        (
            "PUT",
            "/console/api/policy/guardrails/no-secrets/on",
            json!({ "on": true }),
        ),
    ];
    for (method, path, body) in changes {
        let body = (!body.is_null()).then_some(body);
        let (status, refused) = call(&s, method, path, &viewer, body).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
        assert!(error(&refused).contains("edit_policy"), "{path}: {refused}");
    }
    assert_eq!(s.policy()?, POLICY);
    assert!(s.audit()?.contains(r#""code":"read_only""#));

    // A change sent from another site is refused before anything is read.
    let admin = sign_in(&s, ADMIN_KEY).await?;
    let request = Request::put("/console/api/policy/mode")
        .header(header::HOST, HOST)
        .header(header::ORIGIN, "https://evil.example")
        .header(header::COOKIE, &admin)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"mode":"observe"}"#))?;
    let response = s.app.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(s.policy()?, POLICY);
    Ok(())
}

#[tokio::test]
async fn a_commented_policy_keeps_its_comments_through_add_edit_and_remove() -> TestResult {
    let s = setup("comments")?;
    let commented = POLICY
        .replace(
            "version: 1\n",
            "# Owned by the platform team.\nversion: 1\n",
        )
        .replace(
            "  - name: openai\n",
            "  # The main account.\n  - name: openai\n",
        )
        .replace(
            "    models: [\"*\"]\n",
            "    models: [\"*\"] # everyone, for now\n",
        )
        + "# Last line.\n";
    std::fs::write(s.dir.join("enterplace.policy.yaml"), &commented)?;
    let cookie = sign_in(&s, ADMIN_KEY).await?;
    let comments = [
        "# Owned by the platform team.",
        "  # The main account.\n  - name: openai",
        "# everyone, for now",
        "# Last line.",
    ];
    let steps = [
        (
            "POST",
            "/console/api/providers",
            Some(
                json!({ "preset": "groq", "key_env": "GROQ_API_KEY", "models": ["llama-3.3-70b"] }),
            ),
        ),
        (
            "PUT",
            "/console/api/providers/openai",
            Some(json!({ "models": ["gpt-4o-mini"] })),
        ),
        ("DELETE", "/console/api/providers/groq", None),
    ];
    for (method, path, body) in steps {
        let (status, done) = call(&s, method, path, &cookie, body).await?;
        assert_eq!(status, StatusCode::OK, "{path}: {done}");
        let policy = s.policy()?;
        for comment in comments {
            assert!(
                policy.contains(comment),
                "{method} {path} lost {comment}:\n{policy}"
            );
        }
    }
    Ok(())
}

async fn raw(
    s: &Setup,
    method: &str,
    path: &str,
    cookie: &str,
    form: &str,
) -> Result<(StatusCode, axum::http::HeaderMap), Box<dyn std::error::Error>> {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, HOST)
        .header(header::ORIGIN, format!("http://{HOST}"))
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(form.to_string()))?;
    let response = s.app.clone().oneshot(request).await?;
    Ok((response.status(), response.headers().clone()))
}

fn location(headers: &axum::http::HeaderMap) -> String {
    headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

#[tokio::test]
async fn signing_in_returns_to_the_page_the_person_was_going_to() -> TestResult {
    let s = setup("next")?;
    // A page sends a person who is not signed in to sign in, naming itself.
    let (_, headers) = raw(&s, "GET", "/console/app/", "", "").await?;
    assert_eq!(
        location(&headers),
        "/console/sign-in?next=%2Fconsole%2Fapp%2F"
    );
    let (_, headers) = raw(&s, "GET", "/console/models?add=1", "", "").await?;
    assert_eq!(
        location(&headers),
        "/console/sign-in?next=%2Fconsole%2Fmodels%3Fadd%3D1"
    );
    // The sign-in page keeps it; the app's # route is added by the page's script, as here.
    let (status, headers) = raw(
        &s,
        "GET",
        "/console/sign-in?next=%2Fconsole%2Fapp%2F",
        "",
        "",
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let kept = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.starts_with("enterplace_next=%2Fconsole%2Fapp%2F;"));
    assert!(kept, "{headers:?}");
    let (status, headers) = raw(
        &s,
        "POST",
        "/console/sign-in",
        "enterplace_next=%2Fconsole%2Fapp%2F%23%2Fpolicy",
        &format!("key={ADMIN_KEY}"),
    )
    .await?;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location(&headers), "/console/app/#/policy");
    // Anything that is not a console page on this origin is ignored: Start here, as before.
    for bad in [
        "https%3A%2F%2Fevil.example%2F",
        "%2F%2Fevil.example%2Fconsole%2F",
        "%2Fconsole%2F..%2F..%2Fadmin",
        "%2Fconsole%2Fsign-out",
        "%2Fconsole%5C%5Cevil.example",
    ] {
        let (_, headers) = raw(
            &s,
            "POST",
            "/console/sign-in",
            &format!("enterplace_next={bad}"),
            &format!("key={ADMIN_KEY}"),
        )
        .await?;
        assert_eq!(location(&headers), "/console/start", "{bad}");
    }
    Ok(())
}

/// The policy kept as versions in a store, in memory, as `store.policy_from: store` keeps it in Postgres.
#[derive(Debug, Default)]
struct Versions(std::sync::Mutex<Vec<enterplace_core::store::PolicyVersion>>);

impl enterplace_core::store::Credentials for Versions {}

impl enterplace_core::store::Store for Versions {
    fn keys_text(&self) -> String {
        String::new()
    }
    fn kills(&self) -> Arc<Vec<enterplace_core::kill::Kill>> {
        Arc::default()
    }
    fn add_key(&self, _: &enterplace_core::config::KeyEntry) -> Result<bool, String> {
        Ok(false)
    }
    fn revoke(&self, _: &str) -> Result<Option<enterplace_core::keyfile::Revoked>, String> {
        Ok(None)
    }
    fn set_kill(
        &self,
        _: &enterplace_core::kill::Kill,
    ) -> Result<Option<enterplace_core::kill::Kill>, String> {
        Ok(None)
    }
    fn clear_kill(&self, _: &str, _: &str) -> Result<Option<enterplace_core::kill::Kill>, String> {
        Ok(None)
    }
    fn reserve(
        &self,
        _: enterplace_core::store::Bucket,
        _: f64,
        _: f64,
    ) -> enterplace_core::store::Pending<enterplace_core::store::Reserve> {
        Box::pin(async { Ok(enterplace_core::store::Reserve::Done) })
    }
    fn settle(&self, _: Vec<enterplace_core::store::Change>) {}
    fn lease(
        &self,
        _: String,
        _: u64,
        _: u64,
        _: u64,
    ) -> enterplace_core::store::Pending<enterplace_core::store::Lease> {
        Box::pin(async { Ok(enterplace_core::store::Lease::Over { wait: 1 }) })
    }
    fn give_back(&self, _: i64, _: i64) {}
    fn cooling(&self) -> Arc<std::collections::HashMap<String, std::time::Instant>> {
        Arc::default()
    }
    fn cooled(&self, _: &str, _: std::time::Duration) {}
    fn warmed(&self, _: &str) {}
    fn open_session(
        &self,
        _: String,
        _: String,
        _: std::time::Duration,
    ) -> enterplace_core::store::Pending<()> {
        Box::pin(async { Ok(()) })
    }
    fn session(&self, _: String) -> enterplace_core::store::Pending<Option<String>> {
        Box::pin(async { Ok(None) })
    }
    fn end_session(&self, _: String) {}
    fn policy_versions(&self) -> Result<Arc<Vec<enterplace_core::store::PolicyVersion>>, String> {
        Ok(Arc::new(self.0.lock().map_err(|e| e.to_string())?.clone()))
    }
    fn live_policy(&self) -> Option<enterplace_core::store::PolicyVersion> {
        self.0
            .lock()
            .ok()?
            .iter()
            .rev()
            .find(|v| v.state == enterplace_core::store::LIVE)
            .cloned()
    }
    fn add_policy_version(
        &self,
        new: &enterplace_core::store::NewVersion,
    ) -> Result<enterplace_core::store::PolicyVersion, enterplace_core::store::VersionError> {
        let mut versions = self
            .0
            .lock()
            .map_err(|e| enterplace_core::store::VersionError::Store(e.to_string()))?;
        let live = versions
            .iter()
            .rev()
            .find(|v| v.state == enterplace_core::store::LIVE)
            .map(|v| v.id);
        if new.base != live {
            return Err(enterplace_core::store::VersionError::Conflict(
                "another version went live first. Reload and make the change again.".into(),
            ));
        }
        if !new.pending {
            for v in versions
                .iter_mut()
                .filter(|v| v.state == enterplace_core::store::LIVE)
            {
                v.state = enterplace_core::store::RETIRED.into();
            }
        }
        let version = enterplace_core::store::PolicyVersion {
            id: versions.len() as i64 + 1,
            text: new.text.clone(),
            sha256: sha256_hex(new.text.as_bytes()),
            base: new.base,
            note: new.note.clone(),
            created_by: new.by.clone(),
            created_at: String::new(),
            state: if new.pending {
                enterplace_core::store::PENDING
            } else {
                enterplace_core::store::LIVE
            }
            .into(),
            decided_by: None,
            decided_at: None,
        };
        versions.push(version.clone());
        Ok(version)
    }
}

#[tokio::test]
async fn in_store_mode_each_change_is_a_new_live_version_and_the_file_is_untouched() -> TestResult {
    let s = setup("store")?;
    let versions = Versions::default();
    versions
        .add_policy_version(&enterplace_core::store::NewVersion {
            text: POLICY.into(),
            base: None,
            note: "imported".into(),
            by: "test".into(),
            pending: false,
        })
        .map_err(|e| format!("{e:?}"))?;
    let store: Arc<dyn enterplace_core::store::Store> = Arc::new(versions);
    enterplace_core::store::attach_policy(&s.dir.join("enterplace.policy.yaml"), &store);
    let cookie = sign_in(&s, ADMIN_KEY).await?;
    let (_, me) = call(&s, "GET", "/console/api/me", &cookie, None).await?;
    assert_eq!(me["source"], "store");

    let (status, done) = call(
        &s,
        "POST",
        "/console/api/policy/limits",
        &cookie,
        Some(json!({ "scope": "team", "value": "payments", "usd": 500, "per": "month" })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert!(
        done["message"].as_str().unwrap_or("").contains("version 2"),
        "{done}"
    );
    let live = store.live_policy().ok_or("no live version")?;
    assert_eq!((live.id, live.created_by.as_str()), (2, "noa.bar"));
    assert!(
        live.text.contains("payments") && live.text.contains("usd: 500"),
        "{}",
        live.text
    );
    let (_, policy) = call(&s, "GET", "/console/api/policy", &cookie, None).await?;
    assert_eq!(policy["limits"][0]["entry"]["budget"]["usd"], 500);
    // The file is only the store's starting point: it is not written.
    assert_eq!(s.policy()?, POLICY);
    // A change the check refuses makes no version.
    let (status, refused) = call(
        &s,
        "PUT",
        "/console/api/providers/openai",
        &cookie,
        Some(json!({ "models": ["gpt-4o-mini"], "fallback": "nobody" })),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(error(&refused).contains("enterplace check"), "{refused}");
    assert_eq!(store.policy_versions()?.len(), 2);
    assert!(s.audit()?.contains(r#""action":"add_limit""#));
    Ok(())
}

#[tokio::test]
async fn people_edits_a_key_issues_a_person_token_and_refuses_what_a_role_may_not() -> TestResult {
    let s = setup("people")?;
    let admin = sign_in(&s, ADMIN_KEY).await?;
    let viewer_sha = sha256_hex(VIEWER_KEY.as_bytes());
    // Edit: what the key may do changes, the key does not.
    let (status, done) = call(
        &s,
        "POST",
        "/console/api/people/edit",
        &admin,
        Some(json!({ "sha256": viewer_sha, "tpm": "5000", "models": "gpt-4o-mini", "budget": "", "expires": "", "admin": true })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    let keys = std::fs::read_to_string(s.dir.join("enterplace.keys.yaml"))?;
    assert!(
        keys.contains("tpm: 5000") && keys.contains(&viewer_sha),
        "{keys}"
    );
    let (_, people) = call(&s, "GET", "/console/api/people", &admin, None).await?;
    let row = people["entries"]
        .as_array()
        .and_then(|e| e.iter().find(|e| e["sha256"] == viewer_sha).cloned())
        .ok_or("no row")?;
    assert_eq!(row["fields"]["tpm"], "5000");
    assert!(
        row["status"]["notes"]
            .to_string()
            .contains("5,000 tokens a minute"),
        "{row}"
    );
    // The last admin key keeps its admin.
    std::fs::write(
        s.dir.join("enterplace.keys.yaml"),
        format!(
            "keys:\n  - name: noa.bar\n    team: platform\n    sha256: {}\n    admin: true\n",
            sha256_hex(ADMIN_KEY.as_bytes())
        ),
    )?;
    let (status, refused) = call(
        &s,
        "POST",
        "/console/api/people/edit",
        &admin,
        Some(json!({ "sha256": sha256_hex(ADMIN_KEY.as_bytes()), "admin": false })),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(error(&refused).contains("only admin key"), "{refused}");
    // A person token: named for the person, reaching no model on its own, shown once.
    let (status, made) = call(
        &s,
        "POST",
        "/console/api/people/issue",
        &admin,
        Some(json!({ "name": "maya.cohen", "team": "payments", "person_token": true })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{made}");
    assert!(
        made["key"]
            .as_str()
            .unwrap_or("")
            .starts_with("enterplace_u_"),
        "{made}"
    );
    assert!(s.audit()?.contains(r#""person_token":true"#));
    // A key that is not in the file is named as gone, with what to do.
    let (status, refused) = call(
        &s,
        "POST",
        "/console/api/people/rotate",
        &admin,
        Some(json!({ "sha256": "00" })),
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(error(&refused).contains("Reload"), "{refused}");
    Ok(())
}

#[tokio::test]
async fn a_viewer_sees_the_keys_and_changes_none() -> TestResult {
    let s = setup("people-viewer")?;
    let viewer = sign_in(&s, VIEWER_KEY).await?;
    let (status, people) = call(&s, "GET", "/console/api/people", &viewer, None).await?;
    assert_eq!(status, StatusCode::OK, "{people}");
    assert_eq!(
        (
            people["may"]["issue"].as_bool(),
            people["may"]["revoke"].as_bool()
        ),
        (Some(false), Some(false))
    );
    let before = std::fs::read_to_string(s.dir.join("enterplace.keys.yaml"))?;
    let sha = sha256_hex(ADMIN_KEY.as_bytes());
    for (path, body) in [
        (
            "/console/api/people/issue",
            json!({ "name": "x", "team": "y" }),
        ),
        (
            "/console/api/people/revoke",
            json!({ "sha256": sha, "confirm": "noa.bar" }),
        ),
        (
            "/console/api/people/edit",
            json!({ "sha256": sha, "tpm": "1" }),
        ),
        ("/console/api/people/rotate", json!({ "sha256": sha })),
    ] {
        let (status, refused) = call(&s, "POST", path, &viewer, Some(body)).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {refused}");
        assert!(
            error(&refused).contains("ask an admin") || error(&refused).contains("Ask an admin"),
            "{path}: {refused}"
        );
    }
    assert_eq!(
        std::fs::read_to_string(s.dir.join("enterplace.keys.yaml"))?,
        before
    );
    Ok(())
}
