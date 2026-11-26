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

    // A variable that is not set where Enterplace runs is refused: every gateway would refuse the policy with it and
    // keep the one it has, while the console said it was in force.
    let before = s.policy()?;
    let (status, refused) = call(
        &s,
        "POST",
        "/console/api/providers",
        &cookie,
        Some(json!({ "preset": "groq", "key_env": "ENTERPLACE_TEST_UNSET_GROQ_KEY", "models": "llama-3.3-70b" })),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert!(
        error(&refused).contains("ENTERPLACE_TEST_UNSET_GROQ_KEY is not set")
            && error(&refused).contains("Paste the key"),
        "{refused}"
    );
    assert_eq!(s.policy()?, before);
    // Add, from the catalog, with the key in an environment variable. Cargo sets CARGO_MANIFEST_DIR for the test,
    // so it stands for a variable that holds a key here.
    let (status, done) = call(
        &s,
        "POST",
        "/console/api/providers",
        &cookie,
        Some(json!({ "preset": "groq", "key_env": "CARGO_MANIFEST_DIR", "models": "llama-3.3-70b, llama-3.1-8b" })),
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
            && policy.contains("key_env: CARGO_MANIFEST_DIR"),
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
    // Copy for your agent on Limits: per team and person, with tokens per day, the check and the docs page.
    let limits = policy["limit_agent"].as_str().unwrap_or("");
    for part in [
        "limits:",
        "team: payments",
        "tpd:",
        "person:",
        "enterplace check",
        "budgets-and-rate-limits.md",
    ] {
        assert!(limits.contains(part), "{part}: {limits}");
    }
    // Copy for your agent on Guardrails: the lines, the file they go in, the check, and the docs page.
    let agent = policy["guard_agent"].as_str().unwrap_or("");
    for part in [
        "guardrails:",
        "shadow_until:",
        "default_guardrails:",
        &format!(
            "enterplace check {}",
            s.dir.join("enterplace.policy.yaml").display()
        ),
        "https://docs.enterplace.dev/governance/guardrails.md",
    ] {
        assert!(agent.contains(part), "{part}: {agent}");
    }
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

    // A team no key names and no request came from is a typo until the form says it is new.
    let (status, refused) = call(
        &s,
        "POST",
        "/console/api/policy/limits",
        &cookie,
        Some(json!({ "scope": "team", "value": "payments", "usd": 500, "per": "month" })),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert!(
        error(&refused).contains("There is no team payments")
            && error(&refused).contains("Create team payments"),
        "{refused}"
    );
    // Limits: budgets per team and per person, tokens per key, a cap on one model.
    for body in [
        json!({ "scope": "team", "value": "payments", "usd": 500, "per": "month", "create": true }),
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
    // Try first: until the date it records what it would do and blocks nothing; an edit without it ends the trial,
    // and a date the check cannot read is refused.
    let (status, done) = call(
        &s,
        "PUT",
        "/console/api/policy/guardrails/card-numbers",
        &cookie,
        Some(json!({ "type": "regex", "action": "block", "patterns": "card: \\b\\d{16}\\b", "shadow_until": "2026-12-31" })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert!(
        s.policy()?.contains("shadow_until: 2026-12-31"),
        "{}",
        s.policy()?
    );
    let (status, refused) = call(
        &s,
        "PUT",
        "/console/api/policy/guardrails/card-numbers",
        &cookie,
        Some(json!({ "type": "regex", "action": "block", "patterns": "card: \\b\\d{16}\\b", "shadow_until": "next week" })),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert!(error(&refused).contains("shadow_until"), "{refused}");
    let (status, done) = call(
        &s,
        "PUT",
        "/console/api/policy/guardrails/card-numbers",
        &cookie,
        Some(json!({ "type": "regex", "action": "block", "patterns": "card: \\b\\d{16}\\b" })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert!(!s.policy()?.contains("shadow_until"), "{}", s.policy()?);
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

    // A new guardrail the form asks to run on every request is on at once, not left for a rule to name.
    let (status, done) = call(
        &s,
        "POST",
        "/console/api/policy/guardrails",
        &cookie,
        Some(json!({ "name": "no-cards", "type": "pii", "action": "warn", "on": ["request"], "every": true })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert!(
        s.policy()?.contains("default_guardrails: [no-cards]"),
        "{}",
        s.policy()?
    );
    // Tested on a sample: it names the kind it found and masks it, and nothing is sent anywhere.
    let (status, tested) = call(
        &s,
        "POST",
        "/console/api/policy/guardrails/no-secrets/test",
        &cookie,
        Some(json!({ "text": concat!("deploy with AKIA", "IOSFODNN7EXAMPLE") })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{tested}");
    assert!(
        tested["hits"] == 1
            && tested["message"]
                .as_str()
                .unwrap_or("")
                .contains("aws_access_key")
            && !tested.to_string().contains("IOSFODNN7"),
        "{tested}"
    );
    let (status, tested) = call(
        &s,
        "POST",
        "/console/api/policy/guardrails/no-secrets/test",
        &cookie,
        Some(json!({ "text": "nothing to see" })),
    )
    .await?;
    assert!(status == StatusCode::OK && tested["hits"] == 0, "{tested}");

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
                json!({ "preset": "groq", "key_env": "CARGO_MANIFEST_DIR", "models": ["llama-3.3-70b"] }),
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
    let (_, headers) = raw(&s, "GET", "/console/app/?q=pay", "", "").await?;
    assert_eq!(
        location(&headers),
        "/console/sign-in?next=%2Fconsole%2Fapp%2F%3Fq%3Dpay"
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
        Some(json!({ "scope": "team", "value": "payments", "usd": 500, "per": "month", "create": true })),
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
    // The Audit log's Changes say what changed in words, never the action's code.
    let (_, changes) = call(
        &s,
        "GET",
        "/console/api/audit?verdict=changes",
        &cookie,
        None,
    )
    .await?;
    let rows = changes["rows"].as_array().cloned().unwrap_or_default();
    assert!(
        rows.iter().any(|r| r["title"]
            .as_str()
            .is_some_and(|t| t.contains("changed the policy: Add a limit"))),
        "{changes}"
    );
    assert!(
        !changes.to_string().contains("add_limit\""),
        "an action code in the list: {changes}"
    );
    Ok(())
}

/// Prices: the old address opens the app's dialog; in store mode a model is added and a price changed as new
/// versions, a stale page, a bad price and a role without edit_policy are refused, and each is recorded.
#[tokio::test]
async fn prices_add_a_model_and_change_a_price_as_new_versions() -> TestResult {
    let s = setup("prices")?;
    let (status, headers) = raw(&s, "GET", "/console/models?add=1&provider=openai", "", "").await?;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        location(&headers),
        "/console/app/#/prices?add=1&provider=openai"
    );
    let (_, headers) = raw(&s, "GET", "/console/models?price=gpt-4o", "", "").await?;
    assert_eq!(location(&headers), "/console/app/#/prices?price=gpt-4o");
    let (_, headers) = raw(&s, "GET", "/console/models", "", "").await?;
    assert_eq!(location(&headers), "/console/app/#/prices");

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
    let (status, list) = call(&s, "GET", "/console/api/prices", &cookie, None).await?;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(
        (list["editable"].clone(), list["base"].clone()),
        (json!(true), json!(1))
    );
    assert!(list["file"].is_null(), "{list}");
    assert!(
        list["note"].as_str().unwrap_or("").contains("A form edit"),
        "{list}"
    );
    let row = &list["models"][0];
    assert_eq!(row["model"], "gpt-4o-mini");
    assert_eq!(row["provider"], "openai (openai)");
    assert_eq!(row["source"], "built in");
    assert_eq!(row["aliases"], "none");

    // Add a model with its price and an alias: version 2.
    let (status, done) = call(
        &s,
        "POST",
        "/console/api/prices/add",
        &cookie,
        Some(json!({ "provider": "openai", "model": "m9", "input": "1.5", "output": "6", "aliases": "fast", "base": 1 })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert!(error(&done).is_empty() && done["version"] == 2, "{done}");
    let live = store.live_policy().ok_or("no live version")?;
    assert!(
        live.text.contains("m9") && live.text.contains("fast") && live.text.contains("input: 1.5"),
        "{}",
        live.text
    );
    let (_, list) = call(&s, "GET", "/console/api/prices", &cookie, None).await?;
    let m9 = list["models"]
        .as_array()
        .and_then(|m| m.iter().find(|m| m["model"] == "m9").cloned())
        .ok_or("m9 is not listed")?;
    assert_eq!(
        (
            m9["price"].clone(),
            m9["source"].clone(),
            m9["aliases"].clone(),
            m9["input"].clone()
        ),
        (
            json!("$1.50 / $6.00"),
            json!("policy"),
            json!("fast"),
            json!("1.5")
        )
    );

    // A page read before version 2 is refused, not overwritten.
    let (status, stale) = call(
        &s,
        "POST",
        "/console/api/prices/price",
        &cookie,
        Some(json!({ "model": "gpt-4o", "input": "2", "output": "8", "base": "1" })),
    )
    .await?;
    assert_eq!(status, StatusCode::CONFLICT, "{stale}");
    let (status, done) = call(
        &s,
        "POST",
        "/console/api/prices/price",
        &cookie,
        Some(json!({ "model": "gpt-4o", "input": "2", "output": "8", "base": 2 })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert!(error(&done).is_empty() && done["version"] == 3, "{done}");

    // A price that is not a number, an alias a name may not hold, a provider the policy lacks.
    for (path, body, words) in [
        (
            "price",
            json!({ "model": "gpt-4o", "input": "-1", "output": "8", "base": 3 }),
            "0 or more",
        ),
        (
            "add",
            json!({ "provider": "openai", "model": "m10", "input": "1", "output": "1", "aliases": "a b", "base": 3 }),
            "The alias \"a b\"",
        ),
        (
            "add",
            json!({ "provider": "nobody", "model": "m10", "input": "1", "output": "1", "base": 3 }),
            "There is no provider \"nobody\"",
        ),
    ] {
        let (status, refused) = call(
            &s,
            "POST",
            &format!("/console/api/prices/{path}"),
            &cookie,
            Some(body),
        )
        .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
        assert!(error(&refused).contains(words), "{refused}");
    }
    assert_eq!(store.policy_versions()?.len(), 3);

    // A role without edit_policy is refused, and the refusal is recorded.
    let viewer = sign_in(&s, VIEWER_KEY).await?;
    let (_, list) = call(&s, "GET", "/console/api/prices", &viewer, None).await?;
    assert_eq!(list["editable"], false);
    let (status, refused) = call(
        &s,
        "POST",
        "/console/api/prices/price",
        &viewer,
        Some(json!({ "model": "gpt-4o", "input": "1", "output": "1", "base": 3 })),
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(error(&refused).contains("read only"), "{refused}");
    let audit = s.audit()?;
    assert!(
        audit.contains(r#""action":"add_model""#)
            && audit.contains(r#""action":"price_model""#)
            && audit.contains("invalid_request"),
        "{audit}"
    );
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
async fn people_labels_each_key_and_counts_requests_per_key_not_per_name() -> TestResult {
    let s = setup("people-kinds")?;
    let admin = sign_in(&s, ADMIN_KEY).await?;
    // The admin's own person token, as first sign-in makes it: the same name as their admin key.
    let (status, made) = call(
        &s,
        "POST",
        "/console/api/people/issue",
        &admin,
        Some(json!({ "name": "noa.bar", "team": "platform", "person_token": true })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{made}");
    let token = &sha256_hex(made["key"].as_str().ok_or("no key")?.as_bytes())[..8];
    // The keys file keeps what it is, so the label does not depend on the audit log.
    let keys = std::fs::read_to_string(s.dir.join("enterplace.keys.yaml"))?;
    assert!(keys.contains("person-token"), "{keys}");
    let admin_key = &sha256_hex(ADMIN_KEY.as_bytes())[..8];
    // A workload key, and a person token made before the keys file kept its kind: only its issue record says so.
    let old_token = sha256_hex(b"enterplace_u_old");
    let mut keys = std::fs::read_to_string(s.dir.join("enterplace.keys.yaml"))?;
    keys.push_str(&format!(
        "  - name: nightly.etl\n    team: data\n    sha256: {}\n    metadata: {{ kind: workload }}\n  - name: dan.levi\n    team: data\n    sha256: {old_token}\n",
        sha256_hex(b"enterplace_workload")
    ));
    std::fs::write(s.dir.join("enterplace.keys.yaml"), keys)?;
    let mut log = s.audit()?;
    let line = |key: &str, time: &str| {
        format!(
            "{}\n",
            json!({ "time": time, "person": "noa.bar", "team": "platform", "key": key, "verdict": "allow" })
        )
    };
    for _ in 0..3 {
        log.push_str(&line(admin_key, "2026-11-18T10:00:00Z"));
    }
    log.push_str(&line(token, "2026-11-18T11:00:00Z"));
    log.push_str(&format!(
        "{}\n",
        json!({ "event": "admin", "time": "2026-11-01T09:00:00Z", "person": "noa.bar", "action": "issue_key", "verdict": "allow", "target": { "name": "dan.levi", "team": "data", "sha256_prefix": &old_token[..8], "admin": false, "person_token": true } })
    ));
    std::fs::write(s.dir.join("enterplace-audit.jsonl"), log)?;
    let (status, people) = call(&s, "GET", "/console/api/people", &admin, None).await?;
    assert_eq!(status, StatusCode::OK, "{people}");
    let row = |hash: &str| {
        people["entries"]
            .as_array()
            .and_then(|e| e.iter().find(|e| e["hash"] == hash).cloned())
            .ok_or(format!("no row {hash}: {people}"))
    };
    let (by_admin, by_token) = (row(admin_key)?, row(token)?);
    assert_eq!(
        (&by_admin["name"], &by_admin["kind"], &by_admin["requests"]),
        (&json!("noa.bar"), &json!("admin key"), &json!(3))
    );
    assert_eq!(
        (&by_token["name"], &by_token["kind"], &by_token["requests"]),
        (&json!("noa.bar"), &json!("person token"), &json!(1))
    );
    assert_eq!(
        row(&sha256_hex(b"enterplace_workload")[..8])?["kind"],
        "workload key"
    );
    assert_eq!(row(&old_token[..8])?["kind"], "person token");
    assert_eq!(
        row(&sha256_hex(VIEWER_KEY.as_bytes())[..8])?["kind"],
        "admin key"
    );
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

/// The policy of an install with Claude Code and Codex on subscription logins, one taking unnamed requests.
const PASSTHROUGH_POLICY: &str = "\
version: 1
providers:
  - name: openai
    kind: openai
    url: https://api.openai.com
    key_env: OPENAI_API_KEY
    models: [gpt-4o-mini]
  - name: claude-subscriptions
    kind: anthropic
    url: https://api.anthropic.com
    auth: passthrough
    identity: optional
    models: [\"claude-*\"]
  - name: chatgpt-subscriptions
    kind: openai
    url: https://chatgpt.com/backend-api/codex
    auth: passthrough
    models: [gpt-5-codex]
rules:
  - name: everyone
    principals: { any: true }
    models: [\"*\"]
roles:
  - name: viewer
    permissions: [see_keys, see_records, see_spend]
";

#[tokio::test]
async fn named_requests_are_switched_for_every_passthrough_provider_and_audited() -> TestResult {
    let s = setup("names")?;
    std::fs::write(s.dir.join("enterplace.policy.yaml"), PASSTHROUGH_POLICY)?;
    let cookie = sign_in(&s, ADMIN_KEY).await?;

    // One provider takes unnamed requests, so the install does.
    let (status, me) = call(&s, "GET", "/console/api/me", &cookie, None).await?;
    assert_eq!(status, StatusCode::OK, "{me}");
    assert_eq!(me["names"]["passthrough"], true, "{me}");
    assert_eq!(me["names"]["required"], false, "{me}");

    let path = "/console/api/policy/identity";
    let (status, done) = call(&s, "PUT", path, &cookie, Some(json!({ "required": true }))).await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    let policy = s.policy()?;
    assert_eq!(policy.matches("identity: required").count(), 2, "{policy}");
    assert!(!policy.contains("identity: optional"), "{policy}");
    let audit = s.audit()?;
    let record = audit
        .lines()
        .rev()
        .find(|l| l.contains(r#""action":"set_identity""#))
        .ok_or("no set_identity record")?;
    assert!(record.contains(r#""person":"noa.bar""#), "{record}");
    let (_, me) = call(&s, "GET", "/console/api/me", &cookie, None).await?;
    assert_eq!(me["names"]["required"], true, "{me}");

    let (status, done) = call(&s, "PUT", path, &cookie, Some(json!({ "required": false }))).await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    let policy = s.policy()?;
    assert_eq!(policy.matches("identity: optional").count(), 2, "{policy}");
    let (_, me) = call(&s, "GET", "/console/api/me", &cookie, None).await?;
    assert_eq!(me["names"]["required"], false, "{me}");

    // Not a boolean: nothing changes, and the refusal names the body to send.
    let (status, refused) =
        call(&s, "PUT", path, &cookie, Some(json!({ "required": "yes" }))).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert!(
        error(&refused).contains("{\"required\": true}"),
        "{refused}"
    );
    assert_eq!(s.policy()?, policy);

    // A role without edit_policy changes nothing, and the refusal is recorded.
    let viewer = sign_in(&s, VIEWER_KEY).await?;
    let (status, refused) =
        call(&s, "PUT", path, &viewer, Some(json!({ "required": true }))).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    assert!(error(&refused).contains("edit_policy"), "{refused}");
    assert_eq!(s.policy()?, policy);
    assert!(s.audit()?.contains(r#""code":"read_only""#));
    Ok(())
}

#[tokio::test]
async fn named_requests_need_no_switch_without_a_passthrough_provider() -> TestResult {
    let s = setup("names-none")?;
    let cookie = sign_in(&s, ADMIN_KEY).await?;
    let (_, me) = call(&s, "GET", "/console/api/me", &cookie, None).await?;
    assert_eq!(me["names"]["passthrough"], false, "{me}");
    assert_eq!(me["names"]["required"], true, "{me}");
    let (status, refused) = call(
        &s,
        "PUT",
        "/console/api/policy/identity",
        &cookie,
        Some(json!({ "required": false })),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert!(
        error(&refused).contains("No provider takes subscription logins"),
        "{refused}"
    );
    assert_eq!(s.policy()?, POLICY);
    Ok(())
}

/// A store in memory that keeps keys, kill switches and sessions, as Postgres or Cloudflare keeps them for every
/// gateway pointed at it.
#[derive(Debug, Default)]
struct Shared {
    keys: String,
    kills: std::sync::Mutex<Vec<enterplace_core::kill::Kill>>,
    sessions: std::sync::Mutex<std::collections::HashMap<String, String>>,
}

impl enterplace_core::store::Credentials for Shared {}

impl enterplace_core::store::Store for Shared {
    fn keys_text(&self) -> String {
        self.keys.clone()
    }
    fn kills(&self) -> Arc<Vec<enterplace_core::kill::Kill>> {
        Arc::new(self.kills.lock().map(|k| k.clone()).unwrap_or_default())
    }
    fn add_key(&self, _: &enterplace_core::config::KeyEntry) -> Result<bool, String> {
        Ok(false)
    }
    fn revoke(&self, _: &str) -> Result<Option<enterplace_core::keyfile::Revoked>, String> {
        Ok(None)
    }
    fn set_kill(
        &self,
        kill: &enterplace_core::kill::Kill,
    ) -> Result<Option<enterplace_core::kill::Kill>, String> {
        let mut kills = self.kills.lock().map_err(|e| e.to_string())?;
        let old = kills
            .iter()
            .position(|k| k.scope == kill.scope && k.value == kill.value)
            .map(|at| kills.remove(at));
        kills.push(kill.clone());
        Ok(old)
    }
    fn clear_kill(
        &self,
        scope: &str,
        value: &str,
    ) -> Result<Option<enterplace_core::kill::Kill>, String> {
        let mut kills = self.kills.lock().map_err(|e| e.to_string())?;
        Ok(kills
            .iter()
            .position(|k| k.scope == scope && k.value == value)
            .map(|at| kills.remove(at)))
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
        id: String,
        who: String,
        _: std::time::Duration,
    ) -> enterplace_core::store::Pending<()> {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.insert(id, who);
        }
        Box::pin(async { Ok(()) })
    }
    fn session(&self, id: String) -> enterplace_core::store::Pending<Option<String>> {
        let who = self.sessions.lock().ok().and_then(|s| s.get(&id).cloned());
        Box::pin(async move { Ok(who) })
    }
    fn end_session(&self, _: String) {}
}

/// Stop traffic and Restore traffic in the console go through the store when one is configured, as
/// `enterplace kill` and /admin/kills do: every gateway sees the switch, the file beside the keys is not written,
/// and the Audit log and People list the switches the store holds.
#[tokio::test]
async fn stop_and_restore_traffic_go_through_the_store_when_one_is_configured() -> TestResult {
    let s = setup("kills-store")?;
    let keys = s.dir.join("enterplace.keys.yaml");
    let shared = Shared {
        keys: std::fs::read_to_string(&keys)?,
        ..Shared::default()
    };
    let store: Arc<dyn enterplace_core::store::Store> = Arc::new(shared);
    enterplace_core::store::attach(&keys, &store);
    let cookie = sign_in(&s, ADMIN_KEY).await?;
    let (status, done) = call(
        &s,
        "POST",
        "/console/api/audit/stop",
        &cookie,
        Some(json!({ "scope": "team", "value": "platform", "reason": "runaway agent" })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    let on = store.kills();
    assert!(
        on.len() == 1 && on[0].value == "platform" && on[0].reason == "runaway agent",
        "{on:?}"
    );
    assert!(
        !enterplace_core::kill::path_beside(&keys).exists(),
        "the file beside the keys was written while a store holds the switches"
    );
    let (_, page) = call(&s, "GET", "/console/api/audit", &cookie, None).await?;
    assert_eq!(page["kills"][0]["value"], "platform", "{page}");
    // Copy for your agent: the restore command of this switch, and stopping traffic with every flag.
    let restore = page["kills"][0]["agent"].as_str().unwrap_or("");
    assert!(
        restore.contains("enterplace unkill --team platform")
            && restore.contains("ENTERPLACE_ADMIN_KEY"),
        "{restore}"
    );
    let stop = page["stop_agent"].as_str().unwrap_or("");
    for flag in [
        "--person",
        "--team",
        "--key-prefix",
        "--model",
        "--all",
        "--reason",
        "unkill",
    ] {
        assert!(stop.contains(flag), "{flag}: {stop}");
    }
    assert!(page["kills_error"].is_null(), "{page}");

    let (status, done) = call(
        &s,
        "POST",
        "/console/api/audit/restore",
        &cookie,
        Some(json!({ "scope": "team", "value": "platform" })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert!(store.kills().is_empty(), "{:?}", store.kills());
    let (_, page) = call(&s, "GET", "/console/api/audit", &cookie, None).await?;
    assert_eq!(page["kills"], json!([]), "{page}");
    Ok(())
}

/// People says how 200 people get keys without an admin issuing each: single sign-on with `enterplace login`, off
/// until the policy sets it, and an agent prompt that sets it up with the redirect URL, the policy lines and the check.
#[tokio::test]
async fn people_says_how_everyone_gets_a_key_and_hands_single_sign_on_to_an_agent() -> TestResult {
    let s = setup("bring")?;
    let cookie = sign_in(&s, ADMIN_KEY).await?;
    let (status, page) = call(&s, "GET", "/console/api/people", &cookie, None).await?;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["bring"]["on"], false, "{page}");
    assert!(
        page["bring"]["state"]
            .as_str()
            .is_some_and(|t| t.contains("no console.sso")),
        "{page}"
    );
    let agent = page["bring"]["agent"].as_str().unwrap_or("");
    for part in [
        "/console/sso/callback",
        "self_issue:",
        "ENTERPLACE_SSO_SECRET",
        "enterplace check",
        "enterplace login",
        "https://docs.enterplace.dev/governance/single-sign-on.md",
    ] {
        assert!(agent.contains(part), "{part}: {agent}");
    }
    Ok(())
}
