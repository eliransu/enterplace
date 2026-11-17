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
async fn policy_basics_change_rules_budgets_guardrails_aliases_and_mode() -> TestResult {
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

    // Budgets per team and per person.
    for body in [
        json!({ "scope": "team", "name": "payments", "usd": 500, "per": "month" }),
        json!({ "scope": "person", "name": "maya.cohen", "usd": "20", "per": "day" }),
    ] {
        let (status, done) = call(
            &s,
            "PUT",
            "/console/api/policy/budgets",
            &cookie,
            Some(body),
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{done}");
    }
    let (status, done) = call(
        &s,
        "PUT",
        "/console/api/policy/budgets",
        &cookie,
        Some(json!({ "scope": "team", "name": "payments", "usd": 800, "per": "month" })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    let (_, policy) = call(&s, "GET", "/console/api/policy", &cookie, None).await?;
    assert_eq!(
        policy["budgets"].as_array().map(Vec::len),
        Some(2),
        "{policy}"
    );
    assert_eq!(policy["budgets"][0]["usd"], 800);
    let (status, refused) = call(
        &s,
        "PUT",
        "/console/api/policy/budgets",
        &cookie,
        Some(json!({ "scope": "team", "name": "payments", "usd": -1, "per": "month" })),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(error(&refused).contains("above 0"), "{refused}");
    let (status, done) = call(
        &s,
        "DELETE",
        "/console/api/policy/budgets/person/maya.cohen",
        &cookie,
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");

    // Guardrails on and off for every request.
    let (status, done) = call(
        &s,
        "PUT",
        "/console/api/policy/guardrails/no-secrets",
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
        "/console/api/policy/guardrails/no-secrets",
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
            "PUT",
            "/console/api/policy/budgets",
            json!({ "scope": "team", "name": "x", "usd": 1, "per": "day" }),
        ),
        (
            "PUT",
            "/console/api/policy/guardrails/no-secrets",
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
