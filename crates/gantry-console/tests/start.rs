//! Start here, the console home: the welcome on an empty install, the kept choice, each choice's checklist, a
//! request turning its step done through state.json, the empty pages, and roles that see only what they may do.

use std::{path::PathBuf, sync::Arc};

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
};
use gantry_console::{ConsoleConfig, router};
use gantry_core::{
    audit::{AuditLog, Entry},
    id::sha256_hex,
};
use http_body_util::BodyExt;
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const ADMIN_KEY: &str = "gantry_admin_key_for_start";
const VIEWER_KEY: &str = "gantry_viewer_key_for_start";
const HOST: &str = "127.0.0.1:19851";
const BASE: &str = "http://127.0.0.1:19851";

const POLICY: &str = "\
version: 1
mode: observe
providers:
  - name: openai
    kind: openai
    url: https://api.openai.com
    key_env: OPENAI_API_KEY
    models: [gpt-4o-mini]
rules:
  - name: everyone
    principals: { any: true }
    models: [\"*\"]
roles:
  - name: viewer
    permissions: [see_keys, see_records, see_spend]
";

struct Setup {
    app: Router,
    dir: PathBuf,
    log: Arc<AuditLog>,
}

fn setup(name: &str) -> Result<Setup, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!("gantry-start-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("gantry.policy.yaml"), POLICY)?;
    std::fs::write(
        dir.join("gantry.keys.yaml"),
        format!(
            "keys:\n  - name: noa.bar\n    team: platform\n    sha256: {}\n    admin: true\n  - name: vic.viewer\n    team: platform\n    sha256: {}\n    admin: true\n    role: viewer\n",
            sha256_hex(ADMIN_KEY.as_bytes()),
            sha256_hex(VIEWER_KEY.as_bytes())
        ),
    )?;
    let log = Arc::new(AuditLog::open(&dir.join("gantry-audit.jsonl"))?);
    let config = ConsoleConfig {
        policy: dir.join("gantry.policy.yaml"),
        keys: dir.join("gantry.keys.yaml"),
        audit: dir.join("gantry-audit.jsonl"),
        log: Some(log.clone()),
    };
    Ok(Setup {
        app: Router::new().nest("/console", router(config)),
        dir,
        log,
    })
}

async fn send(
    app: &Router,
    request: Request<Body>,
) -> Result<(StatusCode, HeaderMap, String), Box<dyn std::error::Error>> {
    let response = app.clone().oneshot(request).await?;
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await?.to_bytes();
    Ok((
        parts.status,
        parts.headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    ))
}

fn get(path: &str, cookie: &str) -> Result<Request<Body>, axum::http::Error> {
    Request::get(path)
        .header(header::HOST, HOST)
        .header(header::COOKIE, cookie)
        .body(Body::empty())
}

fn post(path: &str, cookie: &str, form: &str) -> Result<Request<Body>, axum::http::Error> {
    Request::post(path)
        .header(header::HOST, HOST)
        .header(header::ORIGIN, format!("http://{HOST}"))
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(form.to_string()))
}

fn location(headers: &HeaderMap) -> &str {
    headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

async fn sign_in(app: &Router, key: &str) -> Result<String, Box<dyn std::error::Error>> {
    let (status, headers, _) =
        send(app, post("/console/sign-in", "", &format!("key={key}"))?).await?;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location(&headers), "/console/start");
    let cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .ok_or("no cookie was set")?;
    Ok(cookie.split(';').next().unwrap_or("").to_string())
}

/// A request through the gateway by `person`, as the server records it.
fn request(s: &Setup, id: &str, person: &str, team: &str) -> TestResult {
    s.log.append(&Entry {
        id,
        person: Some(person),
        team: Some(team),
        user_agent: Some("claude-cli/2.1.0"),
        method: "POST",
        path: "/v1/messages",
        model: Some("claude-sonnet-5-5"),
        allowed: true,
        rule: Some("everyone"),
        provider: "anthropic",
        policy_sha256: "x",
        ..Entry::default()
    })?;
    Ok(())
}

fn signature(json: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value: serde_json::Value = serde_json::from_str(json)?;
    Ok(value["signature"].as_str().unwrap_or("").to_string())
}

#[tokio::test]
async fn an_empty_install_opens_on_the_welcome_and_the_choice_is_kept() -> TestResult {
    let s = setup("welcome")?;
    let cookie = sign_in(&s.app, ADMIN_KEY).await?;
    // The brand and the root open Start here.
    let (_, headers, _) = send(&s.app, get("/console", &cookie)?).await?;
    assert_eq!(location(&headers), "/console/start");
    let (status, _, page) = send(&s.app, get("/console/start", &cookie)?).await?;
    assert_eq!(status, StatusCode::OK);
    for part in [
        "What do you want to start with?",
        "g-pick",
        "Coding agents",
        "Our own apps and agents",
        "MCP tools",
        "A spend limit for the team",
        "Claude Team seats we can only watch",
        "Start with coding agents",
        "Skip and open the console",
        &format!("Running at {BASE}"),
    ] {
        assert!(page.contains(part), "{part}: {page}");
    }
    assert!(!page.contains("g-nav--side"), "the welcome has no nav");

    let (status, headers, _) =
        send(&s.app, post("/console/start/pick", &cookie, "choice=apps")?).await?;
    assert_eq!(
        (status, location(&headers)),
        (StatusCode::SEE_OTHER, "/console/start")
    );
    let kept = std::fs::read_to_string(s.dir.join("gantry-start.json"))?;
    assert!(kept.contains(r#""choice":"apps""#), "{kept}");
    let audit = std::fs::read_to_string(s.dir.join("gantry-audit.jsonl"))?;
    assert!(
        audit.contains(r#""action":"start_choice""#),
        "the choice is recorded"
    );
    let (_, _, page) = send(&s.app, get("/console/start", &cookie)?).await?;
    assert!(
        page.contains("Our own apps and agents: 0 of 3 done"),
        "{page}"
    );
    assert!(
        page.contains(r#"aria-current="page">Start here"#),
        "Start here is first in the nav"
    );

    // Changed later, and skipped: the console opens on Start here with the pick in the shell.
    let (_, _, page) = send(&s.app, get("/console/start?pick=1", &cookie)?).await?;
    assert!(
        page.contains("g-nav--side") && page.contains("g-pick"),
        "{page}"
    );
    let (_, _, _) = send(&s.app, post("/console/start/pick", &cookie, "skip=1")?).await?;
    let kept = std::fs::read_to_string(s.dir.join("gantry-start.json"))?;
    assert!(kept.contains(r#""skipped":true"#), "{kept}");
    Ok(())
}

#[tokio::test]
async fn each_choice_has_its_checklist_with_lines_from_the_real_config() -> TestResult {
    let s = setup("choices")?;
    let cookie = sign_in(&s.app, ADMIN_KEY).await?;
    // The current step carries its lines; the steps ahead say what they bring.
    let expect: [(&str, &[&str]); 5] = [
        (
            "coding",
            &[
                "Make a key for the first person",
                "Point Claude Code at Gantry and send one prompt",
                "Add a second person",
                "Let people make their own keys",
                "Optional",
            ],
        ),
        (
            "apps",
            &[
                "Make a key for the app",
                "Change the base URL and send one request",
                "Set a monthly budget for the app",
            ],
        ),
        (
            "mcp",
            &[
                "Put an MCP server behind Gantry",
                "  - name: github",
                "tools: [github.*]",
                "GITHUB_MCP_AUTHORIZATION",
                "Connect Claude Code and call one tool",
            ],
        ),
        (
            "limit",
            &[
                "Make a key",
                "Send requests through Gantry",
                "Set a monthly budget for each team",
                "Enforce the budget",
            ],
        ),
        (
            "watch",
            &[
                "Add a license with watch mode",
                "Enterprise",
                "export GANTRY_LICENSE=",
                "Make a watch token",
                "Paste the settings into claude.ai",
            ],
        ),
    ];
    for (choice, parts) in expect {
        send(
            &s.app,
            post("/console/start/pick", &cookie, &format!("choice={choice}"))?,
        )
        .await?;
        let (_, _, page) = send(&s.app, get("/console/start", &cookie)?).await?;
        for part in parts {
            assert!(
                page.contains(&gantry_console::html::esc(part)),
                "{choice}: {part}"
            );
        }
        for part in ["Turns done when", "Then you see", r#"data-state="now""#] {
            assert!(page.contains(part), "{choice}: {part}");
        }
    }
    // A policy kept in the file: the lines come with Copy and the file's path, no draft button.
    let (_, _, page) = send(&s.app, get("/console/start?track=mcp", &cookie)?).await?;
    assert!(
        page.contains("gantry.policy.yaml") && !page.contains("/console/policy/edit?add="),
        "{page}"
    );
    // Tabs pick the tool's lines by address.
    send(
        &s.app,
        post(
            "/console/start/key",
            &cookie,
            "kind=person&name=sarah.miller&team=platform",
        )?,
    )
    .await?;
    let (_, _, page) = send(&s.app, get("/console/start?track=coding", &cookie)?).await?;
    assert!(
        page.contains(&format!("export ANTHROPIC_BASE_URL={BASE}")),
        "{page}"
    );
    let (_, _, page) = send(
        &s.app,
        get("/console/start?track=coding&tool=codex", &cookie)?,
    )
    .await?;
    assert!(
        page.contains(&format!("base_url = &quot;{BASE}/v1&quot;")),
        "{page}"
    );
    let (_, _, page) = send(&s.app, get("/console/start?track=apps", &cookie)?).await?;
    assert!(page.contains("Showing Our own apps and agents"), "{page}");
    Ok(())
}

#[tokio::test]
async fn a_key_made_on_the_checklist_shows_once_and_a_request_turns_its_step_done() -> TestResult {
    let s = setup("live")?;
    let cookie = sign_in(&s.app, ADMIN_KEY).await?;
    send(
        &s.app,
        post("/console/start/pick", &cookie, "choice=coding")?,
    )
    .await?;
    let (_, _, before) = send(&s.app, get("/console/start/state.json", &cookie)?).await?;
    assert!(
        before.contains(r#""steps":["now","ahead","ahead","ahead"]"#),
        "{before}"
    );

    let (status, _, page) = send(
        &s.app,
        post(
            "/console/start/key",
            &cookie,
            "kind=person&name=sarah.miller&team=platform",
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{page}");
    let keys = std::fs::read_to_string(s.dir.join("gantry.keys.yaml"))?;
    assert!(keys.contains("name: sarah.miller"), "{keys}");
    // The key is in the lines to paste, once; the step that waits for traffic listens and the page polls.
    assert!(page.contains("export ANTHROPIC_API_KEY=gantry_"), "{page}");
    assert!(
        page.contains(r#"data-state="listening""#) && page.contains("data-start-poll"),
        "{page}"
    );
    assert!(
        page.contains("Listening for the first request from sarah.miller"),
        "{page}"
    );
    assert!(
        page.contains(r#"href="/console/start">Check now"#),
        "works without the script"
    );
    let (_, _, later) = send(&s.app, get("/console/start", &cookie)?).await?;
    assert!(
        !later.contains("export ANTHROPIC_API_KEY=gantry_"),
        "shown once"
    );
    assert!(later.contains("&lt;key of sarah.miller&gt;"), "{later}");

    let (_, _, waiting) = send(&s.app, get("/console/start/state.json", &cookie)?).await?;
    assert!(
        waiting.contains(r#""steps":["done","listening","ahead","ahead"]"#),
        "{waiting}"
    );
    request(&s, "01START0000000000000000001", "sarah.miller", "platform")?;
    let (_, _, arrived) = send(&s.app, get("/console/start/state.json", &cookie)?).await?;
    assert!(
        arrived.contains(r#""steps":["done","done","now","ahead"]"#),
        "{arrived}"
    );
    assert_ne!(
        signature(&waiting)?,
        signature(&arrived)?,
        "the page reloads"
    );

    // The first data on Start here, with the next step under it.
    let (_, _, page) = send(&s.app, get("/console/start", &cookie)?).await?;
    for part in [
        "Your first requests arrived",
        "First requests through Gantry",
        "What you are seeing",
        "claude-sonnet-5-5",
        "Next step",
        "Add a second person",
    ] {
        assert!(page.contains(part), "{part}: {page}");
    }

    // A second person, then the five steps once the required steps are done.
    let made = std::fs::read_to_string(s.dir.join("gantry.keys.yaml"))?;
    std::fs::write(
        s.dir.join("gantry.keys.yaml"),
        format!(
            "{made}  - name: mike.johnson\n    team: payments\n    sha256: {}\n",
            sha256_hex(b"gantry_mike")
        ),
    )?;
    request(&s, "01START0000000000000000002", "mike.johnson", "payments")?;
    let (_, _, page) = send(&s.app, get("/console/start", &cookie)?).await?;
    assert!(page.contains("Show the five steps"), "{page}");
    send(&s.app, post("/console/start/pick", &cookie, "steps=1")?).await?;
    let (_, _, page) = send(&s.app, get("/console/start", &cookie)?).await?;
    for part in [
        "g-setup",
        "See",
        "Know",
        "Limit",
        "Protect",
        "Prove",
        "Step 3 of 5",
        "Also start with",
        "Show the steps",
    ] {
        assert!(page.contains(part), "{part}: {page}");
    }
    Ok(())
}

#[tokio::test]
async fn empty_pages_say_what_fills_them_and_open_the_start_here_step() -> TestResult {
    let s = setup("empty")?;
    let cookie = sign_in(&s.app, ADMIN_KEY).await?;
    let pages = [
        (
            "/console/requests",
            "No requests yet",
            "/console/start?track=coding#step-1",
            "/integrations/coding-tools/",
        ),
        (
            "/console/analytics",
            "Nothing to rank yet",
            "/console/start?track=coding#step-2",
            "/operations/request-log/",
        ),
        (
            "/console/spend",
            "No spend and no budgets yet",
            "/console/start?track=limit#step-3",
            "/governance/budgets-and-rate-limits/",
        ),
        (
            "/console/people",
            "Only your admin key so far",
            "/console/start?track=coding#step-1",
            "/governance/keys/",
        ),
        (
            "/console/teams",
            "No teams yet",
            "/console/start?track=coding#step-1",
            "/governance/teams/",
        ),
        (
            "/console/policy",
            "One rule lets everyone in",
            "/console/start?track=limit#step-3",
            "/governance/policy/",
        ),
        (
            "/console/audit",
            "Only setup records so far",
            "/console/start?track=coding#step-2",
            "/governance/audit-log/",
        ),
    ];
    for (path, title, action, docs) in pages {
        let (status, _, page) = send(&s.app, get(path, &cookie)?).await?;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(page.contains(title), "{path}: {page}");
        assert!(
            page.contains(&format!(r#"class="g-btn t-body" href="{action}""#)),
            "{path}: action"
        );
        assert!(
            page.contains(&format!("https://gantry-docs.eliran.me{docs}")),
            "{path}: docs"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_role_sees_only_the_actions_it_may_take() -> TestResult {
    let s = setup("roles")?;
    let admin = sign_in(&s.app, ADMIN_KEY).await?;
    send(
        &s.app,
        post("/console/start/pick", &admin, "choice=coding")?,
    )
    .await?;
    let viewer = sign_in(&s.app, VIEWER_KEY).await?;
    let (_, _, page) = send(&s.app, get("/console/start", &viewer)?).await?;
    assert!(page.contains("Make a key for the first person"), "{page}");
    assert!(
        !page.contains(r#"action="/console/start/key""#),
        "no key form: {page}"
    );
    assert!(!page.contains("Change what to start with"), "{page}");
    assert!(page.contains("Your role cannot make keys"), "{page}");
    // Its own forms are refused and recorded, whatever it sends.
    let (status, _, _) = send(
        &s.app,
        post("/console/start/key", &viewer, "kind=person&name=x&team=y")?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let keys = std::fs::read_to_string(s.dir.join("gantry.keys.yaml"))?;
    assert!(!keys.contains("name: x\n"), "{keys}");
    let (_, headers, _) = send(&s.app, post("/console/start/pick", &viewer, "choice=mcp")?).await?;
    assert_eq!(location(&headers), "/console/start");
    let kept = std::fs::read_to_string(s.dir.join("gantry-start.json"))?;
    assert!(kept.contains(r#""choice":"coding""#), "{kept}");
    // Empty pages offer it the docs, not the action.
    let (_, _, page) = send(&s.app, get("/console/teams", &viewer)?).await?;
    assert!(
        page.contains("No teams yet")
            && !page.contains(r#"href="/console/start?track=coding#step-1""#),
        "{page}"
    );
    Ok(())
}
