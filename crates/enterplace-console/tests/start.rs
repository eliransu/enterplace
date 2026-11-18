//! Start here, the console home: the welcome on an empty install, the kept choice, each choice's checklist, a
//! request turning its step done through state.json, the empty pages, and roles that see only what they may do.

use std::{path::PathBuf, sync::Arc};

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
};
use enterplace_console::{ConsoleConfig, router};
use enterplace_core::{
    audit::{AuditLog, Entry},
    id::sha256_hex,
};
use http_body_util::BodyExt;
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const ADMIN_KEY: &str = "enterplace_admin_key_for_start";
const VIEWER_KEY: &str = "enterplace_viewer_key_for_start";
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
    let dir = std::env::temp_dir().join(format!("enterplace-start-{}-{name}", std::process::id()));
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
    let kept = std::fs::read_to_string(s.dir.join("enterplace-start.json"))?;
    assert!(kept.contains(r#""choice":"apps""#), "{kept}");
    let audit = std::fs::read_to_string(s.dir.join("enterplace-audit.jsonl"))?;
    assert!(
        audit.contains(r#""action":"start_choice""#),
        "the choice is recorded"
    );
    let (_, _, page) = send(&s.app, get("/console/start", &cookie)?).await?;
    assert!(
        page.contains("Our own apps and agents: 1 of 5 done"),
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
    let kept = std::fs::read_to_string(s.dir.join("enterplace-start.json"))?;
    assert!(kept.contains(r#""skipped":true"#), "{kept}");
    Ok(())
}

#[tokio::test]
async fn each_choice_has_its_checklist_with_lines_from_the_real_config() -> TestResult {
    let s = setup("choices")?;
    let cookie = sign_in(&s.app, ADMIN_KEY).await?;
    // The first request is sent, so each choice's own steps are current.
    request(&s, "01START0000000000000000000", "noa.bar", "platform")?;
    // The current step carries its lines; the steps ahead say what they bring.
    let expect: [(&str, &[&str]); 5] = [
        (
            "coding",
            &[
                "How does your team pay for its coding agents?",
                "Claude subscriptions, for Claude Code",
                "API keys, any coding agent",
                "Make a key for the first person",
                "Point your coding agent at Enterplace and send one prompt",
                "Add a second person",
                "Let people make their own keys",
                "Copy for your agent",
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
                "Put an MCP server behind Enterplace",
                "  - name: github",
                "tools: [github.*]",
                "GITHUB_MCP_AUTHORIZATION",
                "Connect an MCP client and call one tool",
            ],
        ),
        (
            "limit",
            &[
                "Make a key",
                "Set a monthly budget for each team",
                "Enforce the budget",
            ],
        ),
        (
            "watch",
            &[
                "Add a license with watch mode",
                "Enterprise",
                "export ENTERPLACE_LICENSE=",
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
                page.contains(&enterplace_console::html::esc(part)),
                "{choice}: {part}"
            );
        }
        // The step in front holds what to do and nothing more: no "Turns done when" and "Then you see" blocks.
        assert!(page.contains(r#"data-state="now""#), "{choice}");
        for gone in [
            "Turns done when",
            "Then you see",
            "Paste it into Claude Code",
        ] {
            assert!(!page.contains(gone), "{choice}: {gone}");
        }
    }
    // A policy kept in the file: the lines come with Copy and the file's path, no draft button.
    let (_, _, page) = send(&s.app, get("/console/start?track=mcp", &cookie)?).await?;
    assert!(
        page.contains("enterplace.policy.yaml") && !page.contains("/console/policy/edit?add="),
        "{page}"
    );
    // Tabs pick the tool's lines by address.
    send(
        &s.app,
        post(
            "/console/start/key",
            &cookie,
            "kind=person&name=sarah.miller&team=platform&pay=api",
        )?,
    )
    .await?;
    let (_, _, page) = send(&s.app, get("/console/start?track=coding&pay=api", &cookie)?).await?;
    assert!(
        page.contains(&format!("export ANTHROPIC_BASE_URL={BASE}")),
        "{page}"
    );
    let (_, _, page) = send(
        &s.app,
        get("/console/start?track=coding&pay=api&tool=codex", &cookie)?,
    )
    .await?;
    assert!(
        page.contains(&format!("base_url = &quot;{BASE}/v1&quot;")),
        "{page}"
    );
    // Gemini CLI has its own lines, and the tabs keep the API key answer instead of falling back to subscriptions.
    let (_, _, page) = send(
        &s.app,
        get("/console/start?track=coding&pay=api&tool=gemini", &cookie)?,
    )
    .await?;
    assert!(
        page.contains(&format!("export GOOGLE_GEMINI_BASE_URL={BASE}"))
            && page.contains("/console/start?pay=api&amp;tool=codex#step-4"),
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
    // Connect a model is done (the policy has a provider); Send your first request listens.
    let (_, _, before) = send(&s.app, get("/console/start/state.json?pay=api", &cookie)?).await?;
    assert!(
        before.contains(r#""steps":["done","listening","ahead","ahead","ahead","ahead"]"#),
        "{before}"
    );
    request(&s, "01START0000000000000000000", "noa.bar", "platform")?;
    let (_, _, before) = send(&s.app, get("/console/start/state.json?pay=api", &cookie)?).await?;
    assert!(
        before.contains(r#""steps":["done","done","now","ahead","ahead","ahead"]"#),
        "{before}"
    );

    let (status, _, page) = send(
        &s.app,
        post(
            "/console/start/key",
            &cookie,
            "kind=person&name=sarah.miller&team=platform&pay=api",
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{page}");
    let keys = std::fs::read_to_string(s.dir.join("enterplace.keys.yaml"))?;
    assert!(keys.contains("name: sarah.miller"), "{keys}");
    // The key is in the lines to paste, once; the step that waits for traffic listens and the page polls.
    assert!(
        page.contains("export ANTHROPIC_API_KEY=enterplace_"),
        "{page}"
    );
    assert!(
        page.contains(r#"data-state="listening""#) && page.contains("data-start-poll"),
        "{page}"
    );
    assert!(
        page.contains("Waiting for the first request from sarah.miller"),
        "{page}"
    );
    // The page polls; without a script the step's Check now link does the same.
    assert!(
        page.contains(r#"<noscript><a class="g-link t-small" href="/console/start">Check now"#),
        "works without the script: {page}"
    );
    let (_, _, later) = send(&s.app, get("/console/start?pay=api", &cookie)?).await?;
    assert!(
        !later.contains("export ANTHROPIC_API_KEY=enterplace_"),
        "shown once"
    );
    assert!(later.contains("&lt;key of sarah.miller&gt;"), "{later}");

    let (_, _, waiting) = send(&s.app, get("/console/start/state.json?pay=api", &cookie)?).await?;
    assert!(
        waiting.contains(r#""steps":["done","done","done","listening","ahead","ahead"]"#),
        "{waiting}"
    );
    request(&s, "01START0000000000000000001", "sarah.miller", "platform")?;
    let (_, _, arrived) = send(&s.app, get("/console/start/state.json?pay=api", &cookie)?).await?;
    assert!(
        arrived.contains(r#""steps":["done","done","done","done","now","ahead"]"#),
        "{arrived}"
    );
    assert_ne!(
        signature(&waiting)?,
        signature(&arrived)?,
        "the page reloads"
    );

    // The first data on Start here, with the next step under it.
    let (_, _, page) = send(&s.app, get("/console/start?pay=api", &cookie)?).await?;
    // The live strip: tools, the gate, providers, a count of the last 10 minutes and the newest requests.
    for part in [
        "Your first requests arrived",
        r#"aria-label="Live traffic""#,
        "in the last 10 minutes",
        r#"<span class="t-mono-sm">claude-code</span>"#,
        r#"<span class="t-mono-sm">anthropic</span>"#,
        "claude-sonnet-5-5",
        r#"class="g-flowing__disc" data-outcome="pass""#,
        "Your steps",
        "Add a second person",
    ] {
        assert!(page.contains(part), "{part}: {page}");
    }
    // Only the newest request's disc moves: the page redraws when one arrives, and each new one crosses once.
    assert_eq!(page.matches("g-flowing__disc--new").count(), 1, "{page}");

    // A second person, then the five steps once the required steps are done.
    let made = std::fs::read_to_string(s.dir.join("enterplace.keys.yaml"))?;
    std::fs::write(
        s.dir.join("enterplace.keys.yaml"),
        format!(
            "{made}  - name: mike.johnson\n    team: payments\n    sha256: {}\n",
            sha256_hex(b"enterplace_mike")
        ),
    )?;
    request(&s, "01START0000000000000000002", "mike.johnson", "payments")?;
    let (_, _, page) = send(&s.app, get("/console/start?pay=api", &cookie)?).await?;
    assert!(page.contains("Show the five steps"), "{page}");
    send(&s.app, post("/console/start/pick", &cookie, "steps=1")?).await?;
    let (_, _, page) = send(&s.app, get("/console/start?pay=api", &cookie)?).await?;
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
    // Requests is in the app: its API carries the empty state, the one line to paste, and the one reason a desktop
    // user sees nothing arrive.
    let request = Request::get("/console/api/requests")
        .header(header::HOST, HOST)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())?;
    let (_, _, requests) = send(&s.app, request).await?;
    let requests: serde_json::Value = serde_json::from_str(&requests)?;
    assert_eq!(requests["empty"]["title"], "No requests yet");
    assert_eq!(
        requests["empty"]["action"]["href"],
        "/console/start?track=coding#step-2"
    );
    assert_eq!(
        requests["empty"]["docs"],
        "https://docs.enterplace.dev/integrations/coding-tools/"
    );
    assert!(
        requests["empty"]["command"]
            .as_str()
            .is_some_and(|c| c.starts_with("export ANTHROPIC_BASE_URL=")),
        "{requests}"
    );
    let notes = requests["empty"]["notes"].to_string();
    assert!(
        notes.contains("Claude desktop app") && notes.contains("Run claude in a terminal"),
        "{notes}"
    );
    let pages = [
        (
            "/console/teams",
            "No teams yet",
            "/console/start?track=coding#step-2",
            "/governance/teams/",
        ),
        (
            "/console/policy",
            "One rule lets everyone in",
            "/console/start?track=limit#step-5",
            "/governance/policy/",
        ),
    ];
    // The audit log is in the app too, with the same empty state while only setup records are in the chain.
    let request = Request::get("/console/api/audit")
        .header(header::HOST, HOST)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())?;
    let (_, _, audit) = send(&s.app, request).await?;
    let audit: serde_json::Value = serde_json::from_str(&audit)?;
    assert_eq!(audit["empty"]["title"], "Only setup records so far");
    assert_eq!(
        audit["empty"]["action"]["href"],
        "/console/start?track=coding#step-2"
    );
    assert_eq!(
        audit["empty"]["docs"],
        "https://docs.enterplace.dev/governance/audit-log/"
    );
    // People is in the app: its API carries the same empty state for the app to show.
    let request = Request::get("/console/api/people")
        .header(header::HOST, HOST)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())?;
    let (_, _, people) = send(&s.app, request).await?;
    let people: serde_json::Value = serde_json::from_str(&people)?;
    assert_eq!(people["empty"]["title"], "Only your admin key so far");
    assert_eq!(
        people["empty"]["action"]["href"],
        "/console/start?track=coding#step-2"
    );
    assert_eq!(
        people["empty"]["docs"],
        "https://docs.enterplace.dev/governance/keys/"
    );
    // Analytics is in the app too: nothing at all is the empty state, not a chart of zeros.
    let request = Request::get("/console/api/analytics")
        .header(header::HOST, HOST)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())?;
    let (_, _, analytics) = send(&s.app, request).await?;
    let analytics: serde_json::Value = serde_json::from_str(&analytics)?;
    assert_eq!(
        analytics["empty"]["title"], "Nothing to rank yet",
        "{analytics}"
    );
    assert_eq!(
        analytics["empty"]["action"]["href"],
        "/console/start?track=coding#step-2"
    );
    assert_eq!(
        analytics["empty"]["docs"],
        "https://docs.enterplace.dev/operations/request-log/"
    );
    // Spend is in the app too: its API carries the same empty state, with the policy lines that add a budget.
    let request = Request::get("/console/api/spend")
        .header(header::HOST, HOST)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())?;
    let (_, _, spend) = send(&s.app, request).await?;
    let spend: serde_json::Value = serde_json::from_str(&spend)?;
    assert_eq!(spend["empty"]["title"], "No spend and no budgets yet");
    assert_eq!(
        spend["empty"]["action"]["href"],
        "/console/start?track=limit#step-5"
    );
    assert_eq!(
        spend["empty"]["docs"],
        "https://docs.enterplace.dev/governance/budgets-and-rate-limits/"
    );
    assert_eq!(spend["empty"]["lines"][0], "limits:");
    for (path, title, action, docs) in pages {
        let (status, _, page) = send(&s.app, get(path, &cookie)?).await?;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(page.contains(title), "{path}: {page}");
        assert!(
            page.contains(&format!(r#"class="g-btn t-body" href="{action}""#)),
            "{path}: action"
        );
        assert!(
            page.contains(&format!("https://docs.enterplace.dev{docs}")),
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
    request(&s, "01START0000000000000000000", "noa.bar", "platform")?;
    let viewer = sign_in(&s.app, VIEWER_KEY).await?;
    send(&s.app, get("/console/start", &viewer)?).await?;
    let (_, _, page) = send(&s.app, get("/console/start?pay=api", &viewer)?).await?;
    assert!(page.contains("Make a key for the first person"), "{page}");
    assert!(
        !page.contains(r#"action="/console/start/key""#),
        "no key form: {page}"
    );
    assert!(!page.contains("Change what to start with"), "{page}");
    assert!(page.contains("Your role cannot make keys"), "{page}");
    let (_, _, page) = send(&s.app, get("/console/start", &viewer)?).await?;
    assert!(
        !page.contains(r#"action="/console/start/passthrough""#)
            && !page.contains(r#"action="/console/start/key""#),
        "no forms: {page}"
    );
    // Its own forms are refused and recorded, whatever it sends.
    let (status, _, _) = send(
        &s.app,
        post("/console/start/key", &viewer, "kind=person&name=x&team=y")?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let keys = std::fs::read_to_string(s.dir.join("enterplace.keys.yaml"))?;
    assert!(!keys.contains("name: x\n"), "{keys}");
    let (_, headers, _) = send(&s.app, post("/console/start/pick", &viewer, "choice=mcp")?).await?;
    assert_eq!(location(&headers), "/console/start");
    let kept = std::fs::read_to_string(s.dir.join("enterplace-start.json"))?;
    assert!(kept.contains(r#""choice":"coding""#), "{kept}");
    // Empty pages offer it the docs, not the action.
    let (_, _, page) = send(&s.app, get("/console/teams", &viewer)?).await?;
    assert!(
        page.contains("No teams yet")
            && !page.contains(r#"href="/console/start?track=coding#step-2""#),
        "{page}"
    );
    Ok(())
}

/// Credentials kept in memory, standing in for the sealed file `enterplace serve` opens without a store.
#[derive(Default)]
struct Vault(std::sync::Mutex<Vec<(String, String)>>);

impl enterplace_core::store::Credentials for Vault {
    fn credentials(&self) -> Result<Arc<Vec<enterplace_core::store::Credential>>, String> {
        let held = self.0.lock().map_err(|e| e.to_string())?;
        Ok(Arc::new(
            held.iter()
                .map(|(name, _)| enterplace_core::store::Credential {
                    name: name.clone(),
                    provider: name.clone(),
                    fingerprint: "...test".into(),
                    created_by: "test".into(),
                    created_at: String::new(),
                    rotated_by: None,
                    rotated_at: None,
                    generation: 1,
                })
                .collect(),
        ))
    }
    fn add_credential(
        &self,
        name: &str,
        _provider: &str,
        value: &str,
        _by: &str,
    ) -> Result<Option<enterplace_core::store::Credential>, String> {
        self.0
            .lock()
            .map_err(|e| e.to_string())?
            .push((name.into(), value.into()));
        Ok(self.credentials()?.last().cloned())
    }
}

#[tokio::test]
async fn connect_a_model_seals_the_key_and_adds_the_provider_or_the_demo_model_is_chosen()
-> TestResult {
    let s = setup("connect")?;
    // The policy as enterplace start writes it with no key: the demo model only.
    std::fs::write(
        s.dir.join("enterplace.policy.yaml"),
        "version: 1\nmode: observe\nproviders:\n  - name: demo\n    preset: demo\n    models: [enterplace-demo]\nrules:\n  - name: everyone\n    principals: { any: true }\n    models: [\"*\"]\nroles:\n  - name: viewer\n    permissions: [see_keys]\n",
    )?;
    let cookie = sign_in(&s.app, ADMIN_KEY).await?;
    send(&s.app, post("/console/start/pick", &cookie, "choice=apps")?).await?;
    let (_, _, page) = send(&s.app, get("/console/start", &cookie)?).await?;
    for part in [
        "Connect a model",
        "Try without a key",
        "Send your first request",
    ] {
        assert!(page.contains(part), "{part}: {page}");
    }
    // No master key and no store: the page says how to get one, and the form is refused with the same fix.
    assert!(page.contains("ENTERPLACE_MASTER_KEY"), "{page}");
    let (status, _, page) = send(
        &s.app,
        post(
            "/console/start/connect",
            &cookie,
            "provider=anthropic&key=sk-ant-test-1234",
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(page.contains("master key"), "{page}");

    // Try without a key: the first request names the demo model.
    let (_, headers, _) = send(&s.app, post("/console/start/demo", &cookie, "")?).await?;
    assert_eq!(location(&headers), "/console/start?pay=api#step-2");
    let (_, _, page) = send(&s.app, get("/console/start", &cookie)?).await?;
    assert!(page.contains("Using the demo model"), "{page}");
    assert!(
        page.contains("&quot;model&quot;:&quot;enterplace-demo&quot;"),
        "{page}"
    );
    assert!(
        page.contains(&format!("curl {BASE}/v1/chat/completions")),
        "{page}"
    );

    // A key for the first request: in the lines, shown once, and no person's or app's key.
    let (status, _, page) = send(&s.app, post("/console/start/first-key", &cookie, "")?).await?;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(page.contains("Authorization: Bearer enterplace_"), "{page}");
    let (_, _, page) = send(&s.app, get("/console/start?tool=python", &cookie)?).await?;
    assert!(
        page.contains("os.environ[&quot;ENTERPLACE_KEY&quot;]"),
        "{page}"
    );
    assert!(page.contains("Make a key for the app"), "{page}");
    let (_, _, state) = send(&s.app, get("/console/start/state.json", &cookie)?).await?;
    assert!(
        state.contains(r#""steps":["done","listening","ahead","ahead","ahead"]"#),
        "{state}"
    );

    // With a place to keep it, the key is sealed and the provider joins the policy, reading that credential.
    let vault: Arc<dyn enterplace_core::store::Credentials> = Arc::new(Vault::default());
    enterplace_core::store::attach_credentials(&s.dir.join("enterplace.keys.yaml"), &vault);
    std::fs::write(
        enterplace_core::store::credentials_file(&s.dir.join("enterplace.policy.yaml")),
        "[]",
    )?;
    let (status, headers, page) = send(
        &s.app,
        post(
            "/console/start/connect",
            &cookie,
            "provider=anthropic&key=sk-ant-test-1234",
        )?,
    )
    .await?;
    assert_eq!(
        (status, location(&headers)),
        (StatusCode::SEE_OTHER, "/console/start?pay=api#step-2"),
        "{page}"
    );
    assert_eq!(
        vault.credential_value("anthropic").ok().flatten(),
        None,
        "the stand-in keeps no values to open"
    );
    assert_eq!(vault.credentials()?.len(), 1);
    let policy = std::fs::read_to_string(s.dir.join("enterplace.policy.yaml"))?;
    assert!(
        policy.contains("  - name: anthropic\n    preset: anthropic\n    credential: anthropic\n"),
        "{policy}"
    );
    let audit = std::fs::read_to_string(s.dir.join("enterplace-audit.jsonl"))?;
    assert!(
        audit.contains(r#""action":"add_credential""#)
            && audit.contains(r#""action":"connect_provider""#),
        "{audit}"
    );
    assert!(
        !audit.contains("sk-ant-test-1234"),
        "the key is in no record"
    );
    let (_, _, page) = send(&s.app, get("/console/start", &cookie)?).await?;
    assert!(
        page.contains("Connected: <span class=\"t-mono\">anthropic</span>"),
        "{page}"
    );
    assert!(
        page.contains("&quot;model&quot;:&quot;claude-sonnet-5-5&quot;"),
        "{page}"
    );
    Ok(())
}

#[tokio::test]
async fn the_start_link_signs_in_once_and_only_from_this_machine_and_a_pasted_export_line_signs_in()
-> TestResult {
    let s = setup("link")?;
    // Only from this machine: a request with no loopback address is refused, and the link is not spent.
    let code = enterplace_console::offer_start_link(&sha256_hex(ADMIN_KEY.as_bytes()), false)
        .ok_or("no randomness")?;
    let link = format!("/console/sign-in/{code}");
    let (status, _, page) = send(&s.app, get(&link, "")?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{page}");
    assert!(page.contains("machine that runs Enterplace"), "{page}");
    // In a container any address may use it: the browser comes through the container's network.
    let code = enterplace_console::offer_start_link(&sha256_hex(ADMIN_KEY.as_bytes()), true)
        .ok_or("no randomness")?;
    let link = format!("/console/sign-in/{code}");
    let (status, headers, _) = send(&s.app, get(&link, "")?).await?;
    assert_eq!(
        (status, location(&headers)),
        (StatusCode::SEE_OTHER, "/console/start")
    );
    assert!(headers.get(header::SET_COOKIE).is_some());
    let (status, _, page) = send(&s.app, get(&link, "")?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "once: {page}");
    let audit = std::fs::read_to_string(s.dir.join("enterplace-audit.jsonl"))?;
    assert!(audit.contains(r#""via":"start_link""#), "{audit}");

    // The whole line enterplace start prints, quotes and all, signs in too; a wrong key says so plainly.
    let line = format!("key=export%20ENTERPLACE_KEY%3D%22{ADMIN_KEY}%22%20");
    let (status, headers, _) = send(&s.app, post("/console/sign-in", "", &line)?).await?;
    assert_eq!(
        (status, location(&headers)),
        (StatusCode::SEE_OTHER, "/console/start")
    );
    let (_, _, page) = send(
        &s.app,
        post("/console/sign-in", "", "key=sk-not-enterplace")?,
    )
    .await?;
    assert!(page.contains("That is not a Enterplace key"), "{page}");
    Ok(())
}

/// A Claude Code request on `person`'s own Claude subscription, as the server records it.
fn subscribed(s: &Setup, id: &str, person: &str, team: &str) -> TestResult {
    let record = serde_json::json!({
        "id": id,
        "person": person,
        "team": team,
        "user_agent": "claude-cli/2.1.325 (external, cli)",
        "method": "POST",
        "path": "/v1/messages",
        "model": "claude-sonnet-4-5",
        "verdict": "allow",
        "rule": "everyone",
        "provider": "claude-subscriptions",
        "auth": "passthrough",
        "identity": "x-enterplace-user",
    });
    let serde_json::Value::Object(map) = record else {
        return Err("not an object".into());
    };
    s.log.append_record(&map)?;
    Ok(())
}

#[tokio::test]
async fn claude_subscriptions_need_no_api_key_and_each_step_copies_for_an_agent() -> TestResult {
    let s = setup("subscriptions")?;
    let cookie = sign_in(&s.app, ADMIN_KEY).await?;
    send(
        &s.app,
        post("/console/start/pick", &cookie, "choice=coding")?,
    )
    .await?;

    // API keys are the default answer, since every coding agent takes them. Picking subscriptions shows their
    // steps, and the first one turns them on with one click.
    let (_, _, page) = send(&s.app, get("/console/start", &cookie)?).await?;
    assert!(
        page.contains(r#"href="/console/start?track=coding&amp;pay=api" aria-current="true""#),
        "{page}"
    );
    let (_, _, page) = send(&s.app, get("/console/start?pay=subscriptions", &cookie)?).await?;
    assert!(
        page.contains(
            r#"href="/console/start?track=coding&amp;pay=subscriptions" aria-current="true""#
        ),
        "{page}"
    );
    assert!(
        page.contains(r#"action="/console/start/passthrough""#),
        "{page}"
    );
    assert!(
        !page.contains("ANTHROPIC_API_KEY="),
        "no API key anywhere: {page}"
    );
    let (_, _, state) = send(
        &s.app,
        get("/console/start/state.json?pay=subscriptions", &cookie)?,
    )
    .await?;
    assert!(
        state.contains(r#""steps":["now","ahead","ahead","ahead"]"#),
        "{state}"
    );
    let (status, headers, _) =
        send(&s.app, post("/console/start/passthrough", &cookie, "")?).await?;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        location(&headers),
        "/console/start?track=coding&pay=subscriptions#step-2"
    );
    let policy = std::fs::read_to_string(s.dir.join("enterplace.policy.yaml"))?;
    assert!(
        policy.contains("auth: passthrough") && policy.contains("identity: optional"),
        "{policy}"
    );
    let (_, _, state) = send(
        &s.app,
        get("/console/start/state.json?pay=subscriptions", &cookie)?,
    )
    .await?;
    assert!(
        state.contains(r#""steps":["done","listening","ahead","ahead"]"#),
        "{state}"
    );

    // A person token, not a key: the lines keep Claude Code's own login.
    let (status, _, page) = send(
        &s.app,
        post(
            "/console/start/key",
            &cookie,
            "kind=person_token&name=sarah.miller&team=platform",
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{page}");
    let token = page
        .split("x-enterplace-user: ")
        .nth(1)
        .and_then(|rest| rest.split(['&', '"', '<', '\n', ' ']).next())
        .ok_or("no person token in the lines")?
        .to_string();
    assert!(token.starts_with("enterplace_u_"), "{token}");
    assert!(
        page.contains(&format!("export ANTHROPIC_BASE_URL={BASE}"))
            && page.contains(&format!(
                "export ANTHROPIC_CUSTOM_HEADERS=&quot;x-enterplace-user: {token}&quot;"
            )),
        "{page}"
    );
    assert!(
        page.contains("keep using your normal Claude login"),
        "{page}"
    );
    assert!(!page.contains("ANTHROPIC_API_KEY="), "{page}");
    // Copy for your agent: the goal, the exact values and the docs as Markdown.
    let prompt = page
        .split(r#"<pre id="agent-step-2" hidden>"#)
        .nth(1)
        .and_then(|rest| rest.split("</pre>").next())
        .ok_or("no agent prompt for step 2")?;
    for part in [
        BASE,
        token.as_str(),
        "x-enterplace-user",
        "https://docs.enterplace.dev/integrations/claude-code.md",
        "claude -p",
    ] {
        assert!(prompt.contains(part), "{part}: {prompt}");
    }
    assert!(!prompt.contains(ADMIN_KEY), "never an admin key");
    assert!(
        page.contains(r#"data-copy="agent-step-2" data-agent-prompt"#),
        "{page}"
    );
    // Managed settings for an MDM rollout.
    let (_, _, page) = send(
        &s.app,
        get("/console/start?setup=mdm&pay=subscriptions", &cookie)?,
    )
    .await?;
    assert!(
        page.contains("&quot;ANTHROPIC_CUSTOM_HEADERS&quot;: &quot;x-enterplace-user:"),
        "{page}"
    );
    assert!(page.contains("managed-settings.json"), "{page}");

    // The step turns done when the first subscription request from that person arrives.
    let keys = std::fs::read_to_string(s.dir.join("enterplace.keys.yaml"))?;
    assert!(keys.contains(&sha256_hex(token.as_bytes())), "{keys}");
    subscribed(&s, "01SUB00000000000000000000", "sarah.miller", "platform")?;
    let (_, _, state) = send(
        &s.app,
        get("/console/start/state.json?pay=subscriptions", &cookie)?,
    )
    .await?;
    assert!(
        state.contains(r#""steps":["done","done","now","ahead"]"#),
        "{state}"
    );
    let (_, _, page) = send(&s.app, get("/console/start?pay=subscriptions", &cookie)?).await?;
    assert!(
        page.contains("Your steps") && page.contains("Add a second person"),
        "{page}"
    );

    // Anthropic API keys keep today's steps.
    let (_, _, page) = send(&s.app, get("/console/start?pay=api", &cookie)?).await?;
    assert!(page.contains("Let people make their own keys"), "{page}");
    Ok(())
}

/// Every "Copy for your agent" prompt on every choice links a docs page as Markdown, and the page exists: the docs
/// build writes `<page>.md` for each `.mdx` under docs/src/content/docs.
#[tokio::test]
async fn every_agent_prompt_links_a_docs_page_that_exists() -> TestResult {
    let s = setup("agent-docs")?;
    let cookie = sign_in(&s.app, ADMIN_KEY).await?;
    let docs = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/src/content/docs");
    let mut prompts = 0;
    for track in ["coding", "coding&pay=api", "apps", "mcp", "limit", "watch"] {
        let (_, _, page) = send(
            &s.app,
            get(&format!("/console/start?track={track}"), &cookie)?,
        )
        .await?;
        for part in page.split(r#"<pre id="agent-step-"#).skip(1) {
            let prompt = part.split("</pre>").next().unwrap_or_default();
            prompts += 1;
            assert!(
                prompt.contains(BASE),
                "{track}: the gateway's address: {prompt}"
            );
            let link = prompt
                .split("https://docs.enterplace.dev/")
                .nth(1)
                .and_then(|rest| rest.split(".md").next())
                .ok_or_else(|| format!("{track}: no docs link: {prompt}"))?;
            assert!(
                docs.join(format!("{link}.mdx")).exists(),
                "{track}: {link}.md has no page"
            );
        }
    }
    // Only the current step of each is shown open, with its prompt.
    assert!(prompts >= 6, "{prompts}");
    Ok(())
}

/// The numbers of "N of M done" in a page's lead line.
fn done_count(page: &str) -> Option<(usize, usize)> {
    page.match_indices(" done").find_map(|(end, _)| {
        let (before, total) = page[..end].rsplit_once(" of ")?;
        let total = total.parse().ok()?;
        let done = before.rsplit(' ').next()?.parse().ok()?;
        Some((done, total))
    })
}

#[tokio::test]
async fn every_track_lists_all_its_steps_and_the_count_matches_them() -> TestResult {
    let s = setup("counts")?;
    let cookie = sign_in(&s.app, ADMIN_KEY).await?;
    // Traffic has arrived, which used to hide the done steps on the tracks that show the first requests.
    request(&s, "01START0000000000000000000", "noa.bar", "platform")?;
    for (track, query) in [
        ("coding", "track=coding&pay=api"),
        ("coding", "track=coding&pay=subscriptions"),
        ("apps", "track=apps"),
        ("mcp", "track=mcp"),
        ("limit", "track=limit"),
        ("watch", "track=watch"),
    ] {
        let (_, _, page) = send(&s.app, get(&format!("/console/start?{query}"), &cookie)?).await?;
        let (done, total) = done_count(&page).ok_or_else(|| format!("{query}: no count"))?;
        let items = page.matches(r#"class="g-check__item""#).count();
        let marked = page.matches(r#"data-state="done""#).count();
        assert_eq!(items, total, "{query}: every step is listed");
        assert_eq!(marked, done, "{query}: the done steps are listed");
        if track == "watch" || query.contains("subscriptions") {
            assert!(!page.contains("Connect a model"), "{query}");
        } else {
            // Connect a model never reads Now while the first request reads Done.
            assert!(page.contains("Send your first request"), "{query}");
            let connect = page.find("Connect a model").ok_or("no connect step")?;
            let state = page[..connect].rfind("data-state=\"").ok_or("no state")?;
            assert!(page[state..].starts_with("data-state=\"done\""), "{query}");
        }
    }
    Ok(())
}
