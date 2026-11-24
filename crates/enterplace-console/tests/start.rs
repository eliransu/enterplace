//! Start here, the console home, through the console app's JSON API: the welcome on an empty install, the kept
//! choice, each choice's checklist, a key shown once, a request turning its step done as the app polls, the empty
//! pages, and roles that see only what they may do.

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
use serde_json::{Value, json};
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

fn api_get(path: &str, cookie: &str) -> Result<Request<Body>, axum::http::Error> {
    get(&format!("/console/api/{path}"), cookie)
}

fn api_post(path: &str, cookie: &str, body: Value) -> Result<Request<Body>, axum::http::Error> {
    Request::post(format!("/console/api/{path}"))
        .header(header::HOST, HOST)
        .header(header::ORIGIN, format!("http://{HOST}"))
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
}

/// Start here as the app reads it, for the view `query` asks for.
async fn start(
    app: &Router,
    cookie: &str,
    query: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let (status, _, body) = send(app, api_get(&format!("start?{query}"), cookie)?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(serde_json::from_str(&body)?)
}

/// A change on Start here: its status and its answer.
async fn change(
    app: &Router,
    cookie: &str,
    path: &str,
    body: Value,
) -> Result<(StatusCode, Value), Box<dyn std::error::Error>> {
    let (status, _, text) = send(app, api_post(&format!("start/{path}"), cookie, body)?).await?;
    Ok((status, serde_json::from_str(&text)?))
}

/// Every block anywhere in `v` whose `type` is `kind`.
fn blocks<'a>(v: &'a Value, kind: &str, out: &mut Vec<&'a Value>) {
    match v {
        Value::Object(map) => {
            if map.get("type").and_then(Value::as_str) == Some(kind) {
                out.push(v);
            }
            for item in map.values() {
                blocks(item, kind, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                blocks(item, kind, out);
            }
        }
        _ => {}
    }
}

/// The lines block `id`, as Copy copies it.
fn lines(state: &Value, id: &str) -> String {
    let mut found = Vec::new();
    blocks(state, "lines", &mut found);
    found
        .iter()
        .find(|b| b["id"] == id)
        .and_then(|b| b["lines"].as_array())
        .map(|l| {
            l.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

/// Whether a form or a button posts to `action`.
fn posts(state: &Value, action: &str) -> bool {
    let mut found = Vec::new();
    blocks(state, "form", &mut found);
    blocks(state, "button", &mut found);
    found.iter().any(|b| b["action"] == action)
}

fn states(state: &Value) -> Vec<String> {
    state["states"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn step<'a>(state: &'a Value, title: &str) -> &'a Value {
    state["steps"]
        .as_array()
        .and_then(|s| s.iter().find(|s| s["title"] == title))
        .unwrap_or(&Value::Null)
}

#[tokio::test]
async fn the_old_addresses_land_on_the_app_route() -> TestResult {
    let s = setup("moved")?;
    // No session needed: the app asks for one, and sign-in comes back to the app route.
    for (path, to) in [
        ("/console/start", "/console/app/#/start"),
        (
            "/console/start?track=coding&pay=subscriptions&setup=mdm",
            "/console/app/#/start?track=coding&pay=subscriptions&setup=mdm",
        ),
        ("/console/start?pick=1", "/console/app/#/start?pick=1"),
        (
            "/console/start/state.json?pay=api",
            "/console/api/start?pay=api",
        ),
    ] {
        let (status, headers, _) = send(&s.app, get(path, "")?).await?;
        assert_eq!((status, location(&headers)), (StatusCode::SEE_OTHER, to));
    }
    // The old form routes are gone: the app posts to the API.
    let cookie = sign_in(&s.app, ADMIN_KEY).await?;
    let (status, _, _) = send(&s.app, post("/console/start/pick", &cookie, "choice=apps")?).await?;
    assert_ne!(status, StatusCode::SEE_OTHER);
    assert!(!s.dir.join("enterplace-start.json").exists());
    Ok(())
}

#[tokio::test]
async fn an_empty_install_opens_on_the_welcome_and_the_choice_is_kept() -> TestResult {
    let s = setup("welcome")?;
    let cookie = sign_in(&s.app, ADMIN_KEY).await?;
    // The brand and the root open Start here.
    let (_, headers, _) = send(&s.app, get("/console", &cookie)?).await?;
    assert_eq!(location(&headers), "/console/start");
    let state = start(&s.app, &cookie, "").await?;
    assert_eq!(state["view"], "welcome", "{state}");
    assert_eq!(state["base"], BASE);
    assert_eq!(state["may_choose"], true);
    let tracks = state["tracks"].to_string();
    for part in [
        "Coding agents",
        "Our own apps and agents",
        "MCP tools",
        "A spend limit for the team",
        "Claude Team seats we can only watch",
        "coding agents",
    ] {
        assert!(tracks.contains(part), "{part}: {tracks}");
    }
    // The signed-in person's own token, as the start link makes it, leaves the install empty.
    let (status, _) = change(
        &s.app,
        &cookie,
        "key",
        json!({ "kind": "person_token", "name": "noa.bar", "team": "platform" }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(start(&s.app, &cookie, "").await?["view"], "welcome");

    let (status, answer) = change(&s.app, &cookie, "pick", json!({ "choice": "apps" })).await?;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let kept = std::fs::read_to_string(s.dir.join("enterplace-start.json"))?;
    assert!(kept.contains(r#""choice":"apps""#), "{kept}");
    let audit = std::fs::read_to_string(s.dir.join("enterplace-audit.jsonl"))?;
    assert!(
        audit.contains(r#""action":"start_choice""#),
        "the choice is recorded"
    );
    let state = start(&s.app, &cookie, "").await?;
    assert_eq!(state["lead"], "Our own apps and agents: 1 of 5 done.");

    // Changed later, and skipped: Start here shows the pick in the console.
    let state = start(&s.app, &cookie, "pick=1").await?;
    assert_eq!(state["view"], "pick", "{state}");
    let (status, _) = change(&s.app, &cookie, "pick", json!({ "skip": "1" })).await?;
    assert_eq!(status, StatusCode::OK);
    let kept = std::fs::read_to_string(s.dir.join("enterplace-start.json"))?;
    assert!(kept.contains(r#""skipped":true"#), "{kept}");
    // Nothing picked: the answer names the choices.
    let (status, answer) = change(&s.app, &cookie, "pick", json!({ "choice": "nope" })).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        answer["error"].to_string().contains("coding, apps"),
        "{answer}"
    );
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
                "Make a key for the first person",
                "Point your coding agent at Enterplace and send one prompt",
                "Add a second person",
                "Let people make their own keys",
            ],
        ),
        (
            "apps",
            &[
                "Make a key for the app",
                "Point your app at Enterplace and send one request",
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
        change(&s.app, &cookie, "pick", json!({ "choice": choice })).await?;
        let state = start(&s.app, &cookie, "").await?;
        let text = state.to_string();
        for part in parts {
            assert!(text.contains(part), "{choice}: {part}");
        }
        // The step in front holds what to do, and its prompt for a coding agent.
        assert!(states(&state).contains(&"now".to_string()), "{choice}");
        let open = state["steps"]
            .as_array()
            .and_then(|s| s.iter().find(|s| s["state"] == "now"))
            .ok_or("no current step")?;
        assert!(!open["agent"].as_str().unwrap_or("").is_empty(), "{choice}");
        for gone in [
            "Turns done when",
            "Then you see",
            "Paste it into Claude Code",
        ] {
            assert!(!text.contains(gone), "{choice}: {gone}");
        }
    }
    // Coding agents asks how the team pays, API keys first.
    let state = start(&s.app, &cookie, "track=coding").await?;
    assert_eq!(state["pay"], "api");
    // A policy kept in the file: the lines come with Copy and the file's path, no draft button.
    let state = start(&s.app, &cookie, "track=mcp").await?;
    let mut policy = Vec::new();
    blocks(&state, "policy", &mut policy);
    assert!(
        policy.iter().all(|b| b["way"]["kind"] == "copy"
            && b["way"]["path"]
                .as_str()
                .is_some_and(|p| p.ends_with("enterplace.policy.yaml"))),
        "{state}"
    );
    assert!(!state.to_string().contains("/console/policy/edit?add="));
    // Tabs pick the tool's lines by the route's query.
    change(
        &s.app,
        &cookie,
        "key",
        json!({ "kind": "person", "name": "sarah.miller", "team": "platform", "pay": "api" }),
    )
    .await?;
    let state = start(&s.app, &cookie, "track=coding&pay=api").await?;
    assert!(
        lines(&state, "lines-coding").contains(&format!("export ANTHROPIC_BASE_URL={BASE}")),
        "{state}"
    );
    let state = start(&s.app, &cookie, "track=coding&pay=api&tool=codex").await?;
    assert!(
        lines(&state, "lines-coding").contains(&format!("base_url = \"{BASE}/v1\"")),
        "{state}"
    );
    // Gemini CLI has its own lines, and the tabs keep the API key answer instead of falling back to subscriptions.
    let state = start(&s.app, &cookie, "track=coding&pay=api&tool=gemini").await?;
    assert!(
        lines(&state, "lines-coding").contains(&format!("export GOOGLE_GEMINI_BASE_URL={BASE}")),
        "{state}"
    );
    let mut found = Vec::new();
    blocks(&state, "lines", &mut found);
    let tabs = &found
        .iter()
        .find(|b| b["id"] == "lines-coding")
        .ok_or("no lines")?["tabs"];
    assert_eq!(tabs["param"], "tool");
    assert_eq!(tabs["keep"]["pay"], "api");
    assert_eq!(tabs["selected"], "gemini");
    let state = start(&s.app, &cookie, "track=apps").await?;
    assert!(
        state["viewing"]
            .as_str()
            .is_some_and(|v| v.contains("Showing Our own apps and agents")),
        "{state}"
    );
    Ok(())
}

#[tokio::test]
async fn a_key_made_on_the_checklist_shows_once_and_a_request_turns_its_step_done() -> TestResult {
    let s = setup("live")?;
    let cookie = sign_in(&s.app, ADMIN_KEY).await?;
    change(&s.app, &cookie, "pick", json!({ "choice": "coding" })).await?;
    // Connect a model is done (the policy has a provider); Send your first request listens.
    let before = start(&s.app, &cookie, "pay=api").await?;
    assert_eq!(
        states(&before),
        ["done", "listening", "ahead", "ahead", "ahead", "ahead"]
    );
    request(&s, "01START0000000000000000000", "noa.bar", "platform")?;
    let before = start(&s.app, &cookie, "pay=api").await?;
    assert_eq!(
        states(&before),
        ["done", "done", "now", "ahead", "ahead", "ahead"]
    );

    let (status, made) = change(
        &s.app,
        &cookie,
        "key",
        json!({ "kind": "person", "name": "sarah.miller", "team": "platform", "pay": "api" }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{made}");
    let keys = std::fs::read_to_string(s.dir.join("enterplace.keys.yaml"))?;
    assert!(keys.contains("name: sarah.miller"), "{keys}");
    // The key is in the lines to paste, once, and in the banner; the step that waits for traffic listens.
    let shown = &made["state"];
    assert_eq!(made["query"], "track=coding&pay=api");
    assert!(
        lines(shown, "lines-coding").contains("export ANTHROPIC_API_KEY=enterplace_"),
        "{shown}"
    );
    assert!(
        shown["made"]["key"]
            .as_str()
            .is_some_and(|k| k.starts_with("enterplace_"))
    );
    let listening = step(
        shown,
        "Point your coding agent at Enterplace and send one prompt",
    );
    assert_eq!(listening["state"], "listening");
    assert_eq!(
        listening["listen"],
        "Waiting for the first request from sarah.miller."
    );
    assert_eq!(listening["open"]["href"], "/console/requests");
    let later = start(&s.app, &cookie, "track=coding&pay=api").await?;
    assert!(
        !later
            .to_string()
            .contains("export ANTHROPIC_API_KEY=enterplace_"),
        "shown once"
    );
    assert!(later["made"].is_null());
    assert!(
        lines(&later, "lines-coding").contains("<key of sarah.miller>"),
        "{later}"
    );
    // The view held with the key and the one polled agree until a step changes.
    assert_eq!(later["signature"], shown["signature"]);

    let waiting = start(&s.app, &cookie, "pay=api").await?;
    assert_eq!(
        states(&waiting),
        ["done", "done", "done", "listening", "ahead", "ahead"]
    );
    request(&s, "01START0000000000000000001", "sarah.miller", "platform")?;
    let arrived = start(&s.app, &cookie, "pay=api").await?;
    assert_eq!(
        states(&arrived),
        ["done", "done", "done", "done", "now", "ahead"]
    );
    assert_ne!(
        waiting["signature"], arrived["signature"],
        "the app shows the new state"
    );
    assert!(
        step(
            &arrived,
            "Point your coding agent at Enterplace and send one prompt"
        )["done_text"]
            .as_str()
            .is_some_and(|t| t.contains("`sarah.miller`") && t.contains("claude-code, ")),
        "{arrived}"
    );

    // The first data on Start here, with the next step under it.
    // The live strip: tools, the gate, providers, a count of the last 10 minutes and the newest requests.
    assert!(
        arrived["lead"]
            .as_str()
            .is_some_and(|l| l.starts_with("Your first requests arrived")),
        "{arrived}"
    );
    let live = &arrived["live"];
    assert!(
        live["count"]
            .as_str()
            .is_some_and(|c| c.contains("in the last 10 minutes")),
        "{live}"
    );
    assert_eq!(live["tools"][0], "claude-code");
    assert_eq!(live["providers"][0], "anthropic");
    assert_eq!(live["rows"][0]["model"], "claude-sonnet-5-5");
    assert_eq!(live["rows"][0]["refused"], false);
    assert_eq!(live["rows"][0]["id"], "01START0000000000000000001");
    assert!(step(&arrived, "Add a second person")["state"] == "now");

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
    let state = start(&s.app, &cookie, "pay=api").await?;
    assert_eq!(state["banner"], true, "{state}");
    assert_eq!(state["complete"], true);
    change(&s.app, &cookie, "pick", json!({ "steps": "1" })).await?;
    let state = start(&s.app, &cookie, "pay=api").await?;
    assert_eq!(state["view"], "folded", "{state}");
    let names: Vec<&Value> = state["stages"]["steps"]
        .as_array()
        .map(|s| s.iter().map(|s| &s["name"]).collect())
        .unwrap_or_default();
    assert_eq!(names, ["See", "Know", "Limit", "Protect", "Prove"]);
    assert_eq!(state["stages"]["current"]["n"], 3, "Step 3 of 5");
    assert_eq!(state["others"].as_array().map(Vec::len), Some(4));
    // Show the steps.
    let state = start(&s.app, &cookie, "pay=api&view=checklist").await?;
    assert_eq!(state["view"], "checklist");
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
    // The raw policy is in the app: its API carries the first-run state, its button naming the budget step.
    let request = Request::get("/console/api/policy/raw")
        .header(header::HOST, HOST)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())?;
    let (_, _, raw) = send(&s.app, request).await?;
    let raw: serde_json::Value = serde_json::from_str(&raw)?;
    assert_eq!(raw["next"]["title"], "One rule lets everyone in", "{raw}");
    assert_eq!(
        raw["next"]["action"]["href"],
        "/console/start?track=limit#step-5"
    );
    assert_eq!(raw["next"]["action"]["label"], "Add a budget");
    assert_eq!(
        raw["next"]["docs"],
        "https://docs.enterplace.dev/governance/policy/"
    );
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
    // Teams is in the app: only admin keys so far is no team yet.
    let request = Request::get("/console/api/teams")
        .header(header::HOST, HOST)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())?;
    let (_, _, teams) = send(&s.app, request).await?;
    let teams: serde_json::Value = serde_json::from_str(&teams)?;
    assert_eq!(teams["empty"]["title"], "No teams yet", "{teams}");
    assert_eq!(
        teams["empty"]["action"]["href"],
        "/console/start?track=coding#step-2"
    );
    assert_eq!(
        teams["empty"]["docs"],
        "https://docs.enterplace.dev/governance/teams/"
    );
    Ok(())
}

#[tokio::test]
async fn a_role_sees_only_the_actions_it_may_take() -> TestResult {
    let s = setup("roles")?;
    let admin = sign_in(&s.app, ADMIN_KEY).await?;
    change(&s.app, &admin, "pick", json!({ "choice": "coding" })).await?;
    request(&s, "01START0000000000000000000", "noa.bar", "platform")?;
    let viewer = sign_in(&s.app, VIEWER_KEY).await?;
    let state = start(&s.app, &viewer, "pay=api").await?;
    let text = state.to_string();
    assert!(text.contains("Make a key for the first person"), "{text}");
    assert!(!posts(&state, "key"), "no key form: {state}");
    assert_eq!(state["may_choose"], false, "no Change what to start with");
    assert!(text.contains("Your role cannot make keys"), "{text}");
    let state = start(&s.app, &viewer, "pay=subscriptions").await?;
    assert!(
        !posts(&state, "passthrough") && !posts(&state, "key"),
        "no forms: {state}"
    );
    // Its own changes are refused and recorded, whatever it sends.
    let (status, answer) = change(
        &s.app,
        &viewer,
        "key",
        json!({ "kind": "person", "name": "x", "team": "y" }),
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    assert!(
        answer["error"]
            .to_string()
            .contains("Your role cannot make keys")
    );
    let keys = std::fs::read_to_string(s.dir.join("enterplace.keys.yaml"))?;
    assert!(!keys.contains("name: x\n"), "{keys}");
    let (status, _) = change(&s.app, &viewer, "pick", json!({ "choice": "mcp" })).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = change(&s.app, &viewer, "passthrough", json!({})).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = change(&s.app, &viewer, "demo", json!({})).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let kept = std::fs::read_to_string(s.dir.join("enterplace-start.json"))?;
    assert!(kept.contains(r#""choice":"coding""#), "{kept}");
    let audit = std::fs::read_to_string(s.dir.join("enterplace-audit.jsonl"))?;
    assert!(
        audit.contains(r#""action":"issue_key""#) && audit.contains("read_only"),
        "{audit}"
    );
    // A change from another site is refused.
    let request = Request::post("/console/api/start/pick")
        .header(header::HOST, HOST)
        .header(header::ORIGIN, "http://evil.example")
        .header(header::COOKIE, &admin)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"choice":"mcp"}"#))?;
    let (status, _, _) = send(&s.app, request).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // Not signed in: the app sends the person to sign in.
    let (status, _, _) = send(&s.app, api_get("start", "")?).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Empty pages offer it the docs, not the action.
    let request = Request::get("/console/api/teams")
        .header(header::HOST, HOST)
        .header(header::COOKIE, &viewer)
        .body(Body::empty())?;
    let (_, _, teams) = send(&s.app, request).await?;
    let teams: serde_json::Value = serde_json::from_str(&teams)?;
    assert!(
        teams["empty"]["title"] == "No teams yet"
            && teams["empty"].get("action").is_none()
            && teams["issue"] == false,
        "{teams}"
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
    change(&s.app, &cookie, "pick", json!({ "choice": "apps" })).await?;
    let state = start(&s.app, &cookie, "").await?;
    let text = state.to_string();
    for part in [
        "Connect a model",
        "Try without a key",
        "Send your first request",
    ] {
        assert!(text.contains(part), "{part}: {text}");
    }
    assert!(posts(&state, "demo"));
    // No master key and no store: the page says how to get one, and the change is refused with the same fix.
    assert!(text.contains("ENTERPLACE_MASTER_KEY"), "{text}");
    assert!(!posts(&state, "connect"), "{state}");
    let (status, answer) = change(
        &s.app,
        &cookie,
        "connect",
        json!({ "provider": "anthropic", "key": "sk-ant-test-1234" }),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        answer["error"].to_string().contains("master key"),
        "{answer}"
    );

    // Try without a key: the first request names the demo model.
    let (status, answer) = change(&s.app, &cookie, "demo", json!({})).await?;
    assert_eq!(
        (status, &answer["query"]),
        (StatusCode::OK, &json!("pay=api"))
    );
    let state = start(&s.app, &cookie, "").await?;
    assert!(
        step(&state, "Connect a model")["done_text"]
            .as_str()
            .is_some_and(|t| t.starts_with("Using the demo model")),
        "{state}"
    );
    let first = lines(&state, "lines-first");
    assert!(
        first.contains("\"model\":\"enterplace-demo\"")
            && first.contains(&format!("curl {BASE}/v1/chat/completions")),
        "{first}"
    );

    // A key for the first request: in the lines, shown once, and no person's or app's key.
    let (status, made) = change(&s.app, &cookie, "first-key", json!({})).await?;
    assert_eq!(status, StatusCode::OK, "{made}");
    assert!(
        lines(&made["state"], "lines-first").contains("Authorization: Bearer enterplace_"),
        "{made}"
    );
    let state = start(&s.app, &cookie, "tool=python").await?;
    assert!(
        lines(&state, "lines-first").contains("os.environ[\"ENTERPLACE_KEY\"]"),
        "{state}"
    );
    assert!(
        state.to_string().contains("Make a key for the app"),
        "{state}"
    );
    assert_eq!(
        states(&state),
        ["done", "listening", "ahead", "ahead", "ahead"]
    );

    // With a place to keep it, the key is sealed and the provider joins the policy, reading that credential.
    let vault: Arc<dyn enterplace_core::store::Credentials> = Arc::new(Vault::default());
    enterplace_core::store::attach_credentials(&s.dir.join("enterplace.keys.yaml"), &vault);
    std::fs::write(
        enterplace_core::store::credentials_file(&s.dir.join("enterplace.policy.yaml")),
        "[]",
    )?;
    let (status, answer) = change(
        &s.app,
        &cookie,
        "connect",
        json!({ "provider": "anthropic", "key": "sk-ant-test-1234" }),
    )
    .await?;
    assert_eq!(
        (status, &answer["query"]),
        (StatusCode::OK, &json!("pay=api")),
        "{answer}"
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
    assert!(
        !answer.to_string().contains("sk-ant-test-1234"),
        "nor in the answer"
    );
    let state = start(&s.app, &cookie, "").await?;
    assert!(
        step(&state, "Connect a model")["done_text"]
            .as_str()
            .is_some_and(|t| t.starts_with("Connected: `anthropic`")),
        "{state}"
    );
    assert!(
        lines(&state, "lines-first").contains("\"model\":\"claude-sonnet-5-5\""),
        "{state}"
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
    change(&s.app, &cookie, "pick", json!({ "choice": "coding" })).await?;

    // API keys are the default answer, since every coding agent takes them. Picking subscriptions shows their
    // steps, and the first one turns them on with one click.
    let state = start(&s.app, &cookie, "").await?;
    assert_eq!(state["pay"], "api");
    let state = start(&s.app, &cookie, "pay=subscriptions").await?;
    assert_eq!(state["pay"], "subscriptions");
    assert_eq!(state["query"], "track=coding&pay=subscriptions");
    assert!(posts(&state, "passthrough"), "{state}");
    assert!(
        !state.to_string().contains("ANTHROPIC_API_KEY="),
        "no API key anywhere: {state}"
    );
    assert_eq!(states(&state), ["now", "ahead", "ahead", "ahead"]);
    let (status, answer) = change(&s.app, &cookie, "passthrough", json!({})).await?;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["query"], "track=coding&pay=subscriptions");
    let policy = std::fs::read_to_string(s.dir.join("enterplace.policy.yaml"))?;
    assert!(
        policy.contains("auth: passthrough") && policy.contains("identity: optional"),
        "{policy}"
    );
    let state = start(&s.app, &cookie, "pay=subscriptions").await?;
    assert_eq!(states(&state), ["done", "listening", "ahead", "ahead"]);

    // A person token, not a key: the lines keep Claude Code's own login.
    let (status, made) = change(
        &s.app,
        &cookie,
        "key",
        json!({ "kind": "person_token", "name": "sarah.miller", "team": "platform" }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{made}");
    let shown = &made["state"];
    assert_eq!(made["query"], "track=coding&pay=subscriptions");
    assert_eq!(shown["made"]["word"], "Person token");
    let token = shown["made"]["key"].as_str().unwrap_or("").to_string();
    assert!(token.starts_with("enterplace_u_"), "{token}");
    let pasted = lines(shown, "lines-subscription");
    assert!(
        pasted.contains(&format!("export ANTHROPIC_BASE_URL={BASE}"))
            && pasted.contains(&format!(
                "export ANTHROPIC_CUSTOM_HEADERS=\"x-enterplace-user: {token}\""
            ))
            && pasted.contains("keep using your normal Claude login"),
        "{pasted}"
    );
    assert!(!shown.to_string().contains("ANTHROPIC_API_KEY="), "{shown}");
    // Copy for your agent: the goal, the exact values and the docs as Markdown.
    let prompt = step(shown, "Point Claude Code at Enterplace")["agent"]
        .as_str()
        .unwrap_or("")
        .to_string();
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
    // Managed settings for an MDM rollout.
    let state = start(&s.app, &cookie, "setup=mdm&pay=subscriptions").await?;
    assert!(
        lines(&state, "lines-subscription")
            .contains("\"ANTHROPIC_CUSTOM_HEADERS\": \"x-enterplace-user:"),
        "{state}"
    );
    assert!(
        state.to_string().contains("managed-settings.json"),
        "{state}"
    );

    // The step turns done when the first subscription request from that person arrives.
    let keys = std::fs::read_to_string(s.dir.join("enterplace.keys.yaml"))?;
    assert!(keys.contains(&sha256_hex(token.as_bytes())), "{keys}");
    subscribed(&s, "01SUB00000000000000000000", "sarah.miller", "platform")?;
    let state = start(&s.app, &cookie, "pay=subscriptions").await?;
    assert_eq!(states(&state), ["done", "done", "now", "ahead"]);
    assert!(state["live"].is_object(), "{state}");
    assert_eq!(step(&state, "Add a second person")["state"], "now");

    // Anthropic API keys keep today's steps.
    let state = start(&s.app, &cookie, "pay=api").await?;
    assert!(
        state.to_string().contains("Let people make their own keys"),
        "{state}"
    );
    Ok(())
}

#[tokio::test]
async fn the_signed_in_person_s_own_token_is_in_the_lines_and_in_the_agent_prompt() -> TestResult {
    let s = setup("mine")?;
    let cookie = sign_in(&s.app, ADMIN_KEY).await?;
    change(&s.app, &cookie, "pick", json!({ "choice": "coding" })).await?;
    change(&s.app, &cookie, "passthrough", json!({})).await?;
    // Signed in with a key, nobody made noa.bar a token yet: one button makes it in their own name.
    let state = start(&s.app, &cookie, "pay=subscriptions").await?;
    let mut buttons = Vec::new();
    blocks(&state, "button", &mut buttons);
    let mine = buttons
        .iter()
        .find(|b| b["label"] == "Make my token")
        .ok_or("no Make my token")?;
    assert_eq!(mine["action"], "key");
    assert_eq!(mine["body"]["name"], "noa.bar");
    // The provider takes unnamed requests: one line, no placeholder to paste.
    assert!(
        !lines(&state, "lines-subscription").contains("x-enterplace-user"),
        "{state}"
    );
    let (status, _) = change(&s.app, &cookie, "key", mine["body"].clone()).await?;
    assert_eq!(status, StatusCode::OK);
    // Kept for them this run: every later view carries it, in the lines and in Copy for your agent.
    let state = start(&s.app, &cookie, "pay=subscriptions").await?;
    let pasted = lines(&state, "lines-subscription");
    let token = pasted
        .split("x-enterplace-user: ")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .ok_or("no token in the lines")?
        .to_string();
    assert!(token.starts_with("enterplace_u_"), "{pasted}");
    let point = step(&state, "Point Claude Code at Enterplace");
    assert!(
        point["agent"].as_str().is_some_and(|a| a.contains(&token)),
        "{point}"
    );
    assert_eq!(
        point["listen"],
        "Waiting for the first request from noa.bar."
    );
    assert!(
        state
            .to_string()
            .contains("The lines carry your person token, so your requests show as `noa.bar`."),
        "{state}"
    );

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
        let state = start(&s.app, &cookie, &format!("track={track}")).await?;
        for step in state["steps"].as_array().cloned().unwrap_or_default() {
            let prompt = step["agent"].as_str().unwrap_or("");
            if prompt.is_empty() {
                continue;
            }
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
    // Only the current step of each holds its prompt.
    assert!(prompts >= 6, "{prompts}");
    Ok(())
}

/// The numbers of "N of M done" in a lead line.
fn done_count(lead: &str) -> Option<(usize, usize)> {
    lead.match_indices(" done").find_map(|(end, _)| {
        let (before, total) = lead[..end].rsplit_once(" of ")?;
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
        let state = start(&s.app, &cookie, query).await?;
        let (done, total) = done_count(state["lead"].as_str().unwrap_or(""))
            .ok_or_else(|| format!("{query}: no count"))?;
        let list = state["steps"].as_array().cloned().unwrap_or_default();
        assert_eq!(list.len(), total, "{query}: every step is listed");
        assert_eq!(
            list.iter().filter(|s| s["state"] == "done").count(),
            done,
            "{query}: the done steps are listed"
        );
        let connect = step(&state, "Connect a model");
        if track == "watch" || query.contains("subscriptions") {
            assert!(connect.is_null(), "{query}");
        } else {
            // Connect a model never reads Now while the first request reads Done.
            assert!(
                !step(&state, "Send your first request").is_null(),
                "{query}"
            );
            assert_eq!(connect["state"], "done", "{query}");
        }
    }
    Ok(())
}
