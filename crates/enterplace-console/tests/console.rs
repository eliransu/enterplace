//! The console through its routes, as the server mounts it: sign-in, sessions, every page, issue and revoke.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

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

const ADMIN_KEY: &str = "enterplace_admin_key_for_tests";
const MAYA_KEY: &str = "enterplace_maya_key_for_tests";
const HOST: &str = "127.0.0.1:19850";

const POLICY: &str = "\
# Who may use which model.
version: 1
providers:
  - name: openai
    kind: openai
    url: https://api.openai.com
    key_env: OPENAI_API_KEY
    models: [gpt-4o-mini, gpt-4o]
rules:
  - name: payments-team
    principals: { team: payments }
    models: [gpt-4o-mini]
  - name: everyone-else
    principals: { any: true }
    models: [\"*\"]
";

fn keys_text() -> String {
    format!(
        "keys:\n  - name: noa.bar\n    team: platform\n    sha256: {}\n    admin: true\n  - name: maya.cohen\n    team: payments\n    sha256: {}\n",
        sha256_hex(ADMIN_KEY.as_bytes()),
        sha256_hex(MAYA_KEY.as_bytes())
    )
}

struct Setup {
    app: Router,
    dir: PathBuf,
    log: Arc<AuditLog>,
}

impl Setup {
    fn keys(&self) -> PathBuf {
        self.dir.join("enterplace.keys.yaml")
    }
    fn audit(&self) -> PathBuf {
        self.dir.join("enterplace-audit.jsonl")
    }
}

fn setup(name: &str) -> Result<Setup, Box<dyn std::error::Error>> {
    let dir =
        std::env::temp_dir().join(format!("enterplace-console-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("enterplace.policy.yaml"), POLICY)?;
    std::fs::write(dir.join("enterplace.keys.yaml"), keys_text())?;
    let log = AuditLog::open(&dir.join("enterplace-audit.jsonl"))?;
    let policy_sha256 = sha256_hex(POLICY.as_bytes());
    let maya = sha256_hex(MAYA_KEY.as_bytes());
    let base = Entry {
        method: "POST",
        path: "/v1/chat/completions",
        policy_sha256: &policy_sha256,
        ..Entry::default()
    };
    log.append(&Entry {
        id: "01AAAAAAAAAAAAAAAAAAAAAAA1",
        person: Some("maya.cohen"),
        key: Some(&maya[..8]),
        team: Some("payments"),
        model: Some("gpt-4o-mini"),
        allowed: true,
        rule: Some("payments-team"),
        rule_line: Some(10),
        provider: "openai",
        ..base.clone()
    })?;
    log.append(&Entry {
        id: "01AAAAAAAAAAAAAAAAAAAAAAA2",
        person: Some("maya.cohen"),
        key: Some(&maya[..8]),
        team: Some("payments"),
        model: Some("gpt-4o"),
        code: Some("model_not_allowed"),
        rule: Some("payments-team"),
        rule_line: Some(10),
        ..base.clone()
    })?;
    log.append(&Entry {
        id: "01AAAAAAAAAAAAAAAAAAAAAAA3",
        key: Some("deadbeef"),
        model: Some("gpt-4o"),
        code: Some("unknown_key"),
        ..base
    })?;
    let log = Arc::new(log);
    let config = ConsoleConfig {
        policy: dir.join("enterplace.policy.yaml"),
        keys: dir.join("enterplace.keys.yaml"),
        audit: dir.join("enterplace-audit.jsonl"),
        // The server's own log: console actions go into the same chain as requests.
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

/// A call to the console app's JSON API, signed in with `cookie`, and its answer as JSON.
async fn call(
    app: &Router,
    method: &str,
    path: &str,
    cookie: &str,
    body: serde_json::Value,
) -> Result<(StatusCode, HeaderMap, serde_json::Value), Box<dyn std::error::Error>> {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, HOST)
        .header(header::ORIGIN, format!("http://{HOST}"))
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(if body.is_null() {
            String::new()
        } else {
            body.to_string()
        }))?;
    let (status, headers, text) = send(app, request).await?;
    Ok((
        status,
        headers,
        serde_json::from_str(&text).unwrap_or(serde_json::Value::Null),
    ))
}

/// The Spend page, as the app reads it.
async fn spend(
    app: &Router,
    cookie: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let (status, _, spend) = call(
        app,
        "GET",
        "/console/api/spend",
        cookie,
        serde_json::Value::Null,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{spend}");
    Ok(spend)
}

/// The People page's keys, as the app reads them.
async fn people(
    app: &Router,
    cookie: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let (status, _, people) = call(
        app,
        "GET",
        "/console/api/people",
        cookie,
        serde_json::Value::Null,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{people}");
    Ok(people)
}

/// One key of the People page, by name.
fn key_named<'a>(
    people: &'a serde_json::Value,
    name: &str,
) -> Result<&'a serde_json::Value, String> {
    people["entries"]
        .as_array()
        .and_then(|e| e.iter().find(|e| e["name"] == name))
        .ok_or_else(|| format!("no key for {name}: {people}"))
}

/// The audit log as the app reads it, for `query` (`verdict=refused&q=maya.cohen`, `record=<id>`).
async fn audit(
    app: &Router,
    cookie: &str,
    query: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let (status, _, page) = call(
        app,
        "GET",
        &format!("/console/api/audit?{query}"),
        cookie,
        serde_json::Value::Null,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{page}");
    Ok(page)
}

/// The sheet of one record, as the app opens it from its row.
async fn sheet(
    app: &Router,
    cookie: &str,
    record: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let page = audit(app, cookie, &format!("record={record}")).await?;
    Ok(page["record"].clone())
}

/// The audit page and its open record as one text, for checks that it says something somewhere.
async fn page_text(
    app: &Router,
    cookie: &str,
    query: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(audit(app, cookie, query).await?.to_string())
}

/// One record's sheet as text, for checks that it says something somewhere.
async fn sheet_text(
    app: &Router,
    cookie: &str,
    record: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(sheet(app, cookie, record).await?.to_string())
}

/// The value of the sheet's fact `label`, or "".
fn fact<'a>(sheet: &'a serde_json::Value, label: &str) -> &'a str {
    sheet["facts"]
        .as_array()
        .and_then(|f| f.iter().find(|f| f["label"] == label))
        .and_then(|f| f["text"].as_str())
        .unwrap_or("")
}

/// Whether a listed row carries this verdict tag.
fn has_tag(page: &serde_json::Value, kind: &str, word: &str, detail: &str) -> bool {
    let tag = serde_json::json!({ "kind": kind, "word": word, "detail": detail });
    page["rows"]
        .as_array()
        .is_some_and(|rows| rows.iter().any(|r| r["verdict"] == tag))
}

/// The IDs of the listed rows, newest first.
fn ids(page: &serde_json::Value) -> Vec<String> {
    page["rows"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|r| r["id"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Verify chain now, as the app sends it.
async fn verify(
    app: &Router,
    cookie: &str,
    chain: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let (status, _, answer) = call(
        app,
        "POST",
        "/console/api/audit/verify",
        cookie,
        serde_json::json!({ "chain": chain }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{answer}");
    Ok(answer)
}

fn location(headers: &HeaderMap) -> &str {
    headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

/// Signs in with the admin key and returns the cookie to send back.
async fn sign_in(app: &Router) -> Result<String, Box<dyn std::error::Error>> {
    let (status, headers, _) = send(
        app,
        post("/console/sign-in", "", &format!("key={ADMIN_KEY}"))?,
    )
    .await?;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .ok_or("no cookie was set")?;
    Ok(cookie.split(';').next().unwrap_or("").to_string())
}

#[tokio::test]
async fn an_admin_key_signs_in_with_a_session_cookie_that_is_not_the_key() -> TestResult {
    let s = setup("sign-in")?;
    let (status, _, page) = send(&s.app, get("/console/sign-in", "")?).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains(r#"action="/console/sign-in""#) && page.contains(r#"type="password""#));

    let (status, headers, _) = send(
        &s.app,
        post("/console/sign-in", "", &format!("key={ADMIN_KEY}"))?,
    )
    .await?;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location(&headers), "/console/start");
    let cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .ok_or("no cookie")?;
    for part in [
        "enterplace_console=",
        "HttpOnly",
        "SameSite=Strict",
        "Path=/console",
        "Max-Age=28800",
    ] {
        assert!(cookie.contains(part), "{cookie}");
    }
    assert!(
        !cookie.contains("Secure"),
        "plain HTTP got a Secure cookie: {cookie}"
    );
    assert!(
        !cookie.contains(ADMIN_KEY) && !cookie.contains(&sha256_hex(ADMIN_KEY.as_bytes())),
        "{cookie}"
    );
    let id = cookie
        .split(';')
        .next()
        .unwrap_or("")
        .trim_start_matches("enterplace_console=");
    assert_eq!(id.len(), 64, "{id}");

    // Behind a proxy that terminates TLS, the cookie is Secure.
    let mut tls = post("/console/sign-in", "", &format!("key={ADMIN_KEY}"))?;
    tls.headers_mut()
        .insert("x-forwarded-proto", "https".parse()?);
    tls.headers_mut()
        .insert(header::ORIGIN, format!("https://{HOST}").parse()?);
    let (_, headers, _) = send(&s.app, tls).await?;
    assert!(
        headers
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|c| c.contains("; Secure"))
    );
    Ok(())
}

#[tokio::test]
async fn a_wrong_key_or_a_key_that_is_not_an_admin_is_refused_with_the_error_state() -> TestResult {
    let s = setup("wrong-key")?;
    for key in ["enterplace_nobody", MAYA_KEY, ""] {
        let (status, headers, page) =
            send(&s.app, post("/console/sign-in", "", &format!("key={key}"))?).await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{key}");
        assert!(headers.get(header::SET_COOKIE).is_none(), "{key}");
        assert!(
            page.contains(r#"aria-invalid="true""#) && page.contains("g-field__error"),
            "{key}"
        );
    }
    // The same answer for an unknown key and a known one without admin: the page does not say which keys exist.
    let (_, _, unknown) = send(
        &s.app,
        post("/console/sign-in", "", "key=enterplace_nobody")?,
    )
    .await?;
    let (_, _, member) = send(
        &s.app,
        post("/console/sign-in", "", &format!("key={MAYA_KEY}"))?,
    )
    .await?;
    assert_eq!(unknown, member);
    Ok(())
}

#[tokio::test]
async fn a_form_from_another_site_is_refused() -> TestResult {
    let s = setup("origin")?;
    let mut request = post("/console/sign-in", "", &format!("key={ADMIN_KEY}"))?;
    request
        .headers_mut()
        .insert(header::ORIGIN, "http://evil.example".parse()?);
    let (status, headers, _) = send(&s.app, request).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(headers.get(header::SET_COOKIE).is_none());
    let mut bare = post("/console/sign-in", "", &format!("key={ADMIN_KEY}"))?;
    bare.headers_mut().remove(header::ORIGIN);
    assert_eq!(send(&s.app, bare).await?.0, StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn every_page_needs_a_live_session_except_sign_in_and_its_assets() -> TestResult {
    let s = setup("session")?;
    for path in [
        "/console",
        // People and the audit log moved to the app: their old addresses only point there, and the app needs the
        // session.
        "/console/app/",
    ] {
        for cookie in ["", "enterplace_console=not-a-session"] {
            let (status, headers, page) = send(&s.app, get(path, cookie)?).await?;
            assert_eq!(status, StatusCode::SEE_OTHER, "{path} {cookie}");
            // Sent to sign in, naming the page to come back to.
            assert!(
                location(&headers).starts_with("/console/sign-in?next=%2Fconsole"),
                "{path}: {}",
                location(&headers)
            );
            assert!(!page.contains("maya.cohen"), "{path}");
        }
    }
    // Spend moved to the app: its API refuses without a session, and the old address only points at the app.
    let (status, _, refused) = call(
        &s.app,
        "GET",
        "/console/api/spend",
        "enterplace_console=forged",
        serde_json::Value::Null,
    )
    .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{refused}");
    assert!(!refused.to_string().contains("maya.cohen"), "{refused}");
    for path in ["/console/spend", "/console/spend?menu=1"] {
        let (status, headers, _) = send(&s.app, get(path, "")?).await?;
        assert_eq!(
            (status, location(&headers)),
            (StatusCode::SEE_OTHER, "/console/app/#/usage/spend"),
            "{path}"
        );
    }
    // The old address of the audit log keeps what it asked for on the way to the app, session or not.
    let (status, headers, page) = send(
        &s.app,
        get(
            "/console/audit?record=01AAAAAAAAAAAAAAAAAAAAAAA1&verdict=refused",
            "",
        )?,
    )
    .await?;
    assert_eq!(
        (status, location(&headers)),
        (
            StatusCode::SEE_OTHER,
            "/console/app/#/audit?verdict=refused&record=01AAAAAAAAAAAAAAAAAAAAAAA1"
        )
    );
    assert!(!page.contains("maya.cohen"));
    let (status, _, page) = call(
        &s.app,
        "GET",
        "/console/api/audit",
        "enterplace_console=forged",
        serde_json::Value::Null,
    )
    .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!page.to_string().contains("maya.cohen"));
    for (path, body) in [
        (
            "/console/api/people/issue",
            serde_json::json!({ "name": "x", "team": "y" }),
        ),
        (
            "/console/api/people/revoke",
            serde_json::json!({ "sha256": "00", "confirm": "x" }),
        ),
        (
            "/console/api/audit/verify",
            serde_json::json!({ "chain": "" }),
        ),
        (
            "/console/api/audit/restore",
            serde_json::json!({ "scope": "all", "value": "" }),
        ),
    ] {
        let (status, _, refused) =
            call(&s.app, "POST", path, "enterplace_console=forged", body).await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
        assert!(
            refused["error"].as_str().unwrap_or("").contains("Sign in"),
            "{refused}"
        );
    }
    assert!(
        std::fs::read_to_string(s.keys())?.lines().count() == keys_text().lines().count(),
        "a key was written without a session"
    );
    for asset in [
        "/console/assets/bundle.css",
        "/console/assets/tokens.css",
        "/console/assets/console.js",
        "/console/assets/fonts/FamiljenGrotesk-Variable.woff2",
    ] {
        assert_eq!(
            send(&s.app, get(asset, "")?).await?.0,
            StatusCode::OK,
            "{asset}"
        );
    }

    let cookie = sign_in(&s.app).await?;
    let (status, _, me) = call(
        &s.app,
        "GET",
        "/console/api/me",
        &cookie,
        serde_json::Value::Null,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert!(me["name"] == "noa.bar" && me["role"] == "admin", "{me}");
    let (status, headers, _) = send(&s.app, get("/console/app/", &cookie)?).await?;
    assert_eq!(status, StatusCode::OK);
    let csp = headers
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(csp.contains("default-src 'self'"), "{csp}");
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );

    // Sign out ends the session on the server, not only in the browser.
    let (status, headers, _) = send(&s.app, get("/console/sign-out", &cookie)?).await?;
    assert_eq!(
        (status, location(&headers)),
        (StatusCode::SEE_OTHER, "/console/sign-in?out=1")
    );
    assert!(
        headers
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|c| c.contains("Max-Age=0"))
    );
    assert_eq!(
        send(&s.app, get("/console/app/", &cookie)?).await?.0,
        StatusCode::SEE_OTHER
    );

    // A key that is no longer an admin's ends its sessions at the next request.
    let cookie = sign_in(&s.app).await?;
    std::fs::write(s.keys(), keys_text().replace("    admin: true\n", ""))?;
    assert_eq!(
        send(&s.app, get("/console/app/", &cookie)?).await?.0,
        StatusCode::SEE_OTHER
    );
    std::fs::write(s.keys(), keys_text())?;
    assert_eq!(
        send(&s.app, get("/console/app/", &cookie)?).await?.0,
        StatusCode::SEE_OTHER,
        "a dropped session came back"
    );
    Ok(())
}

#[tokio::test]
async fn the_audit_log_shows_records_newest_first_with_filters_and_a_record_sheet() -> TestResult {
    let s = setup("audit")?;
    let cookie = sign_in(&s.app).await?;
    let page = audit(&s.app, &cookie, "").await?;
    let listed = ids(&page);
    let (first, last) = (
        listed
            .iter()
            .position(|id| id == "01AAAAAAAAAAAAAAAAAAAAAAA3")
            .ok_or("no record 3")?,
        listed
            .iter()
            .position(|id| id == "01AAAAAAAAAAAAAAAAAAAAAAA1")
            .ok_or("no record 1")?,
    );
    assert!(first < last, "not newest first");
    let text = page.to_string();
    assert!(
        text.contains("model not allowed")
            && text.contains("key hash deadbeef")
            && page["pager"]["text"] == "1 to 4 of 4 decisions",
        "{page}"
    );
    assert!(
        page["verified"]["text"]
            .as_str()
            .unwrap_or("")
            .contains("has not been verified")
    );

    let refused = audit(&s.app, &cookie, "verdict=refused").await?;
    assert!(
        !ids(&refused).contains(&"01AAAAAAAAAAAAAAAAAAAAAAA1".to_string())
            && refused["pager"]["text"] == "1 to 2 of 2 decisions"
    );
    let model = audit(&s.app, &cookie, "model=gpt-4o-mini").await?;
    assert_eq!(model["pager"]["text"], "1 to 1 of 1 decisions");
    assert_eq!(ids(&model), ["01AAAAAAAAAAAAAAAAAAAAAAA1"]);
    let person = audit(&s.app, &cookie, "q=maya.cohen").await?;
    assert!(
        person["pager"]["text"] == "1 to 2 of 2 decisions"
            && !ids(&person).contains(&"01AAAAAAAAAAAAAAAAAAAAAAA3".to_string())
    );
    let none = audit(&s.app, &cookie, "q=nobody").await?;
    assert_eq!(none["rows"], serde_json::json!([]));
    assert_eq!(none["matched"], 0);

    let page = audit(&s.app, &cookie, "record=01AAAAAAAAAAAAAAAAAAAAAAA2").await?;
    let opened = &page["record"];
    assert!(
        opened["title"] == "This model is not allowed for this person"
            && opened["lead"]
                .as_str()
                .unwrap_or("")
                .contains("does not list gpt-4o"),
        "{opened}"
    );
    for label in ["Record", "Record hash", "Previous", "Policy file"] {
        assert!(!fact(opened, label).is_empty(), "{label}: {opened}");
    }
    assert_eq!(fact(opened, "Rule"), "payments-team, line 10");
    assert_eq!(fact(opened, "Request"), "POST /v1/chat/completions");
    let hit = opened["snippet"]["lines"]
        .as_array()
        .and_then(|l| l.iter().find(|l| l["kind"] == "hit"))
        .ok_or("no deciding line")?;
    assert_eq!(hit["n"], 10);
    assert_eq!(opened["actions"][0]["label"], "Open policy at line 10");
    assert!(page["rows"].as_array().is_some_and(|rows| {
        rows.iter()
            .any(|r| r["id"] == "01AAAAAAAAAAAAAAAAAAAAAAA2" && r["selected"] == true)
    }));
    // An ID that is in no record says so, instead of opening nothing.
    let missing = sheet(&s.app, &cookie, "01NOSUCHRECORD").await?;
    assert_eq!(missing["title"], "No record has this ID");
    Ok(())
}

#[tokio::test]
async fn verify_chain_now_reports_an_unbroken_chain_and_a_broken_one() -> TestResult {
    let s = setup("verify")?;
    let cookie = sign_in(&s.app).await?;
    let answer = verify(&s.app, &cookie, "").await?;
    // Records 1 to 3 are requests; record 4 is the sign-in.
    assert_eq!(
        answer["message"],
        "Chain verified: unbroken from record 1 to record 4."
    );
    let page = audit(&s.app, &cookie, "").await?;
    let (_, last) = enterplace_core::audit::verify(&s.audit())?;
    assert!(
        page["verified"]["text"]
            .as_str()
            .unwrap_or("")
            .contains("unbroken from record 1 to record 4")
            && page["verified"]["last_hash"] == last.as_str()
            && page["verified"]["recent"] == true,
        "{page}"
    );

    let text = std::fs::read_to_string(s.audit())?;
    std::fs::write(s.audit(), text.replacen("gpt-4o\"", "gpt-5o\"", 1))?;
    verify(&s.app, &cookie, "").await?;
    let page = audit(&s.app, &cookie, "").await?;
    let banner = page["verified"]["banner"].as_str().unwrap_or("");
    assert!(
        banner.starts_with("The chain is broken") && banner.contains("record 2"),
        "{page}"
    );
    assert_eq!(page["verified"]["open"]["label"], "Open record 2");
    // A broken chain hides today's figures and warns over the list.
    assert!(page["stats"].is_null() && page["caution"] == true, "{page}");
    Ok(())
}

#[tokio::test]
async fn people_policy_and_spend_render_from_the_files() -> TestResult {
    let s = setup("pages")?;
    let cookie = sign_in(&s.app).await?;
    // The old address opens the same view in the app.
    let (status, headers, _) = send(&s.app, get("/console/people", &cookie)?).await?;
    assert_eq!(
        (status, location(&headers)),
        (StatusCode::SEE_OTHER, "/console/app/#/people")
    );
    let people = people(&s.app, &cookie).await?;
    let maya = &sha256_hex(MAYA_KEY.as_bytes())[..8];
    let row = key_named(&people, "maya.cohen")?;
    assert_eq!(
        (row["team"].as_str(), row["hash"].as_str()),
        (Some("payments"), Some(maya))
    );
    let admin = key_named(&people, "noa.bar")?;
    assert_eq!(
        (admin["team"].as_str(), admin["admin"].as_bool()),
        (Some("platform"), Some(true))
    );
    assert_eq!(
        people["lead"],
        "2 keys for 2 people and apps in 2 teams. A key is shown once: Enterplace keeps only its hash."
    );
    // maya.cohen sent two requests; noa.bar none.
    assert_eq!(
        (row["requests"].as_u64(), admin["last"].as_str()),
        (Some(2), Some("never"))
    );

    // The raw policy moved to the app: the old address keeps the line it asked for.
    let (status, headers, _) = send(&s.app, get("/console/policy?line=10", &cookie)?).await?;
    assert_eq!(
        (status, location(&headers)),
        (StatusCode::SEE_OTHER, "/console/app/#/policy/raw?line=10")
    );
    let (status, _, policy) = call(
        &s.app,
        "GET",
        "/console/api/policy/raw",
        &cookie,
        serde_json::Value::Null,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{policy}");
    assert!(
        policy["lines"].as_array().is_some_and(|l| l.len() >= 15) && policy["lines"][14]["n"] == 15,
        "{policy}"
    );
    let rules = policy["rules"].to_string();
    assert!(
        rules.contains("payments-team")
            && rules.contains("Team payments may use gpt-4o-mini")
            && rules.contains("Everyone else may use every model"),
        "{rules}"
    );
    assert!(
        policy["providers"]
            .to_string()
            .contains("openai at https://api.openai.com")
            && !policy.to_string().contains("OPENAI_API_KEY=")
            && policy["tag"] == "Read only"
            && policy["edit"] == false,
        "{policy}"
    );

    std::fs::write(
        s.dir.join("enterplace.policy.yaml"),
        POLICY.replace("    models: [gpt-4o-mini]\n", "    modles: [gpt-4o-mini]\n"),
    )?;
    let (_, _, broken) = call(
        &s.app,
        "GET",
        "/console/api/policy/raw",
        &cookie,
        serde_json::Value::Null,
    )
    .await?;
    // The problem is placed under its line.
    assert!(
        broken["lines"]
            .as_array()
            .is_some_and(|lines| lines.iter().any(|l| l["problems"]
                .to_string()
                .contains(r#"Did you mean \"models\"?"#))),
        "{broken}"
    );
    assert!(
        broken["lead"]
            .as_str()
            .is_some_and(|l| l.starts_with("enterplace check refuses this file")),
        "{broken}"
    );

    // With the policy broken, spend is still shown from the log, and the budgets say why they are missing.
    let spend = spend(&s.app, &cookie).await?;
    assert_eq!(
        spend["budgets"]["problem"]["title"], "The policy file has problems",
        "{spend}"
    );
    assert!(
        spend["budgets"]["problem"]["body"]
            .as_str()
            .is_some_and(|b| b.contains("Open the policy to fix them")),
        "{spend}"
    );
    // The models table is still shown, with its row of requests stopped before sending.
    assert!(
        spend["stopped"].is_string() && spend["models"].is_array(),
        "{spend}"
    );
    Ok(())
}

#[tokio::test]
async fn an_issued_key_is_shown_once_and_its_hash_is_appended() -> TestResult {
    let s = setup("issue")?;
    let cookie = sign_in(&s.app).await?;
    // The old Issue link opens the app's Issue dialog.
    let (_, headers, _) = send(
        &s.app,
        get(
            "/console/people?issue=1&name=ci.release&team=platform",
            &cookie,
        )?,
    )
    .await?;
    assert_eq!(
        location(&headers),
        "/console/app/#/people?issue=1&name=ci.release&team=platform"
    );

    let before = std::fs::read_to_string(s.keys())?;
    let (status, headers, made) = call(
        &s.app,
        "POST",
        "/console/api/people/issue",
        &cookie,
        serde_json::json!({ "name": "svc-invoice-bot", "team": "payments" }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{made}");
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let key = made["key"].as_str().ok_or("the key is not in the answer")?;
    assert!(
        key.starts_with("enterplace_") && key.len() == 11 + 64,
        "{key}"
    );
    // The lines for each tool carry the key.
    assert!(
        made["lines"].as_array().is_some_and(|l| l
            .iter()
            .any(|l| l.as_str() == Some(&format!("export OPENAI_API_KEY={key}")))),
        "{made}"
    );
    let after = std::fs::read_to_string(s.keys())?;
    assert!(
        after.starts_with(&before),
        "the file was rewritten, not appended to"
    );
    assert!(
        after.contains("name: svc-invoice-bot")
            && after.contains(&sha256_hex(key.as_bytes()))
            && !after.contains(key)
    );

    let (status, _, refused) = call(
        &s.app,
        "POST",
        "/console/api/people/issue",
        &cookie,
        serde_json::json!({ "name": "bad name", "team": "t" }),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        refused["error"]
            .as_str()
            .unwrap_or("")
            .contains("letters, digits"),
        "{refused}"
    );
    assert_eq!(std::fs::read_to_string(s.keys())?, after);
    Ok(())
}

#[tokio::test]
async fn a_key_is_revoked_only_with_its_name_typed_and_never_the_last_admin() -> TestResult {
    let s = setup("revoke")?;
    let cookie = sign_in(&s.app).await?;
    let maya = sha256_hex(MAYA_KEY.as_bytes());
    // The old Revoke link opens the app's dialog for the same key.
    let (_, headers, _) = send(
        &s.app,
        get(&format!("/console/people?revoke={maya}"), &cookie)?,
    )
    .await?;
    assert_eq!(
        location(&headers),
        format!("/console/app/#/people?revoke={maya}")
    );

    let before = std::fs::read_to_string(s.keys())?;
    let (status, _, refused) = call(
        &s.app,
        "POST",
        "/console/api/people/revoke",
        &cookie,
        serde_json::json!({ "sha256": maya, "confirm": "maya" }),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        refused["error"]
            .as_str()
            .unwrap_or("")
            .contains("Type maya.cohen exactly"),
        "{refused}"
    );
    assert_eq!(std::fs::read_to_string(s.keys())?, before);

    let (status, _, done) = call(
        &s.app,
        "POST",
        "/console/api/people/revoke",
        &cookie,
        serde_json::json!({ "sha256": maya, "confirm": "maya.cohen" }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert!(
        done["message"]
            .as_str()
            .unwrap_or("")
            .contains(&format!("key hash {}", &maya[..8])),
        "{done}"
    );
    let after = std::fs::read_to_string(s.keys())?;
    assert!(
        !after.contains(&maya) && !after.contains("maya.cohen") && after.contains("noa.bar"),
        "{after}"
    );
    assert!(enterplace_core::config::keys_problems(Path::new("k"), &after).is_empty());

    let admin = sha256_hex(ADMIN_KEY.as_bytes());
    let (status, _, refused) = call(
        &s.app,
        "POST",
        "/console/api/people/revoke",
        &cookie,
        serde_json::json!({ "sha256": admin, "confirm": "noa.bar" }),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        refused["error"]
            .as_str()
            .unwrap_or("")
            .contains("only admin key"),
        "{refused}"
    );
    assert!(std::fs::read_to_string(s.keys())?.contains(&admin));
    Ok(())
}

/// The admin records the console wrote, oldest first.
fn admin_records(s: &Setup) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    Ok(std::fs::read_to_string(s.audit())?
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|r| r["event"] == "admin")
        .collect())
}

#[tokio::test]
async fn sign_in_sign_out_issue_and_revoke_are_each_recorded_with_who_did_them() -> TestResult {
    let s = setup("records")?;
    // A wrong key is recorded as refused, by the first 8 hex of its hash, never the key.
    send(
        &s.app,
        post("/console/sign-in", "", "key=enterplace_wrong_key_x")?,
    )
    .await?;
    let cookie = sign_in(&s.app).await?;
    let (status, _, made) = call(
        &s.app,
        "POST",
        "/console/api/people/issue",
        &cookie,
        serde_json::json!({ "name": "ops.lead", "team": "ops", "admin": true }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{made}");
    let key = made["key"].as_str().ok_or("no key")?.to_string();
    let maya = sha256_hex(MAYA_KEY.as_bytes());
    call(
        &s.app,
        "POST",
        "/console/api/people/revoke",
        &cookie,
        serde_json::json!({ "sha256": maya, "confirm": "maya.cohen" }),
    )
    .await?;
    send(&s.app, get("/console/sign-out", &cookie)?).await?;

    let records = admin_records(&s)?;
    let summary: Vec<(String, String, String)> = records
        .iter()
        .map(|r| {
            (
                r["action"].as_str().unwrap_or("").to_string(),
                r["verdict"].as_str().unwrap_or("").to_string(),
                r["person"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    let row = |a: &str, v: &str, p: &str| (a.to_string(), v.to_string(), p.to_string());
    assert_eq!(
        summary,
        [
            row("console_sign_in", "refused", "unknown"),
            row("console_sign_in", "allow", "noa.bar"),
            row("issue_key", "allow", "noa.bar"),
            row("revoke_key", "allow", "noa.bar"),
            row("console_sign_out", "allow", "noa.bar"),
        ]
    );
    assert_eq!(
        records[0]["key"],
        &sha256_hex(b"enterplace_wrong_key_x")[..8]
    );
    assert_eq!(records[1]["via"], "console");
    assert_eq!(
        records[2]["target"],
        serde_json::json!({"name": "ops.lead", "team": "ops", "sha256_prefix": &sha256_hex(key.as_bytes())[..8], "admin": true})
    );
    assert_eq!(records[3]["target"]["name"], "maya.cohen");
    let log = std::fs::read_to_string(s.audit())?;
    assert!(
        !log.contains(&key) && !log.contains(ADMIN_KEY) && !log.contains("enterplace_wrong_key_x")
    );
    enterplace_core::audit::verify(&s.audit())?;
    // The audit page shows them as admin actions, not as requests.
    let cookie = sign_in(&s.app).await?;
    let page = audit(&s.app, &cookie, "").await?;
    assert!(
        page["rows"]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|r| r["verdict"]
                == serde_json::json!({ "kind": "", "word": "Admin:", "detail": "issued a key" }))),
        "{page}"
    );
    // The three requests of the setup, and none of the admin records.
    assert_eq!(page["stats"]["checked"], "3", "{page}");
    let issue_id = records[2]["id"].as_str().unwrap_or("");
    let issued = sheet(&s.app, &cookie, issue_id).await?;
    assert!(
        issued["lead"]
            .as_str()
            .unwrap_or("")
            .contains("noa.bar issued an admin key for ops.lead, key hash "),
        "{issued}"
    );

    // The new admin key is marked admin in the file, and it can sign in.
    let entries =
        enterplace_core::config::key_entries(&s.keys(), &std::fs::read_to_string(s.keys())?)
            .map_err(|e| e.join("\n"))?;
    assert!(entries.iter().any(|e| e.name == "ops.lead" && e.admin));
    let (status, _, _) = send(&s.app, post("/console/sign-in", "", &format!("key={key}"))?).await?;
    assert_eq!(status, StatusCode::SEE_OTHER);
    Ok(())
}

#[tokio::test]
async fn the_issue_dialog_has_an_admin_choice() -> TestResult {
    let s = setup("admin-choice")?;
    let cookie = sign_in(&s.app).await?;
    // The admin choice is offered to an admin of the whole install.
    assert_eq!(people(&s.app, &cookie).await?["may"]["full_admin"], true);
    // A plain issue stays a plain key.
    call(
        &s.app,
        "POST",
        "/console/api/people/issue",
        &cookie,
        serde_json::json!({ "name": "bot", "team": "ops" }),
    )
    .await?;
    let entries =
        enterplace_core::config::key_entries(&s.keys(), &std::fs::read_to_string(s.keys())?)
            .map_err(|e| e.join("\n"))?;
    assert!(entries.iter().any(|e| e.name == "bot" && !e.admin));
    assert_eq!(
        admin_records(&s)?
            .last()
            .map(|r| r["target"]["admin"].clone()),
        Some(false.into())
    );
    Ok(())
}

#[tokio::test]
async fn a_console_with_no_audit_log_refuses_to_sign_anyone_in() -> TestResult {
    let s = setup("no-log")?;
    let app = Router::new().nest(
        "/console",
        router(ConsoleConfig {
            policy: s.dir.join("enterplace.policy.yaml"),
            keys: s.keys(),
            audit: s.audit(),
            log: None,
        }),
    );
    let (status, headers, page) = send(
        &app,
        post("/console/sign-in", "", &format!("key={ADMIN_KEY}"))?,
    )
    .await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(headers.get(header::SET_COOKIE).is_none());
    assert!(page.contains("audit log"), "{page}");
    Ok(())
}

#[tokio::test]
async fn the_record_sheet_shows_guardrail_findings_and_never_matched_text() -> TestResult {
    let s = setup("guard-sheet")?;
    let cookie = sign_in(&s.app).await?;
    let entry = Entry {
        id: "01AAAAAAAAAAAAAAAAAAAAAAG1",
        person: Some("maya.cohen"),
        team: Some("payments"),
        method: "POST",
        path: "/v1/messages",
        model: Some("claude-a"),
        code: Some("guardrail_blocked"),
        rule: Some("payments-team"),
        rule_line: Some(10),
        ..Entry::default()
    };
    let mut record = enterplace_core::audit::record(&entry);
    record.insert(
        "guardrails".into(),
        serde_json::json!([
            {"guardrail": "no-secrets", "detector": "secrets", "kind": "aws_access_key", "action": "block", "count": 2},
            {"guardrail": "mask-pii", "detector": "pii", "kind": "email_address", "action": "mask", "count": 1}
        ]),
    );
    // Appended the way the server writes a request record with findings.
    s.log.append_record(&record)?;
    let blocked = sheet(&s.app, &cookie, "01AAAAAAAAAAAAAAAAAAAAAAG1").await?;
    assert_eq!(blocked["title"], "The prompt held an AWS access key");
    // Each finding is its badge, then the guardrail and how many: never the text that matched.
    let findings: Vec<_> = blocked["facts"]
        .as_array()
        .map(|f| {
            f.iter()
                .filter(|f| f["label"] == "Finding")
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(
        findings,
        [
            serde_json::json!({ "label": "Finding", "tag": { "kind": "block", "word": "Block", "detail": "aws_access_key" }, "text": "no-secrets, 2" }),
            serde_json::json!({ "label": "Finding", "tag": { "kind": "mask", "word": "Mask", "detail": "email_address" }, "text": "mask-pii, 1" }),
        ],
        "{blocked}"
    );
    let list = audit(&s.app, &cookie, "").await?;
    assert_eq!(list["rows"][0]["verdict"]["kind"], "block");
    Ok(())
}

#[tokio::test]
async fn spend_shows_this_months_usage_against_the_budgets() -> TestResult {
    let s = setup("spend")?;
    let budgeted = POLICY
        .replace(
            "    models: [gpt-4o-mini]\n",
            "    models: [gpt-4o-mini]\n    budget: { usd: 1, per: month }\n",
        )
        .replace(
            "    models: [\"*\"]\n",
            "    models: [\"*\"]\nprices:\n  local: { input: 0, output: 0 }\n",
        );
    std::fs::write(s.dir.join("enterplace.policy.yaml"), budgeted)?;
    // The setup holds the server's log open: usage records join that chain, as the server writes them.
    let log = &s.log;
    let usage =
        |id: &str, person: &str, team: &str, model: &str, cost: Option<f64>, charged: f64| {
            let mut record = serde_json::Map::new();
            for (k, v) in [
                ("event", "usage"),
                ("id", id),
                ("person", person),
                ("team", team),
                ("model", model),
                ("provider", "openai"),
            ] {
                record.insert(k.into(), v.into());
            }
            record.insert("time".into(), enterplace_core::audit::timestamp().into());
            record.insert("input_tokens".into(), 1000.into());
            record.insert("output_tokens".into(), 10.into());
            record.insert(
                "cost_usd".into(),
                cost.map_or(serde_json::Value::Null, Into::into),
            );
            record.insert("charged_usd".into(), charged.into());
            record
        };
    log.append_record(&usage(
        "01AAAAAAAAAAAAAAAAAAAAAAA1",
        "maya.cohen",
        "payments",
        "gpt-4o-mini",
        Some(0.6),
        0.6,
    ))?;
    log.append_record(&usage(
        "01AAAAAAAAAAAAAAAAAAAAAAA4",
        "maya.cohen",
        "payments",
        "gpt-4o-mini",
        Some(0.5),
        0.5,
    ))?;
    log.append_record(&usage(
        "01AAAAAAAAAAAAAAAAAAAAAAA5",
        "noa.bar",
        "platform",
        "local",
        None,
        0.0,
    ))?;
    let cookie = sign_in(&s.app).await?;
    let page = spend(&s.app, &cookie).await?;
    let lead = page["lead"].as_str().unwrap_or("");
    assert!(
        lead.starts_with("$1.10 spent in") && lead.contains("Team payments spent its $1.00 on"),
        "{page}"
    );
    assert_eq!(
        page["action"],
        serde_json::json!({ "label": "Edit the payments budget in the policy", "href": "/console/policy?line=10" })
    );
    let meter = page["budgets"]["meters"]
        .as_array()
        .and_then(|m| m.iter().find(|m| m["label"] == "payments"))
        .ok_or("no payments meter")?;
    assert_eq!(
        (meter["text"].as_str(), meter["over"].as_bool()),
        (Some("$1.10 of $1.00"), Some(true)),
        "{meter}"
    );
    // The pace line and the day the budget ran out, on the chart.
    let chart = &page["chart"];
    assert!(chart["pace"].as_f64().is_some_and(|p| p > 0.0), "{chart}");
    let mark = chart["mark"].as_u64().ok_or("no mark")?;
    assert!(
        chart["days"]
            .as_array()
            .is_some_and(|d| d.iter().any(|d| d["mark"] == true && d["day"] == mark)),
        "{chart}"
    );
    let model = &page["models"][0];
    assert_eq!(
        (model["model"].as_str(), model["usd"].as_str()),
        (Some("gpt-4o-mini"), Some("$1.10"))
    );
    let top = &page["spenders"][0];
    assert_eq!(top["href"], "/console/audit?q=maya.cohen");
    // The model is an identifier: the app keeps it whole, apart from the sentence.
    assert_eq!(
        (top["sent"].as_str(), top["mostly"].as_str()),
        (Some("Sent 2 requests, $1.10"), Some("gpt-4o-mini"))
    );
    assert!(
        page["note"]
            .as_str()
            .is_some_and(|n| n.contains("1 answer reported no usage or had no price")),
        "{page}"
    );
    // The two refused requests of the setup.
    assert_eq!(page["stopped"], "2");
    // Usage records belong to this page, not to the list of decisions.
    let list = audit(&s.app, &cookie, "").await?;
    // The three requests of the setup and the sign-in's admin record; none of the three usage records.
    assert_eq!(list["pager"]["text"], "1 to 4 of 4 decisions", "{list}");
    // m12-3: Verify chain now walks every record of the chain, usage ones too, as enterplace audit verify counts them.
    let lines = std::fs::read_to_string(s.audit())?.lines().count();
    assert!(
        list["verified"]["text"]
            .as_str()
            .unwrap_or("")
            .contains(&format!("walks all {lines} records")),
        "{lines}: {list}"
    );
    Ok(())
}

#[tokio::test]
async fn people_shows_a_keys_expiry_and_budget() -> TestResult {
    let s = setup("key-attrs")?;
    std::fs::write(
        s.keys(),
        format!(
            "{}  - name: ci.bot\n    team: platform\n    sha256: {}\n    expires: 2099-01-01\n    budget: {{ usd: 20, per: month }}\n",
            keys_text(),
            sha256_hex(b"enterplace_ci_bot")
        ),
    )?;
    let cookie = sign_in(&s.app).await?;
    let people = people(&s.app, &cookie).await?;
    // Round 11: the status says the key is live and when it expires, and its budget is a meter.
    let status = &key_named(&people, "ci.bot")?["status"];
    assert_eq!(
        (status["tag"].as_str(), status["kind"].as_str()),
        (Some("Active"), Some("allow"))
    );
    assert_eq!(status["notes"], serde_json::json!(["expires 2099-01-01"]));
    assert_eq!(status["meter"]["text"], "$0.00 of $20.00 this month");
    Ok(())
}

// ---------------------------------------------------------------- round 10 review

/// A sign-in post with exactly the origin headers given, as a browser would send them.
fn sign_in_with(headers: &[(&str, &str)]) -> Result<Request<Body>, axum::http::Error> {
    let mut request = Request::post("/console/sign-in")
        .header(header::HOST, HOST)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    request.body(Body::from(format!("key={ADMIN_KEY}")))
}

#[tokio::test]
async fn a_browser_form_from_this_console_is_accepted_and_one_from_another_site_is_not()
-> TestResult {
    let s = setup("origin-browser")?;
    // The policy that makes Chrome send the real origin on a same-origin form post, not "null".
    let (_, headers, _) = send(&s.app, get("/console/sign-in", "")?).await?;
    assert_eq!(
        headers
            .get(header::REFERRER_POLICY)
            .and_then(|v| v.to_str().ok()),
        Some("same-origin")
    );
    // Chrome with an older page cached, or a privacy setting: Origin null, but the fetch metadata says same origin.
    let (status, _, _) = send(
        &s.app,
        sign_in_with(&[("origin", "null"), ("sec-fetch-site", "same-origin")])?,
    )
    .await?;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (status, _, _) = send(
        &s.app,
        sign_in_with(&[("origin", &format!("http://{HOST}"))])?,
    )
    .await?;
    assert_eq!(status, StatusCode::SEE_OTHER);
    for refused in [
        vec![("origin", "http://evil.example")],
        vec![
            ("origin", "http://evil.example"),
            ("sec-fetch-site", "same-origin"),
        ],
        vec![("origin", "null"), ("sec-fetch-site", "cross-site")],
        vec![("origin", "null"), ("sec-fetch-site", "same-site")],
        vec![("origin", "null")],
        vec![("sec-fetch-site", "cross-site")],
        vec![],
    ] {
        let (status, headers, page) = send(&s.app, sign_in_with(&refused)?).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{refused:?}");
        assert!(headers.get(header::SET_COOKIE).is_none(), "{refused:?}");
        // The refusal is a console page with a way back, not bare text.
        assert!(
            headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.starts_with("text/html")),
            "{refused:?}"
        );
        assert!(
            page.contains("g-empty")
                && page.contains("/console/assets/bundle.css")
                && page.contains(r#"href="/console/sign-in""#),
            "{page}"
        );
    }
    // A page that does not exist is a console page too.
    let (status, _, page) = send(&s.app, get("/console/nope", "")?).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(page.contains("g-empty") && page.contains(r#"href="/console/start""#));
    Ok(())
}

/// Appends a request record with guardrail findings, as the server writes one.
fn guarded_record(
    s: &Setup,
    id: &str,
    code: Option<&str>,
    findings: serde_json::Value,
) -> TestResult {
    let entry = Entry {
        id,
        person: Some("maya.cohen"),
        team: Some("payments"),
        method: "POST",
        path: "/v1/chat/completions",
        model: Some("gpt-4o-mini"),
        allowed: code.is_none(),
        code,
        rule: Some("payments-team"),
        rule_line: Some(10),
        provider: if code.is_none() { "openai" } else { "" },
        ..Entry::default()
    };
    let mut record = enterplace_core::audit::record(&entry);
    record.insert("guardrails".into(), findings);
    s.log.append_record(&record)?;
    Ok(())
}

#[tokio::test]
async fn guardrail_blocks_and_masks_carry_their_finding_badge() -> TestResult {
    let s = setup("badges")?;
    guarded_record(
        &s,
        "01AAAAAAAAAAAAAAAAAAAAAAB1",
        Some("guardrail_blocked"),
        serde_json::json!([{"guardrail": "no-secrets", "kind": "aws_access_key", "action": "block", "count": 1}]),
    )?;
    guarded_record(
        &s,
        "01AAAAAAAAAAAAAAAAAAAAAAM1",
        None,
        serde_json::json!([
            {"guardrail": "mask-pii", "kind": "credit_card", "action": "mask", "count": 1},
            {"guardrail": "mask-pii", "kind": "email_address", "action": "mask", "count": 2}
        ]),
    )?;
    guarded_record(
        &s,
        "01AAAAAAAAAAAAAAAAAAAAAAV1",
        Some("guardrail_blocked"),
        serde_json::json!([{"guardrail": "moderation", "kind": "harassment_threatening", "action": "block", "count": 1}]),
    )?;
    let cookie = sign_in(&s.app).await?;
    // m12-9. A vendor category has a title that names the guardrail and the category in words.
    let vendor = sheet(&s.app, &cookie, "01AAAAAAAAAAAAAAAAAAAAAAV1").await?;
    assert_eq!(
        vendor["title"], "Guardrail moderation blocked harassment threatening",
        "{vendor}"
    );
    let list = audit(&s.app, &cookie, "").await?;
    assert!(has_tag(&list, "block", "Block", "aws_access_key"), "{list}");
    assert!(has_tag(&list, "mask", "Mask", "credit_card"), "{list}");
    // Blocks are counted apart from refusals by policy.
    assert_eq!(list["stats"]["blocked"], "2", "{list}");

    let block = sheet(&s.app, &cookie, "01AAAAAAAAAAAAAAAAAAAAAAB1").await?;
    assert_eq!(block["title"], "The prompt held an AWS access key");
    let mask = sheet(&s.app, &cookie, "01AAAAAAAAAAAAAAAAAAAAAAM1").await?;
    assert_eq!(mask["title"], "Masked 3 findings, then sent to openai");
    // One row per finding, each with its badge, never one run-on string.
    let findings: Vec<(String, String)> = mask["facts"]
        .as_array()
        .map(|f| {
            f.iter()
                .filter(|f| f["label"] == "Finding")
                .map(|f| (f["tag"]["detail"].to_string(), f["text"].to_string()))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(
        findings,
        [
            ("\"credit_card\"".to_string(), "\"mask-pii, 1\"".to_string()),
            (
                "\"email_address\"".to_string(),
                "\"mask-pii, 2\"".to_string()
            ),
        ],
        "{mask}"
    );
    // The filters of the design.
    let blocked = audit(&s.app, &cookie, "verdict=blocked").await?;
    assert_eq!(
        blocked["pager"]["text"], "1 to 2 of 2 decisions",
        "{blocked}"
    );
    let masked = audit(&s.app, &cookie, "verdict=masked").await?;
    assert_eq!(masked["pager"]["text"], "1 to 1 of 1 decisions");
    assert_eq!(ids(&masked), ["01AAAAAAAAAAAAAAAAAAAAAAM1"]);
    Ok(())
}

#[tokio::test]
async fn admin_records_are_tagged_in_words_and_a_refused_one_says_it_was_tried() -> TestResult {
    let s = setup("admin-words")?;
    send(
        &s.app,
        post("/console/sign-in", "", "key=enterplace_wrong_key_y")?,
    )
    .await?;
    let cookie = sign_in(&s.app).await?;
    let list = audit(&s.app, &cookie, "").await?;
    assert!(
        has_tag(&list, "refused", "Refused:", "sign-in")
            && has_tag(&list, "", "Admin:", "signed in")
            && !list["rows"].to_string().contains("console_sign_in"),
        "{list}"
    );
    // A row opens on its time.
    assert!(
        list["rows"][0]["open"]
            .as_str()
            .unwrap_or("")
            .starts_with("Open decision "),
        "{list}"
    );
    let refused = admin_records(&s)?
        .first()
        .and_then(|r| r["id"].as_str().map(str::to_string))
        .ok_or("no record")?;
    let tried = sheet(&s.app, &cookie, &refused).await?;
    assert!(
        tried["lead"]
            .as_str()
            .unwrap_or("")
            .contains("tried to sign in"),
        "{tried}"
    );
    Ok(())
}

#[tokio::test]
async fn issue_and_revoke_records_name_the_key_hash_and_search_finds_them() -> TestResult {
    let s = setup("hash-search")?;
    let cookie = sign_in(&s.app).await?;
    let maya = sha256_hex(MAYA_KEY.as_bytes());
    call(
        &s.app,
        "POST",
        "/console/api/people/revoke",
        &cookie,
        serde_json::json!({ "sha256": maya, "confirm": "maya.cohen" }),
    )
    .await?;
    // A request with the revoked key, as the gateway records it.
    s.log.append(&Entry {
        id: "01AAAAAAAAAAAAAAAAAAAAAAU1",
        key: Some(&maya[..8]),
        method: "POST",
        path: "/v1/chat/completions",
        code: Some("unknown_key"),
        ..Entry::default()
    })?;
    let revoke = admin_records(&s)?
        .into_iter()
        .find(|r| r["action"] == "revoke_key")
        .ok_or("no revoke record")?;
    let id = revoke["id"].as_str().unwrap_or("");
    let revoked = sheet(&s.app, &cookie, id).await?;
    assert_eq!(fact(&revoked, "Key hash"), &maya[..8], "{revoked}");
    for q in [&maya[..8], "maya.cohen"] {
        let found = audit(&s.app, &cookie, &format!("q={q}")).await?;
        assert!(ids(&found).iter().any(|i| i == id), "{q}: {found}");
    }
    // The revoked key's later use points back at who revoked it.
    let used = sheet(&s.app, &cookie, "01AAAAAAAAAAAAAAAAAAAAAAU1").await?;
    assert!(
        fact(&used, "Revoked").starts_with("Revoked by noa.bar")
            && used["actions"].as_array().is_some_and(|a| a
                .iter()
                .any(|a| a["href"] == format!("#/audit?record={id}"))),
        "{used}"
    );
    // A link to the revoke's toast keeps the key hash, for the app to say.
    let (_, headers, _) = send(
        &s.app,
        get(
            &format!("/console/people?revoked=maya.cohen&hash={}", &maya[..8]),
            &cookie,
        )?,
    )
    .await?;
    assert_eq!(
        location(&headers),
        format!(
            "/console/app/#/people?revoked=maya.cohen&hash={}",
            &maya[..8]
        )
    );
    Ok(())
}

#[tokio::test]
async fn the_last_hash_is_shown_whole_to_keep_for_expect_last() -> TestResult {
    let s = setup("last-hash")?;
    let cookie = sign_in(&s.app).await?;
    verify(&s.app, &cookie, "").await?;
    let page = audit(&s.app, &cookie, "").await?;
    let (_, last) = enterplace_core::audit::verify(&s.audit())?;
    assert_eq!(last.len(), 64);
    assert!(
        page["verified"]["last_hash"] == last.as_str()
            && page["verified"]["note"]
                .as_str()
                .unwrap_or("")
                .contains("--expect-last"),
        "{page}"
    );
    Ok(())
}

#[tokio::test]
async fn policy_and_keys_changes_open_a_sheet_with_the_change() -> TestResult {
    let s = setup("changes")?;
    let mut start = serde_json::Map::new();
    start.insert("event".into(), "config_loaded".into());
    start.insert("time".into(), enterplace_core::audit::timestamp().into());
    start.insert("trigger".into(), "start".into());
    start.insert("policy".into(), POLICY.into());
    s.log.append_record(&start)?;
    let mut loaded = serde_json::Map::new();
    loaded.insert("event".into(), "config_loaded".into());
    loaded.insert("time".into(), enterplace_core::audit::timestamp().into());
    loaded.insert("trigger".into(), "file_change".into());
    loaded.insert("policy_sha256_before".into(), "a".repeat(64).into());
    loaded.insert("keys_sha256_before".into(), "b".repeat(64).into());
    loaded.insert("policy_sha256".into(), "c".repeat(64).into());
    loaded.insert("keys_sha256".into(), "d".repeat(64).into());
    loaded.insert(
        "policy".into(),
        POLICY
            .replace("gpt-4o-mini]", "gpt-4o-mini, gpt-4o]")
            .into(),
    );
    loaded.insert(
        "keys_added".into(),
        serde_json::json!([{"name": "lior.amit", "team": "platform", "sha256_prefix": "2d5bce25"}]),
    );
    loaded.insert("keys_removed".into(), serde_json::json!([]));
    s.log.append_record(&loaded)?;
    let mut rejected = serde_json::Map::new();
    rejected.insert("event".into(), "config_rejected".into());
    rejected.insert("time".into(), enterplace_core::audit::timestamp().into());
    rejected.insert("trigger".into(), "file_change".into());
    rejected.insert("problem_count".into(), 1.into());
    rejected.insert(
        "problems".into(),
        serde_json::json!(["enterplace.policy.yaml:12: \"modls\" is not a key Enterplace knows."]),
    );
    s.log.append_record(&rejected)?;
    let cookie = sign_in(&s.app).await?;
    let list = audit(&s.app, &cookie, "verdict=changes").await?;
    // Records 4 to 6: a change has no decision ID, so it opens by its record number.
    let listed = ids(&list);
    assert!(
        listed.contains(&"5".to_string())
            && listed.contains(&"6".to_string())
            && list["rows"].to_string().contains("file change"),
        "{list}"
    );
    // A row without a decision ID is never labelled with an empty one.
    assert!(
        !list["rows"].to_string().contains(r#""Open decision ""#),
        "{list}"
    );
    let sheet = sheet_text(&s.app, &cookie, "5").await?;
    for expected in [
        // Round 11: the title names what changed.
        "The policy and keys files changed",
        "lior.amit",
        "2d5bce25",
        &"c".repeat(64),
        &"a".repeat(64),
        // The policy line that changed, against the version before it.
        "gpt-4o-mini, gpt-4o]",
    ] {
        assert!(sheet.contains(expected), "missing {expected}: {sheet}");
    }
    let sheet = sheet_text(&s.app, &cookie, "6").await?;
    assert!(
        sheet.contains("A change to the policy or keys file was rejected")
            && sheet.contains("is not a key Enterplace knows"),
        "{sheet}"
    );
    Ok(())
}

#[tokio::test]
async fn a_budget_refusal_sheet_names_the_budget_what_was_spent_and_when_it_resets() -> TestResult {
    let s = setup("budget-sheet")?;
    let budgeted = POLICY.replace(
        "    models: [gpt-4o-mini]\n",
        "    models: [gpt-4o-mini]\n    budget: { usd: 1, per: month }\n",
    );
    std::fs::write(s.dir.join("enterplace.policy.yaml"), &budgeted)?;
    let mut usage = serde_json::Map::new();
    for (k, v) in [
        ("event", "usage"),
        ("id", "01AAAAAAAAAAAAAAAAAAAAAAA1"),
        ("person", "maya.cohen"),
        ("team", "payments"),
        ("model", "gpt-4o-mini"),
    ] {
        usage.insert(k.into(), v.into());
    }
    usage.insert("time".into(), enterplace_core::audit::timestamp().into());
    usage.insert("charged_usd".into(), 0.88.into());
    s.log.append_record(&usage)?;
    let sha = sha256_hex(budgeted.as_bytes());
    s.log.append(&Entry {
        id: "01AAAAAAAAAAAAAAAAAAAAAAX1",
        person: Some("maya.cohen"),
        team: Some("payments"),
        method: "POST",
        path: "/v1/chat/completions",
        model: Some("gpt-4o-mini"),
        code: Some("budget_exceeded"),
        rule: Some("payments-team"),
        rule_line: Some(10),
        policy_sha256: &sha,
        ..Entry::default()
    })?;
    let cookie = sign_in(&s.app).await?;
    let sheet = sheet_text(&s.app, &cookie, "01AAAAAAAAAAAAAAAAAAAAAAX1").await?;
    assert!(
        sheet.contains("The payments team's budget is spent"),
        "{sheet}"
    );
    assert!(
        sheet.contains("$0.88 of $1.00 spent this month") && sheet.contains("Refused until 1 "),
        "{sheet}"
    );
    Ok(())
}

// ---------------------------------------------------------------- round 11 review

/// A keys file where maya.cohen's key has a budget of $1 a day and ci.release's key has expired.
fn keys_with_limits() -> String {
    format!(
        "keys:\n  - name: noa.bar\n    team: platform\n    sha256: {}\n    admin: true\n  - name: maya.cohen\n    team: payments\n    sha256: {}\n    budget: {{ usd: 1, per: day }}\n  - name: ci.release\n    team: platform\n    sha256: {}\n    expires: 2020-11-01\n",
        sha256_hex(ADMIN_KEY.as_bytes()),
        sha256_hex(MAYA_KEY.as_bytes()),
        sha256_hex(b"enterplace_ci_release")
    )
}

fn usage_record(
    person: &str,
    key: &str,
    charged: f64,
) -> serde_json::Map<String, serde_json::Value> {
    let mut usage = serde_json::Map::new();
    for (k, v) in [
        ("event", "usage"),
        ("id", "01AAAAAAAAAAAAAAAAAAAAAAU1"),
        ("person", person),
        ("team", "payments"),
        ("key", key),
        ("model", "gpt-4o-mini"),
        ("provider", "openai"),
    ] {
        usage.insert(k.into(), v.into());
    }
    usage.insert("time".into(), enterplace_core::audit::timestamp().into());
    usage.insert("charged_usd".into(), charged.into());
    usage
}

/// Writes the keys file with limits, a spend of $0.82 against maya.cohen's key, and its refusal and an expired key's.
fn limited(s: &Setup) -> Result<(), Box<dyn std::error::Error>> {
    let keys = keys_with_limits();
    std::fs::write(s.keys(), &keys)?;
    let (keys_sha, maya) = (sha256_hex(keys.as_bytes()), sha256_hex(MAYA_KEY.as_bytes()));
    let policy_sha = sha256_hex(POLICY.as_bytes());
    s.log
        .append_record(&usage_record("maya.cohen", &maya[..8], 0.82))?;
    let base = Entry {
        method: "POST",
        path: "/v1/chat/completions",
        policy_sha256: &policy_sha,
        keys_sha256: &keys_sha,
        ..Entry::default()
    };
    s.log.append(&Entry {
        id: "01AAAAAAAAAAAAAAAAAAAAAAK1",
        person: Some("maya.cohen"),
        team: Some("payments"),
        key: Some(&maya[..8]),
        model: Some("gpt-4o-mini"),
        code: Some("key_budget_exceeded"),
        rule: Some("payments-team"),
        rule_line: Some(10),
        ..base.clone()
    })?;
    let ci = sha256_hex(b"enterplace_ci_release");
    s.log.append(&Entry {
        id: "01AAAAAAAAAAAAAAAAAAAAAAK2",
        person: Some("ci.release"),
        team: Some("platform"),
        key: Some(&ci[..8]),
        code: Some("key_expired"),
        ..base
    })?;
    Ok(())
}

#[tokio::test]
async fn key_budget_and_expired_key_sheets_name_the_key_its_amounts_and_the_way_out() -> TestResult
{
    let s = setup("key-sheets")?;
    limited(&s)?;
    let cookie = sign_in(&s.app).await?;
    let sheet = sheet_text(&s.app, &cookie, "01AAAAAAAAAAAAAAAAAAAAAAK1").await?;
    for expected in [
        "maya.cohen's key budget is spent",
        "$0.82 of $1.00 spent today",
        "Refused until 00:00 UTC",
        r#"{"label":"Budget","text":"$0.82 of $1.00 spent today"}"#,
        r#"{"label":"Resets","text":"#,
    ] {
        assert!(sheet.contains(expected), "missing {expected}: {sheet}");
    }
    assert!(
        !sheet.contains("Enterplace refused it with the code"),
        "{sheet}"
    );
    let sheet = sheet_text(&s.app, &cookie, "01AAAAAAAAAAAAAAAAAAAAAAK2").await?;
    for expected in [
        "ci.release's key expired on 1 November 2020",
        "Issue a new key on People",
        "#/people?issue=1&name=ci.release&team=platform",
    ] {
        assert!(sheet.contains(expected), "missing {expected}: {sheet}");
    }
    Ok(())
}

#[tokio::test]
async fn people_shows_each_keys_status_its_budget_meter_and_the_fix() -> TestResult {
    let s = setup("people-status")?;
    limited(&s)?;
    let cookie = sign_in(&s.app).await?;
    let people = people(&s.app, &cookie).await?;
    let ci = &key_named(&people, "ci.release")?["status"];
    assert_eq!(
        (ci["tag"].as_str(), ci["kind"].as_str()),
        (Some("Expired"), Some("refused"))
    );
    assert_eq!(
        ci["fix"],
        serde_json::json!({ "kind": "reissue", "name": "ci.release", "team": "platform" })
    );
    // m12-3: "$0.82 of $1" is not spent; the next request would pass it.
    let maya = &key_named(&people, "maya.cohen")?["status"];
    assert_eq!(maya["tag"], "Budget reached");
    assert_eq!(maya["meter"]["text"], "$0.82 of $1.00 today");
    assert_eq!(maya["meter"]["over"], true);
    assert_eq!(maya["fix"]["kind"], "refusals");
    // The expiry and budget live in the status, not beside the team.
    assert!(
        !people.to_string().contains("budget $1.00 a day"),
        "{people}"
    );
    Ok(())
}

#[tokio::test]
async fn sheets_of_the_request_refusals_say_the_cause_and_the_fix() -> TestResult {
    let s = setup("request-sheets")?;
    let sha = sha256_hex(POLICY.as_bytes());
    for (id, code, path) in [
        (
            "01AAAAAAAAAAAAAAAAAAAAAAR1",
            "max_tokens_needed",
            "/v1/responses",
        ),
        (
            "01AAAAAAAAAAAAAAAAAAAAAAR2",
            "bad_limits",
            "/v1/chat/completions",
        ),
        (
            "01AAAAAAAAAAAAAAAAAAAAAAR3",
            "wrong_route",
            "/v1/embeddings",
        ),
        (
            "01AAAAAAAAAAAAAAAAAAAAAAR4",
            "unreadable_request",
            "/v1/chat/completions",
        ),
    ] {
        s.log.append(&Entry {
            id,
            person: Some("maya.cohen"),
            team: Some("payments"),
            method: "POST",
            path,
            model: Some("gpt-4o-mini"),
            code: Some(code),
            policy_sha256: &sha,
            ..Entry::default()
        })?;
    }
    let cookie = sign_in(&s.app).await?;
    for (id, expected) in [
        ("01AAAAAAAAAAAAAAAAAAAAAAR1", "max_output_tokens"),
        ("01AAAAAAAAAAAAAAAAAAAAAAR1", "max_output for gpt-4o-mini"),
        ("01AAAAAAAAAAAAAAAAAAAAAAR2", "at most once"),
        ("01AAAAAAAAAAAAAAAAAAAAAAR3", "/v1/embeddings"),
        ("01AAAAAAAAAAAAAAAAAAAAAAR4", "plain JSON"),
    ] {
        let sheet = sheet_text(&s.app, &cookie, id).await?;
        assert!(sheet.contains(expected), "missing {expected}: {sheet}");
        assert!(
            !sheet.contains("Enterplace refused it with the code"),
            "{sheet}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn the_issue_dialog_takes_an_expiry_and_a_budget() -> TestResult {
    let s = setup("issue-limits")?;
    let cookie = sign_in(&s.app).await?;
    let (status, _, made) = call(
        &s.app,
        "POST",
        "/console/api/people/issue",
        &cookie,
        serde_json::json!({ "name": "lior.amit", "team": "platform", "expires": "2099-01-31", "budget": "0.005", "per": "day" }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{made}");
    let keys = std::fs::read_to_string(s.keys())?;
    assert!(
        keys.contains("expires: 2099-01-31") && keys.contains("budget: { usd: 0.005, per: day }"),
        "{keys}"
    );
    // A small budget reads in four places under a cent, not as $0.00.
    let people = people(&s.app, &cookie).await?;
    assert_eq!(
        key_named(&people, "lior.amit")?["status"]["meter"]["text"],
        "$0.00 of $0.0050 today"
    );
    let (status, _, refused) = call(
        &s.app,
        "POST",
        "/console/api/people/issue",
        &cookie,
        serde_json::json!({ "name": "lior.amit", "team": "platform", "budget": "-3", "per": "day" }),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        refused["error"]
            .as_str()
            .unwrap_or("")
            .contains("a budget is a number of US dollars above 0"),
        "{refused}"
    );
    Ok(())
}

#[tokio::test]
async fn changes_list_in_their_own_table_and_a_repair_is_one_of_them() -> TestResult {
    let s = setup("repaired")?;
    let mut repaired = serde_json::Map::new();
    repaired.insert("event".into(), "audit_repaired".into());
    repaired.insert("time".into(), enterplace_core::audit::timestamp().into());
    repaired.insert("removed_bytes".into(), 40.into());
    repaired.insert("removed_sha256".into(), "bf20eb45".repeat(8).into());
    repaired.insert("removed_text".into(), "{\"n\":4,\"id\":\"01AB".into());
    s.log.append_record(&repaired)?;
    let cookie = sign_in(&s.app).await?;
    let list = page_text(&s.app, &cookie, "verdict=changes").await?;
    for expected in [
        r#""noun":"changes""#,
        r#""id":"4""#,
        "of 2 changes",
        "noa.bar signed in to the console",
    ] {
        assert!(list.contains(expected), "missing {expected}: {list}");
    }
    let sheet = sheet_text(&s.app, &cookie, "4").await?;
    for expected in [
        "The cut last line of the audit log was removed",
        "enterplace audit repair",
        "40 bytes",
        &"bf20eb45".repeat(8),
        r#"{\"n\":4,\"id\":\"01AB"#,
    ] {
        assert!(sheet.contains(expected), "missing {expected}: {sheet}");
    }
    Ok(())
}

#[tokio::test]
async fn spend_lists_key_budgets_with_the_team_ones() -> TestResult {
    let s = setup("spend-keys")?;
    limited(&s)?;
    let cookie = sign_in(&s.app).await?;
    let page = spend(&s.app, &cookie).await?;
    assert!(
        page["budgets"]["meters"].as_array().is_some_and(|m| m
            .iter()
            .any(|m| m["label"] == "maya.cohen's key" && m["text"] == "$0.82 of $1.00 today")),
        "{page}"
    );
    Ok(())
}

#[tokio::test]
async fn the_console_styles_stack_tables_below_1100px_and_keep_identifiers_whole() -> TestResult {
    let s = setup("css")?;
    let (status, _, css) = send(&s.app, get("/console/assets/console.css", "")?).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(css.contains("@media (max-width:1100px)"), "{css}");
    assert!(
        !css.contains("td{min-width:0;overflow-wrap:anywhere}"),
        "{css}"
    );
    Ok(())
}

#[tokio::test]
async fn a_security_lead_stops_traffic_sees_what_observe_let_through_and_exports_the_chain()
-> TestResult {
    let s = setup("security-lead")?;
    let cookie = sign_in(&s.app).await?;
    // Stop traffic from the console: the switch is on, with the reason, and recorded first.
    let (status, _, answer) = call(
        &s.app,
        "POST",
        "/console/api/audit/stop",
        &cookie,
        serde_json::json!({ "scope": "person", "value": "maya.cohen", "reason": "leaked key" }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let on = enterplace_core::kill::read(&enterplace_core::kill::path_beside(&s.keys()))?;
    assert!(
        on.len() == 1 && on[0].value == "maya.cohen" && on[0].reason == "leaked key",
        "{on:?}"
    );
    assert!(
        admin_records(&s)?.iter().any(|r| r["action"] == "set_kill"
            && r["target"]["value"] == "maya.cohen"
            && r["target"]["reason"] == "leaked key"),
        "recorded"
    );
    // No reason, no switch: the refusal says what to fix.
    let (status, _, refused) = call(
        &s.app,
        "POST",
        "/console/api/audit/stop",
        &cookie,
        serde_json::json!({ "scope": "team", "value": "payments", "reason": " " }),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert!(
        refused["error"].as_str().unwrap_or("").contains("reason"),
        "{refused}"
    );

    // A request observe mode let through says what would have stopped it, in the list, its filter and its sheet.
    let mut record = serde_json::Map::new();
    for (k, v) in [
        ("id", serde_json::json!("01AAAAAAAAAAAAAAAAAAAAAAW1")),
        ("time", serde_json::json!("2026-11-13T13:50:00.000Z")),
        ("person", serde_json::json!("maya.cohen")),
        ("team", serde_json::json!("payments")),
        ("method", serde_json::json!("POST")),
        ("path", serde_json::json!("/v1/chat/completions")),
        ("model", serde_json::json!("gpt-4o-mini")),
        ("verdict", serde_json::json!("allow")),
        ("provider", serde_json::json!("openai")),
        ("outcome", serde_json::json!("would_refuse")),
        (
            "guardrails",
            serde_json::json!([{ "guardrail": "no-secrets", "detector": "secrets", "kind": "aws_access_key", "action": "shadow", "count": 1 }]),
        ),
        (
            "would_refuse",
            serde_json::json!([{ "code": "guardrail_blocked", "by": "observe", "message": "Refused: guardrail \"no-secrets\" would block this request.", "guardrail": "no-secrets" }]),
        ),
    ] {
        record.insert(k.into(), v);
    }
    s.log.append_record(&record)?;
    let page = audit(&s.app, &cookie, "verdict=would").await?;
    let rows = page["rows"].as_array().cloned().unwrap_or_default();
    assert!(
        rows.len() == 1
            && rows[0]["verdict"]["word"] == "Would block:"
            && rows[0]["verdict"]["detail"] == "aws_access_key",
        "{page}"
    );
    let opened = sheet(&s.app, &cookie, "01AAAAAAAAAAAAAAAAAAAAAAW1").await?;
    assert!(
        opened["title"]
            .as_str()
            .unwrap_or("")
            .contains("would have been refused")
            && fact(&opened, "Verdict") == "Allowed, would have been refused",
        "{opened}"
    );

    // The export is the chain as written, a file the auditor verifies, and taking it is recorded.
    let (status, headers, body) = send(&s.app, get("/console/audit/export", &cookie)?).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers
            .get(header::CONTENT_DISPOSITION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("enterplace-audit.jsonl")),
        "{headers:?}"
    );
    assert!(body.contains("01AAAAAAAAAAAAAAAAAAAAAAW1"), "{body}");
    assert!(
        admin_records(&s)?
            .iter()
            .any(|r| r["action"] == "export_audit"),
        "recorded"
    );
    let (status, _, _) = send(
        &s.app,
        get("/console/audit/export", "enterplace_console=forged")?,
    )
    .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // The rows the filter shows, as a CSV a spreadsheet opens: only those rows, named columns, and recorded too.
    let (status, headers, csv) = send(
        &s.app,
        get("/console/audit/export.csv?verdict=refused", &cookie)?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{csv}");
    assert!(
        headers
            .get(header::CONTENT_DISPOSITION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains(".csv")),
        "{headers:?}"
    );
    let mut lines = csv.lines();
    assert_eq!(
        lines.next(),
        Some("time,decision,person,team,key kind,model or tool,verdict,reason")
    );
    let rows: Vec<&str> = lines.collect();
    assert!(
        rows.iter().any(|r| r.contains("01AAAAAAAAAAAAAAAAAAAAAAA2")
            && r.contains(",maya.cohen,payments,key,gpt-4o,")
            && r.contains("model not allowed")),
        "{csv}"
    );
    assert!(
        !rows
            .iter()
            .any(|r| r.contains("01AAAAAAAAAAAAAAAAAAAAAAA1")),
        "an allowed row is not in a refused view: {csv}"
    );
    assert!(
        admin_records(&s)?
            .iter()
            .any(|r| r["action"] == "export_audit_csv" && r["target"]["verdict"] == "refused"),
        "the CSV download is recorded"
    );
    Ok(())
}

#[tokio::test]
async fn a_kill_switch_shows_a_banner_on_audit_and_in_the_sheet_of_a_request_it_stopped()
-> TestResult {
    let s = setup("kills")?;
    let cookie = sign_in(&s.app).await?;
    let page = audit(&s.app, &cookie, "").await?;
    assert_eq!(
        page["kills"],
        serde_json::json!([]),
        "a banner with no switch on"
    );
    let kills =
        enterplace_core::kill::Switches::open(enterplace_core::kill::path_beside(&s.keys()));
    kills.set(enterplace_core::kill::Kill {
        scope: "person".into(),
        value: "maya.cohen".into(),
        reason: "retrying <the same> ticket".into(),
        by: "noa.bar".into(),
        at: "2026-11-13T13:48:02.000Z".into(),
    })?;
    s.log.append(&Entry {
        id: "01AAAAAAAAAAAAAAAAAAAAAAK1",
        person: Some("maya.cohen"),
        team: Some("payments"),
        method: "POST",
        path: "/v1/chat/completions",
        model: Some("gpt-4o-mini"),
        code: Some("killed"),
        ..Entry::default()
    })?;
    let page = audit(&s.app, &cookie, "").await?;
    // One line per switch, in words, with what turns it off.
    let kill = &page["kills"][0];
    assert!(
        kill["label"] == "person maya.cohen"
            && kill["by"] == "noa.bar"
            && kill["reason"] == "retrying <the same> ticket"
            && kill["command"] == "enterplace unkill --person maya.cohen"
            && page["may_restore"] == true,
        "{page}"
    );
    let stopped = sheet(&s.app, &cookie, "01AAAAAAAAAAAAAAAAAAAAAAK1").await?;
    assert!(
        stopped["lead"]
            .as_str()
            .unwrap_or("")
            .starts_with("Kill switch person maya.cohen was on")
            && fact(&stopped, "Switch") == "person maya.cohen, still on",
        "{stopped}"
    );
    // Restore traffic turns the switch off, as enterplace unkill does, and the admin record says who did it.
    let (status, _, answer) = call(
        &s.app,
        "POST",
        "/console/api/audit/restore",
        &cookie,
        serde_json::json!({ "scope": "person", "value": "maya.cohen" }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(
        answer["message"],
        "Traffic restored for person maya.cohen. Every gateway lets it through within 2 seconds."
    );
    assert!(
        enterplace_core::kill::read(&enterplace_core::kill::path_beside(&s.keys()))?.is_empty(),
        "the switch is off"
    );
    assert!(
        admin_records(&s)?
            .iter()
            .any(|r| r["action"] == "clear_kill"
                && r["target"]["value"] == "maya.cohen"
                && r["verdict"] == "allow"),
        "recorded"
    );
    let after = audit(&s.app, &cookie, "record=01AAAAAAAAAAAAAAAAAAAAAAK1").await?;
    assert!(
        fact(&after["record"], "Switch") == "Off now" && after["kills"] == serde_json::json!([]),
        "{after}"
    );
    // A switch that does not parse is refused with what to do, and nothing is recorded.
    let (status, _, refused) = call(
        &s.app,
        "POST",
        "/console/api/audit/restore",
        &cookie,
        serde_json::json!({ "scope": "planet", "value": "x" }),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert!(
        refused["error"]
            .as_str()
            .unwrap_or("")
            .contains("Restore traffic"),
        "{refused}"
    );
    // People's form still turns a switch off through the console's own route.
    kills.set(enterplace_core::kill::Kill {
        scope: "person".into(),
        value: "maya.cohen".into(),
        reason: "again".into(),
        by: "noa.bar".into(),
        at: "2026-11-13T14:00:00.000Z".into(),
    })?;
    let (status, _, _) = send(
        &s.app,
        post(
            "/console/kills/restore",
            &cookie,
            "scope=person&value=maya.cohen",
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        enterplace_core::kill::read(&enterplace_core::kill::path_beside(&s.keys()))?.is_empty()
    );
    Ok(())
}

// ---------------------------------------------------------------- round 12 review

/// `enterplace unkill --person maya.cohen` as a page writes it: it wraps only between its words.
const UNKILL_MAYA: &str = "enterplace unkill --person maya.cohen";

/// An admin record of a kill switch set or cleared, as the admin API writes it.
fn kill_record(
    s: &Setup,
    id: &str,
    action: &str,
    scope: &str,
    value: &str,
    reason: &str,
) -> TestResult {
    let mut target = serde_json::json!({ "scope": scope, "value": value });
    if !reason.is_empty() {
        target["reason"] = reason.into();
    }
    let record = serde_json::json!({
        "event": "admin",
        "id": id,
        "time": enterplace_core::audit::timestamp(),
        "person": "noa.bar",
        "team": "platform",
        "action": action,
        "target": target,
        "verdict": "allow",
        "code": null,
    });
    let serde_json::Value::Object(record) = record else {
        return Err("not an object".into());
    };
    s.log.append_record(&record)?;
    Ok(())
}

fn killed_record(s: &Setup, id: &str, model: Option<&str>) -> TestResult {
    s.log.append(&Entry {
        id,
        person: Some("maya.cohen"),
        team: Some("payments"),
        method: "POST",
        path: "/v1/chat/completions",
        model,
        code: Some("killed"),
        ..Entry::default()
    })?;
    Ok(())
}

#[tokio::test]
async fn a_killed_sheet_tells_the_story_of_the_switch_that_stopped_it_and_whether_that_one_is_still_on()
-> TestResult {
    // M12-2 and M12-3. A model switch stops maya.cohen and is cleared; then a person switch stops her and stays on.
    let s = setup("killed-story")?;
    let kills =
        enterplace_core::kill::Switches::open(enterplace_core::kill::path_beside(&s.keys()));
    kill_record(
        &s,
        "01AAAAAAAAAAAAAAAAAAAAAAS1",
        "set_kill",
        "model",
        "gpt-4o",
        "provider incident",
    )?;
    killed_record(&s, "01AAAAAAAAAAAAAAAAAAAAAAK1", Some("gpt-4o"))?;
    kill_record(
        &s,
        "01AAAAAAAAAAAAAAAAAAAAAAS2",
        "clear_kill",
        "model",
        "gpt-4o",
        "",
    )?;
    kill_record(
        &s,
        "01AAAAAAAAAAAAAAAAAAAAAAS3",
        "set_kill",
        "person",
        "maya.cohen",
        "retrying a ticket in a loop",
    )?;
    kills.set(enterplace_core::kill::Kill {
        scope: "person".into(),
        value: "maya.cohen".into(),
        reason: "retrying a ticket in a loop".into(),
        by: "noa.bar".into(),
        at: enterplace_core::audit::timestamp(),
    })?;
    killed_record(&s, "01AAAAAAAAAAAAAAAAAAAAAAK2", None)?;
    let cookie = sign_in(&s.app).await?;

    let sheet1 = sheet(&s.app, &cookie, "01AAAAAAAAAAAAAAAAAAAAAAK1").await?;
    assert_eq!(
        sheet1["title"], "A kill switch stopped maya.cohen",
        "{sheet1}"
    );
    assert!(
        sheet1["lead"]
            .as_str()
            .unwrap_or("")
            .contains("Kill switch model gpt-4o was on: provider incident"),
        "{sheet1}"
    );
    // The person switch on now did not stop this request: it was set after.
    assert_eq!(fact(&sheet1, "Switch"), "model gpt-4o, off now", "{sheet1}");
    assert!(
        !sheet1
            .to_string()
            .contains("Enterplace refused it with the code"),
        "{sheet1}"
    );
    for label in ["Switch", "Reason", "Set by"] {
        assert!(
            !fact(&sheet1, label).is_empty(),
            "missing {label}: {sheet1}"
        );
    }
    assert!(fact(&sheet1, "Turn off").is_empty(), "{sheet1}");

    let sheet2 = sheet(&s.app, &cookie, "01AAAAAAAAAAAAAAAAAAAAAAK2").await?;
    assert!(
        sheet2["title"] == "A kill switch stopped maya.cohen"
            && fact(&sheet2, "Switch") == "person maya.cohen, still on"
            && fact(&sheet2, "Turn off") == UNKILL_MAYA
            && !sheet2.to_string().contains("model gpt-4o"),
        "{sheet2}"
    );
    // m12-4. Kill switch records read in words.
    let list = page_text(&s.app, &cookie, "").await?;
    assert!(
        list.contains("stopped traffic")
            && list.contains("restored traffic")
            && !list.contains("set_kill")
            && !list.contains("clear_kill"),
        "{list}"
    );
    // m12-5. One block per switch: its scope in mono, its reason, since when and by whom, and the one command.
    let page = audit(&s.app, &cookie, "").await?;
    assert!(
        page["kills"][0]["label"] == "person maya.cohen"
            && page["kills"][0]["by"] == "noa.bar"
            && page["may_restore"] == true,
        "{page}"
    );
    Ok(())
}

#[tokio::test]
async fn tpm_and_key_model_sheets_name_the_limit_and_the_list_that_refused() -> TestResult {
    // M12-6. A tokens-a-minute refusal names its limit, and a key's own models list is named as the cause.
    let s = setup("tpm-key-model")?;
    let policy = POLICY.replace(
        "    models: [gpt-4o-mini]\n",
        "    models: [gpt-4o-mini, gpt-4o]\n    rate: { tpm: 1500 }\n",
    );
    std::fs::write(s.dir.join("enterplace.policy.yaml"), &policy)?;
    let keys = keys_text().replace(
        "    team: payments\n",
        "    team: payments\n    models: [gpt-4o-mini]\n    tpm: 100\n",
    );
    std::fs::write(s.keys(), &keys)?;
    let (policy_sha, keys_sha) = (sha256_hex(policy.as_bytes()), sha256_hex(keys.as_bytes()));
    let maya = sha256_hex(MAYA_KEY.as_bytes());
    let base = Entry {
        person: Some("maya.cohen"),
        team: Some("payments"),
        key: Some(&maya[..8]),
        method: "POST",
        path: "/v1/chat/completions",
        rule: Some("payments-team"),
        rule_line: Some(10),
        policy_sha256: &policy_sha,
        keys_sha256: &keys_sha,
        ..Entry::default()
    };
    s.log.append(&Entry {
        id: "01AAAAAAAAAAAAAAAAAAAAAAT1",
        model: Some("gpt-4o-mini"),
        code: Some("rate_limited"),
        ..base.clone()
    })?;
    s.log.append(&Entry {
        id: "01AAAAAAAAAAAAAAAAAAAAAAT2",
        model: Some("gpt-4o"),
        code: Some("model_not_allowed"),
        ..base.clone()
    })?;
    // UX12-2. A record that names the limit that refused it: the sheet keeps only that one.
    for (id, of, value) in [
        ("01AAAAAAAAAAAAAAAAAAAAAAT3", "key", 100),
        ("01AAAAAAAAAAAAAAAAAAAAAAT4", "team", 1500),
    ] {
        let mut record = enterplace_core::audit::record(&Entry {
            id,
            model: Some("gpt-4o-mini"),
            code: Some("rate_limited"),
            ..base.clone()
        });
        record.insert(
            "limit".into(),
            serde_json::json!({ "kind": "tpm", "of": of, "value": value }),
        );
        s.log.append_record(&record)?;
    }
    let cookie = sign_in(&s.app).await?;
    let tpm = sheet_text(&s.app, &cookie, "01AAAAAAAAAAAAAAAAAAAAAAT1").await?;
    // The record does not say whether the rule's limit or the key's refused it, so the sheet says so and names both.
    assert!(
        tpm.contains("1,500 tokens a minute")
            && tpm.contains("100 tokens a minute")
            && tpm.contains("the record does not say which")
            && !tpm.contains("sent too many requests")
            && !tpm.contains("has changed since"),
        "{tpm}"
    );
    for (id, expected, not) in [
        (
            "01AAAAAAAAAAAAAAAAAAAAAAT3",
            "maya.cohen's key used up its tokens for the minute",
            "1,500",
        ),
        (
            "01AAAAAAAAAAAAAAAAAAAAAAT4",
            "The payments team used up its tokens for the minute",
            "Key limit",
        ),
    ] {
        let sheet = sheet_text(&s.app, &cookie, id).await?;
        assert!(sheet.contains(expected) && !sheet.contains(not), "{sheet}");
    }
    // m13-3: a request larger than the whole minute's limit says so, with both numbers and no retry promise.
    let mut record = enterplace_core::audit::record(&Entry {
        id: "01AAAAAAAAAAAAAAAAAAAAAAT5",
        model: Some("gpt-4o-mini"),
        code: Some("rate_limited"),
        ..base.clone()
    });
    record.insert(
        "limit".into(),
        serde_json::json!({ "kind": "tpm", "of": "key", "value": 100, "request_could_use": 528 }),
    );
    s.log.append_record(&record)?;
    // m13-4: a key-model refusal under a policy that changed since does not claim what the rule listed.
    s.log.append(&Entry {
        id: "01AAAAAAAAAAAAAAAAAAAAAAT6",
        model: Some("gpt-4o"),
        code: Some("model_not_allowed"),
        policy_sha256: &sha256_hex(b"an older policy"),
        ..base.clone()
    })?;
    let big = sheet_text(&s.app, &cookie, "01AAAAAAAAAAAAAAAAAAAAAAT5").await?;
    assert!(
        big.contains("This request alone is larger than maya.cohen's key allows in a minute")
            && big.contains("could use 528 tokens")
            && !big.contains("was told when to send again"),
        "{big}"
    );
    let old = sheet_text(&s.app, &cookie, "01AAAAAAAAAAAAAAAAAAAAAAT6").await?;
    assert!(
        old.contains(
            "the record does not say whether rule payments-team or the key's own models refused"
        ) || old.contains("key does not allow"),
        "{old}"
    );
    assert!(!old.contains("does not list gpt-4o"), "{old}");
    let model = sheet_text(&s.app, &cookie, "01AAAAAAAAAAAAAAAAAAAAAAT2").await?;
    assert!(
        model.contains("maya.cohen's key does not allow gpt-4o")
            && model.contains(r#"{"label":"Key models","text":"gpt-4o-mini"}"#)
            && !model.contains("does not list gpt-4o"),
        "{model}"
    );
    Ok(())
}

#[tokio::test]
async fn a_self_issued_key_sheet_names_its_expiry() -> TestResult {
    // m12-8.
    let s = setup("self-issue")?;
    let record = serde_json::json!({
        "event": "admin",
        "via": "console",
        "id": "01AAAAAAAAAAAAAAAAAAAAAAL1",
        "time": enterplace_core::audit::timestamp(),
        "person": "dana@example.com",
        "team": "developers",
        "action": "self_issue_key",
        "target": { "via": "enterplace login", "name": "dana@example.com", "team": "developers", "sha256_prefix": "eb5c90c0", "expires": "2026-12-13T06:16:26Z" },
        "verdict": "allow",
        "code": null,
    });
    let serde_json::Value::Object(record) = record else {
        return Err("not an object".into());
    };
    s.log.append_record(&record)?;
    let cookie = sign_in(&s.app).await?;
    let sheet = sheet_text(&s.app, &cookie, "01AAAAAAAAAAAAAAAAAAAAAAL1").await?;
    assert!(
        sheet.contains(r#"{"label":"Expires","text":"13 December 2026"}"#),
        "{sheet}"
    );
    let list = page_text(&s.app, &cookie, "").await?;
    assert!(
        list.contains("enterplace login key") && !list.contains("self_issue_key"),
        "{list}"
    );
    Ok(())
}

#[tokio::test]
async fn people_shows_a_stopped_person_and_a_keys_own_models_and_tpm() -> TestResult {
    // m12-6, m12-7 and UX p14.
    let s = setup("people-stopped")?;
    std::fs::write(
        s.keys(),
        keys_text().replace(
            "    team: payments\n",
            "    team: payments\n    models: [gpt-4o-mini]\n    tpm: 50000\n    expires: 2026-12-13T06:16:26Z\n",
        ),
    )?;
    let kills =
        enterplace_core::kill::Switches::open(enterplace_core::kill::path_beside(&s.keys()));
    kills.set(enterplace_core::kill::Kill {
        scope: "person".into(),
        value: "maya.cohen".into(),
        reason: "retrying a ticket in a loop".into(),
        by: "noa.bar".into(),
        at: enterplace_core::audit::timestamp(),
    })?;
    let cookie = sign_in(&s.app).await?;
    let people = people(&s.app, &cookie).await?;
    let status = &key_named(&people, "maya.cohen")?["status"];
    assert_eq!(
        (status["tag"].as_str(), status["kind"].as_str()),
        (Some("Stopped"), Some("refused"))
    );
    let notes = status["notes"].to_string();
    assert!(
        notes.contains("retrying a ticket in a loop")
            && notes.contains("models gpt-4o-mini")
            && notes.contains("50,000 tokens a minute")
            && !people.to_string().contains("expires 2026-12-13T06:16:26Z"),
        "{status}"
    );
    assert_eq!(
        status["fix"],
        serde_json::json!({ "kind": "restore", "scope": "person", "value": "maya.cohen" })
    );
    Ok(())
}

/// M13-1: an answer guardrail's record folds into its request: the row's badge, the sheet's story and findings,
/// the Blocked filter and the counter; its own number opens the request's sheet. M13-2: the price source shows.
#[tokio::test]
async fn an_answer_guardrail_shows_on_its_request_and_the_price_source_shows() -> TestResult {
    let s = setup("answer-fold")?;
    let answer = |id: &str, verdict: &str, found: serde_json::Value| {
        let mut record = serde_json::Map::new();
        record.insert("event".into(), "answer_guardrails".into());
        record.insert("id".into(), id.into());
        record.insert("time".into(), enterplace_core::audit::timestamp().into());
        record.insert("verdict".into(), verdict.into());
        record.insert("guardrails".into(), found);
        record
    };
    s.log.append_record(&answer(
        "01AAAAAAAAAAAAAAAAAAAAAAA1",
        "block",
        serde_json::json!([{"guardrail": "no-secrets-out", "kind": "aws_access_key", "action": "block", "count": 1}]),
    ))?;
    let mut usage = serde_json::Map::new();
    for (k, v) in [
        ("event", "usage"),
        ("id", "01AAAAAAAAAAAAAAAAAAAAAAA1"),
        ("person", "maya.cohen"),
        ("team", "payments"),
        ("model", "gpt-4o-mini"),
        ("provider", "openai"),
        ("price_source", "litellm"),
    ] {
        usage.insert(k.into(), v.into());
    }
    usage.insert("time".into(), enterplace_core::audit::timestamp().into());
    usage.insert("charged_usd".into(), 0.0035.into());
    usage.insert("cost_usd".into(), 0.0035.into());
    s.log.append_record(&usage)?;
    let n = std::fs::read_to_string(s.audit())?
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|r| r["event"] == "answer_guardrails")
        .and_then(|r| r["n"].as_u64())
        .ok_or("no answer record")?;
    let cookie = sign_in(&s.app).await?;

    let list = audit(&s.app, &cookie, "").await?;
    assert!(
        has_tag(&list, "block", "Block", "aws_access_key")
            && !list.to_string().contains("answer_guardrails"),
        "{list}"
    );
    assert_eq!(list["stats"]["blocked"], "1", "{list}");
    let blocked = page_text(&s.app, &cookie, "verdict=blocked").await?;
    assert!(blocked.contains("01AAAAAAAAAAAAAAAAAAAAAAA1"), "{blocked}");

    for selected in ["01AAAAAAAAAAAAAAAAAAAAAAA1".to_string(), n.to_string()] {
        let sheet = sheet_text(&s.app, &cookie, &selected).await?;
        assert!(
            sheet.contains("Guardrail no-secrets-out withheld the answer")
                && sheet.contains("guardrail_blocked")
                && sheet.contains("on the answer")
                && sheet.contains("maya.cohen")
                && sheet.contains("LiteLLM table"),
            "{selected}: {sheet}"
        );
    }

    let spend = spend(&s.app, &cookie).await?;
    let model = &spend["models"][0];
    assert!(
        model["priced"]
            .as_str()
            .is_some_and(|p| p.contains("priced from the LiteLLM table"))
            && spend["note"]
                .as_str()
                .is_some_and(|n| n.contains("Prices this month came from the LiteLLM table"))
            && model["usd"] == "$0.0035",
        "{spend}"
    );
    Ok(())
}

#[tokio::test]
async fn a_custom_role_sees_only_the_pages_it_may_and_an_org_role_only_its_keys() -> TestResult {
    const FIN_KEY: &str = "enterplace_fin_key_for_tests";
    const KEEPER_KEY: &str = "enterplace_keeper_key_for_tests";
    let s = setup("roles")?;
    let policy = format!(
        "{POLICY}orgs: [acme]\nroles:\n  - name: finance\n    permissions: [see_spend]\n  - name: keeper\n    permissions: [see_keys, issue_keys]\n"
    );
    std::fs::write(s.dir.join("enterplace.policy.yaml"), policy)?;
    std::fs::write(
        s.keys(),
        format!(
            "{}  - name: fin\n    team: money\n    sha256: {}\n    role: finance\n  - name: keeper\n    team: ops\n    sha256: {}\n    org: acme\n    role: keeper\n  - name: acme-bot\n    team: bots\n    sha256: {}\n    org: acme\n",
            keys_text(),
            sha256_hex(FIN_KEY.as_bytes()),
            sha256_hex(KEEPER_KEY.as_bytes()),
            sha256_hex(b"enterplace_acme_bot_key")
        ),
    )?;
    let cookie_of = |headers: &HeaderMap| {
        headers
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .map(|c| c.split(';').next().unwrap_or("").to_string())
            .unwrap_or_default()
    };
    let (status, headers, _) = send(
        &s.app,
        post("/console/sign-in", "", &format!("key={FIN_KEY}"))?,
    )
    .await?;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let fin = cookie_of(&headers);
    spend(&s.app, &fin).await?;
    let (status, _, body) = call(
        &s.app,
        "GET",
        "/console/api/people",
        &fin,
        serde_json::Value::Null,
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or("")
            .contains("does not have the see_keys permission"),
        "{body}"
    );
    // The audit log is not its page: it starts on spend.
    let (status, headers, _) = send(&s.app, get("/console/audit", &fin)?).await?;
    assert_eq!(
        (status, location(&headers)),
        (StatusCode::SEE_OTHER, "/console/spend")
    );

    let (_, headers, _) = send(
        &s.app,
        post("/console/sign-in", "", &format!("key={KEEPER_KEY}"))?,
    )
    .await?;
    let keeper = cookie_of(&headers);
    // Analytics needs see_spend: finance has it, the keeper role does not.
    let (status, _, body) = call(
        &s.app,
        "GET",
        "/console/api/analytics",
        &fin,
        serde_json::Value::Null,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _, body) = call(
        &s.app,
        "GET",
        "/console/api/analytics",
        &keeper,
        serde_json::Value::Null,
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or("")
            .contains("does not have the see_spend permission"),
        "{body}"
    );
    let body = people(&s.app, &keeper).await?.to_string();
    assert!(
        body.contains("acme-bot") && !body.contains("maya.cohen"),
        "an org role sees its org's keys only"
    );
    // It may issue a key, and the key goes into its organization.
    let (status, _, body) = call(
        &s.app,
        "POST",
        "/console/api/people/issue",
        &keeper,
        serde_json::json!({ "name": "acme-new", "team": "bots" }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let saved = std::fs::read_to_string(s.keys())?;
    let new = saved.split("- name: acme-new").nth(1).ok_or("no entry")?;
    assert!(new.contains("org: acme"), "{saved}");
    // It may not revoke: revoke_keys is not in its role.
    let bot = sha256_hex(b"enterplace_acme_bot_key");
    let (status, _, refused) = call(
        &s.app,
        "POST",
        "/console/api/people/revoke",
        &keeper,
        serde_json::json!({ "sha256": bot, "confirm": "acme-bot" }),
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    assert!(std::fs::read_to_string(s.keys())?.contains(&bot));
    Ok(())
}

#[tokio::test]
async fn every_page_says_when_observe_mode_lets_everything_through() -> TestResult {
    let s = setup("observe-banner")?;
    let cookie = sign_in(&s.app).await?;
    let page = page_text(&s.app, &cookie, "").await?;
    assert!(!page.contains("Observe mode"), "enforcing shows no banner");
    std::fs::write(
        s.dir.join("enterplace.policy.yaml"),
        format!("mode: observe\n{POLICY}"),
    )?;
    // One short line, the same on every page, once.
    // The app says it on every page of its own, from what it reads of the signed-in person.
    let (_, _, me) = call(
        &s.app,
        "GET",
        "/console/api/me",
        &cookie,
        serde_json::Value::Null,
    )
    .await?;
    assert_eq!(me["observe"], true);
    Ok(())
}

#[tokio::test]
async fn with_per_org_chains_an_org_role_reads_its_own_chain_and_an_admin_switches_between_them()
-> TestResult {
    const AUDITOR_KEY: &str = "enterplace_auditor_key_for_tests";
    let s = setup("per-org")?;
    let policy = format!(
        "{POLICY}orgs: [acme]\naudit: {{ per_org: true }}\nroles:\n  - name: auditor\n    permissions: [see_records]\n"
    );
    std::fs::write(s.dir.join("enterplace.policy.yaml"), policy)?;
    std::fs::write(
        s.keys(),
        format!(
            "{}  - name: ana\n    team: audit\n    sha256: {}\n    org: acme\n    role: auditor\n",
            keys_text(),
            sha256_hex(AUDITOR_KEY.as_bytes())
        ),
    )?;
    // acme's chain: its decision, and one that follows a decision of acme's and names no organization.
    let acme = enterplace_core::audit::org_path(&s.audit(), "acme");
    std::fs::create_dir_all(acme.parent().ok_or("no folder")?)?;
    let chain = AuditLog::open(&acme)?;
    for (id, org) in [("ACMEDECISION1", Some("acme")), ("ACMEDECISION2", None)] {
        let mut record = enterplace_core::audit::record(&Entry {
            id,
            person: Some("acme-bot"),
            method: "POST",
            path: "/v1/chat/completions",
            allowed: true,
            ..Entry::default()
        });
        if let Some(org) = org {
            record.insert("org".into(), org.into());
        }
        chain.append_record(&record)?;
    }
    chain.flush();
    drop(chain);

    let (status, headers, _) = send(
        &s.app,
        post("/console/sign-in", "", &format!("key={AUDITOR_KEY}"))?,
    )
    .await?;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let ana = headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(|c| c.split(';').next().unwrap_or("").to_string())
        .unwrap_or_default();
    let page = page_text(&s.app, &ana, "").await?;
    assert!(
        page.contains("ACMEDECISION1") && page.contains("ACMEDECISION2"),
        "the whole of acme's chain: {page}"
    );
    assert!(
        !page.contains("maya.cohen"),
        "nothing of the install's chain"
    );
    assert!(page.contains("organization acme"), "{page}");
    // Verify checks acme's chain, whatever the address asks for.
    verify(&s.app, &ana, "").await?;
    let page = page_text(&s.app, &ana, "").await?;
    assert!(
        page.contains("unbroken from record 1 to record 2"),
        "{page}"
    );

    // An admin kept to no organization starts on the install's chain and may switch to acme's.
    let cookie = sign_in(&s.app).await?;
    let page = page_text(&s.app, &cookie, "").await?;
    assert!(
        page.contains("maya.cohen")
            && !page.contains("ACMEDECISION1")
            && page.contains(r#"{"label":"acme","chain":"acme","shown":false}"#),
        "{page}"
    );
    let page = page_text(&s.app, &cookie, "chain=acme").await?;
    assert!(
        page.contains("ACMEDECISION1") && !page.contains("maya.cohen"),
        "{page}"
    );
    Ok(())
}

#[tokio::test]
async fn a_key_is_rotated_from_its_page_shown_once_and_the_old_one_ends_after_the_grace()
-> TestResult {
    let s = setup("rotate")?;
    let cookie = sign_in(&s.app).await?;
    let old = sha256_hex(MAYA_KEY.as_bytes());
    let rotate = |grace: &str| serde_json::json!({ "sha256": old, "grace": grace });

    // A grace that is not a time changes nothing and says how to write one.
    let (status, _, refused) = call(
        &s.app,
        "POST",
        "/console/api/people/rotate",
        &cookie,
        rotate("soon"),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        refused["error"].as_str().unwrap_or("").contains("48h"),
        "{refused}"
    );
    assert!(!std::fs::read_to_string(s.keys())?.contains("replaced_by"));

    let (status, headers, made) = call(
        &s.app,
        "POST",
        "/console/api/people/rotate",
        &cookie,
        rotate("48h"),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{made}");
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let key = made["key"]
        .as_str()
        .ok_or("the new key is not in the answer")?;
    assert!(key.starts_with("enterplace_") && key != MAYA_KEY, "{key}");
    assert!(
        made["message"]
            .as_str()
            .unwrap_or("")
            .contains("key_rotated"),
        "the answer says how to find who still uses the old key"
    );
    let new = sha256_hex(key.as_bytes());
    let entries =
        enterplace_core::config::key_entries(&s.keys(), &std::fs::read_to_string(s.keys())?)
            .map_err(|e| e.join(" "))?;
    let old_entry = entries
        .iter()
        .find(|e| e.sha256 == old)
        .ok_or("old key gone")?;
    let new_entry = entries
        .iter()
        .find(|e| e.sha256 == new)
        .ok_or("no new key")?;
    assert_eq!(old_entry.options.replaced_by.as_deref(), Some(&new[..8]));
    assert!(
        old_entry.expires.is_some(),
        "the old key ends after the grace"
    );
    assert_eq!(
        (new_entry.name.as_str(), new_entry.team.as_str()),
        ("maya.cohen", "payments")
    );
    assert!(!std::fs::read_to_string(s.keys())?.contains(key));
    // The People page says the old key was replaced, for its editor.
    let people = people(&s.app, &cookie).await?;
    let rows = people["entries"].as_array().cloned().unwrap_or_default();
    assert!(
        rows.iter()
            .any(|e| e["sha256"] == old && e["fields"]["replaced_by"] == new[..8]),
        "{people}"
    );

    // Recorded with both hash prefixes and never the key; a second rotation of the old key is refused.
    s.log.flush();
    let records = admin_records(&s)?;
    let rotated = records
        .iter()
        .find(|r| r["action"] == "rotate_key" && r["target"]["replaced_by"] == new[..8])
        .ok_or("the rotation is not recorded")?;
    assert_eq!(rotated["target"]["sha256_prefix"], old[..8]);
    assert!(!std::fs::read_to_string(s.audit())?.contains(key));
    let (status, _, refused) = call(
        &s.app,
        "POST",
        "/console/api/people/rotate",
        &cookie,
        rotate("1h"),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        refused["error"]
            .as_str()
            .unwrap_or("")
            .contains("already rotated"),
        "{refused}"
    );
    Ok(())
}

/// UX #19, #29, #30: one set of verdict words, the row opens on its time, and refusals are not said to be by policy.
#[tokio::test]
async fn audit_rows_say_verdicts_in_words_and_open_on_their_time() -> TestResult {
    let s = setup("verdict-words")?;
    killed_record(&s, "01AAAAAAAAAAAAAAAAAAAAAAK1", Some("gpt-4o"))?;
    kill_record(
        &s,
        "01AAAAAAAAAAAAAAAAAAAAAAK2",
        "set_kill",
        "person",
        "maya.cohen",
        "a loop",
    )?;
    let cookie = sign_in(&s.app).await?;
    let page = audit(&s.app, &cookie, "").await?;
    for (kind, word, detail) in [
        ("allow", "Allowed", ""),
        ("refused", "Refused:", "unknown key"),
        ("refused", "Refused:", "kill switch"),
        ("", "Admin:", "signed in"),
        ("", "Admin:", "stopped traffic"),
    ] {
        assert!(
            has_tag(&page, kind, word, detail),
            "{word} {detail}: {page}"
        );
    }
    assert!(page["stats"]["refused"].is_string(), "{page}");
    // A row opens on its time, named for a screen reader by its decision.
    let row = page["rows"]
        .as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|r| r["id"] == "01AAAAAAAAAAAAAAAAAAAAAAA3")
        })
        .ok_or("no row")?;
    assert_eq!(row["open"], "Open decision 01AAAAAAAAAAAAAAAAAAAAAAA3");
    assert_ne!(row["time"], "01AAAAAAAAAAAAAAAAAAAAAAA3");
    let rows = page["rows"].to_string();
    for gone in [
        "unknown_key",
        "\"Allow\"",
        "by policy",
        "Time (UTC) and decision",
    ] {
        assert!(!rows.contains(gone), "{gone}: {rows}");
    }
    let opened = sheet(&s.app, &cookie, "01AAAAAAAAAAAAAAAAAAAAAAA1").await?;
    assert!(
        fact(&opened, "Verdict") == "Allowed"
            && fact(&opened, "Decision") == "01AAAAAAAAAAAAAAAAAAAAAAA1",
        "{opened}"
    );
    Ok(())
}

/// UX #38, #40: the row offers Edit only, Revoke is on the edit page, one page has no pager, and the key forms match.
#[tokio::test]
async fn people_rows_offer_edit_and_the_key_forms_keep_one_hint() -> TestResult {
    let s = setup("people-actions")?;
    let cookie = sign_in(&s.app).await?;
    let people = people(&s.app, &cookie).await?;
    // Every row may be edited by an admin of the whole install; revoke is in the editor, not on the row.
    assert!(
        people["entries"]
            .as_array()
            .is_some_and(|e| e.iter().all(|e| e["editable"] == true)),
        "{people}"
    );
    assert_eq!(
        (
            people["may"]["issue"].as_bool(),
            people["may"]["revoke"].as_bool()
        ),
        (Some(true), Some(true))
    );
    let maya = sha256_hex(MAYA_KEY.as_bytes());
    // The old editor address opens the app's editor for the same key.
    let (_, headers, _) = send(
        &s.app,
        get(&format!("/console/people/edit?sha256={maya}"), &cookie)?,
    )
    .await?;
    assert_eq!(
        location(&headers),
        format!("/console/app/#/people?edit={maya}")
    );
    // The editor's fields start from the key as it is.
    let fields = &key_named(&people, "maya.cohen")?["fields"];
    assert_eq!(fields["expires"], "");
    assert!(fields["replaced_by"].is_null(), "{fields}");
    Ok(())
}

/// UX #35: at no spend the page is one empty state, not an empty chart and people ranked at $0.
#[tokio::test]
async fn spend_at_zero_is_one_empty_state() -> TestResult {
    let s = setup("spend-zero")?;
    let cookie = sign_in(&s.app).await?;
    let mut demo = usage_record("maya.cohen", "deadbeef", 0.0);
    demo.insert("model".into(), "enterplace-demo".into());
    s.log.append_record(&demo)?;
    let spend = spend(&s.app, &cookie).await?;
    assert_eq!(
        (
            spend["empty"]["title"].as_str(),
            spend["empty"]["body"].as_str()
        ),
        (Some("No spend yet"), Some("Demo requests are free."))
    );
    // One empty state: no chart, no people ranked at $0 and no models table.
    assert!(
        spend["chart"].is_null() && spend["spenders"].is_null() && spend["stopped"].is_null(),
        "{spend}"
    );
    Ok(())
}

/// UX #47: the sign-in page says admin-only once, and signing out says it worked.
#[tokio::test]
async fn sign_in_says_admin_only_once_and_sign_out_is_confirmed() -> TestResult {
    let s = setup("sign-in-once")?;
    let (_, _, page) = send(&s.app, get("/console/sign-in", "")?).await?;
    assert!(
        page.contains("Admin keys only.")
            && !page.contains("Admins only")
            && !page.contains("8 hours")
            && !page.contains("never stored"),
        "{page}"
    );
    let cookie = sign_in(&s.app).await?;
    let (_, headers, _) = send(&s.app, get("/console/sign-out", &cookie)?).await?;
    let (_, _, out) = send(&s.app, get(location(&headers), "")?).await?;
    assert!(out.contains("You signed out."), "{out}");
    Ok(())
}

/// UX #25, #26: a policy kept in a file says read only once, with no edit or export to contradict it.
#[tokio::test]
async fn a_file_kept_policy_offers_nothing_that_edits_it() -> TestResult {
    let s = setup("read-only-file")?;
    std::fs::write(
        s.dir.join("enterplace.policy.yaml"),
        POLICY.replace(
            "  - name: payments-team\n    principals: { team: payments }\n    models: [gpt-4o-mini]\n",
            "",
        ),
    )?;
    let cookie = sign_in(&s.app).await?;
    let (_, _, prices) = call(
        &s.app,
        "GET",
        "/console/api/prices",
        &cookie,
        serde_json::Value::Null,
    )
    .await?;
    // Prices are the one exception: a price is changed in the file too, through the same checked save as every
    // other policy edit (round 3: a file-kept policy had no way to change a price).
    assert!(
        prices["docs"]
            .as_str()
            .unwrap_or("")
            .ends_with("/operations/console-editing/")
            && prices["editable"] == true
            && prices["file"].is_null()
            && prices["agent"]
                .as_str()
                .unwrap_or("")
                .contains("enterplace check"),
        "{prices}"
    );
    let (status, _, saved) = call(
        &s.app,
        "POST",
        "/console/api/prices/price",
        &cookie,
        serde_json::json!({ "model": "gpt-4o", "input": "1", "output": "1" }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{saved}");
    let file = std::fs::read_to_string(s.dir.join("enterplace.policy.yaml"))?;
    assert!(file.contains("gpt-4o"), "{file}");
    let (_, _, policy) = call(
        &s.app,
        "GET",
        "/console/api/policy/raw",
        &cookie,
        serde_json::Value::Null,
    )
    .await?;
    assert!(
        policy["next"]["action"]["label"] == "Add a budget"
            && policy["next"]["act"] == true
            && policy["edit"] == false
            && policy["store"] == false,
        "{policy}"
    );
    Ok(())
}

#[tokio::test]
async fn teams_list_each_team_with_its_people_rule_owner_and_budget() -> TestResult {
    let s = setup("teams")?;
    // The old address points at the app, keeping its query, and needs no session: the app asks for one.
    let (status, headers, _) = send(&s.app, get("/console/teams?q=pay", "")?).await?;
    assert_eq!(
        (status, location(&headers)),
        (StatusCode::SEE_OTHER, "/console/app/#/teams?q=pay")
    );
    let (status, _, _) = call(
        &s.app,
        "GET",
        "/console/api/teams",
        "",
        serde_json::Value::Null,
    )
    .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let cookie = sign_in(&s.app).await?;
    let (status, _, page) = call(
        &s.app,
        "GET",
        "/console/api/teams",
        &cookie,
        serde_json::Value::Null,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert!(page["issue"] == true && page["empty"].is_null(), "{page}");
    let teams = page["teams"].as_array().cloned().unwrap_or_default();
    let names: Vec<&str> = teams.iter().filter_map(|t| t["name"].as_str()).collect();
    assert_eq!(names, ["payments", "platform"], "{page}");
    // The first rule naming the team decides for it; a team no rule names falls to the one for everyone.
    assert_eq!(
        teams[0],
        serde_json::json!({
            "name": "payments", "keys": "1 key", "owner": null,
            "people": [{ "name": "maya.cohen", "admin": false }],
            "rule": "payments-team", "budget": "none",
        })
    );
    assert!(
        teams[1]["rule"] == "everyone-else (everyone)"
            && teams[1]["people"] == serde_json::json!([{ "name": "noa.bar", "admin": true }]),
        "{page}"
    );

    // A team the policy lists shows before its first key, with its owner; a team's budget is its rule's.
    std::fs::write(
        s.dir.join("enterplace.policy.yaml"),
        POLICY.replace(
            "    models: [gpt-4o-mini]\n",
            "    models: [gpt-4o-mini]\n    budget: { usd: 1, per: month }\n",
        ) + "teams:\n  - name: web\n    owner: dana@example.com\n",
    )?;
    let (_, _, page) = call(
        &s.app,
        "GET",
        "/console/api/teams",
        &cookie,
        serde_json::Value::Null,
    )
    .await?;
    let teams = page["teams"].as_array().cloned().unwrap_or_default();
    let web = teams
        .iter()
        .find(|t| t["name"] == "web")
        .ok_or("no web team")?;
    assert!(
        web["keys"] == "0 keys"
            && web["owner"] == "dana@example.com"
            && web["rule"] == "everyone-else (everyone)",
        "{page}"
    );
    assert_eq!(teams[0]["budget"], "$1.00 a month", "{page}");

    // A limits: entry for the team counts beside its rule's budget, and the column says it too.
    std::fs::write(
        s.dir.join("enterplace.policy.yaml"),
        POLICY.to_string()
            + "limits:\n  - team: payments\n    budget: { usd: 50, per: month }\n    rate: { tpd: 300 }\n",
    )?;
    let (_, _, page) = call(
        &s.app,
        "GET",
        "/console/api/teams",
        &cookie,
        serde_json::Value::Null,
    )
    .await?;
    let teams = page["teams"].as_array().cloned().unwrap_or_default();
    assert_eq!(
        teams[0]["budget"], "$50.00 a month, 300 tokens per day",
        "{page}"
    );

    // Only admin keys: no team yet, and the way to make one.
    std::fs::write(s.dir.join("enterplace.policy.yaml"), POLICY)?;
    std::fs::write(
        s.keys(),
        format!(
            "keys:\n  - name: noa.bar\n    team: platform\n    sha256: {}\n    admin: true\n",
            sha256_hex(ADMIN_KEY.as_bytes())
        ),
    )?;
    let (_, _, page) = call(
        &s.app,
        "GET",
        "/console/api/teams",
        &cookie,
        serde_json::Value::Null,
    )
    .await?;
    assert!(
        page["empty"]["title"] == "No teams yet"
            && page["empty"]["action"]["label"] == "Make a person token with a team"
            && page["teams"] == serde_json::json!([]),
        "{page}"
    );

    // A policy that does not load says why.
    std::fs::write(s.dir.join("enterplace.policy.yaml"), "version: [")?;
    let (status, _, page) = call(
        &s.app,
        "GET",
        "/console/api/teams",
        &cookie,
        serde_json::Value::Null,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page["error"]
            .as_str()
            .is_some_and(|e| e.starts_with("The policy did not load:")),
        "{page}"
    );
    Ok(())
}

/// A sign-in attempt from `from`, as the server marks each request with its peer address.
fn attempt(key: &str, from: [u8; 4]) -> Result<Request<Body>, axum::http::Error> {
    let mut request = post("/console/sign-in", "", &format!("key={key}"))?;
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            from, 40000,
        ))));
    Ok(request)
}

#[tokio::test]
async fn five_failed_sign_ins_lock_the_source_out_and_the_lockout_is_recorded_once() -> TestResult {
    let s = setup("lockout")?;
    let (here, elsewhere) = ([198, 51, 100, 7], [198, 51, 100, 8]);
    for n in 1..=5 {
        let (status, _, _) = send(&s.app, attempt("enterplace_wrong_key_x", here)?).await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "failure {n}");
    }
    // Locked: the right key is not even looked at, and the answer says for how long.
    for key in [ADMIN_KEY, "enterplace_wrong_key_x"] {
        let (status, headers, page) = send(&s.app, attempt(key, here)?).await?;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{page}");
        let wait: u64 = headers
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .ok_or("no Retry-After")?;
        assert!((29 * 60..=30 * 60).contains(&wait), "{wait}");
        assert!(
            page.contains("sign_in_locked") && page.contains("30 more minutes"),
            "{page}"
        );
    }
    // Another address signs in as before.
    let (status, _, _) = send(&s.app, attempt(ADMIN_KEY, elsewhere)?).await?;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let records = admin_records(&s)?;
    let of = |action: &str, code: serde_json::Value| {
        records
            .iter()
            .filter(|r| r["action"] == action && r["code"] == code)
            .count()
    };
    assert_eq!(
        of("console_sign_in", "not_admin".into()),
        5,
        "each failure is recorded"
    );
    let locked: Vec<_> = records
        .iter()
        .filter(|r| r["action"] == "console_sign_in_locked")
        .collect();
    assert_eq!(
        locked.len(),
        1,
        "the lockout is recorded once, not per refused attempt"
    );
    assert_eq!(locked[0]["target"]["scope"], "source:198.51.100.7");
    assert_eq!(locked[0]["target"]["failures"], 5);
    assert_eq!(locked[0]["target"]["locked_seconds"], 1800);
    assert_eq!(locked[0]["client"], "198.51.100.7");
    Ok(())
}

#[tokio::test]
async fn a_good_sign_in_forgets_the_failures_before_it_and_an_empty_form_counts_as_none()
-> TestResult {
    let s = setup("lockout-reset")?;
    let here = [198, 51, 100, 9];
    for round in 0..2 {
        for _ in 0..4 {
            let (status, _, _) = send(&s.app, attempt("enterplace_wrong_key_x", here)?).await?;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "round {round}");
            let (status, _, _) = send(&s.app, attempt("", here)?).await?;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "an empty form is not an attempt"
            );
        }
        let (status, _, _) = send(&s.app, attempt(ADMIN_KEY, here)?).await?;
        assert_eq!(
            status,
            StatusCode::SEE_OTHER,
            "round {round}: four failures, then in"
        );
    }
    Ok(())
}

#[tokio::test]
async fn people_import_checks_every_line_first_then_issues_each_key_once() -> TestResult {
    let s = setup("import")?;
    let cookie = sign_in(&s.app).await?;
    // Every wrong line comes back with what to fix, and nothing is issued.
    let (status, _, body) = call(
        &s.app,
        "POST",
        "/console/api/people/import",
        &cookie,
        serde_json::json!({ "text": "name,team,budget,kind\nlee.park,payments,lots\nlee.park,payments\nnoa,ops,,robot\n" }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let errors = body["errors"].as_array().cloned().unwrap_or_default();
    let lines: Vec<u64> = errors.iter().filter_map(|e| e["line"].as_u64()).collect();
    assert_eq!(lines, [2, 3, 4], "{body}");
    assert!(
        errors[0]["error"].as_str().unwrap_or("").contains("lots"),
        "{body}"
    );
    let before = std::fs::read_to_string(s.keys())?;
    assert!(!before.contains("lee.park"), "{before}");

    // A clean list: two keys and a person token, shown once, with one Copy all and a CSV.
    let (status, _, body) = call(
        &s.app,
        "POST",
        "/console/api/people/import",
        &cookie,
        serde_json::json!({ "text": "lee.park,payments,50\nnoa.tal,ops\ndana.levi,ops,,person\n" }),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let issued = body["issued"].as_array().cloned().unwrap_or_default();
    assert_eq!(issued.len(), 3, "{body}");
    assert!(
        issued[2]["key"]
            .as_str()
            .unwrap_or("")
            .starts_with("enterplace_u_"),
        "{body}"
    );
    let csv = body["csv"].as_str().unwrap_or("");
    assert!(
        csv.starts_with("name,team,key\nlee.park,payments,enterplace_"),
        "{csv}"
    );
    assert_eq!(body["lines"].as_str().unwrap_or("").lines().count(), 3);
    let keys = std::fs::read_to_string(s.keys())?;
    assert!(
        keys.contains("lee.park") && keys.contains("dana.levi"),
        "{keys}"
    );
    // No key reaches the keys file or the audit chain; the import is one record with the count.
    let log = std::fs::read_to_string(s.audit())?;
    for made in &issued {
        let key = made["key"].as_str().unwrap_or("none");
        assert!(!log.contains(key) && !keys.contains(key));
    }
    let imports: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("\"action\":\"import_keys\""))
        .collect();
    assert_eq!(imports.len(), 1, "{log}");
    assert!(imports[0].contains("\"count\":3"), "{}", imports[0]);
    // The same list again: each name already has a key, so nothing is issued.
    let (_, _, body) = call(
        &s.app,
        "POST",
        "/console/api/people/import",
        &cookie,
        serde_json::json!({ "text": "lee.park,payments,50\n" }),
    )
    .await?;
    assert!(
        body["errors"].to_string().contains("already has a key"),
        "{body}"
    );
    Ok(())
}
