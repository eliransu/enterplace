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
    let base = Entry {
        method: "POST",
        path: "/v1/chat/completions",
        policy_sha256: &policy_sha256,
        ..Entry::default()
    };
    log.append(&Entry {
        id: "01AAAAAAAAAAAAAAAAAAAAAAA1",
        person: Some("maya.cohen"),
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
        "/console/audit",
        "/console/people",
        "/console/policy",
        "/console/spend",
        "/console/audit?record=01AAAAAAAAAAAAAAAAAAAAAAA1",
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
    for (path, form) in [
        ("/console/people/issue", "name=x&team=y"),
        ("/console/people/revoke", "sha256=00&confirm=x"),
        ("/console/audit/verify", ""),
    ] {
        let (status, headers, _) =
            send(&s.app, post(path, "enterplace_console=forged", form)?).await?;
        assert_eq!(
            (status, location(&headers)),
            (StatusCode::SEE_OTHER, "/console/sign-in"),
            "{path}"
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
    let (status, headers, page) = send(&s.app, get("/console/audit", &cookie)?).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains(r#"g-muted">noa.bar</span><span class="t-small g-muted">admin</span>"#)
            && page.contains("Checking requests")
            && page.contains(r#"data-live="checking""#)
    );
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
        send(&s.app, get("/console/audit", &cookie)?).await?.0,
        StatusCode::SEE_OTHER
    );

    // A key that is no longer an admin's ends its sessions at the next request.
    let cookie = sign_in(&s.app).await?;
    std::fs::write(s.keys(), keys_text().replace("    admin: true\n", ""))?;
    assert_eq!(
        send(&s.app, get("/console/audit", &cookie)?).await?.0,
        StatusCode::SEE_OTHER
    );
    std::fs::write(s.keys(), keys_text())?;
    assert_eq!(
        send(&s.app, get("/console/audit", &cookie)?).await?.0,
        StatusCode::SEE_OTHER,
        "a dropped session came back"
    );
    Ok(())
}

#[tokio::test]
async fn the_audit_log_shows_records_newest_first_with_filters_and_a_record_sheet() -> TestResult {
    let s = setup("audit")?;
    let cookie = sign_in(&s.app).await?;
    let (status, _, page) = send(&s.app, get("/console/audit", &cookie)?).await?;
    assert_eq!(status, StatusCode::OK);
    let (first, last) = (
        page.find("01AAAAAAAAAAAAAAAAAAAAAAA3")
            .ok_or("no record 3")?,
        page.find("01AAAAAAAAAAAAAAAAAAAAAAA1")
            .ok_or("no record 1")?,
    );
    assert!(first < last, "not newest first");
    assert!(
        page.contains("model not allowed")
            && page.contains("key hash deadbeef")
            && page.contains("1 to 4 of 4 decisions")
    );
    assert!(page.contains("has not been verified"));

    let (_, _, refused) = send(&s.app, get("/console/audit?verdict=refused", &cookie)?).await?;
    assert!(
        !refused.contains("01AAAAAAAAAAAAAAAAAAAAAAA1")
            && refused.contains("1 to 2 of 2 decisions")
    );
    let (_, _, model) = send(&s.app, get("/console/audit?model=gpt-4o-mini", &cookie)?).await?;
    assert!(
        model.contains("1 to 1 of 1 decisions") && model.contains("01AAAAAAAAAAAAAAAAAAAAAAA1")
    );
    let (_, _, person) = send(&s.app, get("/console/audit?q=maya.cohen", &cookie)?).await?;
    assert!(
        person.contains("1 to 2 of 2 decisions") && !person.contains("01AAAAAAAAAAAAAAAAAAAAAAA3")
    );
    let (_, _, none) = send(&s.app, get("/console/audit?q=nobody", &cookie)?).await?;
    assert!(none.contains("No decision matches"));

    let (_, _, sheet) = send(
        &s.app,
        get("/console/audit?record=01AAAAAAAAAAAAAAAAAAAAAAA2", &cookie)?,
    )
    .await?;
    assert!(
        sheet.contains(r#"role="dialog""#)
            && sheet.contains("This model is not allowed for this person")
            && sheet.contains("does not list gpt-4o")
    );
    for field in [
        "Record</dt>",
        "Record hash",
        "Previous",
        "Policy file",
        "payments-team, line 10",
        "POST /v1/chat/completions",
    ] {
        assert!(sheet.contains(field), "{field}");
    }
    assert!(sheet.contains("g-code__line--hit") && sheet.contains("Open policy at line 10"));
    assert!(sheet.contains(r#"aria-selected="true""#));
    Ok(())
}

#[tokio::test]
async fn verify_chain_now_reports_an_unbroken_chain_and_a_broken_one() -> TestResult {
    let s = setup("verify")?;
    let cookie = sign_in(&s.app).await?;
    let (status, headers, _) = send(&s.app, post("/console/audit/verify", &cookie, "")?).await?;
    assert_eq!(
        (status, location(&headers)),
        (StatusCode::SEE_OTHER, "/console/audit")
    );
    let (_, _, page) = send(&s.app, get("/console/audit", &cookie)?).await?;
    let (_, last) = enterplace_core::audit::verify(&s.audit())?;
    assert!(
        // Records 1 to 3 are requests; record 4 is the sign-in.
        page.contains("unbroken from record 1 to record 4") && page.contains(&last[..12]),
        "{page}"
    );

    let text = std::fs::read_to_string(s.audit())?;
    std::fs::write(s.audit(), text.replacen("gpt-4o\"", "gpt-5o\"", 1))?;
    send(&s.app, post("/console/audit/verify", &cookie, "")?).await?;
    let (_, _, page) = send(&s.app, get("/console/audit", &cookie)?).await?;
    assert!(
        page.contains("The chain is broken")
            && page.contains("record 2")
            && page.contains("Open record 2"),
        "{page}"
    );
    Ok(())
}

#[tokio::test]
async fn people_policy_and_spend_render_from_the_files() -> TestResult {
    let s = setup("pages")?;
    let cookie = sign_in(&s.app).await?;
    let (status, _, people) = send(&s.app, get("/console/people", &cookie)?).await?;
    assert_eq!(status, StatusCode::OK);
    let maya = &sha256_hex(MAYA_KEY.as_bytes())[..8];
    assert!(
        people.contains("maya.cohen")
            && people.contains("payments")
            && people.contains(&format!(">{maya}</td>"))
    );
    assert!(
        people.contains("platform, admin")
            && people.contains("2 keys for 2 people and workloads in 2 teams")
    );
    // maya.cohen sent two requests; noa.bar none.
    assert!(
        people.contains(r#"<td class="g-table__num g-table__wide">2</td>"#)
            && people.contains("never")
    );

    let (_, _, policy) = send(&s.app, get("/console/policy?line=10", &cookie)?).await?;
    assert!(
        policy.contains(r#"<span class="g-code__n">15</span>"#)
            && policy.contains("g-code__line--hit")
    );
    assert!(
        policy.contains("payments-team")
            && policy.contains("Team payments may use gpt-4o-mini")
            && policy.contains("Everyone else may use every model")
    );
    assert!(
        policy.contains("openai at https://api.openai.com")
            && !policy.contains("OPENAI_API_KEY=")
            && policy.contains("Read only")
    );

    std::fs::write(
        s.dir.join("enterplace.policy.yaml"),
        POLICY.replace("    models: [gpt-4o-mini]\n", "    modles: [gpt-4o-mini]\n"),
    )?;
    let (_, _, broken) = send(&s.app, get("/console/policy", &cookie)?).await?;
    assert!(
        broken.contains("g-code__line--error")
            && broken.contains("Did you mean &quot;models&quot;?"),
        "{broken}"
    );

    // With the policy broken, spend is still shown from the log, and the budgets say why they are missing.
    let (_, _, spend) = send(&s.app, get("/console/spend", &cookie)?).await?;
    assert!(
        spend.contains("The policy file has problems")
            && spend.contains("Stopped before sending")
            && spend.contains(r#"aria-current="page">Spend"#),
        "{spend}"
    );
    let (_, _, menu) = send(&s.app, get("/console/spend?menu=1", &cookie)?).await?;
    assert!(menu.contains("g-menu-sheet"));
    Ok(())
}

#[tokio::test]
async fn an_issued_key_is_shown_once_and_its_hash_is_appended() -> TestResult {
    let s = setup("issue")?;
    let cookie = sign_in(&s.app).await?;
    let (_, _, dialog) = send(&s.app, get("/console/people?issue=1", &cookie)?).await?;
    assert!(dialog.contains(r#"action="/console/people/issue""#));

    let before = std::fs::read_to_string(s.keys())?;
    let (status, headers, page) = send(
        &s.app,
        post(
            "/console/people/issue",
            &cookie,
            "name=svc-invoice-bot&team=payments",
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let at = page
        .find(r#"id="new-key">"#)
        .ok_or("the key is not shown")?
        + r#"id="new-key">"#.len();
    let key = &page[at..at + 11 + 64];
    assert!(key.starts_with("enterplace_"), "{key}");
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

    let (status, _, page) = send(
        &s.app,
        post("/console/people/issue", &cookie, "name=bad%20name&team=t")?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(page.contains(r#"aria-invalid="true""#) && page.contains("letters, digits"));
    assert_eq!(std::fs::read_to_string(s.keys())?, after);
    Ok(())
}

#[tokio::test]
async fn a_key_is_revoked_only_with_its_name_typed_and_never_the_last_admin() -> TestResult {
    let s = setup("revoke")?;
    let cookie = sign_in(&s.app).await?;
    let maya = sha256_hex(MAYA_KEY.as_bytes());
    let (_, _, dialog) = send(
        &s.app,
        get(&format!("/console/people?revoke={maya}"), &cookie)?,
    )
    .await?;
    assert!(
        dialog.contains("Revoke this key?")
            && dialog.contains("The key of maya.cohen stops working")
            && dialog.contains(r#"data-confirm="maya.cohen""#)
            && dialog.contains("g-btn--flame")
    );

    let before = std::fs::read_to_string(s.keys())?;
    let (status, _, page) = send(
        &s.app,
        post(
            "/console/people/revoke",
            &cookie,
            &format!("sha256={maya}&confirm=maya"),
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(page.contains("Type maya.cohen exactly"));
    assert_eq!(std::fs::read_to_string(s.keys())?, before);

    let (status, headers, _) = send(
        &s.app,
        post(
            "/console/people/revoke",
            &cookie,
            &format!("sha256={maya}&confirm=maya.cohen"),
        )?,
    )
    .await?;
    assert_eq!(
        (status, location(&headers)),
        (
            StatusCode::SEE_OTHER,
            format!("/console/people?revoked=maya.cohen&hash={}", &maya[..8]).as_str()
        )
    );
    let after = std::fs::read_to_string(s.keys())?;
    assert!(
        !after.contains(&maya) && !after.contains("maya.cohen") && after.contains("noa.bar"),
        "{after}"
    );
    assert!(enterplace_core::config::keys_problems(Path::new("k"), &after).is_empty());

    let admin = sha256_hex(ADMIN_KEY.as_bytes());
    let (status, _, page) = send(
        &s.app,
        post(
            "/console/people/revoke",
            &cookie,
            &format!("sha256={admin}&confirm=noa.bar"),
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(page.contains("only admin key"));
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
    let (status, _, page) = send(
        &s.app,
        post(
            "/console/people/issue",
            &cookie,
            "name=ops.lead&team=ops&admin=1",
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{page}");
    let at = page.find(r#"id="new-key">"#).ok_or("no key")? + r#"id="new-key">"#.len();
    let key = page[at..at + 11 + 64].to_string();
    let maya = sha256_hex(MAYA_KEY.as_bytes());
    send(
        &s.app,
        post(
            "/console/people/revoke",
            &cookie,
            &format!("sha256={maya}&confirm=maya.cohen"),
        )?,
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
    let (_, _, page) = send(&s.app, get("/console/audit", &cookie)?).await?;
    assert!(
        page.contains(
            r#"<span class="t-tag">Admin:</span><span class="t-mono-sm">issued a key</span>"#
        ),
        "{page}"
    );
    // The three requests of the setup, and none of the admin records.
    assert!(
        page.contains(r#"<p class="g-stat__figure t-lg">3</p><p class="g-stat__label t-small">requests checked today"#),
        "{page}"
    );
    let issue_id = records[2]["id"].as_str().unwrap_or("");
    let (_, _, sheet) = send(
        &s.app,
        get(&format!("/console/audit?record={issue_id}"), &cookie)?,
    )
    .await?;
    assert!(
        sheet.contains("noa.bar issued an admin key for ops.lead, key hash "),
        "{sheet}"
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
    let (_, _, dialog) = send(&s.app, get("/console/people?issue=1", &cookie)?).await?;
    assert!(
        dialog.contains(
            r#"<label class="g-choice t-body"><input type="checkbox" name="admin" value="1">"#
        ),
        "{dialog}"
    );
    // A plain issue stays a plain key.
    send(
        &s.app,
        post("/console/people/issue", &cookie, "name=bot&team=ops")?,
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
    let (_, _, sheet) = send(
        &s.app,
        get("/console/audit?record=01AAAAAAAAAAAAAAAAAAAAAAG1", &cookie)?,
    )
    .await?;
    assert!(
        sheet.contains("The prompt held an AWS access key"),
        "{sheet}"
    );
    assert!(
        sheet.contains(r#"aws_access_key</span></span><span style="white-space: nowrap">no-secrets, 2</span></span></dd>"#)
            && sheet.contains(r#"email_address</span></span><span style="white-space: nowrap">mask-pii, 1</span></span></dd>"#),
        "{sheet}"
    );
    let (_, _, list) = send(&s.app, get("/console/audit", &cookie)?).await?;
    assert!(list.contains("g-tag--block"));
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
    let (status, _, page) = send(&s.app, get("/console/spend", &cookie)?).await?;
    assert_eq!(status, StatusCode::OK);
    for expected in [
        "$1.10 spent in",
        "payments spent its $1.00 on",
        "Edit the payments budget in the policy",
        "/console/policy?line=10",
        r#"data-state="over""#,
        "$1.10 of $1.00",
        "g-chart__pace",
        "g-chart__mark",
        "<td>gpt-4o-mini</td><td class=\"g-table__num\">$1.10</td>",
        "/console/audit?q=maya.cohen",
        // The model is an identifier: it never breaks at its dash.
        r#"Sent 2 requests, $1.10, most of it on <span class="t-mono" style="white-space: nowrap">gpt-4o-mini</span>."#,
        "1 answer reported no usage or had no price",
        // The two refused requests of the setup.
        r#"<td class="g-table__num g-table__wide">2</td><td class="g-table__num g-table__wide">0</td>"#,
    ] {
        assert!(page.contains(expected), "missing {expected}: {page}");
    }
    // Usage records belong to this page, not to the list of decisions.
    let (_, _, audit) = send(&s.app, get("/console/audit", &cookie)?).await?;
    // The three requests of the setup and the sign-in's admin record; none of the three usage records.
    assert!(audit.contains("1 to 4 of 4"), "{audit}");
    // m12-3: Verify chain now walks every record of the chain, usage ones too, as enterplace audit verify counts them.
    let lines = std::fs::read_to_string(s.audit())?.lines().count();
    assert!(
        audit.contains(&format!("walks all {lines} records")),
        "{lines}: {audit}"
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
    let (status, _, people) = send(&s.app, get("/console/people", &cookie)?).await?;
    assert_eq!(status, StatusCode::OK);
    // Round 11: the status says the key is live and when it expires, and its budget is a meter.
    for expected in [
        r#"<span class="g-tag g-tag--allow t-tag">Active</span><span class="g-table__sub" style="white-space: normal">expires 2099-01-01</span>"#,
        "$0.00 of $20.00 this month",
    ] {
        assert!(people.contains(expected), "missing {expected}: {people}");
    }
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
    let (_, _, vendor) = send(
        &s.app,
        get("/console/audit?record=01AAAAAAAAAAAAAAAAAAAAAAV1", &cookie)?,
    )
    .await?;
    assert!(
        vendor.contains("Guardrail moderation blocked harassment threatening"),
        "{vendor}"
    );
    let (_, _, list) = send(&s.app, get("/console/audit", &cookie)?).await?;
    assert!(
        list.contains(r#"<span class="g-tag g-tag--block"><span class="t-tag">Block</span><span class="t-mono-sm">aws_access_key</span>"#),
        "{list}"
    );
    assert!(
        list.contains(r#"<span class="g-tag g-tag--mask"><span class="t-tag">Mask</span><span class="t-mono-sm">credit_card</span>"#),
        "{list}"
    );
    // Blocks are counted apart from refusals by policy.
    assert!(list.contains("blocked by a guardrail today"), "{list}");

    let (_, _, block) = send(
        &s.app,
        get("/console/audit?record=01AAAAAAAAAAAAAAAAAAAAAAB1", &cookie)?,
    )
    .await?;
    assert!(
        block.contains("The prompt held an AWS access key"),
        "{block}"
    );
    let (_, _, mask) = send(
        &s.app,
        get("/console/audit?record=01AAAAAAAAAAAAAAAAAAAAAAM1", &cookie)?,
    )
    .await?;
    assert!(
        mask.contains("Masked 3 findings, then sent to openai"),
        "{mask}"
    );
    // One row per finding, each with its badge, never one run-on string.
    assert!(
        mask.contains(r#"credit_card</span></span><span style="white-space: nowrap">mask-pii, 1</span></span></dd>"#)
            && mask.contains(r#"email_address</span></span><span style="white-space: nowrap">mask-pii, 2</span></span></dd>"#)
            && !mask.contains("; mask-pii"),
        "{mask}"
    );
    // The filters of the design.
    let (_, _, blocked) = send(&s.app, get("/console/audit?verdict=blocked", &cookie)?).await?;
    assert!(blocked.contains("1 to 2 of 2 decisions"), "{blocked}");
    let (_, _, masked) = send(&s.app, get("/console/audit?verdict=masked", &cookie)?).await?;
    assert!(
        masked.contains("1 to 1 of 1 decisions") && masked.contains("01AAAAAAAAAAAAAAAAAAAAAAM1")
    );
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
    let (_, _, list) = send(&s.app, get("/console/audit", &cookie)?).await?;
    assert!(
        list.contains(r#"<span class="g-tag g-tag--refused"><span class="t-tag">Refused:</span><span class="t-mono-sm">sign-in</span>"#)
            && list.contains(r#"<span class="g-tag"><span class="t-tag">Admin:</span><span class="t-mono-sm">signed in</span>"#)
            && !list.contains("console_sign_in"),
        "{list}"
    );
    assert!(list.contains("<th>Time</th>"));
    let refused = admin_records(&s)?
        .first()
        .and_then(|r| r["id"].as_str().map(str::to_string))
        .ok_or("no record")?;
    let (_, _, sheet) = send(
        &s.app,
        get(&format!("/console/audit?record={refused}"), &cookie)?,
    )
    .await?;
    assert!(sheet.contains("tried to sign in"), "{sheet}");
    Ok(())
}

#[tokio::test]
async fn issue_and_revoke_records_name_the_key_hash_and_search_finds_them() -> TestResult {
    let s = setup("hash-search")?;
    let cookie = sign_in(&s.app).await?;
    let maya = sha256_hex(MAYA_KEY.as_bytes());
    send(
        &s.app,
        post(
            "/console/people/revoke",
            &cookie,
            &format!("sha256={maya}&confirm=maya.cohen"),
        )?,
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
    let (_, _, sheet) = send(
        &s.app,
        get(&format!("/console/audit?record={id}"), &cookie)?,
    )
    .await?;
    assert!(
        sheet.contains(&format!(
            "Key hash</dt><dd class=\"t-mono-sm\">{}",
            &maya[..8]
        )),
        "{sheet}"
    );
    for q in [&maya[..8], "maya.cohen"] {
        let (_, _, found) = send(&s.app, get(&format!("/console/audit?q={q}"), &cookie)?).await?;
        assert!(found.contains(id), "{q}: {found}");
    }
    // The revoked key's later use points back at who revoked it.
    let (_, _, used) = send(
        &s.app,
        get("/console/audit?record=01AAAAAAAAAAAAAAAAAAAAAAU1", &cookie)?,
    )
    .await?;
    assert!(
        used.contains("Revoked by noa.bar") && used.contains(&format!("record={id}")),
        "{used}"
    );
    // The toast after a revoke names the key hash too.
    let (_, _, people) = send(
        &s.app,
        get(
            &format!("/console/people?revoked=maya.cohen&hash={}", &maya[..8]),
            &cookie,
        )?,
    )
    .await?;
    assert!(
        people.contains(&format!("key hash {}", &maya[..8])),
        "{people}"
    );
    Ok(())
}

#[tokio::test]
async fn the_last_hash_is_shown_whole_to_keep_for_expect_last() -> TestResult {
    let s = setup("last-hash")?;
    let cookie = sign_in(&s.app).await?;
    send(&s.app, post("/console/audit/verify", &cookie, "")?).await?;
    let (_, _, page) = send(&s.app, get("/console/audit", &cookie)?).await?;
    let (_, last) = enterplace_core::audit::verify(&s.audit())?;
    assert!(
        page.contains(&format!(r#"id="last-hash">{last}<"#))
            && page.contains(r#"data-copy="last-hash""#)
            && page.contains("--expect-last"),
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
    let (_, _, list) = send(&s.app, get("/console/audit?verdict=changes", &cookie)?).await?;
    // Records 4 to 6: a change has no decision ID, so it opens by its record number.
    assert!(
        list.contains("record=5") && list.contains("record=6") && list.contains("file change"),
        "{list}"
    );
    assert!(!list.contains(r#"aria-label="Open decision ""#), "{list}");
    let (_, _, sheet) = send(&s.app, get("/console/audit?record=5", &cookie)?).await?;
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
    let (_, _, sheet) = send(&s.app, get("/console/audit?record=6", &cookie)?).await?;
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
    let (_, _, sheet) = send(
        &s.app,
        get("/console/audit?record=01AAAAAAAAAAAAAAAAAAAAAAX1", &cookie)?,
    )
    .await?;
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
    let (_, _, sheet) = send(
        &s.app,
        get("/console/audit?record=01AAAAAAAAAAAAAAAAAAAAAAK1", &cookie)?,
    )
    .await?;
    for expected in [
        "maya.cohen's key budget is spent",
        "$0.82 of $1.00 spent today",
        "Refused until 00:00 UTC",
        "<dt class=\"t-tag\">Budget</dt>",
        "<dt class=\"t-tag\">Resets</dt>",
    ] {
        assert!(sheet.contains(expected), "missing {expected}: {sheet}");
    }
    assert!(
        !sheet.contains("Enterplace refused it with the code"),
        "{sheet}"
    );
    let (_, _, sheet) = send(
        &s.app,
        get("/console/audit?record=01AAAAAAAAAAAAAAAAAAAAAAK2", &cookie)?,
    )
    .await?;
    for expected in [
        "ci.release's key expired on 1 November 2020",
        "Issue a new key on People",
        "/console/people?issue=1",
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
    let (_, _, people) = send(&s.app, get("/console/people", &cookie)?).await?;
    for expected in [
        "<th>Status</th>",
        r#"<th aria-label="Actions"></th>"#,
        r#"<span class="g-tag g-tag--refused t-tag">Expired</span>"#,
        // m12-3: "$0.82 of $1" is not spent; the next request would pass it.
        r#"<span class="g-tag g-tag--refused t-tag">Budget reached</span>"#,
        "$0.82 of $1.00 today",
        r#"role="meter""#,
        "Issue a new key",
        "/console/people?issue=1&amp;name=ci.release&amp;team=platform",
    ] {
        assert!(people.contains(expected), "missing {expected}: {people}");
    }
    // The sub line keeps the team; expiry and budget live in the status.
    assert!(!people.contains("budget $1.00 a day"), "{people}");
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
        let (_, _, sheet) = send(
            &s.app,
            get(&format!("/console/audit?record={id}"), &cookie)?,
        )
        .await?;
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
    let (_, _, page) = send(&s.app, get("/console/people?issue=1", &cookie)?).await?;
    for expected in [
        r#"type="date""#,
        r#"name="expires""#,
        r#"name="budget""#,
        r#"name="per""#,
    ] {
        assert!(page.contains(expected), "missing {expected}: {page}");
    }
    let (status, _, _) = send(
        &s.app,
        post(
            "/console/people/issue",
            &cookie,
            "name=lior.amit&team=platform&expires=2099-01-31&budget=0.005&per=day",
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let keys = std::fs::read_to_string(s.keys())?;
    assert!(
        keys.contains("expires: 2099-01-31") && keys.contains("budget: { usd: 0.005, per: day }"),
        "{keys}"
    );
    // A small budget reads in four places under a cent, not as $0.00.
    let (_, _, people) = send(&s.app, get("/console/people", &cookie)?).await?;
    assert!(people.contains("$0.00 of $0.0050 today"), "{people}");
    let (status, _, page) = send(
        &s.app,
        post(
            "/console/people/issue",
            &cookie,
            "name=lior.amit&team=platform&budget=-3&per=day",
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        page.contains("a budget is a number of US dollars above 0"),
        "{page}"
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
    let (_, _, list) = send(&s.app, get("/console/audit?verdict=changes", &cookie)?).await?;
    for expected in [
        "<th>Who</th><th>Change and reason</th><th>Time</th>",
        "record=4",
        "of 2 changes",
        "noa.bar signed in to the console",
    ] {
        assert!(list.contains(expected), "missing {expected}: {list}");
    }
    let (_, _, sheet) = send(&s.app, get("/console/audit?record=4", &cookie)?).await?;
    for expected in [
        "The cut last line of the audit log was removed",
        "enterplace audit repair",
        "40 bytes",
        &"bf20eb45".repeat(8),
        "{&quot;n&quot;:4,&quot;id&quot;:&quot;01AB",
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
    let (_, _, page) = send(&s.app, get("/console/spend", &cookie)?).await?;
    assert!(
        page.contains("maya.cohen&#39;s key") && page.contains("$0.82 of $1.00 today"),
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
async fn a_kill_switch_shows_a_banner_on_audit_and_in_the_sheet_of_a_request_it_stopped()
-> TestResult {
    let s = setup("kills")?;
    let cookie = sign_in(&s.app).await?;
    let (_, _, page) = send(&s.app, get("/console/audit", &cookie)?).await?;
    assert!(
        !page.contains("Traffic is stopped"),
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
    let (_, _, page) = send(&s.app, get("/console/audit", &cookie)?).await?;
    // One line per switch, in words, with the button that turns it off.
    assert!(
        page.contains(r#"<div class="g-banner" role="alert""#)
            && page.contains(
                r#"Traffic stopped for <span class="t-mono">person maya.cohen</span> since "#
            )
            && page.contains("retrying &lt;the same&gt; ticket")
            && page.contains(r#"action="/console/kills/restore""#)
            && page.contains("Restore traffic"),
        "{page}"
    );
    let (_, _, sheet) = send(
        &s.app,
        get("/console/audit?record=01AAAAAAAAAAAAAAAAAAAAAAK1", &cookie)?,
    )
    .await?;
    assert!(
        sheet.contains("Kill switch") && sheet.contains("Still on"),
        "{sheet}"
    );
    // Restore traffic turns the switch off, as enterplace unkill does, and the admin record says who did it.
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
    let (_, _, sheet) = send(
        &s.app,
        get("/console/audit?record=01AAAAAAAAAAAAAAAAAAAAAAK1", &cookie)?,
    )
    .await?;
    assert!(
        sheet.contains("Off now") && !sheet.contains("Traffic is stopped"),
        "{sheet}"
    );
    Ok(())
}

// ---------------------------------------------------------------- round 12 review

/// `enterplace unkill --person maya.cohen` as a page writes it: it wraps only between its words.
const UNKILL_MAYA: &str = r#"<span style="white-space: nowrap">enterplace</span> <span style="white-space: nowrap">unkill</span> <span style="white-space: nowrap">--person</span> <span style="white-space: nowrap">maya.cohen</span>"#;

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

    let (_, _, sheet) = send(
        &s.app,
        get("/console/audit?record=01AAAAAAAAAAAAAAAAAAAAAAK1", &cookie)?,
    )
    .await?;
    assert!(
        sheet.contains("A kill switch stopped maya.cohen"),
        "{sheet}"
    );
    assert!(
        sheet.contains("model gpt-4o") && sheet.contains("provider incident"),
        "{sheet}"
    );
    // The person switch on now did not stop this request: it was set after.
    assert!(
        sheet.contains("Off now")
            && !sheet.contains("Still on")
            // The banner names the person switch on now; the sheet's facts do not.
            && !sheet.contains(r#"<dd class="t-mono-sm">person maya.cohen"#),
        "{sheet}"
    );
    assert!(
        !sheet.contains("Enterplace refused it with the code"),
        "{sheet}"
    );
    for label in [
        r#"<dt class="t-tag">Switch</dt>"#,
        r#"<dt class="t-tag">Reason</dt>"#,
        r#"<dt class="t-tag">Set by</dt>"#,
    ] {
        assert!(sheet.contains(label), "missing {label}: {sheet}");
    }

    let (_, _, sheet) = send(
        &s.app,
        get("/console/audit?record=01AAAAAAAAAAAAAAAAAAAAAAK2", &cookie)?,
    )
    .await?;
    assert!(
        sheet.contains("A kill switch stopped maya.cohen")
            && sheet.contains("person maya.cohen")
            && sheet.contains("Still on")
            && sheet.contains(r#"<dt class="t-tag">Turn off</dt>"#)
            && sheet.contains(UNKILL_MAYA)
            && !sheet.contains("model gpt-4o"),
        "{sheet}"
    );
    // m12-4. Kill switch records read in words.
    let (_, _, list) = send(&s.app, get("/console/audit", &cookie)?).await?;
    // UX m26. The first Tab stop skips the nav.
    let skip = list.find(r##"href="#main">Skip to the page"##);
    assert!(
        skip.is_some()
            && skip < list.find(r#"class="g-nav__brand""#)
            && list.contains(r#"<main class="g-shell__main" id="main""#),
        "{list}"
    );
    assert!(
        list.contains("stopped traffic")
            && list.contains("restored traffic")
            && !list.contains("set_kill")
            && !list.contains("clear_kill"),
        "{list}"
    );
    // m12-5. One block per switch: its scope in mono, its reason, since when and by whom, and the one command.
    assert!(
        list.contains(r#"<span class="t-mono">person maya.cohen</span>"#)
            && list.contains("Traffic stopped for ")
            && list.contains(" by noa.bar: ")
            && list.contains("Restore traffic"),
        "{list}"
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
    let (_, _, tpm) = send(
        &s.app,
        get("/console/audit?record=01AAAAAAAAAAAAAAAAAAAAAAT1", &cookie)?,
    )
    .await?;
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
        let (_, _, sheet) = send(
            &s.app,
            get(&format!("/console/audit?record={id}"), &cookie)?,
        )
        .await?;
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
    let (_, _, big) = send(
        &s.app,
        get("/console/audit?record=01AAAAAAAAAAAAAAAAAAAAAAT5", &cookie)?,
    )
    .await?;
    assert!(
        big.contains("This request alone is larger than maya.cohen's key allows in a minute")
            && big.contains("could use 528 tokens")
            && !big.contains("was told when to send again"),
        "{big}"
    );
    let (_, _, old) = send(
        &s.app,
        get("/console/audit?record=01AAAAAAAAAAAAAAAAAAAAAAT6", &cookie)?,
    )
    .await?;
    assert!(
        old.contains(
            "the record does not say whether rule payments-team or the key's own models refused"
        ) || old.contains("key does not allow"),
        "{old}"
    );
    assert!(!old.contains("does not list gpt-4o"), "{old}");
    let (_, _, model) = send(
        &s.app,
        get("/console/audit?record=01AAAAAAAAAAAAAAAAAAAAAAT2", &cookie)?,
    )
    .await?;
    assert!(
        model.contains("maya.cohen's key does not allow gpt-4o")
            && model.contains(r#"<dt class="t-tag">Key models</dt>"#)
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
    let (_, _, sheet) = send(
        &s.app,
        get("/console/audit?record=01AAAAAAAAAAAAAAAAAAAAAAL1", &cookie)?,
    )
    .await?;
    assert!(
        sheet.contains(r#"<dt class="t-tag">Expires</dt>"#) && sheet.contains("13 December 2026"),
        "{sheet}"
    );
    let (_, _, list) = send(&s.app, get("/console/audit", &cookie)?).await?;
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
    let (_, _, page) = send(&s.app, get("/console/people", &cookie)?).await?;
    assert!(
        page.contains(r#"g-tag--refused t-tag">Stopped</span>"#)
            && page.contains("retrying a ticket in a loop")
            && page.contains(r#"<input type="hidden" name="value" value="maya.cohen"><button class="g-btn g-btn--sm t-small" type="submit">Restore traffic</button>"#)
            && page.contains("models gpt-4o-mini")
            && page.contains("50,000 tokens a minute")
            && !page.contains("T06:16:26Z"),
        "{page}"
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

    let (_, _, list) = send(&s.app, get("/console/audit", &cookie)?).await?;
    assert!(
        list.contains(r#"<span class="g-tag g-tag--block"><span class="t-tag">Block</span><span class="t-mono-sm">aws_access_key</span>"#)
            && !list.contains("answer_guardrails"),
        "{list}"
    );
    assert!(
        list.contains(r#"<p class="g-stat__figure t-lg">1</p><p class="g-stat__label t-small">blocked by a guardrail today"#),
        "{list}"
    );
    let (_, _, blocked) = send(&s.app, get("/console/audit?verdict=blocked", &cookie)?).await?;
    assert!(blocked.contains("01AAAAAAAAAAAAAAAAAAAAAAA1"), "{blocked}");

    for selected in ["01AAAAAAAAAAAAAAAAAAAAAAA1".to_string(), n.to_string()] {
        let (_, _, sheet) = send(
            &s.app,
            get(&format!("/console/audit?record={selected}"), &cookie)?,
        )
        .await?;
        assert!(
            sheet.contains(r#"Guardrail <span style="white-space: nowrap">no-secrets-out</span> withheld the answer"#)
                && sheet.contains("guardrail_blocked")
                && sheet.contains("on the answer")
                && sheet.contains("maya.cohen")
                && sheet.contains("LiteLLM table"),
            "{selected}: {sheet}"
        );
    }

    let (_, _, spend) = send(&s.app, get("/console/spend", &cookie)?).await?;
    assert!(
        spend.contains("priced from the LiteLLM table")
            && spend.contains("Prices this month came from the LiteLLM table")
            && spend.contains(r#"<td class="g-table__num">$0.0035</td>"#),
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
    let (status, _, _) = send(&s.app, get("/console/spend", &fin)?).await?;
    assert_eq!(status, StatusCode::OK);
    let (status, _, body) = send(&s.app, get("/console/people", &fin)?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body.contains("does not have the see_keys permission"),
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
    let (status, _, body) = send(&s.app, get("/console/people", &keeper)?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.contains("acme-bot") && !body.contains("maya.cohen"),
        "an org role sees its org's keys only"
    );
    // It may issue a key, and the key goes into its organization.
    let (status, _, body) = send(
        &s.app,
        post("/console/people/issue", &keeper, "name=acme-new&team=bots")?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let saved = std::fs::read_to_string(s.keys())?;
    let new = saved.split("- name: acme-new").nth(1).ok_or("no entry")?;
    assert!(new.contains("org: acme"), "{saved}");
    // It may not revoke: revoke_keys is not in its role.
    let bot = sha256_hex(b"enterplace_acme_bot_key");
    let (status, _, _) = send(
        &s.app,
        post(
            "/console/people/revoke",
            &keeper,
            &format!("sha256={bot}&confirm=acme-bot"),
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(std::fs::read_to_string(s.keys())?.contains(&bot));
    Ok(())
}

#[tokio::test]
async fn every_page_says_when_observe_mode_lets_everything_through() -> TestResult {
    let s = setup("observe-banner")?;
    let cookie = sign_in(&s.app).await?;
    let (_, _, page) = send(&s.app, get("/console/audit", &cookie)?).await?;
    assert!(!page.contains("Observe mode"), "enforcing shows no banner");
    std::fs::write(
        s.dir.join("enterplace.policy.yaml"),
        format!("mode: observe\n{POLICY}"),
    )?;
    // One short line, the same on every page, once.
    for path in [
        "/console/audit",
        "/console/people",
        "/console/policy",
        "/console/start",
    ] {
        let (status, _, page) = send(&s.app, get(path, &cookie)?).await?;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(
            page.matches("Observe mode: rules only record.").count(),
            1,
            "{path}: {page}"
        );
    }
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
    let (status, _, page) = send(&s.app, get("/console/audit", &ana)?).await?;
    assert_eq!(status, StatusCode::OK, "{page}");
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
    let (status, _, _) = send(&s.app, post("/console/audit/verify?chain=", &ana, "")?).await?;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, _, page) = send(&s.app, get("/console/audit", &ana)?).await?;
    assert!(
        page.contains("unbroken from record 1 to record 2"),
        "{page}"
    );

    // An admin kept to no organization starts on the install's chain and may switch to acme's.
    let cookie = sign_in(&s.app).await?;
    let (_, _, page) = send(&s.app, get("/console/audit", &cookie)?).await?;
    assert!(
        page.contains("maya.cohen")
            && !page.contains("ACMEDECISION1")
            && page.contains("/console/audit?chain=acme"),
        "{page}"
    );
    let (_, _, page) = send(&s.app, get("/console/audit?chain=acme", &cookie)?).await?;
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
    let (status, _, page) = send(
        &s.app,
        get(&format!("/console/people/edit?sha256={old}"), &cookie)?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains(r#"action="/console/people/rotate""#) && page.contains(r#"name="grace""#),
        "the key's page offers the rotation"
    );

    // A grace that is not a time changes nothing and says how to write one.
    let (status, _, page) = send(
        &s.app,
        post(
            "/console/people/rotate",
            &cookie,
            &format!("sha256={old}&grace=soon"),
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(page.contains("48h"), "{page}");
    assert!(!std::fs::read_to_string(s.keys())?.contains("replaced_by"));

    let (status, headers, page) = send(
        &s.app,
        post(
            "/console/people/rotate",
            &cookie,
            &format!("sha256={old}&grace=48h"),
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let at = page
        .find(r#"id="new-key">"#)
        .ok_or("the new key is not shown")?
        + r#"id="new-key">"#.len();
    let key = &page[at..at + 11 + 64];
    assert!(key.starts_with("enterplace_") && key != MAYA_KEY, "{key}");
    assert!(
        page.contains("key_rotated"),
        "the page says how to find who still uses the old key"
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

    // Recorded with both hash prefixes and never the key; a second rotation of the old key is refused.
    s.log.flush();
    let records = admin_records(&s)?;
    let rotated = records
        .iter()
        .find(|r| r["action"] == "rotate_key" && r["target"]["replaced_by"] == new[..8])
        .ok_or("the rotation is not recorded")?;
    assert_eq!(rotated["target"]["sha256_prefix"], old[..8]);
    assert!(!std::fs::read_to_string(s.audit())?.contains(key));
    let (status, _, page) = send(
        &s.app,
        post(
            "/console/people/rotate",
            &cookie,
            &format!("sha256={old}&grace=1h"),
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(page.contains("already rotated"), "{page}");
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
    let (_, _, page) = send(&s.app, get("/console/audit", &cookie)?).await?;
    for words in [
        r#"<span class="g-tag g-tag--allow t-tag">Allowed</span>"#,
        r#"<span class="t-tag">Refused:</span><span class="t-mono-sm">unknown key</span>"#,
        r#"<span class="t-tag">Refused:</span><span class="t-mono-sm">kill switch</span>"#,
        r#"<span class="t-tag">Admin:</span><span class="t-mono-sm">signed in</span>"#,
        r#"<span class="t-tag">Admin:</span><span class="t-mono-sm">stopped traffic</span>"#,
        "refused today</p>",
        "<th>Time</th>",
        r#"aria-label="Open decision 01AAAAAAAAAAAAAAAAAAAAAAA3""#,
    ] {
        assert!(page.contains(words), "{words}: {page}");
    }
    for gone in [
        "unknown_key",
        ">Allow<",
        "by policy",
        "Time (UTC) and decision",
        ">01AAAAAAAAAAAAAAAAAAAAAAA3<",
    ] {
        assert!(!page.contains(gone), "{gone}: {page}");
    }
    let (_, _, sheet) = send(
        &s.app,
        get("/console/audit?record=01AAAAAAAAAAAAAAAAAAAAAAA1", &cookie)?,
    )
    .await?;
    assert!(
        sheet.contains(r#"<dd class="t-mono-sm">Allowed</dd>"#)
            && sheet.contains("01AAAAAAAAAAAAAAAAAAAAAAA1</dd>"),
        "{sheet}"
    );
    Ok(())
}

/// UX #38, #40: the row offers Edit only, Revoke is on the edit page, one page has no pager, and the key forms match.
#[tokio::test]
async fn people_rows_offer_edit_and_the_key_forms_keep_one_hint() -> TestResult {
    let s = setup("people-actions")?;
    let cookie = sign_in(&s.app).await?;
    let (_, _, people) = send(&s.app, get("/console/people", &cookie)?).await?;
    assert!(
        people.contains(r#"<th aria-label="Actions"></th>"#)
            && people.contains(">Edit</a>")
            && !people.contains("<th>Fix</th>")
            && !people.contains("Revoke key")
            && !people.contains("of 2 keys"),
        "{people}"
    );
    let maya = sha256_hex(MAYA_KEY.as_bytes());
    let (_, _, edit) = send(
        &s.app,
        get(&format!("/console/people/edit?sha256={maya}"), &cookie)?,
    )
    .await?;
    assert!(
        edit.contains(&format!(
            r#"href="/console/people?revoke={maya}">Revoke key</a>"#
        )) && edit.contains(r#"id="key-expires" name="expires" value="" type="date""#)
            && edit.contains(r#"<h2 class="t-md" style="margin: 0">Rotate key</h2>"#)
            && !edit.contains("Rotate: how long")
            && edit.matches("g-field__hint").count() == 1,
        "{edit}"
    );
    let (_, _, issue) = send(&s.app, get("/console/people?issue=1", &cookie)?).await?;
    assert_eq!(issue.matches("g-field__hint").count(), 1, "{issue}");
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
    let (_, _, spend) = send(&s.app, get("/console/spend", &cookie)?).await?;
    assert!(
        spend.contains("No spend yet")
            && spend.contains("Demo requests are free.")
            && !spend.contains("Who spent most")
            && !spend.contains("Stopped before sending"),
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

/// UX #25, #26: a policy kept in a file says read only once, with no edit, export or change column to contradict it.
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
    let (_, _, models) = send(&s.app, get("/console/models", &cookie)?).await?;
    assert!(
        models.contains("Read only: prices come from")
            && models.contains("How to edit here")
            && !models.contains("policy_from")
            && !models.contains("<th>Change</th>")
            && !models.contains("A form edit"),
        "{models}"
    );
    let (_, _, policy) = send(&s.app, get("/console/policy", &cookie)?).await?;
    assert!(
        policy.contains(">Add a budget</a>")
            && !policy.contains("Edit the policy")
            && !policy.contains("Export YAML"),
        "{policy}"
    );
    Ok(())
}
