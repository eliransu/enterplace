//! What a binary that embeds the console adds to it: pages with nav entries, a way to sign in, and the accounts that
//! way signs in, all sharing the console's sessions and audit records.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderMap, Request, StatusCode, Uri, header},
    response::Response,
    routing::{get, post},
};
use enterplace_console::{Admin, Console, ConsoleConfig, Extension, Tls, Via, router_with};
use enterplace_core::id::sha256_hex;
use http_body_util::BodyExt;
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const ADMIN_KEY: &str = "enterplace_admin_key_for_extension_tests";
const HOST: &str = "127.0.0.1:19851";

fn ada() -> Admin {
    Admin {
        role: "viewer".into(),
        ..Admin::of_role(
            "ada@example.com",
            "research",
            true,
            Via::Account("acct-1".into()),
        )
    }
}

/// A page an extension serves: only to someone signed in, in the console's shell, marked in the nav.
async fn report(State(console): State<Console>, headers: HeaderMap, uri: Uri) -> Response {
    let Some(admin) = console.signed_in(&headers).await else {
        return enterplace_console::redirect("/console/sign-in");
    };
    let main = enterplace_console::html::head("Report", &format!("For {}", admin.role), "");
    console.page(StatusCode::OK, &admin, "Report", &uri, &main)
}

/// The extension's own way in: here any form signs in as account acct-1, recorded like any sign-in.
async fn account_sign_in(
    State(console): State<Console>,
    headers: HeaderMap,
    uri: Uri,
    tls: Tls,
) -> Response {
    if !enterplace_console::same_origin(&headers) {
        return enterplace_console::foreign();
    }
    console
        .sign_in_account("acct-1", &ada(), &headers, &uri, &tls)
        .await
}

struct Setup {
    app: Router,
    dir: std::path::PathBuf,
    /// Whether account acct-1 may still sign in.
    allowed: Arc<AtomicBool>,
}

fn setup(name: &str) -> Result<Setup, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "enterplace-console-ext-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        dir.join("enterplace.policy.yaml"),
        "version: 1\nproviders:\n  - name: openai\n    kind: openai\n    url: https://api.openai.com\n    key_env: OPENAI_API_KEY\n    models: [m]\nrules:\n  - name: all\n    principals: { any: true }\n    models: [m]\n",
    )?;
    std::fs::write(
        dir.join("enterplace.keys.yaml"),
        format!(
            "keys:\n  - name: noa\n    team: platform\n    sha256: {}\n    admin: true\n",
            sha256_hex(ADMIN_KEY.as_bytes())
        ),
    )?;
    let log = Arc::new(enterplace_core::audit::AuditLog::open(
        &dir.join("enterplace-audit.jsonl"),
    )?);
    let allowed = Arc::new(AtomicBool::new(true));
    let still = allowed.clone();
    let extension = Extension {
        nav: vec![("/console/report".into(), "Report".into())],
        routes: Router::new()
            .route("/report", get(report))
            .route("/sign-in/account", post(account_sign_in)),
        sign_in: Some((
            "/console/sign-in/account".into(),
            "Sign in with email".into(),
        )),
        accounts: Some(Arc::new(move |id: String| {
            let ok = id == "acct-1" && still.load(Ordering::SeqCst);
            Box::pin(async move { ok.then(ada) })
        })),
        watch: None,
    };
    let config = ConsoleConfig {
        policy: dir.join("enterplace.policy.yaml"),
        keys: dir.join("enterplace.keys.yaml"),
        audit: dir.join("enterplace-audit.jsonl"),
        log: Some(log),
    };
    Ok(Setup {
        app: Router::new().nest("/console", router_with(config, None, extension)),
        dir,
        allowed,
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

fn get_page(path: &str, cookie: &str) -> Result<Request<Body>, axum::http::Error> {
    Request::get(path)
        .header(header::HOST, HOST)
        .header(header::COOKIE, cookie)
        .body(Body::empty())
}

fn post_form(path: &str, cookie: &str, form: &str) -> Result<Request<Body>, axum::http::Error> {
    Request::post(path)
        .header(header::HOST, HOST)
        .header(header::ORIGIN, format!("http://{HOST}"))
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(form.to_string()))
}

fn cookie_of(headers: &HeaderMap) -> String {
    headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|c| c.split(';').next())
        .unwrap_or("")
        .to_string()
}

#[tokio::test]
async fn extension_pages_share_the_session_and_appear_in_the_nav() -> TestResult {
    let s = setup("pages")?;
    // Not signed in: the extension's page sends the browser to sign in, as the console's own pages do.
    let (status, headers, _) = send(&s.app, get_page("/console/report", "")?).await?;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        headers.get(header::LOCATION).and_then(|v| v.to_str().ok()),
        Some("/console/sign-in?next=%2Fconsole%2Freport")
    );
    // The sign-in page offers the extension's way in beside the key.
    let (_, _, page) = send(&s.app, get_page("/console/sign-in", "")?).await?;
    assert!(
        page.contains(r#"href="/console/sign-in/account""#) && page.contains("Sign in with email"),
        "{page}"
    );
    // An admin key session reaches the extension's page, and every page carries its nav entry.
    let (status, headers, _) = send(
        &s.app,
        post_form("/console/sign-in", "", &format!("key={ADMIN_KEY}"))?,
    )
    .await?;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let cookie = cookie_of(&headers);
    let (status, _, page) = send(&s.app, get_page("/console/report", &cookie)?).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("For admin"), "{page}");
    assert!(
        page.contains(r#"href="/console/report" aria-current="page">Report"#),
        "{page}"
    );
    let (_, _, teams) = send(&s.app, get_page("/console/teams", &cookie)?).await?;
    assert!(
        teams.contains(r#"href="/console/report">Report"#),
        "{teams}"
    );
    Ok(())
}

#[tokio::test]
async fn an_account_session_is_checked_on_every_request_and_recorded() -> TestResult {
    let s = setup("accounts")?;
    let (status, headers, _) = send(&s.app, post_form("/console/sign-in/account", "", "")?).await?;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let cookie = cookie_of(&headers);
    assert!(cookie.starts_with("enterplace_console="), "{cookie}");
    // The account's role, from the extension, is what the pages show and what read-only checks use.
    let (status, _, page) = send(&s.app, get_page("/console/report", &cookie)?).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains("For viewer") && page.contains("ada@example.com"),
        "{page}"
    );
    let (status, _, _) = send(
        &s.app,
        post_form("/console/api/people/issue", &cookie, "name=x&team=y")?,
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "a viewer issued a key");
    // The extension stops vouching for the account: its session ends at once.
    s.allowed.store(false, Ordering::SeqCst);
    let (status, _, _) = send(&s.app, get_page("/console/teams", &cookie)?).await?;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let log = std::fs::read_to_string(s.dir.join("enterplace-audit.jsonl"))?;
    let sign_in = log
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|r| r["action"] == "console_sign_in" && r["person"] == "ada@example.com")
        .ok_or("the account's sign-in was not recorded")?;
    assert_eq!(sign_in["team"], "research");
    assert_eq!(sign_in["target"]["via"], "account");
    Ok(())
}

#[tokio::test]
async fn an_extension_form_from_another_site_is_refused() -> TestResult {
    let s = setup("foreign")?;
    let request = Request::post("/console/sign-in/account")
        .header(header::HOST, HOST)
        .header(header::ORIGIN, "https://evil.example")
        .body(Body::empty())?;
    let (status, headers, _) = send(&s.app, request).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(headers.get(header::SET_COOKIE).is_none());
    Ok(())
}
