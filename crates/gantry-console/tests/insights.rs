//! The Requests and Analytics pages and the kept body view, through the console's routes, from the local chain.

use std::{path::PathBuf, sync::Arc};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use gantry_console::{ConsoleConfig, router};
use gantry_core::{
    audit::{AuditLog, Entry},
    id::sha256_hex,
    insights::{self, Bodies, FileBodies, Seal},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type Error = Box<dyn std::error::Error>;
type TestResult = Result<(), Error>;

const NOA: &str = "gantry_noa_admin_key_for_tests";
const LEE: &str = "gantry_lee_admin_key_for_tests";
const HOST: &str = "127.0.0.1:19851";

const POLICY: &str = "\
version: 1
providers:
  - name: openai
    kind: openai
    url: https://api.openai.com
    key_env: OPENAI_API_KEY
    models: [gpt-4o-mini, gpt-4o]
prices:
  gpt-4o-mini: { input: 1, output: 1 }
  gpt-4o: { input: 1, output: 1 }
rules:
  - name: payments-team
    principals: { team: payments }
    models: [gpt-4o-mini]
    budget: { usd: 10, per: month }
    capture: { to: console, days: 7, viewers: [noa.bar] }
  - name: everyone-else
    principals: { any: true }
    models: [\"*\"]
";

/// Not a cipher: the console only needs the store to hand bodies back.
#[derive(Debug)]
struct Plain;

impl Seal for Plain {
    fn seal(&self, _: &str, plain: &[u8]) -> Result<Vec<u8>, String> {
        Ok(plain.to_vec())
    }
    fn open(&self, _: &str, sealed: &[u8]) -> Result<Vec<u8>, String> {
        Ok(sealed.to_vec())
    }
}

struct Setup {
    app: Router,
    audit: PathBuf,
    log: Arc<AuditLog>,
}

fn object(v: Value) -> serde_json::Map<String, Value> {
    v.as_object().cloned().unwrap_or_default()
}

fn setup(name: &str) -> Result<Setup, Error> {
    let dir = std::env::temp_dir().join(format!(
        "gantry-console-insights-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("gantry.policy.yaml"), POLICY)?;
    std::fs::write(
        dir.join("gantry.keys.yaml"),
        format!(
            "keys:\n  - name: noa.bar\n    team: platform\n    sha256: {}\n    admin: true\n  - name: lee.k\n    team: platform\n    sha256: {}\n    admin: true\n",
            sha256_hex(NOA.as_bytes()),
            sha256_hex(LEE.as_bytes())
        ),
    )?;
    let audit = dir.join("gantry-audit.jsonl");
    let log = AuditLog::open(&audit)?;
    let decision = |id: &'static str, person: &'static str, team: &'static str, allowed: bool| {
        let mut r = gantry_core::audit::record(&Entry {
            id,
            person: Some(person),
            team: Some(team),
            method: "POST",
            path: "/v1/chat/completions",
            model: Some("gpt-4o-mini"),
            allowed,
            code: (!allowed).then_some("model_not_allowed"),
            rule: Some(if team == "payments" {
                "payments-team"
            } else {
                "everyone-else"
            }),
            provider: if allowed { "openai" } else { "" },
            ..Entry::default()
        });
        r.insert("user_agent".into(), "claude-cli/2.0.1".into());
        // An events guardrail gave the payments request its session and turn.
        if team == "payments" {
            r.insert("session".into(), "ses_0123456789abcdef01234567".into());
            r.insert("turn".into(), "turn_0123456789abcdef".into());
        }
        r
    };
    log.append_record(&decision(
        "01PAY0000000000000000000001",
        "maya.cohen",
        "payments",
        true,
    ))?;
    log.append_record(&object(json!({"event": "usage", "id": "01PAY0000000000000000000001", "provider": "openai", "model": "gpt-4o-mini", "status": 200, "input_tokens": 1000, "output_tokens": 200, "cost_usd": 4.0, "charged_usd": 4.0, "latency_ms": 840, "body": "captured"})))?;
    log.append_record(&decision(
        "01SRC0000000000000000000002",
        "dana.levi",
        "search",
        true,
    ))?;
    log.append_record(&object(json!({"event": "usage", "id": "01SRC0000000000000000000002", "provider": "openai", "model": "gpt-4o-mini", "status": 200, "input_tokens": 10, "output_tokens": 2, "cost_usd": 0.01, "charged_usd": 0.01, "latency_ms": 2400})))?;
    log.append_record(&decision(
        "01REF0000000000000000000003",
        "dana.levi",
        "search",
        false,
    ))?;
    log.flush();
    let log = Arc::new(log);
    let bodies = Arc::new(FileBodies::beside(&audit, Arc::new(Plain)));
    bodies.write(&insights::Body {
        id: "01PAY0000000000000000000001".into(),
        time: gantry_core::audit::timestamp(),
        rule: "payments-team".into(),
        expires: insights::now_secs() + 86_400,
        viewers: vec!["noa.bar".into()],
        request: "card [MASKED credit_card]".into(),
        answer: "done".into(),
    })?;
    let bodies: Arc<dyn Bodies> = bodies;
    insights::attach(&audit, None, Some(bodies));
    let config = ConsoleConfig {
        policy: dir.join("gantry.policy.yaml"),
        keys: dir.join("gantry.keys.yaml"),
        audit: audit.clone(),
        log: Some(log.clone()),
    };
    Ok(Setup {
        app: Router::new().nest("/console", router(config)),
        audit,
        log,
    })
}

async fn send(app: &Router, request: Request<Body>) -> Result<(StatusCode, String, String), Error> {
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .unwrap_or_default()
        .to_string();
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, cookie, String::from_utf8_lossy(&body).into_owned()))
}

fn post(path: &str, cookie: &str, form: &str) -> Result<Request<Body>, axum::http::Error> {
    Request::post(path)
        .header(header::HOST, HOST)
        .header(header::ORIGIN, format!("http://{HOST}"))
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(form.to_string()))
}

fn get(path: &str, cookie: &str) -> Result<Request<Body>, axum::http::Error> {
    Request::get(path)
        .header(header::HOST, HOST)
        .header(header::COOKIE, cookie)
        .body(Body::empty())
}

async fn sign_in(app: &Router, key: &str) -> Result<String, Error> {
    let (_, cookie, _) = send(app, post("/console/sign-in", "", &format!("key={key}"))?).await?;
    Ok(cookie)
}

fn records(s: &Setup) -> Result<Vec<Value>, Error> {
    s.log.flush();
    Ok(std::fs::read_to_string(&s.audit)?
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect())
}

#[tokio::test]
async fn the_request_log_filters_and_proves_each_row() -> TestResult {
    let s = setup("log")?;
    let cookie = sign_in(&s.app, NOA).await?;
    let (status, _, page) = send(&s.app, get("/console/requests", &cookie)?).await?;
    assert_eq!(status, StatusCode::OK);
    for id in [
        "01PAY0000000000000000000001",
        "01SRC0000000000000000000002",
        "01REF0000000000000000000003",
    ] {
        assert!(page.contains(id), "{id} is listed");
    }
    assert!(page.contains(">Verified<") && page.contains(r#"href="/console/requests""#));
    assert!(
        page.contains("aria-current=\"page\">Requests"),
        "the nav marks the page"
    );

    let (_, _, page) = send(&s.app, get("/console/requests?team=payments", &cookie)?).await?;
    assert!(page.contains("01PAY") && !page.contains("01SRC"));
    let (_, _, page) = send(
        &s.app,
        get(
            "/console/requests?outcome=refused&agent=claude-code",
            &cookie,
        )?,
    )
    .await?;
    assert!(page.contains("01REF") && !page.contains("01PAY"));
    let (_, _, page) = send(&s.app, get("/console/requests?min_ms=1000", &cookie)?).await?;
    assert!(page.contains("01SRC") && !page.contains("01PAY"));
    let (_, _, page) = send(&s.app, get("/console/requests?min_ms=fast", &cookie)?).await?;
    assert!(
        page.contains("Write milliseconds as a whole number"),
        "the fix is named"
    );

    let (_, _, page) = send(
        &s.app,
        get(
            "/console/requests?open=01PAY0000000000000000000001",
            &cookie,
        )?,
    )
    .await?;
    assert!(
        page.contains("Read the kept body")
            && page.contains("/console/audit?record=01PAY0000000000000000000001")
    );
    // The row's detail names its session and its turn, and the session is one more text filter.
    assert!(
        page.contains("ses_0123456789abcdef01234567") && page.contains("turn_0123456789abcdef"),
        "the session and the turn are in the row's detail"
    );
    assert!(page.contains(r#"name="session""#) && page.contains(r#"placeholder="Session""#));
    let (_, _, page) = send(
        &s.app,
        get(
            "/console/requests?session=ses_0123456789abcdef01234567",
            &cookie,
        )?,
    )
    .await?;
    assert!(page.contains("01PAY") && !page.contains("01SRC"));
    assert!(page.contains(r#"name="session" value="ses_0123456789abcdef01234567""#));

    // A record changed on disk no longer proves: its row says so.
    let text = std::fs::read_to_string(&s.audit)?.replace("dana.levi", "dana.levy");
    std::fs::write(&s.audit, text)?;
    let (_, _, page) = send(&s.app, get("/console/requests", &cookie)?).await?;
    assert!(page.contains(">Changed<"));
    Ok(())
}

#[tokio::test]
async fn a_kept_body_is_shown_only_to_its_viewers_and_every_view_is_recorded() -> TestResult {
    let s = setup("body")?;
    let noa = sign_in(&s.app, NOA).await?;
    let (status, _, page) = send(
        &s.app,
        post(
            "/console/requests/body",
            &noa,
            "id=01PAY0000000000000000000001",
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("card [MASKED credit_card]") && page.contains("This view is recorded"));
    let viewed = records(&s)?
        .into_iter()
        .find(|r| r["action"] == "view_body" && r["verdict"] == "allow")
        .ok_or("no record of the view")?;
    assert_eq!(viewed["person"], "noa.bar");
    assert_eq!(viewed["target"]["id"], "01PAY0000000000000000000001");

    let lee = sign_in(&s.app, LEE).await?;
    let (status, _, page) = send(
        &s.app,
        post(
            "/console/requests/body",
            &lee,
            "id=01PAY0000000000000000000001",
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(!page.contains("MASKED credit_card") && page.contains("capture: viewers"));
    assert!(records(&s)?.iter().any(|r| r["action"] == "view_body"
        && r["person"] == "lee.k"
        && r["code"] == "not_a_viewer"));

    // A view from another site is refused before anything is read.
    let foreign = Request::post("/console/requests/body")
        .header(header::HOST, HOST)
        .header(header::ORIGIN, "https://evil.example")
        .header(header::COOKIE, &noa)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from("id=01PAY0000000000000000000001"))?;
    let (status, _, page) = send(&s.app, foreign).await?;
    assert_ne!(status, StatusCode::OK);
    assert!(!page.contains("MASKED"));
    Ok(())
}

#[tokio::test]
async fn a_budget_is_forecast_over_its_own_period_and_time_zone() -> TestResult {
    let s = setup("forecast-window")?;
    let policy = s.audit.with_file_name("gantry.policy.yaml");
    std::fs::write(
        &policy,
        POLICY.replace(
            "budget: { usd: 10, per: month }",
            "budget: { usd: 10, per: week, tz: America/New_York }",
        ),
    )?;
    let cookie = sign_in(&s.app, NOA).await?;
    let (status, _, page) = send(&s.app, get("/console/analytics", &cookie)?).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains("team payments")
            && page.contains("$4.00 of $10.00 per week (America/New_York)"),
        "{page}"
    );
    Ok(())
}

#[tokio::test]
async fn analytics_show_totals_percentiles_rankings_and_forecasts() -> TestResult {
    let s = setup("analytics")?;
    let cookie = sign_in(&s.app, NOA).await?;
    let (status, _, page) = send(&s.app, get("/console/analytics?by=team", &cookie)?).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains("latency p95") && page.contains("2,400 ms"),
        "{page}"
    );
    assert!(page.contains("$4.01"), "the cost of both answers");
    assert!(page.contains("By team, most costly first"));
    let payments = page.find(">payments<").ok_or("no payments row")?;
    let search = page.find(">search<").ok_or("no search row")?;
    assert!(payments < search, "the costlier team ranks first");
    assert!(
        page.contains("Budget forecasts")
            && page.contains("team payments")
            && page.contains("$4.00 of $10.00 per month")
    );
    let (_, _, page) = send(
        &s.app,
        get("/console/analytics?by=agent&window=24h", &cookie)?,
    )
    .await?;
    assert!(page.contains(">claude-code<") && page.contains("per hour"));
    Ok(())
}
