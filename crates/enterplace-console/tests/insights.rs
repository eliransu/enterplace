//! The Requests API of the console app, the kept body view and the Analytics page, through the console's routes,
//! from the local chain.

use std::{path::PathBuf, sync::Arc};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use enterplace_console::{ConsoleConfig, router};
use enterplace_core::{
    audit::{AuditLog, Entry},
    id::sha256_hex,
    insights::{self, Bodies, FileBodies, Seal},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type Error = Box<dyn std::error::Error>;
type TestResult = Result<(), Error>;

const NOA: &str = "enterplace_noa_admin_key_for_tests";
const LEE: &str = "enterplace_lee_admin_key_for_tests";
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
        "enterplace-console-insights-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("enterplace.policy.yaml"), POLICY)?;
    std::fs::write(
        dir.join("enterplace.keys.yaml"),
        format!(
            "keys:\n  - name: noa.bar\n    team: platform\n    sha256: {}\n    admin: true\n  - name: lee.k\n    team: platform\n    sha256: {}\n    admin: true\n",
            sha256_hex(NOA.as_bytes()),
            sha256_hex(LEE.as_bytes())
        ),
    )?;
    let audit = dir.join("enterplace-audit.jsonl");
    let log = AuditLog::open(&audit)?;
    let decision = |id: &'static str, person: &'static str, team: &'static str, allowed: bool| {
        let mut r = enterplace_core::audit::record(&Entry {
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
        time: enterplace_core::audit::timestamp(),
        rule: "payments-team".into(),
        expires: insights::now_secs() + 86_400,
        viewers: vec!["noa.bar".into()],
        request: "card [MASKED credit_card]".into(),
        answer: "done".into(),
    })?;
    let bodies: Arc<dyn Bodies> = bodies;
    insights::attach(&audit, None, Some(bodies));
    let config = ConsoleConfig {
        policy: dir.join("enterplace.policy.yaml"),
        keys: dir.join("enterplace.keys.yaml"),
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

/// The JSON the console app reads, with its status.
async fn api(app: &Router, path: &str, cookie: &str) -> Result<(StatusCode, Value), Error> {
    let (status, _, body) = send(app, get(path, cookie)?).await?;
    Ok((status, serde_json::from_str(&body)?))
}

fn ids(list: &Value) -> Vec<String> {
    list["rows"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|r| r["id"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn has(list: &Value, prefix: &str) -> bool {
    ids(list).iter().any(|id| id.starts_with(prefix))
}

#[tokio::test]
async fn the_old_address_lands_on_the_app_with_its_filters_and_open_request() -> TestResult {
    let s = setup("moved")?;
    // No session needed: the app asks for one, and sign-in returns to the app route.
    let (status, location) = {
        let response = s
            .app
            .clone()
            .oneshot(get(
                "/console/requests?team=payments&open=01PAY0000000000000000000001&page=2&junk=x",
                "",
            )?)
            .await?;
        let location = response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        (response.status(), location)
    };
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        location,
        "/console/app/#/requests?team=payments&record=01PAY0000000000000000000001&page=2"
    );
    let (status, _, _) = send(
        &s.app,
        post(
            "/console/requests/body",
            &sign_in(&s.app, NOA).await?,
            "id=01PAY0000000000000000000001",
        )?,
    )
    .await?;
    assert_ne!(status, StatusCode::OK, "the old form route is gone");
    Ok(())
}

#[tokio::test]
async fn the_request_log_filters_and_proves_each_row() -> TestResult {
    let s = setup("log")?;
    let (status, _) = api(&s.app, "/console/api/requests", "").await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let cookie = sign_in(&s.app, NOA).await?;
    let (status, list) = api(&s.app, "/console/api/requests", &cookie).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        ids(&list),
        [
            "01REF0000000000000000000003",
            "01SRC0000000000000000000002",
            "01PAY0000000000000000000001",
        ],
        "newest first"
    );
    // No proof tag saying Verified on every row: a row that does not prove says so in its own tag.
    assert!(
        list["rows"]
            .as_array()
            .is_some_and(|r| r.iter().all(|r| r["proof"].is_null()))
    );
    // Outcomes read as the Audit log reads them.
    let pay = &list["rows"][2];
    assert_eq!(pay["outcome"]["text"], "Allowed");
    assert_eq!(pay["outcome"]["kind"], "allow");
    assert_eq!(
        list["rows"][0]["outcome"]["text"],
        "Refused: model not allowed"
    );
    assert_eq!(pay["tokens"], "1,200");
    assert_eq!(pay["cost"], "$4.00");
    assert_eq!(pay["latency"], "840 ms");
    assert_eq!(list["rows"][1]["latency"], "2,400 ms");
    assert_eq!(pay["person"], "maya.cohen");
    assert_eq!(pay["team"], "payments");
    assert_eq!(list["est_header"], "USD (est.)");
    assert_eq!(list["pager"]["text"], "Page 1, 3 requests");
    assert_eq!(list["pager"]["older"], false);
    assert!(list["empty"].is_null());

    // The filter fields offer the values in the log.
    assert!(
        list["values"]["team"]
            .as_array()
            .is_some_and(|v| v.iter().any(|t| t == "payments")),
        "{list}"
    );

    let (_, list) = api(&s.app, "/console/api/requests?team=payments", &cookie).await?;
    assert!(has(&list, "01PAY") && !has(&list, "01SRC"));
    let (_, list) = api(
        &s.app,
        "/console/api/requests?outcome=refused&agent=claude-code",
        &cookie,
    )
    .await?;
    assert!(has(&list, "01REF") && !has(&list, "01PAY"));
    let (_, list) = api(&s.app, "/console/api/requests?min_ms=1000", &cookie).await?;
    assert!(has(&list, "01SRC") && !has(&list, "01PAY"));
    let (status, refused) = api(&s.app, "/console/api/requests?min_ms=fast", &cookie).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        refused["error"]
            .as_str()
            .is_some_and(|e| e.contains("Write milliseconds as a whole number")),
        "the fix is named: {refused}"
    );
    let (_, list) = api(&s.app, "/console/api/requests?team=nobody", &cookie).await?;
    assert_eq!(list["empty"]["title"], "No request matches");

    let (status, sheet) = api(
        &s.app,
        "/console/api/requests/01PAY0000000000000000000001",
        &cookie,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(sheet["body"], true, "Read the kept body is offered");
    assert_eq!(
        sheet["proof"]["audit"],
        "/console/audit?record=01PAY0000000000000000000001"
    );
    // The row's detail names its session and its turn, and the session is one more text filter.
    let details = sheet["details"].to_string();
    assert!(
        details.contains("ses_0123456789abcdef01234567")
            && details.contains("turn_0123456789abcdef"),
        "the session and the turn are in the row's detail: {details}"
    );
    assert!(
        list["filters"].as_array().is_some_and(|f| f
            .iter()
            .any(|f| f["name"] == "session" && f["label"] == "Session")),
        "{list}"
    );
    let (_, list) = api(
        &s.app,
        "/console/api/requests?session=ses_0123456789abcdef01234567",
        &cookie,
    )
    .await?;
    assert!(has(&list, "01PAY") && !has(&list, "01SRC"));
    assert!(
        list["filters"].as_array().is_some_and(|f| f
            .iter()
            .any(|f| f["name"] == "session" && f["value"] == "ses_0123456789abcdef01234567")),
        "{list}"
    );
    let (status, gone) = api(
        &s.app,
        "/console/api/requests/01NONE000000000000000000009",
        &cookie,
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        gone["error"]
            .as_str()
            .is_some_and(|e| e.contains("No request has the ID"))
    );

    // A record changed on disk no longer proves: its row says so.
    let text = std::fs::read_to_string(&s.audit)?.replace("dana.levi", "dana.levy");
    std::fs::write(&s.audit, text)?;
    let (_, list) = api(&s.app, "/console/api/requests", &cookie).await?;
    assert!(
        list["rows"]
            .as_array()
            .is_some_and(|r| r.iter().any(|r| r["proof"]["text"] == "Changed")),
        "{list}"
    );
    Ok(())
}

#[tokio::test]
async fn a_kept_body_is_shown_only_to_its_viewers_and_every_view_is_recorded() -> TestResult {
    let s = setup("body")?;
    let noa = sign_in(&s.app, NOA).await?;
    let (status, _, page) = send(
        &s.app,
        post(
            "/console/api/requests/body",
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
            "/console/api/requests/body",
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

    // A body never kept is gone, and asking for it is recorded too.
    let (status, _, page) = send(
        &s.app,
        post(
            "/console/api/requests/body",
            &noa,
            "id=01SRC0000000000000000000002",
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(page.contains("keeps no body"), "{page}");
    assert!(
        records(&s)?
            .iter()
            .any(|r| r["action"] == "view_body" && r["code"] == "no_body")
    );

    // A view from another site is refused before anything is read.
    let foreign = Request::post("/console/api/requests/body")
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

/// Who is close to a limit covers every budget the policy sets: rules, a key's own budget from the keys file, and
/// each scope of the `limits:` list, a `*` entry by whoever is heading out first.
#[tokio::test]
async fn every_budget_scope_is_forecast_rules_keys_and_the_limits_list() -> TestResult {
    let s = setup("every-scope")?;
    let dir = s.audit.with_file_name("");
    std::fs::write(
        dir.join("enterplace.policy.yaml"),
        format!(
            "{POLICY}limits:\n  - {{ team: search, budget: {{ usd: 5, per: month }} }}\n  - {{ person: \"*\", budget: {{ usd: 2, per: month }} }}\n  - {{ global: true, budget: {{ usd: 100, per: month }} }}\n  - {{ model: gpt-4o-mini, budget: {{ usd: 50, per: month }} }}\n  - {{ customer: acme, budget: {{ usd: 1, per: month }} }}\n"
        ),
    )?;
    std::fs::write(
        dir.join("enterplace.keys.yaml"),
        format!(
            "keys:\n  - name: noa.bar\n    team: platform\n    sha256: {}\n    admin: true\n  - name: lee.k\n    team: platform\n    sha256: {}\n    admin: true\n    budget: {{ usd: 3, per: month }}\n",
            sha256_hex(NOA.as_bytes()),
            sha256_hex(LEE.as_bytes())
        ),
    )?;
    let lee_key = &sha256_hex(LEE.as_bytes())[..8];
    s.log
        .append_record(&enterplace_core::audit::record(&Entry {
            id: "01LEE0000000000000000000007",
            person: Some("lee.k"),
            team: Some("platform"),
            key: Some(lee_key),
            method: "POST",
            path: "/v1/chat/completions",
            model: Some("gpt-4o-mini"),
            allowed: true,
            rule: Some("everyone-else"),
            provider: "openai",
            ..Entry::default()
        }))?;
    s.log.append_record(&object(json!({"event": "usage", "id": "01LEE0000000000000000000007", "provider": "openai", "model": "gpt-4o-mini", "status": 200, "input_tokens": 10, "output_tokens": 5, "cost_usd": 0.5, "charged_usd": 0.5, "latency_ms": 300})))?;
    s.log.flush();
    let cookie = sign_in(&s.app, NOA).await?;
    let (status, page) = analytics(&s.app, "", &cookie).await?;
    assert_eq!(status, StatusCode::OK, "{page}");
    let forecasts = page["forecasts"].as_array().ok_or("no forecasts")?;
    let text = |label: &str| {
        forecasts
            .iter()
            .find(|f| f["label"] == label)
            .map(|f| f["text"].as_str().unwrap_or_default().to_string())
    };
    for (label, expected) in [
        ("team payments", "$4.00 of $10.00 per month"),
        ("lee.k's key", "$0.50 of $3.00 per month"),
        ("team search", "$0.01 of $5.00 per month"),
        ("maya.cohen (each person)", "$4.00 of $2.00 per month"),
        ("everything", "$4.51 of $100.00 per month"),
        ("model gpt-4o-mini", "$4.51 of $50.00 per month"),
        ("customer acme", "$0.00 of $1.00 per month"),
    ] {
        assert_eq!(text(label).as_deref(), Some(expected), "{label}: {page}");
    }
    assert_eq!(forecasts.len(), 7, "{page}");
    // The one already past its limit leads: that is who to look at.
    assert_eq!(forecasts[0]["label"], "maya.cohen (each person)", "{page}");
    assert!(
        forecasts[0]["note"]
            .as_str()
            .is_some_and(|n| n.starts_with("Set by limits { person: * }")),
        "{page}"
    );
    Ok(())
}

/// A budget that lasts at its pace can still refuse: a request reserves what its most output tokens could cost
/// before it is sent. The forecast says how many it refused this period and the fix, as the Spend page does.
#[tokio::test]
async fn a_forecast_that_lasts_says_what_it_refused_and_the_fix() -> TestResult {
    let s = setup("forecast-refused")?;
    std::fs::write(
        s.audit.with_file_name("enterplace.policy.yaml"),
        format!("{POLICY}limits:\n  - {{ team: search, budget: {{ usd: 5, per: month }} }}\n"),
    )?;
    let refusal = |id: &'static str, team: &'static str, code: &'static str, applied: Value| {
        let mut r = enterplace_core::audit::record(&Entry {
            id,
            person: Some("dana.levi"),
            team: Some(team),
            method: "POST",
            path: "/v1/chat/completions",
            model: Some("gpt-4o-mini"),
            allowed: false,
            code: Some(code),
            rule: Some(if team == "payments" {
                "payments-team"
            } else {
                "everyone-else"
            }),
            ..Entry::default()
        });
        r.insert("applied".into(), applied);
        r
    };
    for id in ["01BUD0000000000000000000010", "01BUD0000000000000000000011"] {
        s.log.append_record(&refusal(
            id,
            "payments",
            "budget_exceeded",
            json!({ "of": "rule", "scope": "team:payments", "limit": "budget", "source": "rule \"payments-team\" (line 12)", "usd": 10.0, "per": "month" }),
        ))?;
    }
    s.log.append_record(&refusal(
        "01BUD0000000000000000000012",
        "search",
        "budget_exceeded",
        json!({ "of": "team", "scope": "team:search", "limit": "budget", "source": "limits { team: search } (line 21)", "usd": 5.0, "per": "month" }),
    ))?;
    s.log.flush();
    let cookie = sign_in(&s.app, NOA).await?;
    let (_, page) = analytics(&s.app, "", &cookie).await?;
    let forecast = |label: &str| {
        page["forecasts"]
            .as_array()
            .and_then(|f| f.iter().find(|f| f["label"] == label))
            .cloned()
            .unwrap_or(Value::Null)
    };
    let payments = forecast("team payments");
    let note = payments["note"].as_str().unwrap_or_default();
    assert!(
        note.contains("At this pace it lasts the period."),
        "{payments}"
    );
    assert!(
        note.contains(
            "2 requests were refused this period because they set no max_tokens, or a large one"
        ),
        "{payments}"
    );
    assert_eq!(
        payments["over"], true,
        "a budget that refuses is shown as spent"
    );
    let search = forecast("team search");
    assert!(
        search["note"].as_str().is_some_and(
            |n| n.contains("1 request was refused this period because they set no max_tokens")
        ),
        "{search}"
    );
    Ok(())
}

#[tokio::test]
async fn a_budget_is_forecast_over_its_own_period_and_time_zone() -> TestResult {
    let s = setup("forecast-window")?;
    let policy = s.audit.with_file_name("enterplace.policy.yaml");
    std::fs::write(
        &policy,
        POLICY.replace(
            "budget: { usd: 10, per: month }",
            "budget: { usd: 10, per: week, tz: America/New_York }",
        ),
    )?;
    let cookie = sign_in(&s.app, NOA).await?;
    let (status, page) = analytics(&s.app, "", &cookie).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["forecasts"][0]["label"], "team payments", "{page}");
    assert_eq!(
        page["forecasts"][0]["text"],
        "$4.00 of $10.00 per week (America/New_York)"
    );
    Ok(())
}

/// A Claude Code subscription login under a rule without `budget_basis: api_equivalent`: the gateway counts none of
/// it against the team's budget (`"budget": "not_counted"`), so neither meter does; the estimate is said beside them.
#[tokio::test]
async fn subscription_traffic_is_beside_the_budget_meter_never_in_it() -> TestResult {
    let s = setup("uncounted")?;
    let mut sub = enterplace_core::audit::record(&Entry {
        id: "01SUB0000000000000000000009",
        person: Some("maya.cohen"),
        team: Some("payments"),
        method: "POST",
        path: "/v1/messages",
        model: Some("gpt-4o-mini"),
        allowed: true,
        rule: Some("payments-team"),
        provider: "openai",
        ..Entry::default()
    });
    sub.insert("user_agent".into(), "claude-cli/2.0.1".into());
    sub.insert("auth".into(), "passthrough".into());
    s.log.append_record(&sub)?;
    s.log.append_record(&object(json!({"event": "usage", "id": "01SUB0000000000000000000009", "time": enterplace_core::audit::timestamp(), "person": "maya.cohen", "team": "payments", "provider": "openai", "model": "gpt-4o-mini", "status": 200, "input_tokens": 100, "output_tokens": 10, "cost_usd": 3.0, "charged_usd": 3.0, "auth": "passthrough", "cost_basis": "api_equivalent_estimate", "caller_paid": true, "budget": "not_counted", "latency_ms": 900})))?;
    s.log.flush();
    let cookie = sign_in(&s.app, NOA).await?;
    let (_, page) = analytics(&s.app, "", &cookie).await?;
    let forecast = &page["forecasts"][0];
    assert_eq!(forecast["text"], "$4.00 of $10.00 per month", "{forecast}");
    assert!(
        forecast["note"].as_str().is_some_and(|n| n.contains(
            "~$3.00 of subscription use (an estimate at API prices) is not counted against the budget"
        )),
        "{forecast}"
    );
    let (_, spend) = api(&s.app, "/console/api/spend", &cookie).await?;
    let meter = &spend["budgets"]["meters"][0];
    // Spend lists the budgets Usage forecasts: one answer on both pages.
    assert_eq!(meter, forecast, "{spend}");
    assert!(
        meter["note"].as_str().is_some_and(|n| n.contains(
            "~$3.00 of subscription use (an estimate at API prices) is not counted against the budget"
        )),
        "{meter}"
    );
    Ok(())
}

/// The console app's Analytics answer for a query, as JSON.
async fn analytics(app: &Router, query: &str, cookie: &str) -> Result<(StatusCode, Value), Error> {
    let (status, _, body) =
        send(app, get(&format!("/console/api/analytics{query}"), cookie)?).await?;
    Ok((status, serde_json::from_str(&body)?))
}

#[tokio::test]
async fn analytics_show_totals_percentiles_rankings_and_forecasts() -> TestResult {
    let s = setup("analytics")?;
    let cookie = sign_in(&s.app, NOA).await?;
    let (status, page) = analytics(&s.app, "?by=team", &cookie).await?;
    assert_eq!(status, StatusCode::OK);
    // Three figures at the top; latency is in its chart and the ranking.
    let stats = page["stats"].as_array().ok_or("no stats")?;
    assert_eq!(stats.len(), 3, "{page}");
    assert!(
        page["metrics"]
            .as_array()
            .is_some_and(|m| m.iter().any(|m| m["label"] == "Latency p95")),
        "{page}"
    );
    assert_eq!(stats[1]["figure"], "$4.01", "the cost of both answers");
    assert_eq!(page["ranking_title"], "By team, most costly first");
    assert_eq!(
        page["ranking"][0]["value"], "payments",
        "the costlier team ranks first"
    );
    assert_eq!(page["ranking"][1]["value"], "search");
    assert_eq!(
        page["ranking"][0]["href"],
        "/console/requests?team=payments"
    );
    assert_eq!(page["ranking"][1]["p95"], "2,400 ms");
    assert_eq!(page["forecasts"][0]["label"], "team payments");
    assert_eq!(page["forecasts"][0]["text"], "$4.00 of $10.00 per month");
    let (_, page) = analytics(&s.app, "?by=agent&window=24h", &cookie).await?;
    assert_eq!(page["ranking"][0]["value"], "claude-code", "{page}");
    assert_eq!(page["chart_title"], "Requests, per hour");

    // A filter that does not parse names the fix; a role without see_spend is refused.
    let (status, page) = analytics(&s.app, "?min_ms=fast", &cookie).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        page["error"]
            .as_str()
            .is_some_and(|e| e.contains("Write milliseconds as a whole number")),
        "{page}"
    );
    let (status, _) = analytics(&s.app, "", "").await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn the_old_analytics_address_opens_the_app_with_its_query() -> TestResult {
    let s = setup("analytics-moved")?;
    let (status, _, _) = send(&s.app, get("/console/analytics", "")?).await?;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let response = s
        .app
        .clone()
        .oneshot(get("/console/analytics?by=team&window=24h", "")?)
        .await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/console/app/#/usage?by=team&window=24h")
    );
    let response = s
        .app
        .clone()
        .oneshot(get("/console/analytics", "")?)
        .await?;
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/console/app/#/usage")
    );
    Ok(())
}

#[tokio::test]
async fn the_request_filters_show_five_labeled_up_front_and_fold_the_rest() -> TestResult {
    let s = setup("filters")?;
    let cookie = sign_in(&s.app, NOA).await?;
    let (_, list) = api(&s.app, "/console/api/requests", &cookie).await?;
    let fields = list["filters"].as_array().cloned().unwrap_or_default();
    let field = |name: &str| fields.iter().find(|f| f["name"] == name).cloned();
    for name in ["person", "team", "model", "from", "to"] {
        let f = field(name).ok_or(format!("no {name} field"))?;
        assert_eq!(f["more"], false, "{name} is shown before More filters");
        assert!(
            f["label"].as_str().is_some_and(|l| !l.is_empty()),
            "{name} has a label"
        );
    }
    for name in ["key", "provider", "session", "code", "min_cost", "max_ms"] {
        let f = field(name).ok_or(format!("no {name} field"))?;
        assert_eq!(f["more"], true, "{name} is behind More filters");
    }
    assert_eq!(
        field("from").ok_or("no from")?["kind"],
        "date",
        "the range is a date picker"
    );
    // More filters is closed until one of its own filters is set.
    assert_eq!(list["more_open"], false);
    let (_, list) = api(&s.app, "/console/api/requests?team=payments", &cookie).await?;
    assert_eq!(list["more_open"], false, "a filter up front opens nothing");
    let (_, list) = api(&s.app, "/console/api/requests?min_ms=1000", &cookie).await?;
    assert_eq!(list["more_open"], true, "a folded filter that is set shows");
    // A link that carries a full time keeps it in a text field: a date picker would drop it.
    let (_, list) = api(
        &s.app,
        "/console/api/requests?from=2026-11-14T09:30:00Z",
        &cookie,
    )
    .await?;
    assert!(
        list["filters"]
            .as_array()
            .is_some_and(|f| f.iter().any(|f| f["name"] == "from" && f["kind"] == "text")),
        "{list}"
    );
    Ok(())
}

#[tokio::test]
async fn the_request_sheet_says_who_what_and_how_and_folds_its_proof() -> TestResult {
    let s = setup("sheet")?;
    let cookie = sign_in(&s.app, NOA).await?;
    let (_, sheet) = api(
        &s.app,
        "/console/api/requests/01PAY0000000000000000000001",
        &cookie,
    )
    .await?;
    assert_eq!(
        sheet["title"], "maya.cohen, gpt-4o-mini, allowed",
        "no ID as the title"
    );
    assert!(sheet["failed"].is_null());
    let facts: Vec<&str> = sheet["facts"]
        .as_array()
        .map(|f| f.iter().filter_map(|f| f[0].as_str()).collect())
        .unwrap_or_default();
    assert_eq!(facts, ["Time", "Person", "Model", "Tokens", "Cost", "Rule"]);
    assert_eq!(sheet["facts"][3][1], "1,200 (1,000 in, 200 out)");
    // The hash is folded under Proof, not one of the six.
    assert!(
        sheet["proof"]["facts"]
            .as_array()
            .is_some_and(|f| f.iter().any(|f| f[0] == "Hash"))
    );
    assert!(
        sheet["proof"]["text"]
            .as_str()
            .is_some_and(|t| t.contains("follows the record before it"))
    );
    let (_, sheet) = api(
        &s.app,
        "/console/api/requests/01REF0000000000000000000003",
        &cookie,
    )
    .await?;
    assert_eq!(
        sheet["title"],
        "dana.levi, gpt-4o-mini, refused (model_not_allowed)"
    );
    Ok(())
}

#[tokio::test]
async fn analytics_draw_one_chart_with_a_metric_switch_and_four_tabs_up_front() -> TestResult {
    let s = setup("analytics-tabs")?;
    let cookie = sign_in(&s.app, NOA).await?;
    let (_, page) = analytics(&s.app, "", &cookie).await?;
    let points = page["chart"]["points"].as_array().ok_or("no chart")?;
    let names: Vec<&str> = page["metrics"]
        .as_array()
        .ok_or("no metrics")?
        .iter()
        .filter_map(|m| m["name"].as_str())
        .collect();
    assert!(
        names.contains(&"cost") && names.contains(&"tokens"),
        "{page}"
    );
    // One bar a day of the window, and only today's is marked to stand out.
    assert!(points.len() >= 7, "{page}");
    assert_eq!(points.iter().filter(|p| p["now"] == true).count(), 1);
    assert_eq!(points.last().map(|p| &p["now"]), Some(&Value::Bool(true)));
    assert_eq!(page["chart"]["top"], "3", "{page}");
    let (_, cost) = analytics(&s.app, "?metric=cost", &cookie).await?;
    assert_eq!(cost["chart_title"], "Cost, USD, per day", "{cost}");

    let label = |list: &Value| -> Vec<String> {
        list.as_array()
            .map(|l| {
                l.iter()
                    .filter_map(|t| t["label"].as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    assert_eq!(label(&page["bys"]), ["Team", "Person", "Model", "Provider"]);
    // The local chain has requests with keys' coding agent but none with a customer: that tab is not shown.
    let more = label(&page["more"]);
    assert!(more.iter().any(|l| l == "Coding agent"), "{page}");
    assert!(
        !more.iter().any(|l| l == "Customer" || l == "Organization"),
        "{page}"
    );
    Ok(())
}

/// One team's (or person's, app's, agent's, model's) trend: the day chart filtered to one value of a ranking, the
/// ranking itself left whole, the filter named so it can be removed, and kept in the share link.
#[tokio::test]
async fn a_ranking_value_filters_the_chart_alone_and_stays_in_the_link() -> TestResult {
    let s = setup("trend")?;
    let cookie = sign_in(&s.app, NOA).await?;
    let (status, page) = analytics(&s.app, "?by=team&trend=team:search", &cookie).await?;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(
        page["trend"],
        json!({ "name": "team", "value": "search", "label": "Team search" })
    );
    assert_eq!(page["chart_title"], "Requests, per day, team search");
    // Today's bar holds search's two requests, not all three.
    let points = page["chart"]["points"].as_array().ok_or("no chart")?;
    assert_eq!(
        points.last().map(|p| &p["shown"]),
        Some(&json!("2")),
        "{page}"
    );
    // The ranking and the figures stay the whole window's.
    assert_eq!(page["stats"][0]["figure"], "3");
    assert_eq!(page["ranking"].as_array().map(Vec::len), Some(2), "{page}");
    assert!(
        page["link"]
            .as_str()
            .is_some_and(|l| l.contains("trend=team%3Asearch")),
        "{page}"
    );
    // Without it, the chart is everything again.
    let (_, all) = analytics(&s.app, "?by=team", &cookie).await?;
    assert_eq!(all["trend"], Value::Null);
    let points = all["chart"]["points"].as_array().ok_or("no chart")?;
    assert_eq!(points.last().map(|p| &p["shown"]), Some(&json!("3")));
    // A trend that does not parse says how to write it.
    let (status, bad) = analytics(&s.app, "?trend=colour:blue", &cookie).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        bad["error"].as_str().is_some_and(
            |e| e.contains("Write it as a dimension and a value, such as trend=team:payments")
        ),
        "{bad}"
    );
    Ok(())
}

#[tokio::test]
async fn live_json_changes_when_a_record_is_written_and_needs_a_session() -> TestResult {
    // The Requests, Analytics, Audit log and Spend pages ask this every 2 seconds and redraw when it changes, so
    // a request shows on the page as it arrives.
    let s = setup("live")?;
    let (status, _, _) = send(&s.app, get("/console/live.json", "")?).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let cookie = sign_in(&s.app, NOA).await?;
    let read = async || -> Result<Value, Error> {
        let (status, _, body) = send(&s.app, get("/console/live.json", &cookie)?).await?;
        assert_eq!(status, StatusCode::OK);
        Ok(serde_json::from_str(&body)?)
    };
    let (before, again) = (read().await?, read().await?);
    assert_eq!(before, again, "nothing was written in between");
    s.log.append_record(&object(json!({"event": "usage", "id": "01LIVE000000000000000000001", "provider": "openai", "model": "gpt-4o-mini", "status": 200, "input_tokens": 1, "output_tokens": 1})))?;
    s.log.flush();
    let after = read().await?;
    assert_ne!(before["signature"], after["signature"]);
    assert!(after["signature"].is_string());
    // The sidebar indicator shows when the last request arrived: the time the log last changed, in milliseconds.
    assert!(before["last_request_ms"].is_u64() && after["last_request_ms"].is_u64());
    Ok(())
}

#[tokio::test]
async fn events_stream_sends_a_change_when_a_record_is_written_and_needs_a_session() -> TestResult {
    // The console app keeps one /console/events stream open and reloads the open page on each change event, so a
    // request shows on the page the moment it is recorded.
    let s = setup("events")?;
    let (status, _, _) = send(&s.app, get("/console/events", "")?).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let cookie = sign_in(&s.app, NOA).await?;
    let response = s
        .app
        .clone()
        .oneshot(get("/console/events", &cookie)?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let kind = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(kind.starts_with("text/event-stream"), "{kind}");
    let mut body = response.into_body();
    let mut next = async || -> Result<String, Error> {
        let wait = std::time::Duration::from_secs(5);
        let frame = tokio::time::timeout(wait, body.frame())
            .await?
            .ok_or("the stream ended")??;
        Ok(
            String::from_utf8_lossy(&frame.into_data().map_err(|_| "not a data frame")?)
                .into_owned(),
        )
    };
    let first = next().await?;
    assert!(first.contains("event: change"), "{first}");
    s.log.append_record(&object(json!({"event": "usage", "id": "01EVNT000000000000000000001", "provider": "openai", "model": "gpt-4o-mini", "status": 200, "input_tokens": 1, "output_tokens": 1})))?;
    s.log.flush();
    let second = next().await?;
    assert!(
        second.contains("event: change") && second != first,
        "{first} then {second}"
    );
    Ok(())
}

/// A request a guardrail let through under warn or mask says what it found, as the Audit log does.
#[tokio::test]
async fn a_warned_request_says_what_the_guardrail_found() -> TestResult {
    let s = setup("warned")?;
    for (id, action, kind) in [
        ("01WRN0000000000000000000004", "warn", "credit_card"),
        ("01MSK0000000000000000000005", "mask", "email"),
    ] {
        let mut r = enterplace_core::audit::record(&Entry {
            id,
            person: Some("maya.cohen"),
            team: Some("payments"),
            method: "POST",
            path: "/v1/chat/completions",
            model: Some("gpt-4o-mini"),
            allowed: true,
            rule: Some("payments-team"),
            provider: "openai",
            ..Entry::default()
        });
        r.insert(
            "guardrails".into(),
            json!([{ "guardrail": "cards", "detector": "pii", "kind": kind, "action": action, "count": 1 }]),
        );
        s.log.append_record(&r)?;
    }
    s.log.flush();
    let cookie = sign_in(&s.app, NOA).await?;
    let (_, list) = api(&s.app, "/console/api/requests", &cookie).await?;
    let outcome = |id: &str| {
        list["rows"]
            .as_array()
            .and_then(|rows| rows.iter().find(|r| r["id"] == id))
            .map(|r| r["outcome"].clone())
            .unwrap_or(Value::Null)
    };
    assert_eq!(
        outcome("01WRN0000000000000000000004"),
        json!({ "kind": "warn", "text": "Found: credit_card" }),
        "{list}"
    );
    assert_eq!(
        outcome("01MSK0000000000000000000005"),
        json!({ "kind": "warn", "text": "Masked: email" }),
        "{list}"
    );
    Ok(())
}

/// A request a limit refused says which limit, in Requests and the Audit log: an ops engineer finds who hit what
/// without opening each record.
#[tokio::test]
async fn a_request_refused_by_a_limit_names_the_limit() -> TestResult {
    let s = setup("limit-named")?;
    let mut r = enterplace_core::audit::record(&Entry {
        id: "01LIM0000000000000000000006",
        person: Some("maya.cohen"),
        team: Some("payments"),
        method: "POST",
        path: "/v1/chat/completions",
        model: Some("gpt-4o-mini"),
        allowed: false,
        code: Some("rate_limited"),
        rule: Some("payments-team"),
        ..Entry::default()
    });
    r.insert(
        "applied".into(),
        json!({ "of": "team", "scope": "team:payments", "limit": "tpd", "source": "limits { team: payments } (line 5)", "value": 300 }),
    );
    s.log.append_record(&r)?;
    s.log.flush();
    let cookie = sign_in(&s.app, NOA).await?;
    let (_, list) = api(&s.app, "/console/api/requests", &cookie).await?;
    let row = list["rows"]
        .as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|r| r["id"] == "01LIM0000000000000000000006")
        })
        .cloned()
        .unwrap_or(Value::Null);
    assert_eq!(
        row["outcome"]["text"], "Refused: rate limited, team payments tokens per day 300",
        "{row}"
    );
    let (_, audit) = api(&s.app, "/console/api/audit?verdict=refused", &cookie).await?;
    assert!(
        audit["rows"].as_array().is_some_and(|rows| rows
            .iter()
            .any(|r| r["verdict"]["detail"] == "rate limited, team payments tokens per day 300")),
        "{audit}"
    );
    Ok(())
}

#[tokio::test]
async fn a_person_splits_by_coding_agent_and_model_with_estimates_marked_shared_and_exported()
-> TestResult {
    let s = setup("split")?;
    // dana.levi on Codex with her own subscription login: its cost is an estimate, not a bill.
    let mut sub = enterplace_core::audit::record(&Entry {
        id: "01SUB0000000000000000000004",
        person: Some("dana.levi"),
        team: Some("search"),
        method: "POST",
        path: "/v1/messages",
        model: Some("claude-sonnet-4-5"),
        allowed: true,
        rule: Some("everyone-else"),
        provider: "anthropic",
        ..Entry::default()
    });
    sub.insert("user_agent".into(), "codex_cli_rs/0.46.0".into());
    sub.insert("auth".into(), "passthrough".into());
    s.log.append_record(&sub)?;
    s.log.append_record(&object(json!({"event": "usage", "id": "01SUB0000000000000000000004", "provider": "anthropic", "model": "claude-sonnet-4-5", "status": 200, "input_tokens": 100, "output_tokens": 10, "cost_usd": 0.5, "charged_usd": 0.0, "latency_ms": 900})))?;
    // A coding agent with no person token: unnamed, shown as a problem with its fix.
    let mut nobody = enterplace_core::audit::record(&Entry {
        id: "01UNK0000000000000000000005",
        person: Some("unknown"),
        team: Some("unknown"),
        method: "POST",
        path: "/v1/messages",
        model: Some("claude-sonnet-4-5"),
        allowed: true,
        rule: Some("everyone-else"),
        provider: "anthropic",
        ..Entry::default()
    });
    nobody.insert("user_agent".into(), "claude-cli/2.0.1".into());
    s.log.append_record(&nobody)?;
    s.log.flush();
    let cookie = sign_in(&s.app, NOA).await?;

    let (status, page) = analytics(&s.app, "?by=person&then=agent,model", &cookie).await?;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["then"], "agent,model");
    assert_eq!(page["then_label"], "Coding agent and model", "{page}");
    let ranking = page["ranking"].as_array().ok_or("no ranking")?;
    let dana = ranking
        .iter()
        .find(|r| r["value"] == "dana.levi")
        .ok_or("no dana.levi")?;
    assert_eq!(dana["usd"], "$0.51", "{dana}");
    assert_eq!(dana["estimated"], "~$0.50", "{dana}");
    let parts = dana["parts"].as_array().ok_or("no parts")?;
    assert_eq!(
        parts[0]["values"],
        json!(["codex", "claude-sonnet-4-5"]),
        "{dana}"
    );
    assert_eq!(parts[0]["estimated"], "~$0.50");
    assert_eq!(parts[1]["values"], json!(["claude-code", "gpt-4o-mini"]));
    assert_eq!(
        parts[1]["requests"], "2",
        "the allowed and the refused request"
    );
    assert_eq!(parts[1]["estimated"], Value::Null, "billed at API prices");
    let unnamed = ranking
        .iter()
        .find(|r| r["value"] == "unknown")
        .ok_or("no unnamed row")?;
    assert_eq!(unnamed["unnamed"], true, "{unnamed}");
    assert_eq!(dana["unnamed"], false);
    // The cost figure says how much of it is an estimate.
    assert_eq!(
        page["stats"][1]["label"], "cost, ~$0.50 of it estimated",
        "{page}"
    );

    // The same view as a link, and as a prompt that lets an agent read it from the admin API with a key the human
    // sets.
    assert_eq!(
        page["link"], "#/usage?by=person&then=agent%2Cmodel&window=7d",
        "{page}"
    );
    let agent = page["agent"].as_str().ok_or("no agent prompt")?;
    assert!(
        agent.contains("/admin/usage?group_by=person&then=agent,model&from="),
        "{agent}"
    );
    assert!(
        agent.contains("$ENTERPLACE_KEY") && !agent.contains(NOA),
        "{agent}"
    );

    // The breakdown in view as CSV, plain numbers, one line per part, in the columns of /admin/usage.
    let (status, _, csv) = send(
        &s.app,
        get(
            "/console/api/analytics?by=person&then=agent,model&format=csv",
            &cookie,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        csv.lines().next(),
        Some(
            "person,agent,model,requests,refused,errors,input_tokens,output_tokens,total_tokens,spend_usd,latency_p50_ms,latency_p95_ms,estimated_usd"
        ),
        "{csv}"
    );
    assert!(
        csv.lines().any(|l| l
            == "\"dana.levi\",\"codex\",\"claude-sonnet-4-5\",1,0,0,100,10,110,0.5,900,900,0.5"),
        "{csv}"
    );

    // This month so far, as a window of its own, so a team's month reads next to its budget.
    let (_, month) = analytics(&s.app, "?by=team&window=month", &cookie).await?;
    assert_eq!(month["window"], "month", "{month}");
    assert!(
        month["lead"]
            .as_str()
            .is_some_and(|l| l.starts_with("This month so far, from the 1st (UTC).")),
        "{month}"
    );
    // One bar a day from the 1st to today, and none for tomorrow.
    let today = &enterplace_core::audit::timestamp()[..10];
    let points = month["chart"]["points"].as_array().ok_or("no chart")?;
    assert_eq!(
        points
            .first()
            .and_then(|p| p["at"].as_str())
            .and_then(|a| a.get(8..10)),
        Some("01"),
        "{month}"
    );
    assert_eq!(
        points.last().and_then(|p| p["at"].as_str()),
        Some(today),
        "{month}"
    );
    // A split by the dimension already ranked is not a split.
    let (status, page) = analytics(&s.app, "?by=person&then=person", &cookie).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{page}");
    Ok(())
}
