//! Devices as the Cloudflare app's tests check it (cloud/tests/test_devices.py): enrolment tokens shown once and
//! revocable, the device profile, reports, drift and coverage, plus what the self-hosted port adds (team scope,
//! expiry, the admin API, the direct state merged with audit traffic) and the license gate. Against a real Postgres.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::enterprise::testing::*;

struct Reply {
    status: StatusCode,
    body: Value,
    text: String,
}

/// A request as an admin API client sends it: a bearer token, JSON, no cookie, no origin.
async fn call(
    app: &Router,
    method: &str,
    path: &str,
    token: &str,
    body: Option<Value>,
) -> Result<Reply, Error> {
    agent(app, method, path, token, "", body).await
}

/// A request as the device agent sends it: the enrolment token as bearer and the person's Gantry key (from `gantry
/// login`) in x-gantry-key, when there is one.
async fn agent(
    app: &Router,
    method: &str,
    path: &str,
    token: &str,
    person_key: &str,
    body: Option<Value>,
) -> Result<Reply, Error> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, HOST)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json");
    if !person_key.is_empty() {
        request = request.header("x-gantry-key", person_key);
    }
    let body = body.map_or_else(Body::empty, |b| Body::from(b.to_string()));
    let response = app.clone().oneshot(request.body(body)?).await?;
    let status = response.status();
    let bytes = response.into_body().collect().await?.to_bytes();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    Ok(Reply {
        status,
        body: serde_json::from_str(&text).unwrap_or(Value::Null),
        text,
    })
}

fn token_in(page: &str) -> Option<String> {
    let rest = page.split("gantry_dev_").nth(1)?;
    let hex: String = rest.chars().take_while(char::is_ascii_hexdigit).collect();
    (hex.len() == 64).then(|| format!("gantry_dev_{hex}"))
}

fn admin_records(gw: &Gateway) -> Result<Vec<Value>, Error> {
    let log = std::fs::read_to_string(&gw.audit)?;
    Ok(log
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|r| r["event"] == "admin")
        .collect())
}

fn report(email: &str, host: &str, tools: Value) -> Value {
    json!({
        "device_id": format!("{host}:{email}"),
        "hostname": host,
        "os_user": "noa",
        "email": email,
        "agent_version": "0.1.0",
        "tools": tools,
    })
}

#[tokio::test]
async fn enrol_profile_report_and_coverage() -> Result<(), Error> {
    let Some(url) = database("devices").await? else {
        return Ok(());
    };
    let gw = gateway("devices", &url, &licensed(&["devices"]))?;
    let mut owner = Browser::admin(&gw.app).await?;

    // Without a profile, devices are sent to the address they enrolled at, managing Claude Code and Codex.
    let made = owner
        .go(
            &gw.app,
            "POST",
            "/console/devices",
            &[
                ("action", "token_create"),
                ("label", "jamf-test"),
                ("team", ""),
                ("days", "30"),
            ],
        )
        .await?;
    assert_eq!(made.status, StatusCode::OK, "{}", made.text);
    let token = token_in(&made.text).ok_or(format!("no token shown: {}", made.text))?;
    let page = owner.go(&gw.app, "GET", "/console/devices", &[]).await?;
    assert!(page.text.contains("jamf-test") && !page.text.contains(&token));

    let wrong = call(&gw.app, "GET", "/device/profile", "gantry_dev_nope", None).await?;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED, "{}", wrong.text);
    assert!(wrong.text.contains("GANTRY_DEVICE_TOKEN"), "{}", wrong.text);
    let first = call(&gw.app, "GET", "/device/profile", &token, None).await?;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text);
    assert_eq!(first.body["gateway_url"], format!("http://{HOST}"));
    assert_eq!(first.body["tools"], json!(["claude-code", "codex"]));

    // A profile for everyone, and one for the platform team (noa's, in the keys file).
    let refused = owner
        .go(
            &gw.app,
            "POST",
            "/console/devices",
            &[
                ("action", "profile_save"),
                ("team", ""),
                ("gateway_url", "http://evil.example"),
                ("tools", "codex"),
            ],
        )
        .await?;
    assert!(refused.text.contains("https address"), "{}", refused.text);
    for (team, gateway, tools) in [
        ("", "https://gw.example.com/", "claude-code, codex"),
        ("platform", "https://platform.example.com", "codex"),
    ] {
        let saved = owner
            .go(
                &gw.app,
                "POST",
                "/console/devices",
                &[
                    ("action", "profile_save"),
                    ("team", team),
                    ("gateway_url", gateway),
                    ("tools", tools),
                ],
            )
            .await?;
        assert!(saved.text.contains("saved"), "{}", saved.text);
    }
    let anyone = call(
        &gw.app,
        "GET",
        "/device/profile?person=someone",
        &token,
        None,
    )
    .await?;
    assert_eq!(
        (&anyone.body["gateway_url"], &anyone.body["tools"]),
        (
            &json!("https://gw.example.com"),
            &json!(["claude-code", "codex"])
        )
    );
    // The device's person is noa, of the platform team: their team's profile.
    let noa = agent(&gw.app, "GET", "/device/profile", &token, ADMIN_KEY, None).await?;
    assert_eq!(
        noa.body["gateway_url"], "https://platform.example.com",
        "{}",
        noa.text
    );
    assert_eq!(noa.body["team"], "platform");
    assert_eq!(noa.body["person"], "noa");

    // Reports: Claude Code through Gantry, Codex straight to OpenAI, one drift.
    let sent = agent(
        &gw.app,
        "POST",
        "/device/report",
        &token,
        ADMIN_KEY,
        Some(report(
            "noa",
            "mbp",
            json!([
                {"tool": "claude-code", "state": "gantry", "installed": true, "configured": true, "drift": true},
                {"tool": "codex", "state": "direct", "installed": true, "configured": false, "drift": false, "endpoints": ["https://api.openai.com/v1"]},
                {"tool": "cursor", "state": "not_installed", "installed": false, "configured": false, "drift": false},
                {"tool": "made-up", "state": "direct", "installed": true}
            ]),
        )),
    )
    .await?;
    assert_eq!(sent.status, StatusCode::OK, "{}", sent.text);
    assert_eq!(sent.body["person"], "noa");
    let bad = call(
        &gw.app,
        "POST",
        "/device/report",
        &token,
        Some(json!({"hostname": 3})),
    )
    .await?;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert!(bad.text.contains("device_id"), "{}", bad.text);

    // Traffic from noa's Claude Code reached Gantry.
    gw.log.append(&gantry_core::audit::Entry {
        id: "D1",
        person: Some("noa"),
        team: Some("platform"),
        user_agent: Some("claude-cli/2.0.14 (external, cli)"),
        allowed: true,
        method: "POST",
        path: "/v1/messages",
        ..Default::default()
    })?;

    // The page reads the store's request index, which the record reaches with the copier's next pass.
    let mut tries = 0;
    let (page, row) = loop {
        let page = owner.go(&gw.app, "GET", "/console/devices", &[]).await?;
        let row = page
            .text
            .split("t-mono-lg\">noa</span>")
            .nth(1)
            .and_then(|r| r.split("g-row\"").next())
            .unwrap_or_default()
            .to_string();
        tries += 1;
        if row.contains("claude-code") || tries == 100 {
            break (page, row);
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    };
    assert!(row.contains("claude-code"), "tools seen: {row}");
    assert!(row.contains("1 device"), "devices: {row}");
    assert!(row.contains("codex on mbp"), "going direct: {row}");
    assert!(page.text.contains("Drift"), "{}", page.text);

    // The download `gantry audit coverage --devices` reads, by session and by admin key.
    let listed = call(
        &gw.app,
        "GET",
        "/console/devices/devices.json",
        ADMIN_KEY,
        None,
    )
    .await?;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.text);
    let device = &listed.body[0];
    assert_eq!(device["person"], "noa");
    assert_eq!(device["team"], "platform");
    let codex = device["tools"]
        .as_array()
        .and_then(|a| a.iter().find(|t| t["tool"] == "codex"))
        .cloned()
        .unwrap_or_default();
    assert_eq!(codex["state"], "direct");
    assert_eq!(codex["endpoints"], json!(["https://api.openai.com/v1"]));
    assert!(!listed.text.contains("made-up"));
    let devices: Vec<gantry_core::coverage::Device> = serde_json::from_str(&listed.text)?;
    assert_eq!(devices.len(), 1);
    let by_session = owner
        .go(&gw.app, "GET", "/console/devices/devices.json", &[])
        .await?;
    assert_eq!(by_session.status, StatusCode::OK);

    // Revoked: refused.
    let id = page
        .text
        .split(r#"name="id" value=""#)
        .nth(1)
        .and_then(|r| r.split('"').next())
        .ok_or("no revoke button")?
        .to_string();
    owner
        .go(
            &gw.app,
            "POST",
            "/console/devices",
            &[("action", "token_revoke"), ("id", &id)],
        )
        .await?;
    let revoked = call(&gw.app, "GET", "/device/profile", &token, None).await?;
    assert_eq!(revoked.status, StatusCode::UNAUTHORIZED);

    let records = admin_records(&gw)?;
    for action in [
        "device_token_created",
        "device_profile_saved",
        "device_token_revoked",
    ] {
        assert!(
            records.iter().any(|r| r["action"] == action),
            "{action} not recorded"
        );
    }
    // The token itself is never on record.
    assert!(!std::fs::read_to_string(&gw.audit)?.contains(&token));
    Ok(())
}

#[tokio::test]
async fn a_report_is_from_the_person_of_its_key_and_a_device_stays_bound() -> Result<(), Error> {
    let Some(url) = database("devices_bound").await? else {
        return Ok(());
    };
    let gw = gateway("devices_bound", &url, &licensed(&["devices"]))?;
    const ANA_KEY: &str = "gantry_ana_0123456789abcdef0123456789abcdef";
    gantry_core::keyfile::add_entry("ana", "web", ANA_KEY, false, &gw.keys)?;
    let mut tokens = Vec::new();
    for team in ["", "web"] {
        let made = call(
            &gw.app,
            "POST",
            "/console/devices/tokens",
            ADMIN_KEY,
            Some(json!({"label": format!("t{team}"), "team": team})),
        )
        .await?;
        tokens.push(made.body["token"].as_str().unwrap_or_default().to_string());
    }
    let (all, web) = (&tokens[0], &tokens[1]);
    let send = |token: &str, key: &str| {
        let (app, token, key) = (gw.app.clone(), token.to_string(), key.to_string());
        async move {
            agent(
                &app,
                "POST",
                "/device/report",
                &token,
                &key,
                Some(report("ana", "mbp", json!([]))),
            )
            .await
        }
    };

    // The person comes from a Gantry key, never from the report.
    let none = send(all, "").await?;
    assert_eq!(none.status, StatusCode::UNAUTHORIZED, "{}", none.text);
    assert!(none.text.contains("person_key_required"), "{}", none.text);
    let bogus = send(all, "gantry_not_a_key").await?;
    assert!(bogus.text.contains("invalid_person_key"), "{}", bogus.text);
    let first = send(all, ADMIN_KEY).await?;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text);
    assert_eq!(
        first.body["person"], "noa",
        "the report said ana: {}",
        first.text
    );

    // Bound to noa and the every-team scope: another person or scope is refused and kept.
    let other_person = send(all, ANA_KEY).await?;
    assert_eq!(
        other_person.status,
        StatusCode::FORBIDDEN,
        "{}",
        other_person.text
    );
    assert!(
        other_person.text.contains("device_bound"),
        "{}",
        other_person.text
    );
    let other_scope = send(web, ADMIN_KEY).await?;
    assert_eq!(
        other_scope.status,
        StatusCode::FORBIDDEN,
        "{}",
        other_scope.text
    );
    let again = send(all, ADMIN_KEY).await?;
    assert_eq!(again.status, StatusCode::OK, "{}", again.text);
    let listed = call(
        &gw.app,
        "GET",
        "/console/devices/devices.json",
        ADMIN_KEY,
        None,
    )
    .await?;
    assert_eq!(listed.body[0]["person"], "noa", "{}", listed.text);
    let mut owner = Browser::admin(&gw.app).await?;
    let page = owner.go(&gw.app, "GET", "/console/devices", &[]).await?;
    assert!(page.text.contains("bound to person noa"), "{}", page.text);
    assert!(
        page.text.contains("bound to the token scope every team"),
        "{}",
        page.text
    );

    // Removed by an admin, the device binds to whoever reports next.
    let removed = call(
        &gw.app,
        "DELETE",
        "/console/devices/devices/mbp:ana",
        ADMIN_KEY,
        None,
    )
    .await?;
    assert_eq!(removed.status, StatusCode::OK, "{}", removed.text);
    let ana = send(web, ANA_KEY).await?;
    assert_eq!(ana.status, StatusCode::OK, "{}", ana.text);
    assert_eq!(
        (&ana.body["person"], &ana.body["team"]),
        (&json!("ana"), &json!("web"))
    );
    assert!(
        admin_records(&gw)?
            .iter()
            .any(|r| r["action"] == "device_removed")
    );
    Ok(())
}

#[tokio::test]
async fn admin_api_issues_team_tokens_that_expire_and_revoke() -> Result<(), Error> {
    let Some(url) = database("devices_api").await? else {
        return Ok(());
    };
    let gw = gateway("devices_api", &url, &licensed(&["devices"]))?;
    let none = call(
        &gw.app,
        "GET",
        "/console/devices/tokens",
        "gantry_wrong",
        None,
    )
    .await?;
    assert_eq!(none.status, StatusCode::UNAUTHORIZED, "{}", none.text);

    let made = call(
        &gw.app,
        "POST",
        "/console/devices/tokens",
        ADMIN_KEY,
        Some(json!({"label": "intune-web", "team": "web", "days": 7})),
    )
    .await?;
    assert_eq!(made.status, StatusCode::CREATED, "{}", made.text);
    let token = made.body["token"].as_str().unwrap_or_default().to_string();
    let id = made.body["id"].as_str().unwrap_or_default().to_string();
    assert!(token.starts_with("gantry_dev_") && !made.body["expires_at"].is_null());
    let too_long = call(
        &gw.app,
        "POST",
        "/console/devices/tokens",
        ADMIN_KEY,
        Some(json!({"label": "x", "days": 4000})),
    )
    .await?;
    assert_eq!(
        too_long.status,
        StatusCode::BAD_REQUEST,
        "{}",
        too_long.text
    );

    // A team token gives its team's view whoever the device says it is.
    let profile = agent(&gw.app, "GET", "/device/profile", &token, ADMIN_KEY, None).await?;
    assert_eq!(profile.body["team"], "web", "{}", profile.text);
    let sent = agent(
        &gw.app,
        "POST",
        "/device/report",
        &token,
        ADMIN_KEY,
        Some(report("noa", "pc", json!([]))),
    )
    .await?;
    assert_eq!(sent.body["team"], "web", "{}", sent.text);

    let listed = call(&gw.app, "GET", "/console/devices/tokens", ADMIN_KEY, None).await?;
    let entry = listed.body["tokens"]
        .as_array()
        .and_then(|a| a.iter().find(|t| t["id"] == id.as_str()))
        .cloned()
        .unwrap_or_default();
    assert_eq!(entry["team"], "web", "{}", listed.text);
    assert_eq!(entry["status"], "active");
    assert!(!listed.text.contains(&token));

    // Expired: refused, and says so.
    let client = {
        use gantry_server::store::tokio_postgres;
        let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
        tokio::spawn(connection);
        client
    };
    client
        .execute(
            "UPDATE enterprise_device_tokens SET expires_at = now() - interval '1 day' WHERE id = $1",
            &[&id],
        )
        .await?;
    let expired = call(&gw.app, "GET", "/device/profile", &token, None).await?;
    assert_eq!(expired.status, StatusCode::UNAUTHORIZED);
    assert!(expired.text.contains("token_expired"), "{}", expired.text);

    let gone = call(
        &gw.app,
        "DELETE",
        &format!("/console/devices/tokens/{id}"),
        ADMIN_KEY,
        None,
    )
    .await?;
    assert_eq!(gone.status, StatusCode::OK, "{}", gone.text);
    let listed = call(&gw.app, "GET", "/console/devices/tokens", ADMIN_KEY, None).await?;
    assert!(listed.text.contains("revoked"), "{}", listed.text);
    let records = admin_records(&gw)?;
    assert!(
        records
            .iter()
            .any(|r| r["action"] == "device_token_created" && r["via"] == "console")
    );
    assert!(
        records
            .iter()
            .any(|r| r["action"] == "device_token_revoked")
    );
    Ok(())
}

/// The real agent against the real routes, over HTTP: enrol, apply, report.
#[tokio::test]
async fn the_agent_enrols_applies_and_reports() -> Result<(), Error> {
    let Some(url) = database("devices_agent").await? else {
        return Ok(());
    };
    let gw = gateway("devices_agent", &url, &licensed(&["devices"]))?;
    let made = call(
        &gw.app,
        "POST",
        "/console/devices/tokens",
        ADMIN_KEY,
        Some(json!({"label": "by-hand"})),
    )
    .await?;
    let token = made.body["token"].as_str().unwrap_or_default().to_string();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let app = gw.app.clone();
    tokio::spawn(async move { axum::serve(listener, app).await });

    let home = gw.dir.join("home");
    std::fs::create_dir_all(home.join(".claude"))?;
    std::fs::create_dir_all(home.join(".gemini"))?;
    std::fs::write(
        home.join(".gemini/settings.json"),
        r#"{"security":{"auth":{"selectedType":"gemini-api-key"}}}"#,
    )?;
    std::fs::create_dir_all(home.join(".config/gantry"))?;
    std::fs::write(
        home.join(".config/gantry/credentials"),
        format!("name=noa\nkey={ADMIN_KEY}\n"),
    )?;
    let opts = crate::device::Options {
        control_plane: format!("http://{address}"),
        token,
        interval: std::time::Duration::from_secs(1),
        dry_run: false,
        once: true,
        home: Some(home.clone()),
    };
    tokio::task::spawn_blocking(move || crate::device::run(opts)).await??;
    let settings = std::fs::read_to_string(home.join(".claude/settings.json"))?;
    assert!(
        settings.contains(&format!("http://{address}")),
        "{settings}"
    );

    let listed = call(
        &gw.app,
        "GET",
        "/console/devices/devices.json",
        ADMIN_KEY,
        None,
    )
    .await?;
    let tools = listed.body[0]["tools"].clone();
    let state = |t: &str| {
        tools
            .as_array()
            .and_then(|a| a.iter().find(|x| x["tool"] == t))
            .map(|x| x["state"].clone())
            .unwrap_or_default()
    };
    assert_eq!(listed.body[0]["person"], "noa", "{}", listed.text);
    assert_eq!(state("claude-code"), "gantry", "{}", listed.text);
    assert_eq!(state("gemini-cli"), "direct", "{}", listed.text);
    Ok(())
}

#[tokio::test]
async fn without_the_feature_devices_answer_license_required() -> Result<(), Error> {
    let Some(url) = database("devices_locked").await? else {
        return Ok(());
    };
    let others = ["members", "scim", "siem", "retention", "alerts"];
    for (n, status) in [unlicensed(), licensed(&others)].iter().enumerate() {
        let test = format!("devices_locked{n}");
        let Some(url) = database(&test).await? else {
            return Ok(());
        };
        let gw = gateway(&test, &url, status)?;
        let mut owner = Browser::admin(&gw.app).await?;
        let page = owner.go(&gw.app, "GET", "/console/devices", &[]).await?;
        assert_eq!(page.status, StatusCode::FORBIDDEN);
        assert!(page.text.contains("license_required"), "{}", page.text);
        let audit = owner.go(&gw.app, "GET", "/console/audit", &[]).await?;
        assert!(
            !audit.text.contains("/console/devices"),
            "nav offers Devices"
        );
        for (method, path) in [("GET", "/device/profile"), ("POST", "/device/report")] {
            let answer = call(&gw.app, method, path, "gantry_dev_x", Some(json!({}))).await?;
            assert_eq!(answer.status, StatusCode::FORBIDDEN, "{path}");
            assert_eq!(
                answer.body["error"]["code"], "license_required",
                "{}",
                answer.text
            );
        }
        let client = {
            use gantry_server::store::tokio_postgres;
            let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
            tokio::spawn(connection);
            client
        };
        let tables: i64 = client
            .query_one(
                "SELECT count(*) FROM information_schema.tables WHERE table_name LIKE 'enterprise_device%'",
                &[],
            )
            .await?
            .try_get(0)?;
        assert_eq!(tables, 0);
    }
    let _ = url;
    Ok(())
}
