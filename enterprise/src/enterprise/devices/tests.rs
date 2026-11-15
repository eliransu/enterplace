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

#[tokio::test]
async fn mcp_servers_are_stored_shown_and_approved_or_blocked() -> Result<(), Error> {
    let Some(url) = database("devices_mcp").await? else {
        return Ok(());
    };
    let gw = gateway("devices_mcp", &url, &licensed(&["devices"]))?;
    let made = call(
        &gw.app,
        "POST",
        "/console/devices/tokens",
        ADMIN_KEY,
        Some(json!({"label": "mcp", "team": ""})),
    )
    .await?;
    let token = made.body["token"].as_str().ok_or("no token")?.to_string();
    // The agent's report as guards2's agent sends it: its OS and each configured MCP server. A target an old agent
    // left a token in is stored without it; a row for a file that could not be read is not a server.
    let mut sent = report("noa", "nuc", json!([]));
    sent["os"] = json!("linux");
    sent["mcp"] = json!([
        {"tool": "cursor", "file": "/home/noa/.cursor/mcp.json", "server": "github", "transport": "http", "target": "https://u:p@api.githubcopilot.com/mcp?token=abc", "via_gantry": false},
        {"tool": "claude-code", "file": "/home/noa/.claude.json", "server": "gantry", "transport": "http", "target": "https://gw.example.com/mcp", "via_gantry": true},
        {"tool": "vscode", "file": "/home/noa/.config/Code/User/mcp.json", "error": "the file is not JSON"}
    ]);
    let stored = agent(
        &gw.app,
        "POST",
        "/device/report",
        &token,
        ADMIN_KEY,
        Some(sent),
    )
    .await?;
    assert_eq!(stored.status, StatusCode::OK, "{}", stored.text);

    let listed = call(
        &gw.app,
        "GET",
        "/console/devices/devices.json",
        ADMIN_KEY,
        None,
    )
    .await?;
    let device = &listed.body[0];
    assert_eq!(device["os"], "linux");
    assert_eq!(
        device["mcp"].as_array().map(Vec::len),
        Some(2),
        "{}",
        listed.text
    );
    assert!(!listed.text.contains("token=abc") && !listed.text.contains("u:p@"));
    let github = device["mcp"]
        .as_array()
        .and_then(|a| a.iter().find(|m| m["server"] == "github"))
        .cloned()
        .unwrap_or_default();
    assert_eq!(github["target"], "https://api.githubcopilot.com/mcp");
    assert_eq!(
        (&github["via_gantry"], &github["decision"]),
        (&json!(false), &json!("pending"))
    );
    // The download `gantry audit coverage --devices` reads takes the new fields.
    let _: Vec<gantry_core::coverage::Device> = serde_json::from_str(&listed.text)?;

    // An admin blocks GitHub's server by API and approves Gantry's on the page; a viewer cannot decide.
    let blocked = call(
        &gw.app,
        "POST",
        "/console/devices/mcp",
        ADMIN_KEY,
        Some(json!({"transport": "http", "target": "https://api.githubcopilot.com/mcp", "decision": "blocked"})),
    )
    .await?;
    assert_eq!(blocked.status, StatusCode::OK, "{}", blocked.text);
    let wrong = call(
        &gw.app,
        "POST",
        "/console/devices/mcp",
        ADMIN_KEY,
        Some(json!({"transport": "http", "target": "x", "decision": "maybe"})),
    )
    .await?;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST, "{}", wrong.text);
    let mut owner = Browser::admin(&gw.app).await?;
    let page = owner.go(&gw.app, "GET", "/console/devices", &[]).await?;
    assert!(page.text.contains("MCP servers"), "{}", page.text);
    assert!(page.text.contains("https://api.githubcopilot.com/mcp"));
    assert!(page.text.contains("not via Gantry") && page.text.contains("via Gantry"));
    let approved = owner
        .go(
            &gw.app,
            "POST",
            "/console/devices",
            &[
                ("action", "mcp_decide"),
                ("transport", "http"),
                ("target", "https://gw.example.com/mcp"),
                ("decision", "approved"),
            ],
        )
        .await?;
    assert!(approved.text.contains("approved"), "{}", approved.text);

    // The profile tells the agent which servers are allowed and which are blocked.
    let profile = agent(&gw.app, "GET", "/device/profile", &token, ADMIN_KEY, None).await?;
    assert_eq!(
        profile.body["mcp"],
        json!({"approved": [{"transport": "http", "target": "https://gw.example.com/mcp"}],
               "blocked": [{"transport": "http", "target": "https://api.githubcopilot.com/mcp"}],
               "via_gateway": false, "enforcement": "report"}),
        "{}",
        profile.text
    );
    let servers = call(&gw.app, "GET", "/console/devices/mcp", ADMIN_KEY, None).await?;
    let decisions: Vec<(Value, Value)> = servers.body["servers"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|m| (m["target"].clone(), m["decision"].clone()))
        .collect();
    assert_eq!(
        decisions,
        [
            (json!("https://api.githubcopilot.com/mcp"), json!("blocked")),
            (json!("https://gw.example.com/mcp"), json!("approved")),
        ]
    );
    // Taken back to pending, it is no longer in the profile.
    call(
        &gw.app,
        "POST",
        "/console/devices/mcp",
        ADMIN_KEY,
        Some(json!({"transport": "http", "target": "https://gw.example.com/mcp", "decision": "pending"})),
    )
    .await?;
    let profile = agent(&gw.app, "GET", "/device/profile", &token, ADMIN_KEY, None).await?;
    assert_eq!(profile.body["mcp"]["approved"], json!([]));

    let decided: Vec<Value> = admin_records(&gw)?
        .into_iter()
        .filter(|r| r["action"] == "device_mcp_decided")
        .collect();
    assert_eq!(decided.len(), 4, "{decided:?}");
    assert_eq!(decided[1]["code"], "invalid_request");
    Ok(())
}

/// The IDs of the enrolment tokens `key`'s holder is shown that still work.
/// What this slice adds: a profile names more tools, denied apps and MCP through the gateway; the agent enforces a
/// blocked MCP server in a tool's file and reports apps; the page and devices.json show each per person.
#[tokio::test]
async fn a_profile_denies_apps_and_the_agent_enforces_blocked_mcp_servers() -> Result<(), Error> {
    let Some(url) = database("devices_enforce").await? else {
        return Ok(());
    };
    let gw = gateway("devices_enforce", &url, &licensed(&["devices"]))?;
    let mut owner = Browser::admin(&gw.app).await?;
    let made = call(
        &gw.app,
        "POST",
        "/console/devices/tokens",
        ADMIN_KEY,
        Some(json!({"label": "enforce"})),
    )
    .await?;
    let token = made.body["token"].as_str().ok_or("no token")?.to_string();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let app = gw.app.clone();
    tokio::spawn(async move { axum::serve(listener, app).await });
    let gateway_url = format!("http://localhost:{}", address.port());

    // A profile is refused for a tool no file configures (with the reason), an unknown app, or one on both lists.
    let save = |tools: &'static str,
                denied: &'static str,
                allowed: &'static str,
                via: &'static str,
                enforcement: &'static str| {
        let gateway_url = gateway_url.clone();
        let app = gw.app.clone();
        let mut owner = Browser {
            cookie: owner.cookie.clone(),
        };
        async move {
            owner
                .go(
                    &app,
                    "POST",
                    "/console/devices",
                    &[
                        ("action", "profile_save"),
                        ("team", ""),
                        ("gateway_url", &gateway_url),
                        ("tools", tools),
                        ("apps_denied", denied),
                        ("apps_allowed", allowed),
                        ("mcp_via_gateway", via),
                        ("mcp_enforcement", enforcement),
                    ],
                )
                .await
        }
    };
    for (tools, denied, allowed, via, enforcement, why) in [
        ("cursor", "", "", "no", "", "Cursor Settings"),
        (
            "codex",
            "notepad",
            "",
            "no",
            "",
            "is not an app the agent looks for",
        ),
        (
            "codex",
            "chatgpt",
            "chatgpt",
            "no",
            "",
            "both allowed and denied",
        ),
        ("codex", "", "", "maybe", "", "is yes or no"),
        ("codex", "", "", "no", "delete", "is report or remove"),
    ] {
        let refused = save(tools, denied, allowed, via, enforcement).await?;
        assert!(refused.text.contains(why), "{why}: {}", refused.text);
    }
    let saved = save(
        "claude-code, gemini-cli, aider",
        "chatgpt, ollama",
        "",
        "yes",
        "remove",
    )
    .await?;
    assert!(saved.text.contains("saved"), "{}", saved.text);
    assert!(
        saved.text.contains("denies chatgpt, ollama"),
        "{}",
        saved.text
    );
    assert!(
        saved
            .text
            .contains("approved MCP servers go through Gantry"),
        "{}",
        saved.text
    );
    assert!(
        saved.text.contains("removes blocked MCP servers"),
        "{}",
        saved.text
    );

    // An admin blocks one server and approves another before any device has them.
    for (transport, target, decision) in [
        ("stdio", "shady-mcp", "blocked"),
        ("http", "https://docs.example.com/mcp", "approved"),
    ] {
        let decided = call(
            &gw.app,
            "POST",
            "/console/devices/mcp",
            ADMIN_KEY,
            Some(json!({"transport": transport, "target": target, "decision": decision})),
        )
        .await?;
        assert_eq!(decided.status, StatusCode::OK, "{}", decided.text);
    }
    let profile = call(&gw.app, "GET", "/device/profile", &token, None).await?;
    assert_eq!(
        profile.body["tools"],
        json!(["claude-code", "gemini-cli", "aider"])
    );
    assert_eq!(
        profile.body["apps"],
        json!({"allowed": [], "denied": ["chatgpt", "ollama"]})
    );
    assert_eq!(profile.body["mcp"]["via_gateway"], true);
    assert_eq!(profile.body["mcp"]["enforcement"], "remove");

    // The agent on a machine with those tools, a denied app, a blocked server and an approved one.
    let home = gw.dir.join("home");
    let put = |file: &str, text: &str| -> Result<(), Error> {
        let path = home.join(file);
        std::fs::create_dir_all(path.parent().ok_or("no parent")?)?;
        Ok(std::fs::write(path, text)?)
    };
    put(".claude/settings.json", "{}")?;
    put(
        ".gemini/settings.json",
        r#"{"security":{"auth":{"selectedType":"gemini-api-key"}}}"#,
    )?;
    put(".aider.conf.yml", "openai-api-key: sk-x\n")?;
    put(".ollama/history", "")?;
    let cursor = r#"{"mcpServers":{"shady":{"command":"/opt/shady-mcp","env":{"T":"s3cret"}},"docs":{"url":"https://docs.example.com/mcp","headers":{"Authorization":"Bearer up"}},"mine":{"command":"mine"}}}"#;
    put(".cursor/mcp.json", cursor)?;
    put(
        ".config/gantry/credentials",
        &format!("name=noa\nkey={ADMIN_KEY}\n"),
    )?;
    let opts = crate::device::Options {
        control_plane: gateway_url.clone(),
        token,
        interval: std::time::Duration::from_secs(1),
        dry_run: false,
        once: true,
        home: Some(home.clone()),
    };
    tokio::task::spawn_blocking(move || crate::device::run(opts)).await??;

    // Each managed tool's documented file holds the gateway.
    assert!(std::fs::read_to_string(home.join(".claude/settings.json"))?.contains(&gateway_url));
    assert_eq!(
        std::fs::read_to_string(home.join(".gemini/.env"))?,
        format!("GOOGLE_GEMINI_BASE_URL={gateway_url}\n")
    );
    assert!(
        std::fs::read_to_string(home.join(".aider.conf.yml"))?
            .contains(&format!("openai-api-base: {gateway_url}/v1"))
    );
    // The blocked server is gone from Cursor's file, the approved one goes through the gateway without its own
    // credential, the undecided one stays, and the file as it was is kept.
    let now: Value =
        serde_json::from_str(&std::fs::read_to_string(home.join(".cursor/mcp.json"))?)?;
    assert_eq!(
        now["mcpServers"],
        json!({"docs": {"url": format!("{gateway_url}/mcp")}, "mine": {"command": "mine"}})
    );
    assert_eq!(
        std::fs::read_to_string(home.join(".cursor/mcp.json.gantry-backup"))?,
        cursor
    );

    let listed = call(
        &gw.app,
        "GET",
        "/console/devices/devices.json",
        ADMIN_KEY,
        None,
    )
    .await?;
    let device = &listed.body[0];
    let tool = |t: &str| {
        device["tools"]
            .as_array()
            .and_then(|a| a.iter().find(|x| x["tool"] == t))
            .cloned()
            .unwrap_or_default()
    };
    for t in ["claude-code", "gemini-cli", "aider"] {
        assert_eq!(tool(t)["state"], "gantry", "{t}: {}", listed.text);
    }
    assert_eq!(tool("cursor")["state"], "installed");
    assert!(
        tool("cursor")["note"]
            .as_str()
            .is_some_and(|n| n.contains("no documented file")),
        "{}",
        listed.text
    );
    assert!(
        device["apps"].as_array().is_some_and(
            |a| a.contains(&json!({"app": "ollama", "status": "denied", "running": false}))
        ),
        "{}",
        listed.text
    );
    assert!(!listed.text.contains("s3cret") && !listed.text.contains("Bearer up"));
    let devices: Vec<gantry_core::coverage::Device> = serde_json::from_str(&listed.text)?;
    let noa = gantry_core::coverage::people(&devices)
        .remove("noa")
        .unwrap_or_default();
    assert!(
        noa.gantry.contains("aider") && noa.blocked_mcp.is_empty(),
        "{noa:?}"
    );
    assert_eq!(noa.denied_apps.len(), 1, "{noa:?}");

    // A blocked server the agent could not take out (an older agent, or a file outside the home) and a denied app
    // a later report lists both show on the person's row; a made-up app is dropped.
    let mut sent = report(
        "noa",
        "mbp",
        json!([{"tool": "codex", "state": "direct", "installed": true}]),
    );
    sent["apps"] = json!([{"app": "chatgpt", "status": "denied", "running": true}, {"app": "notepad", "status": "denied"}]);
    sent["mcp"] = json!([{"tool": "claude-code", "file": "/Library/x/managed-mcp.json", "server": "shady", "transport": "stdio", "target": "shady-mcp", "via_gantry": false}]);
    sent["mcp_actions"] = json!([{"tool": "zed", "file": "/h/settings.json", "server": "other", "transport": "stdio", "target": "shady-mcp", "action": "removed"}, {"tool": "zed", "server": "x", "transport": "stdio", "target": "y", "action": "exploded"}]);
    let stored = agent(
        &gw.app,
        "POST",
        "/device/report",
        &profile_token(&gw).await?,
        ADMIN_KEY,
        Some(sent),
    )
    .await?;
    assert_eq!(stored.status, StatusCode::OK, "{}", stored.text);
    let page = owner.go(&gw.app, "GET", "/console/devices", &[]).await?;
    for shown in [
        "set to Gantry: aider, claude-code, gemini-cli",
        "installed, set by hand: cursor",
        "codex on mbp",
        "denied app",
        "chatgpt on mbp",
        "blocked MCP",
        "shady in claude-code on mbp",
        "MCP enforcement",
        "removed · shady (shady-mcp) in cursor",
        "rewritten · docs (https://docs.example.com/mcp) in cursor",
        "removed · other (shady-mcp) in zed",
        "cursor: Cursor keeps its OpenAI base URL override",
    ] {
        assert!(page.text.contains(shown), "{shown}: {}", page.text);
    }
    assert!(!page.text.contains("notepad") && !page.text.contains("exploded"));
    Ok(())
}

/// Another enrolment token of the same scope, for a report sent by hand.
async fn profile_token(gw: &Gateway) -> Result<String, Error> {
    let made = call(
        &gw.app,
        "POST",
        "/console/devices/tokens",
        ADMIN_KEY,
        Some(json!({"label": "by-hand"})),
    )
    .await?;
    Ok(made.body["token"].as_str().ok_or("no token")?.to_string())
}

async fn listed_ids(app: &Router, key: &str) -> Result<Vec<String>, Error> {
    let listed = call(app, "GET", "/console/devices/tokens", key, None).await?;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.text);
    Ok(listed.body["tokens"]
        .as_array()
        .map(|tokens| {
            tokens
                .iter()
                .filter(|t| t["status"] == "active")
                .filter_map(|t| t["id"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default())
}

#[tokio::test]
async fn an_admin_kept_to_an_organization_or_to_teams_reaches_only_its_own_enrolment_tokens()
-> Result<(), Error> {
    let Some(url) = database("devices_confined").await? else {
        return Ok(());
    };
    let policy = format!("{POLICY}{CONFINED}");
    let gw = gateway_policy(
        "devices_confined",
        &url,
        &licensed(&["devices"]),
        &[],
        &policy,
    )?;
    confined_admins(&gw)?;
    let app = &gw.app;
    let tokens = "/console/devices/tokens";
    let make = async |key: &str, body: Value| -> Result<Reply, Error> {
        call(app, "POST", tokens, key, Some(body)).await
    };
    let id = |reply: &Reply| reply.body["id"].as_str().unwrap_or_default().to_string();
    let revoke = async |key: &str, id: &str| -> Result<StatusCode, Error> {
        Ok(call(app, "DELETE", &format!("{tokens}/{id}"), key, None)
            .await?
            .status)
    };
    let pay = make(ADMIN_KEY, json!({ "label": "a", "team": "payments" })).await?;
    let web = make(ADMIN_KEY, json!({ "label": "b", "team": "web" })).await?;
    let every = make(ADMIN_KEY, json!({ "label": "c" })).await?;
    assert_eq!(every.status, StatusCode::CREATED, "{}", every.text);
    let (pay, web, every) = (id(&pay), id(&web), id(&every));

    // Kept to organization acme: a token it makes is acme's, and it reaches no token of the install or another.
    assert!(listed_ids(app, ACME_KEY).await?.is_empty());
    let acme = make(ACME_KEY, json!({ "label": "x", "team": "payments" })).await?;
    assert_eq!(acme.status, StatusCode::CREATED, "{}", acme.text);
    let acme = id(&acme);
    assert_eq!(listed_ids(app, ACME_KEY).await?, [acme.clone()]);
    for outside in [&pay, &every] {
        assert_eq!(revoke(ACME_KEY, outside).await?, StatusCode::NOT_FOUND);
    }
    let listed = call(app, "GET", tokens, ADMIN_KEY, None).await?;
    assert_eq!(listed.body["tokens"][3]["org"], "acme", "{}", listed.text);
    assert_eq!(listed.body["tokens"][0]["org"], "", "{}", listed.text);

    // Kept to team payments: that team's tokens alone. No team is every team, which is more than it reaches.
    assert_eq!(
        listed_ids(app, PAYMENTS_KEY).await?,
        [pay.clone(), acme.clone()]
    );
    for body in [
        json!({ "label": "x", "team": "web" }),
        json!({ "label": "x" }),
    ] {
        let refused = make(PAYMENTS_KEY, body).await?;
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "{}", refused.text);
        assert_eq!(
            refused.body["error"]["code"], "outside_role",
            "{}",
            refused.text
        );
        assert!(refused.text.contains("teams payments"), "{}", refused.text);
    }
    let own = make(PAYMENTS_KEY, json!({ "label": "x", "team": "payments" })).await?;
    assert_eq!(own.status, StatusCode::CREATED, "{}", own.text);
    for outside in [&web, &every] {
        assert_eq!(revoke(PAYMENTS_KEY, outside).await?, StatusCode::NOT_FOUND);
    }
    assert_eq!(revoke(PAYMENTS_KEY, &pay).await?, StatusCode::OK);
    assert_eq!(revoke(ACME_KEY, &acme).await?, StatusCode::OK);

    // What neither could reach still works.
    assert_eq!(listed_ids(app, ADMIN_KEY).await?, [web, every, id(&own)]);
    assert!(
        admin_records(&gw)?
            .iter()
            .any(|r| r["action"] == "device_token_created" && r["code"] == "outside_role")
    );
    Ok(())
}

#[tokio::test]
async fn an_admin_of_the_whole_install_makes_an_enrolment_token_for_one_organization()
-> Result<(), Error> {
    let Some(url) = database("devices_token_org").await? else {
        return Ok(());
    };
    let policy = format!("{POLICY}{CONFINED}");
    let gw = gateway_policy(
        "devices_token_org",
        &url,
        &licensed(&["devices"]),
        &[],
        &policy,
    )?;
    confined_admins(&gw)?;
    let app = &gw.app;
    let tokens = "/console/devices/tokens";
    let body = json!({ "label": "g", "team": "payments", "org": "globex" });
    let made = call(app, "POST", tokens, ADMIN_KEY, Some(body.clone())).await?;
    assert_eq!(made.status, StatusCode::CREATED, "{}", made.text);
    let listed = call(app, "GET", tokens, ADMIN_KEY, None).await?;
    assert_eq!(listed.body["tokens"][0]["org"], "globex", "{}", listed.text);
    // Not acme's to see; an organization the policy does not list is refused by name, as is another's.
    assert!(listed_ids(app, ACME_KEY).await?.is_empty());
    let unknown = json!({ "label": "x", "org": "initech" });
    let refused = call(app, "POST", tokens, ADMIN_KEY, Some(unknown)).await?;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.text);
    assert!(refused.text.contains("acme, globex"), "{}", refused.text);
    let refused = call(app, "POST", tokens, ACME_KEY, Some(body)).await?;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{}", refused.text);
    assert_eq!(refused.body["error"]["code"], "other_org");
    Ok(())
}

#[tokio::test]
async fn an_admin_kept_to_an_organization_or_to_teams_reaches_only_its_own_devices_and_their_mcp_servers()
-> Result<(), Error> {
    let Some(url) = database("devices_confined_reach").await? else {
        return Ok(());
    };
    let policy = format!("{POLICY}{CONFINED}");
    let gw = gateway_policy(
        "devices_confined_reach",
        &url,
        &licensed(&["devices"]),
        &[],
        &policy,
    )?;
    confined_admins(&gw)?;
    let app = &gw.app;
    // One device each: acme's payments team, the install's web team, and the install's payments team.
    for (maker, team, person_key, host) in [
        (ACME_KEY, "payments", ACME_KEY, "acme-pay"),
        (ADMIN_KEY, "web", ADMIN_KEY, "plain-web"),
        (ADMIN_KEY, "payments", PAYMENTS_KEY, "plain-pay"),
    ] {
        let body = json!({ "label": host, "team": team });
        let made = call(app, "POST", "/console/devices/tokens", maker, Some(body)).await?;
        assert_eq!(made.status, StatusCode::CREATED, "{}", made.text);
        let token = made.body["token"].as_str().ok_or("no token")?.to_string();
        let mut sent = report("x", host, json!([]));
        sent["mcp"] = json!([{"tool": "cursor", "file": "/mcp.json", "server": host, "transport": "http",
            "target": format!("https://{host}.example.com/mcp"), "via_gantry": false}]);
        let stored = agent(
            app,
            "POST",
            "/device/report",
            &token,
            person_key,
            Some(sent),
        )
        .await?;
        assert_eq!(stored.status, StatusCode::OK, "{}", stored.text);
    }
    let hosts = async |key: &str| -> Result<Vec<String>, Error> {
        let listed = call(app, "GET", "/console/devices/devices.json", key, None).await?;
        assert_eq!(listed.status, StatusCode::OK, "{}", listed.text);
        let mut hosts: Vec<String> = listed
            .body
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|d| d["hostname"].as_str().map(str::to_string))
            .collect();
        hosts.sort();
        Ok(hosts)
    };
    let servers = async |key: &str| -> Result<Vec<String>, Error> {
        let listed = call(app, "GET", "/console/devices/mcp", key, None).await?;
        assert_eq!(listed.status, StatusCode::OK, "{}", listed.text);
        Ok(listed.body["servers"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|s| s["servers"].as_str().map(str::to_string))
            .collect())
    };
    let decide = async |key: &str, host: &str| -> Result<Reply, Error> {
        let body = json!({"transport": "http", "target": format!("https://{host}.example.com/mcp"), "decision": "blocked"});
        call(app, "POST", "/console/devices/mcp", key, Some(body)).await
    };
    assert_eq!(
        hosts(ADMIN_KEY).await?,
        ["acme-pay", "plain-pay", "plain-web"]
    );
    assert_eq!(
        servers(ADMIN_KEY).await?,
        ["acme-pay", "plain-pay", "plain-web"]
    );

    // Kept to organization acme: its device and that device's server alone, to see, decide and remove.
    assert_eq!(hosts(ACME_KEY).await?, ["acme-pay"]);
    assert_eq!(servers(ACME_KEY).await?, ["acme-pay"]);
    let refused = decide(ACME_KEY, "plain-web").await?;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{}", refused.text);
    assert_eq!(refused.body["error"]["code"], "outside_role");
    let gone = call(
        app,
        "DELETE",
        "/console/devices/devices/plain-web:x",
        ACME_KEY,
        None,
    )
    .await?;
    assert_eq!(gone.status, StatusCode::NOT_FOUND, "{}", gone.text);
    assert_eq!(
        decide(ACME_KEY, "acme-pay").await?.status,
        StatusCode::OK,
        "its own"
    );

    // Kept to team payments: that team's devices in any organization.
    assert_eq!(hosts(PAYMENTS_KEY).await?, ["acme-pay", "plain-pay"]);
    assert_eq!(servers(PAYMENTS_KEY).await?, ["acme-pay", "plain-pay"]);
    assert_eq!(
        decide(PAYMENTS_KEY, "plain-web").await?.status,
        StatusCode::FORBIDDEN
    );
    // Signed in to the console with the same key, the page shows the same reach.
    let mut browser = Browser::default();
    browser
        .go(app, "POST", "/console/sign-in", &[("key", PAYMENTS_KEY)])
        .await?;
    let page = browser.go(app, "GET", "/console/devices", &[]).await?;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text);
    assert!(
        page.text.contains("plain-pay") && !page.text.contains("plain-web"),
        "{}",
        page.text
    );

    // Nothing outside either reach changed, and the refused decision is on record.
    assert_eq!(hosts(ADMIN_KEY).await?.len(), 3);
    let listed = call(app, "GET", "/console/devices/mcp", ADMIN_KEY, None).await?;
    let decisions: Vec<&str> = listed.body["servers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s["decision"].as_str())
        .collect();
    assert_eq!(
        decisions,
        ["blocked", "pending", "pending"],
        "{}",
        listed.text
    );
    assert!(
        admin_records(&gw)?
            .iter()
            .any(|r| r["action"] == "device_mcp_decided" && r["code"] == "outside_role")
    );
    Ok(())
}
