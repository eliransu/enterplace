//! Teams as a policy object and roles kept to teams: `teams:` with owner, members and the identity provider
//! groups that place people, `GET/POST/PUT/DELETE /admin/teams` saving policy versions, and a role with `teams:`
//! that sees and changes only its teams' keys and records in the admin API.
//!
//! The store tests need GANTRY_TEST_DATABASE_URL; without it they say they were skipped and pass.

use std::path::PathBuf;

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
    routing::post,
};
use gantry_core::keyfile::{self, Attributes};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Error = Box<dyn std::error::Error>;

const ADMIN: &str = "gantry_admin_0123456789abcdef012345678";
const LEAD: &str = "gantry_lead_0123456789abcdef01234567890";
const MAYA: &str = "gantry_maya_0123456789abcdef0123456789";
const OMER: &str = "gantry_omer_0123456789abcdef0123456789";

async fn database(test: &str) -> Result<Option<gantry_server::store::TestDatabase>, Error> {
    gantry_server::store::TestDatabase::create(&format!("gantry_{}_{test}", std::process::id()))
        .await
}

/// A model server that answers every chat request.
async fn provider() -> Result<u16, Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let app = Router::new().route(
        "/v1/chat/completions",
        post(|| async { r#"{"id":"c","object":"chat.completion","choices":[]}"# }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

fn policy(port: u16, store: bool) -> String {
    format!(
        "version: 1
{}providers:
  - name: mock
    kind: openai
    url: http://127.0.0.1:{port}
    allow_private: true
    models: [m]
rules:
  - name: everyone
    principals: {{ any: true }}
    models: [m]
roles:
  - name: payments-lead
    permissions: [see_keys, issue_keys, revoke_keys, see_records, see_spend, edit_policy]
    teams: [payments]
teams:
  - name: payments
    owner: Lead@Example.com
    members: [maya@example.com]
    sso_values: [payments-eng]
",
        if store {
            "store: { postgres_url_env: GANTRY_STORE_URL, policy_from: store }\n"
        } else {
            ""
        }
    )
}

fn dir(name: &str) -> Result<PathBuf, Error> {
    let dir = std::env::temp_dir().join(format!("gantry-teams-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn gateway(name: &str, text: &str, url: Option<&str>) -> Result<gantry_server::Governed, Error> {
    let dir = dir(name)?;
    let policy = dir.join("gantry.policy.yaml");
    std::fs::write(&policy, text)?;
    let keys = dir.join("gantry.keys.yaml");
    if url.is_none() {
        add_keys(&keys)?;
    }
    let url = url.map(str::to_string);
    let gw = gantry_server::governed(&policy, None, &|variable| match variable {
        "GANTRY_STORE_URL" => url.clone(),
        _ => None,
    })?;
    if url.is_some() {
        add_keys(&gw.loaded.keys_path)?;
        gw.reloader.check(gantry_server::Trigger::FileChange);
    }
    Ok(gw)
}

fn add_keys(keys: &std::path::Path) -> TestResult {
    keyfile::add_entry("admin", "ops", ADMIN, true, keys)?;
    let lead = Attributes {
        role: Some("payments-lead".into()),
        ..Attributes::default()
    };
    keyfile::add_with("lead@example.com", "payments", LEAD, &lead, keys)?;
    keyfile::add_entry("maya@example.com", "payments", MAYA, false, keys)?;
    keyfile::add_entry("omer@example.com", "web", OMER, false, keys)?;
    Ok(())
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    key: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Result<(StatusCode, HeaderMap, String), Error> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {key}"));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string()))?)
        .await?;
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await?.to_bytes();
    Ok((
        parts.status,
        parts.headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    ))
}

async fn json_call(
    app: &Router,
    method: &str,
    path: &str,
    key: &str,
    body: &str,
) -> Result<(StatusCode, Value), Error> {
    let (status, _, body) = call(app, method, path, key, &[], body).await?;
    Ok((
        status,
        serde_json::from_str(&body).unwrap_or(Value::String(body)),
    ))
}

#[tokio::test(flavor = "multi_thread")]
async fn teams_are_listed_with_their_keys_and_a_policy_in_the_file_is_not_changed() -> TestResult {
    let gw = gateway("file", &policy(1, false), None)?;
    let (status, body) = json_call(&gw.router, "GET", "/admin/teams", ADMIN, "").await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let names: Vec<&str> = body["teams"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert_eq!(names, ["ops", "payments", "web"]);
    let (status, payments) =
        json_call(&gw.router, "GET", "/admin/teams/payments", ADMIN, "").await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(payments["owner"], "lead@example.com");
    assert_eq!(payments["members"], json!(["maya@example.com"]));
    assert_eq!(payments["sso_values"], json!(["payments-eng"]));
    assert_eq!(payments["in_policy"], true);
    assert_eq!(payments["keys"].as_array().map(Vec::len), Some(2));
    // A team only keys name is listed, not in the policy.
    let (_, web) = json_call(&gw.router, "GET", "/admin/teams/web", ADMIN, "").await?;
    assert_eq!(web["in_policy"], false);
    let (status, body) = json_call(&gw.router, "GET", "/admin/teams/nope", ADMIN, "").await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    // Without the store, the policy is the file's: the API says how to change it.
    let (status, body) = json_call(
        &gw.router,
        "POST",
        "/admin/teams",
        ADMIN,
        r#"{"name":"web"}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.to_string().contains("policy_in_file"), "{body}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_role_kept_to_a_team_sees_and_changes_only_that_teams_keys() -> TestResult {
    let gw = gateway("scoped", &policy(1, false), None)?;
    let (status, body) = json_call(&gw.router, "GET", "/admin/keys", LEAD, "").await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mut names: Vec<&str> = body["keys"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|k| k["name"].as_str())
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["lead@example.com", "maya@example.com"]);
    let (_, teams) = json_call(&gw.router, "GET", "/admin/teams", LEAD, "").await?;
    assert_eq!(teams["teams"].as_array().map(Vec::len), Some(1), "{teams}");

    // Issuing: in the team, yes; in another team, no.
    let (status, body) = json_call(
        &gw.router,
        "POST",
        "/admin/keys",
        LEAD,
        r#"{"name":"ci","team":"payments"}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = json_call(
        &gw.router,
        "POST",
        "/admin/keys",
        LEAD,
        r#"{"name":"ci2","team":"web"}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.to_string().contains("team payments"), "{body}");
    // A key given a role that is not kept to the team would reach past it.
    let (status, body) = json_call(
        &gw.router,
        "POST",
        "/admin/keys",
        LEAD,
        r#"{"name":"ci3","team":"payments","role":"read_only"}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Another team's key cannot be seen, changed or revoked; the team's own can be, but not moved out.
    let omer = &gantry_core::id::sha256_hex(OMER.as_bytes())[..8];
    let maya = &gantry_core::id::sha256_hex(MAYA.as_bytes())[..8];
    for (method, body) in [("GET", ""), ("PATCH", r#"{"rpm":5}"#), ("DELETE", "")] {
        let (status, got) = json_call(
            &gw.router,
            method,
            &format!("/admin/keys/{omer}"),
            LEAD,
            body,
        )
        .await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method}: {got}");
    }
    let (status, got) =
        json_call(&gw.router, "GET", &format!("/admin/keys/{maya}"), LEAD, "").await?;
    assert_eq!(status, StatusCode::OK, "{got}");
    let (status, got) = json_call(
        &gw.router,
        "PATCH",
        &format!("/admin/keys/{maya}"),
        LEAD,
        r#"{"team":"web"}"#,
    )
    .await?;
    assert_ne!(status, StatusCode::OK, "{got}");
    // Kill switches, credentials and teams act on the whole install.
    let (status, got) =
        json_call(&gw.router, "POST", "/admin/teams", LEAD, r#"{"name":"x"}"#).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{got}");
    let (status, got) = json_call(&gw.router, "GET", "/admin/policy", LEAD, "").await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{got}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn teams_are_made_changed_and_removed_as_policy_versions() -> TestResult {
    let Some(url) = database("teams_api").await? else {
        return Ok(());
    };
    let port = provider().await?;
    let gw = gateway("store", &policy(port, true), Some(&url))?;
    let (status, body) = json_call(
        &gw.router,
        "POST",
        "/admin/teams",
        ADMIN,
        r#"{"name":"web","owner":"Omer@Example.com","members":["omer@example.com"],"sso_values":["web-eng"],"metadata":{"cost_center":"4410"}}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(
        (body["version"].clone(), body["state"].clone()),
        (json!(2), json!("live"))
    );
    assert_eq!(body["in_effect"], true, "{body}");
    let (_, web) = json_call(&gw.router, "GET", "/admin/teams/web", ADMIN, "").await?;
    assert_eq!(web["owner"], "omer@example.com");
    assert_eq!(web["metadata"]["cost_center"], "4410");
    assert_eq!(web["in_policy"], true);
    // Twice is a conflict; a member of two teams is refused as gantry check refuses it.
    let (status, _) = json_call(
        &gw.router,
        "POST",
        "/admin/teams",
        ADMIN,
        r#"{"name":"web"}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, body) = json_call(
        &gw.router,
        "PUT",
        "/admin/teams/web",
        ADMIN,
        r#"{"members":["maya@example.com"]}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.to_string().contains("invalid_policy"), "{body}");
    let (status, body) = json_call(
        &gw.router,
        "PUT",
        "/admin/teams/web",
        ADMIN,
        r#"{"owner":"omer@example.com","sso_values":["web-eng","web-ops"]}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, web) = json_call(&gw.router, "GET", "/admin/teams/web", ADMIN, "").await?;
    assert_eq!(web["sso_values"], json!(["web-eng", "web-ops"]));
    assert_eq!(web["members"], json!([]));
    let (status, body) = json_call(&gw.router, "DELETE", "/admin/teams/web", ADMIN, "").await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, web) = json_call(&gw.router, "GET", "/admin/teams/web", ADMIN, "").await?;
    assert_eq!(web["in_policy"], false, "{web}");
    let (status, _) = json_call(&gw.router, "DELETE", "/admin/teams/web", ADMIN, "").await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // Every change is a version in the history, by who made it.
    let (_, versions) = json_call(&gw.router, "GET", "/admin/policy/versions", ADMIN, "").await?;
    assert_eq!(
        versions["versions"].as_array().map(Vec::len),
        Some(4),
        "{versions}"
    );
    // The audit chain holds each call.
    let log = std::fs::read_to_string(&gw.loaded.audit_path)?;
    for action in ["create_team", "update_team", "delete_team", "show_team"] {
        assert!(
            log.contains(&format!("\"action\":\"{action}\"")),
            "{action}"
        );
    }
    Ok(())
}
