//! The Groups page's API (`/console/api/teams`): a group lists its people (person keys and tokens, not the service
//! keys of apps), and an admin creates, renames and deletes a group and adds and removes people. Membership is the
//! key's `team`; every change is an admin record with who made it, and a change that cannot be made safely is
//! refused with what to do instead.

use std::{path::PathBuf, sync::Arc};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use enterplace_console::{ConsoleConfig, router};
use enterplace_core::{audit::AuditLog, id::sha256_hex};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const ADMIN_KEY: &str = "enterplace_admin_key_for_groups";
const VIEWER_KEY: &str = "enterplace_viewer_key_for_groups";
const HOST: &str = "127.0.0.1:19853";

const POLICY: &str = "\
version: 1
providers:
  - name: openai
    kind: openai
    url: https://api.openai.com
    key_env: OPENAI_API_KEY
    models: [gpt-4o-mini]
rules:
  - name: web-team
    principals: { team: web }
    models: [gpt-4o-mini]
  - name: everyone
    principals: { any: true }
    models: [\"*\"]
limits:
  - team: web
    budget: { usd: 50, per: month }
roles:
  - name: viewer
    permissions: [see_keys, see_records, see_spend]
";

struct Setup {
    app: Router,
    dir: PathBuf,
}

impl Setup {
    fn policy(&self) -> Result<String, std::io::Error> {
        std::fs::read_to_string(self.dir.join("enterplace.policy.yaml"))
    }
    fn keys(&self) -> Result<String, std::io::Error> {
        std::fs::read_to_string(self.dir.join("enterplace.keys.yaml"))
    }
    fn audit(&self) -> Result<String, std::io::Error> {
        std::fs::read_to_string(self.dir.join("enterplace-audit.jsonl"))
    }
}

fn hash(name: &str) -> String {
    sha256_hex(format!("enterplace_key_of_{name}").as_bytes())
}

fn setup(name: &str) -> Result<Setup, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!("enterplace-groups-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("enterplace.policy.yaml"), POLICY)?;
    std::fs::write(
        dir.join("enterplace.keys.yaml"),
        format!(
            "keys:
  - name: noa.bar
    team: platform
    sha256: {}
    admin: true
  - name: vic.viewer
    team: platform
    sha256: {}
    admin: true
    role: viewer
  - name: dana.levi
    team: web
    sha256: {}
  - name: eli.cohen
    team: platform
    sha256: {}
  - name: billing-bot
    team: web
    sha256: {}
    metadata: {{\"kind\": \"workload\"}}
",
            sha256_hex(ADMIN_KEY.as_bytes()),
            sha256_hex(VIEWER_KEY.as_bytes()),
            hash("dana.levi"),
            hash("eli.cohen"),
            hash("billing-bot"),
        ),
    )?;
    let log = Arc::new(AuditLog::open(&dir.join("enterplace-audit.jsonl"))?);
    let config = ConsoleConfig {
        policy: dir.join("enterplace.policy.yaml"),
        keys: dir.join("enterplace.keys.yaml"),
        audit: dir.join("enterplace-audit.jsonl"),
        log: Some(log),
    };
    Ok(Setup {
        app: Router::new().nest("/console", router(config)),
        dir,
    })
}

async fn call(
    s: &Setup,
    method: &str,
    path: &str,
    cookie: &str,
    body: Option<Value>,
) -> Result<(StatusCode, Value), Box<dyn std::error::Error>> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, HOST)
        .header(header::ORIGIN, format!("http://{HOST}"))
        .header(header::COOKIE, cookie);
    if body.is_some() {
        request = request.header(header::CONTENT_TYPE, "application/json");
    }
    let request = request.body(Body::from(body.map(|b| b.to_string()).unwrap_or_default()))?;
    let response = s.app.clone().oneshot(request).await?;
    let status = response.status();
    let bytes = response.into_body().collect().await?.to_bytes();
    Ok((
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    ))
}

async fn sign_in(s: &Setup, key: &str) -> Result<String, Box<dyn std::error::Error>> {
    let request = Request::post("/console/sign-in")
        .header(header::HOST, HOST)
        .header(header::ORIGIN, format!("http://{HOST}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("key={key}")))?;
    let response = s.app.clone().oneshot(request).await?;
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .ok_or("no cookie was set")?;
    Ok(cookie.split(';').next().unwrap_or("").to_string())
}

fn error(value: &Value) -> &str {
    value["error"].as_str().unwrap_or("")
}

/// The names of the people in group `name`, as the list says them.
async fn members(
    s: &Setup,
    cookie: &str,
    name: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let (status, list) = call(s, "GET", "/console/api/teams", cookie, None).await?;
    assert_eq!(status, StatusCode::OK, "{list}");
    let group = list["teams"]
        .as_array()
        .and_then(|t| t.iter().find(|g| g["name"] == name))
        .ok_or_else(|| format!("no group {name} in {list}"))?;
    Ok(group["members"]
        .as_array()
        .map(|m| {
            m.iter()
                .filter_map(|p| p["name"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default())
}

#[tokio::test]
async fn groups_are_created_filled_emptied_renamed_and_deleted() -> TestResult {
    let s = setup("manage")?;
    let cookie = sign_in(&s, ADMIN_KEY).await?;

    // A group lists its people with their key hash; the service key of an app is not one of them.
    let (_, list) = call(&s, "GET", "/console/api/teams", &cookie, None).await?;
    assert_eq!(list["manage"], true, "{list}");
    let web = list["teams"]
        .as_array()
        .and_then(|t| t.iter().find(|g| g["name"] == "web"))
        .ok_or("no web group")?;
    assert_eq!(
        web["members"],
        json!([{ "name": "dana.levi", "sha256": hash("dana.levi"), "hash": &hash("dana.levi")[..8], "kind": "key", "admin": false }]),
        "{list}"
    );

    // Create: a new name, listed in the policy's teams so it shows before anyone is in it.
    let (status, done) = call(
        &s,
        "POST",
        "/console/api/teams",
        &cookie,
        Some(json!({ "name": "design" })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert!(s.policy()?.contains("- name: design"), "{}", s.policy()?);
    assert!(members(&s, &cookie, "design").await?.is_empty());
    let (status, refused) = call(
        &s,
        "POST",
        "/console/api/teams",
        &cookie,
        Some(json!({ "name": "web" })),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert!(
        error(&refused).contains("There is a group named web already"),
        "{refused}"
    );
    let (status, refused) = call(
        &s,
        "POST",
        "/console/api/teams",
        &cookie,
        Some(json!({ "name": "bad name" })),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert!(error(&refused).contains("letters, digits"), "{refused}");

    // Add two people: their keys move to the group.
    for person in ["dana.levi", "eli.cohen"] {
        let (status, done) = call(
            &s,
            "POST",
            "/console/api/teams/members",
            &cookie,
            Some(json!({ "name": "design", "sha256": hash(person) })),
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{done}");
        assert!(
            done["message"]
                .as_str()
                .unwrap_or("")
                .contains(&format!("{person} is in group design")),
            "{done}"
        );
    }
    assert_eq!(
        members(&s, &cookie, "design").await?,
        ["dana.levi", "eli.cohen"]
    );
    assert!(
        s.keys()?.contains("name: dana.levi\n    team: design"),
        "{}",
        s.keys()?
    );

    // An app's service key is not a person: it is moved on the Apps page.
    let (status, refused) = call(
        &s,
        "POST",
        "/console/api/teams/members",
        &cookie,
        Some(json!({ "name": "design", "sha256": hash("billing-bot") })),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert!(error(&refused).contains("service key"), "{refused}");
    // A group that does not exist is not made by a typo.
    let (status, refused) = call(
        &s,
        "POST",
        "/console/api/teams/members",
        &cookie,
        Some(json!({ "name": "desing", "sha256": hash("eli.cohen") })),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert!(
        error(&refused).contains("There is no group desing"),
        "{refused}"
    );

    // Remove one: a key is always in one group, so removing moves it to the one picked.
    let (status, done) = call(
        &s,
        "POST",
        "/console/api/teams/members",
        &cookie,
        Some(json!({ "name": "platform", "sha256": hash("eli.cohen") })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert_eq!(members(&s, &cookie, "design").await?, ["dana.levi"]);

    // Delete refuses a group with people in it, and one the policy still names.
    let (status, refused) = call(
        &s,
        "POST",
        "/console/api/teams/remove",
        &cookie,
        Some(json!({ "name": "design" })),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert!(
        error(&refused).contains("Group design still has 1 key"),
        "{refused}"
    );

    // Rename: the keys and every place the policy names the group move with it.
    let (status, done) = call(
        &s,
        "POST",
        "/console/api/teams/rename",
        &cookie,
        Some(json!({ "name": "web", "to": "growth" })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    let policy = s.policy()?;
    assert!(
        policy.contains("team: growth") && !policy.contains("team: web"),
        "{policy}"
    );
    assert!(
        s.keys()?.contains("name: billing-bot\n    team: growth"),
        "{}",
        s.keys()?
    );
    let (status, refused) = call(
        &s,
        "POST",
        "/console/api/teams/rename",
        &cookie,
        Some(json!({ "name": "growth", "to": "design" })),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert!(
        error(&refused).contains("There is a group named design already"),
        "{refused}"
    );

    // A group whose traffic is stopped keeps its name and its people: a move would let them through.
    std::fs::write(
        s.dir.join("enterplace.kills.json"),
        r#"{"kills":[{"scope":"team","value":"growth","reason":"leak","by":"noa.bar","at":"2026-01-01T00:00:00Z"}]}"#,
    )?;
    let (status, refused) = call(
        &s,
        "POST",
        "/console/api/teams/rename",
        &cookie,
        Some(json!({ "name": "growth", "to": "growth2" })),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert!(
        error(&refused).contains("Traffic for group growth is stopped"),
        "{refused}"
    );
    let (status, refused) = call(
        &s,
        "POST",
        "/console/api/teams/members",
        &cookie,
        Some(json!({ "name": "design", "sha256": hash("billing-bot") })),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    std::fs::remove_file(s.dir.join("enterplace.kills.json"))?;

    // Empty the group, then delete it: gone from the policy.
    let (status, done) = call(
        &s,
        "POST",
        "/console/api/teams/members",
        &cookie,
        Some(json!({ "name": "platform", "sha256": hash("dana.levi") })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    let (status, done) = call(
        &s,
        "POST",
        "/console/api/teams/remove",
        &cookie,
        Some(json!({ "name": "design" })),
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert!(!s.policy()?.contains("design"), "{}", s.policy()?);

    // Every change is an admin record with who made it.
    let audit = s.audit()?;
    let records: Vec<Value> = audit
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    for action in ["add_team", "move_key", "rename_team", "remove_team"] {
        assert!(
            records.iter().any(|r| r["action"] == action
                && r["person"] == "noa.bar"
                && r["verdict"] == "allow"),
            "no {action} record in {audit}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_read_only_admin_changes_no_group() -> TestResult {
    let s = setup("viewer")?;
    let cookie = sign_in(&s, VIEWER_KEY).await?;
    let (_, list) = call(&s, "GET", "/console/api/teams", &cookie, None).await?;
    assert_eq!(list["manage"], false, "{list}");
    let (keys, policy) = (s.keys()?, s.policy()?);
    for (path, body) in [
        ("/console/api/teams", json!({ "name": "design" })),
        (
            "/console/api/teams/members",
            json!({ "name": "platform", "sha256": hash("dana.levi") }),
        ),
        (
            "/console/api/teams/rename",
            json!({ "name": "web", "to": "growth" }),
        ),
        ("/console/api/teams/remove", json!({ "name": "web" })),
    ] {
        let (status, refused) = call(&s, "POST", path, &cookie, Some(body)).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {refused}");
    }
    assert_eq!((s.keys()?, s.policy()?), (keys, policy));
    Ok(())
}
