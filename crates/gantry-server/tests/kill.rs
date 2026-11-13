//! Kill switches through the admin API: set with a reason, in force on two nodes within a second, refused as
//! `killed` with the reason and who set it, kept over a restart, cleared, and every change on record. Also a key
//! revoking itself, as `gantry logout` does.

use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
    routing::post,
};
use gantry_core::id::sha256_hex;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Error = Box<dyn std::error::Error>;

const MAYA: &str = "gantry_maya_0123456789abcdef0123456789";
const OMER: &str = "gantry_omer_0123456789abcdef0123456789";
const ADMIN: &str = "gantry_admin_0123456789abcdef012345678";

async fn provider() -> Result<u16, Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    // model-a takes no prompt longer than its context, so alias fbx falls back to model-c.
    let app = Router::new().route(
        "/v1/chat/completions",
        post(|body: Bytes| async move {
            if body.windows(9).any(|w| w == b"\"model-a\"") && body.windows(4).any(|w| w == b"long")
            {
                return axum::response::Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"error":{"code":"context_length_exceeded","message":"too long"}}"#,
                    ))
                    .unwrap_or_default();
            }
            axum::response::Response::builder()
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"choices":[]}"#))
                .unwrap_or_default()
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

fn entry(name: &str, team: &str, key: &str) -> String {
    format!(
        "  - name: {name}\n    team: {team}\n    sha256: {}\n",
        sha256_hex(key.as_bytes())
    )
}

async fn setup(name: &str) -> Result<(PathBuf, PathBuf), Error> {
    let port = provider().await?;
    let dir = std::env::temp_dir().join(format!("gantry-kill-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        dir.join("gantry.policy.yaml"),
        format!(
            "version: 1
providers:
  - name: mock
    kind: openai
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: MOCK_PROVIDER_KEY
    models: [model-a, model-b, model-c]
aliases:
  - name: smart
    deployments:
      - {{ provider: mock, model: model-b }}
  - name: fbx
    context_window_fallback: model-c
    deployments:
      - {{ provider: mock, model: model-a }}
rules:
  - name: everyone
    principals: {{ any: true }}
    models: [model-a, model-b, smart, fbx]
"
        ),
    )?;
    std::fs::write(
        dir.join("gantry.keys.yaml"),
        format!(
            "keys:\n{}{}{}    admin: true\n",
            entry("maya.cohen", "payments", MAYA),
            entry("omer.katz", "support", OMER),
            entry("ops.admin", "ops", ADMIN)
        ),
    )?;
    Ok((dir.join("gantry.policy.yaml"), dir))
}

/// Another node on the same policy and keys: its own copy of the policy, writing its own audit log.
fn other(policy: &Path, name: &str) -> Result<PathBuf, Error> {
    let dir = policy.parent().ok_or("no folder")?;
    let copy = dir.join(format!("{name}.policy.yaml"));
    let audit = dir.join(format!("{name}-audit.jsonl"));
    std::fs::write(
        &copy,
        format!(
            "{}audit:\n  path: {}\n",
            std::fs::read_to_string(policy)?,
            audit.display()
        ),
    )?;
    Ok(copy)
}

fn node(policy: &Path) -> Result<Router, Error> {
    Ok(gantry_server::governed(policy, None, &|_| Some("provider-secret".into()))?.router)
}

fn chat(key: &str, model: &str) -> Result<Request<Body>, axum::http::Error> {
    Request::post("/v1/chat/completions")
        .header(header::AUTHORIZATION, format!("Bearer {key}"))
        .body(Body::from(format!(
            r#"{{"model":"{model}","messages":[]}}"#
        )))
}

fn admin(
    method: &str,
    path: &str,
    key: &str,
    body: &str,
) -> Result<Request<Body>, axum::http::Error> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {key}"))
        .body(Body::from(body.to_string()))
}

async fn answer(app: &Router, request: Request<Body>) -> Result<(StatusCode, Value), Error> {
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, serde_json::from_slice(&body).unwrap_or(Value::Null)))
}

/// The admin records of every node's log in the folder.
fn admin_records(dir: &Path) -> Result<Vec<Value>, Error> {
    let mut text = String::new();
    for name in ["gantry-audit.jsonl", "b-audit.jsonl"] {
        text += &std::fs::read_to_string(dir.join(name)).unwrap_or_default();
    }
    Ok(text
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|r| r["event"] == "admin")
        .collect())
}

/// Waits until `node` answers `want` to `request`, for at most a second.
async fn within_a_second(
    node: &Router,
    want: StatusCode,
    request: impl Fn() -> Result<Request<Body>, axum::http::Error>,
) -> Result<Value, Error> {
    let start = Instant::now();
    loop {
        let (status, body) = answer(node, request()?).await?;
        if status == want {
            return Ok(body);
        }
        if start.elapsed() > Duration::from_secs(1) {
            return Err(format!("still {status} after a second: {body}").into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_switch_with_a_reason_stops_a_person_on_two_nodes_within_a_second() -> TestResult {
    let (policy, dir) = setup("person").await?;
    let (a, b) = (node(&policy)?, node(&other(&policy, "b")?)?);
    assert_eq!(answer(&b, chat(MAYA, "model-a")?).await?.0, StatusCode::OK);

    // No reason, no switch.
    let (status, body) = answer(
        &a,
        admin(
            "POST",
            "/admin/kills",
            ADMIN,
            r#"{"scope":"person","value":"maya.cohen"}"#,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("reason")
    );
    // Only an admin sets one.
    let (status, _) = answer(
        &a,
        admin(
            "POST",
            "/admin/kills",
            MAYA,
            r#"{"scope":"all","reason":"x"}"#,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, body) = answer(
        &a,
        admin(
            "POST",
            "/admin/kills",
            ADMIN,
            r#"{"scope":"person","value":"maya.cohen","reason":"retrying the same ticket in a loop"}"#,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, refused) = answer(&a, chat(MAYA, "model-a")?).await?;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the node that set it applies it at once"
    );
    assert_eq!(refused["error"]["code"], "killed");
    let message = refused["error"]["message"].as_str().unwrap_or("");
    assert!(
        message.contains("retrying the same ticket in a loop") && message.contains("ops.admin"),
        "{message}"
    );
    let on_b = within_a_second(&b, StatusCode::FORBIDDEN, || chat(MAYA, "model-a")).await?;
    assert_eq!(on_b["error"]["code"], "killed");
    // Others go on.
    assert_eq!(answer(&b, chat(OMER, "model-a")?).await?.0, StatusCode::OK);
    // A restart keeps it.
    assert_eq!(
        answer(&node(&other(&policy, "c")?)?, chat(MAYA, "model-a")?)
            .await?
            .0,
        StatusCode::FORBIDDEN
    );
    let (_, listed) = answer(&b, admin("GET", "/admin/kills", ADMIN, "")?).await?;
    assert_eq!(listed["kills"][0]["by"], "ops.admin");

    let (status, _) = answer(
        &b,
        admin(
            "DELETE",
            "/admin/kills",
            ADMIN,
            r#"{"scope":"person","value":"maya.cohen"}"#,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    within_a_second(&a, StatusCode::OK, || chat(MAYA, "model-a")).await?;
    let (status, body) = answer(
        &b,
        admin(
            "DELETE",
            "/admin/kills",
            ADMIN,
            r#"{"scope":"person","value":"maya.cohen"}"#,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "no_such_switch");

    let records = admin_records(&dir)?;
    let set = records
        .iter()
        .find(|r| r["action"] == "set_kill" && r["verdict"] == "allow")
        .ok_or("no set record")?;
    assert_eq!(set["person"], "ops.admin");
    assert_eq!(
        set["target"]["reason"],
        "retrying the same ticket in a loop"
    );
    assert!(
        records
            .iter()
            .any(|r| r["action"] == "clear_kill" && r["verdict"] == "allow")
    );
    let request = std::fs::read_to_string(dir.join("gantry-audit.jsonl"))?;
    assert!(
        request.contains(r#""code":"killed""#),
        "the refusal is not on record"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn team_key_model_and_all_switches_stop_what_they_name() -> TestResult {
    let (policy, _dir) = setup("scopes").await?;
    let a = node(&policy)?;
    let set = |body: &str| admin("POST", "/admin/kills", ADMIN, body);
    let clear = |body: &str| admin("DELETE", "/admin/kills", ADMIN, body);
    for (on, stopped, going) in [
        (
            r#"{"scope":"team","value":"support","reason":"r"}"#,
            (OMER, "model-a"),
            (MAYA, "model-a"),
        ),
        (
            &format!(
                r#"{{"scope":"key_prefix","value":"{}","reason":"r"}}"#,
                &sha256_hex(MAYA.as_bytes())[..12]
            ),
            (MAYA, "model-a"),
            (OMER, "model-a"),
        ),
        (
            r#"{"scope":"model","value":"model-b","reason":"r"}"#,
            (OMER, "model-b"),
            (OMER, "model-a"),
        ),
        (
            r#"{"scope":"all","reason":"r"}"#,
            (OMER, "model-a"),
            ("", ""),
        ),
    ] {
        assert_eq!(answer(&a, set(on)?).await?.0, StatusCode::CREATED, "{on}");
        assert_eq!(
            answer(&a, chat(stopped.0, stopped.1)?).await?.0,
            StatusCode::FORBIDDEN,
            "{on}"
        );
        if !going.0.is_empty() {
            assert_eq!(
                answer(&a, chat(going.0, going.1)?).await?.0,
                StatusCode::OK,
                "{on}"
            );
        }
        // Admins can still clear a switch that stops everyone.
        assert_eq!(answer(&a, clear(on)?).await?.0, StatusCode::OK, "{on}");
        assert_eq!(
            answer(&a, chat(stopped.0, stopped.1)?).await?.0,
            StatusCode::OK,
            "{on}"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_revokes_itself_without_being_an_admin() -> TestResult {
    let (policy, dir) = setup("self").await?;
    let a = node(&policy)?;
    let (status, body) = answer(&a, admin("DELETE", "/admin/keys/self", OMER, "")?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["revoked"]["name"], "omer.katz");
    let keys = std::fs::read_to_string(dir.join("gantry.keys.yaml"))?;
    assert!(!keys.contains(&sha256_hex(OMER.as_bytes())) && keys.contains("maya.cohen"));
    let (status, _) = answer(&a, admin("DELETE", "/admin/keys/self", OMER, "")?).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let last = admin_records(&dir)?
        .into_iter()
        .rfind(|r| r["action"] == "revoke_own_key" && r["verdict"] == "allow")
        .ok_or("no record")?;
    assert_eq!(last["person"], "omer.katz");
    // MIN-2: the record names the key that revoked itself, by its hash prefix.
    assert_eq!(last["key"], sha256_hex(OMER.as_bytes())[..8]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_switch_that_would_stop_nothing_is_refused_and_a_model_switch_stops_its_aliases()
-> TestResult {
    let (policy, _dir) = setup("nothing").await?;
    let a = node(&policy)?;
    let set = |body: &str| admin("POST", "/admin/kills", ADMIN, body);
    // UX12-1: keys from `gantry login` are named by email, so a bare name matches no key.
    let (status, body) = answer(
        &a,
        set(r#"{"scope":"person","value":"maya","reason":"r"}"#)?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], "kill_matches_nothing");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("maya.cohen") && message.contains("force"),
        "{message}"
    );
    for (scope, value) in [
        ("team", "nosuch"),
        ("key_prefix", "00000000"),
        ("model", "gpt-9"),
    ] {
        let on = format!(r#"{{"scope":"{scope}","value":"{value}","reason":"r"}}"#);
        assert_eq!(
            answer(&a, set(&on)?).await?.0,
            StatusCode::BAD_REQUEST,
            "{on}"
        );
    }
    // `force` sets it anyway, for a key about to be issued.
    let forced = r#"{"scope":"person","value":"maya","reason":"r","force":true}"#;
    assert_eq!(answer(&a, set(forced)?).await?.0, StatusCode::CREATED);
    // A switch on a deployment's model stops the alias that sends to it.
    let on = r#"{"scope":"model","value":"model-b","reason":"r"}"#;
    assert_eq!(answer(&a, set(on)?).await?.0, StatusCode::CREATED);
    assert_eq!(
        answer(&a, chat(OMER, "smart")?).await?.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(answer(&a, chat(OMER, "model-a")?).await?.0, StatusCode::OK);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_model_switch_stops_a_named_fallback_to_that_model() -> TestResult {
    // QA14-2: a request to fbx whose deployment refuses the prompt as too long goes to model-c, unless a switch
    // stops model-c: then the caller gets the deployment's own refusal, and model-c is never sent anything.
    let (policy, dir) = setup("fallback").await?;
    let a = node(&policy)?;
    let long = |key: &str| {
        Request::post("/v1/chat/completions")
            .header(header::AUTHORIZATION, format!("Bearer {key}"))
            .body(Body::from(
                r#"{"model":"fbx","messages":[{"role":"user","content":"long"}]}"#,
            ))
    };
    assert_eq!(answer(&a, long(OMER)?).await?.0, StatusCode::OK);
    let on = r#"{"scope":"model","value":"model-c","reason":"incident"}"#;
    assert_eq!(
        answer(&a, admin("POST", "/admin/kills", ADMIN, on)?)
            .await?
            .0,
        StatusCode::CREATED
    );
    let (status, body) = answer(&a, long(OMER)?).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], "context_length_exceeded", "{body}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let log = std::fs::read_to_string(dir.join("gantry-audit.jsonl"))?;
    let used: Vec<Value> = log
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|r| r["event"] == "usage")
        .collect();
    assert_eq!(
        used.iter().filter(|r| r["model"] == "model-c").count(),
        1,
        "only the request before the switch reached model-c"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn the_switch_file_is_private_and_one_the_gateway_cannot_read_stops_everyone() -> TestResult {
    // QA14-16 (KS6, KS8): the file is 0600, and a gateway that cannot read it refuses rather than forwards.
    let (policy, dir) = setup("unreadable").await?;
    let a = node(&policy)?;
    let on = r#"{"scope":"person","value":"maya.cohen","reason":"r"}"#;
    assert_eq!(
        answer(&a, admin("POST", "/admin/kills", ADMIN, on)?)
            .await?
            .0,
        StatusCode::CREATED
    );
    let file = dir.join("gantry.kills.json");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&file)?.permissions().mode() & 0o777,
            0o600
        );
    }
    std::fs::write(&file, "{ not a switch list")?;
    let start = Instant::now();
    loop {
        let (status, body) = answer(&a, chat(OMER, "model-a")?).await?;
        if status == StatusCode::SERVICE_UNAVAILABLE {
            assert_eq!(body["error"]["code"], "kills_unreadable", "{body}");
            return Ok(());
        }
        assert_eq!(status, StatusCode::OK, "{body}");
        if start.elapsed() > Duration::from_secs(3) {
            return Err("an unreadable switch file did not stop requests".into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_switch_file_whose_permissions_keep_the_gateway_out_stops_everyone() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let (policy, dir) = setup("no-permission").await?;
    let a = node(&policy)?;
    let on = r#"{"scope":"person","value":"maya.cohen","reason":"r"}"#;
    assert_eq!(
        answer(&a, admin("POST", "/admin/kills", ADMIN, on)?)
            .await?
            .0,
        StatusCode::CREATED
    );
    let file = dir.join("gantry.kills.json");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000))?;
    // Root reads any file, so the check only means something when the mode keeps this process out.
    if std::fs::read(&file).is_ok() {
        return Ok(());
    }
    let start = Instant::now();
    let result = loop {
        let (status, body) = answer(&a, chat(OMER, "model-a")?).await?;
        if status == StatusCode::SERVICE_UNAVAILABLE {
            break if body["error"]["code"] == "kills_unreadable" {
                Ok(())
            } else {
                Err(format!("wrong code: {body}").into())
            };
        }
        if status != StatusCode::OK || start.elapsed() > Duration::from_secs(3) {
            break Err(format!(
                "a switch file it cannot open did not stop requests: {status} {body}"
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))?;
    result
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_revoking_itself_removes_only_itself_when_another_shares_its_prefix() -> TestResult {
    // QA14-16 (LG4): self-revoke names the key by its whole hash, so a key whose hash starts with the same 8 hex
    // characters is neither removed nor in the way.
    let (policy, dir) = setup("self-twin").await?;
    let omer = sha256_hex(OMER.as_bytes());
    let twin = format!("{}{}", &omer[..8], "0".repeat(56));
    let keys = dir.join("gantry.keys.yaml");
    let text = std::fs::read_to_string(&keys)?;
    std::fs::write(
        &keys,
        format!("{text}  - name: twin\n    team: support\n    sha256: {twin}\n"),
    )?;
    let a = node(&policy)?;
    let (status, body) = answer(&a, admin("DELETE", "/admin/keys/self", OMER, "")?).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["revoked"]["name"], "omer.katz");
    let text = std::fs::read_to_string(&keys)?;
    assert!(!text.contains(&omer) && text.contains(&twin), "{text}");
    Ok(())
}
