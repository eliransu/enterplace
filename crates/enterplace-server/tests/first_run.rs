//! Acceptance test for package 5.3, first run: with no admin key yet, `enterplace serve` offers a one-time setup link.
//! The link makes the first admin key once, shows how to point a client at Enterplace, and that key makes a governed
//! call at once.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::post,
};
use http_body_util::BodyExt;
use tower::ServiceExt;

type Error = Box<dyn std::error::Error>;

async fn provider() -> Result<u16, Error> {
    let app = Router::new().route(
        "/v1/chat/completions",
        post(|| async {
            (
                [(header::CONTENT_TYPE, "application/json")],
                r#"{"id":"c","object":"chat.completion","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":2}}"#,
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

fn policy(dir: &std::path::Path, port: u16) -> Result<std::path::PathBuf, Error> {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir)?;
    let path = dir.join("enterplace.policy.yaml");
    std::fs::write(
        &path,
        format!(
            "version: 1\nproviders:\n  - name: mock\n    kind: openai\n    url: http://127.0.0.1:{port}\n    allow_private: true\n    key_env: MOCK_KEY\n    models: [model-a]\nrules:\n  - name: everyone\n    principals: {{ any: true }}\n    models: [model-a]\n"
        ),
    )?;
    Ok(path)
}

async fn send(app: &Router, request: Request<Body>) -> Result<(StatusCode, String), Error> {
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, String::from_utf8(body.to_vec())?))
}

fn form(path: &str, body: &str) -> Result<Request<Body>, axum::http::Error> {
    Request::post(path)
        .header(header::HOST, "127.0.0.1:8080")
        .header(header::ORIGIN, "http://127.0.0.1:8080")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
}

#[tokio::test]
async fn the_setup_link_makes_the_first_admin_once_and_that_key_makes_a_governed_call()
-> Result<(), Error> {
    let port = provider().await?;
    let dir = std::env::temp_dir().join(format!("enterplace-first-run-{}", std::process::id()));
    let path = policy(&dir, port)?;
    let gw = enterplace_server::governed(&path, None, &|_| Some("provider-secret".into()))?;
    let token = gw
        .setup
        .clone()
        .ok_or("no setup link offered with no admin key")?;
    let link = format!("/console/setup/{token}");

    let (status, page) = send(&gw.router, Request::get(&link).body(Body::empty())?).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains("name=\"name\"") && page.contains("name=\"team\""),
        "{page}"
    );
    let (status, _) = send(
        &gw.router,
        Request::get("/console/setup/not-the-token").body(Body::empty())?,
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "a wrong token gets nothing");

    let (status, page) = send(&gw.router, form(&link, "name=maya.cohen&team=platform")?).await?;
    assert_eq!(status, StatusCode::OK, "{page}");
    let key = page
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .find(|w| w.starts_with("enterplace_") && w.len() == 75)
        .ok_or("no key on the page")?
        .to_string();
    for step in [
        "ANTHROPIC_BASE_URL",
        "OPENAI_BASE_URL",
        "curl",
        "/console",
        "Copy for your agent",
        "ENTERPLACE_API_KEY",
        "model-a",
    ] {
        assert!(page.contains(step), "the page shows {step}");
    }

    // `/console/` with a slash, as a browser or a person types it, is the console, never the API's no_key answer.
    let (status, _) = send(&gw.router, Request::get("/console/").body(Body::empty())?).await?;
    assert!(status.is_redirection(), "/console/ answered {status}");

    let (status, page) = send(&gw.router, form(&link, "name=eve&team=x")?).await?;
    assert_eq!(status, StatusCode::GONE, "the link works once: {page}");
    let (status, _) = send(&gw.router, Request::get(&link).body(Body::empty())?).await?;
    assert_eq!(status, StatusCode::GONE);

    let keys = std::fs::read_to_string(dir.join("enterplace.keys.yaml"))?;
    assert!(
        keys.contains("maya.cohen") && keys.contains("admin: true"),
        "{keys}"
    );
    assert!(!keys.contains("eve"));
    // The first admin also gets their own person token, so the Claude Code lines Start here hands them carry it.
    assert_eq!(keys.matches("name: maya.cohen").count(), 2, "{keys}");

    // The new key is in use within the 2 seconds a reload takes, and makes a governed call.
    let mut status = StatusCode::UNAUTHORIZED;
    for _ in 0..40 {
        gw.reloader.check(enterplace_server::Trigger::FileChange);
        let request = Request::post("/v1/chat/completions")
            .header(header::AUTHORIZATION, format!("Bearer {key}"))
            .body(Body::from(r#"{"model":"model-a","messages":[]}"#))?;
        status = send(&gw.router, request).await?.0;
        if status == StatusCode::OK {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(
        status,
        StatusCode::OK,
        "the first key makes a governed call"
    );
    let audit = std::fs::read_to_string(dir.join("enterplace-audit.jsonl"))?;
    assert!(
        audit.contains("\"action\":\"first_setup\""),
        "the setup is recorded"
    );

    // A Enterplace that already has an admin offers no link.
    let again = enterplace_server::governed(&path, None, &|_| Some("provider-secret".into()));
    drop(gw);
    let again = match again {
        Ok(g) => g,
        // The first instance still held the audit log: start again now that it is gone.
        Err(_) => enterplace_server::governed(&path, None, &|_| Some("provider-secret".into()))?,
    };
    assert!(
        again.setup.is_none(),
        "no setup link once an admin key exists"
    );
    Ok(())
}

/// Where nobody reads the gateway's output (a Cloudflare Container), ENTERPLACE_SETUP_TOKEN gives the setup link's
/// token, so the one who deploys opens the link with the token they set. A short one is not used.
#[tokio::test]
async fn the_setup_token_may_be_set_by_whoever_deploys() -> Result<(), Error> {
    let port = provider().await?;
    let set = "0123456789abcdef0123456789abcdef0123456789abcdef";
    for (name, given, used) in [("set", set, true), ("short", "abc123", false)] {
        let dir = std::env::temp_dir().join(format!(
            "enterplace-first-run-token-{name}-{}",
            std::process::id()
        ));
        let path = policy(&dir, port)?;
        let gw = enterplace_server::governed(&path, None, &|variable| match variable {
            "ENTERPLACE_SETUP_TOKEN" => Some(given.into()),
            "ENTERPLACE_MASTER_KEY" | "ENTERPLACE_MASTER_KEY_FILE" => None,
            _ => Some("provider-secret".into()),
        })?;
        let token = gw.setup.clone().ok_or("no setup link offered")?;
        assert_eq!(token == given, used, "{name}: {token}");
        let (status, page) = send(
            &gw.router,
            Request::get(format!("/console/setup/{token}")).body(Body::empty())?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{page}");
    }
    Ok(())
}
