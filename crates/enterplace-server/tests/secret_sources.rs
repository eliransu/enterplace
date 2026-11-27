//! A provider key in a variable that points at a secret manager: read once at start, sent as the key, and taken
//! anew without a restart when the manager rotates it. The open source gateway only plugs a source in
//! (`enterplace_core::secrets`); the licensed binary brings the managers. Here a fake source stands in for them.

use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
    routing::post,
};
use http_body_util::BodyExt;
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const MAYA: &str = "enterplace_maya_0123456789abcdef0123456789";

struct Fake(Arc<Mutex<String>>);

impl enterplace_core::secrets::Source for Fake {
    fn fetch(&self, reference: &str) -> Result<String, String> {
        if reference != "vault://secret/data/enterplace#openai" {
            return Err(format!("no such secret {reference}"));
        }
        self.0.lock().map(|v| v.clone()).map_err(|e| e.to_string())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_from_a_secret_manager_is_sent_and_a_rotated_one_is_taken_without_a_restart()
-> TestResult {
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let record = seen.clone();
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move |headers: HeaderMap| {
            let record = record.clone();
            async move {
                let auth = headers
                    .get(header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                if let Ok(mut seen) = record.lock() {
                    seen.push(auth);
                }
                r#"{"id":"c","object":"chat.completion","choices":[]}"#
            }
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let value = Arc::new(Mutex::new("sk-first".to_string()));
    assert!(enterplace_core::secrets::install(Arc::new(Fake(
        value.clone()
    ))));
    let vars = || {
        [
            (
                "OPENAI_KEY".to_string(),
                "vault://secret/data/enterplace#openai".to_string(),
            ),
            ("PLAIN".to_string(), "not a reference".to_string()),
        ]
        .into_iter()
    };
    assert_eq!(enterplace_core::secrets::load_from(vars())?, 1);
    // A reference that cannot be read stops the start, naming the variable.
    let err = enterplace_core::secrets::load_from(
        [("OTHER".to_string(), "vault://nope#x".to_string())].into_iter(),
    )
    .err()
    .ok_or("an unreadable reference loaded")?;
    assert!(
        err.contains("OTHER (vault://nope#x)") && err.contains("does not start"),
        "{err}"
    );
    enterplace_core::secrets::load_from(vars())?;

    let dir =
        std::env::temp_dir().join(format!("enterplace-secret-sources-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let policy = dir.join("enterplace.policy.yaml");
    std::fs::write(
        &policy,
        format!(
            "version: 1
providers:
  - name: mock
    kind: openai
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: OPENAI_KEY
    models: [m]
rules:
  - name: everyone
    principals: {{ any: true }}
    models: [m]
"
        ),
    )?;
    enterplace_core::keyfile::add_entry(
        "maya",
        "ops",
        MAYA,
        false,
        &dir.join("enterplace.keys.yaml"),
    )?;
    let gw = enterplace_server::governed(&policy, None, &enterplace_core::secrets::var)?;
    let chat = || async {
        let request = Request::post("/v1/chat/completions")
            .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"model":"m","messages":[]}"#))?;
        let response = gw.router.clone().oneshot(request).await?;
        let status = response.status();
        let _ = response.into_body().collect().await?;
        Ok::<StatusCode, Box<dyn std::error::Error>>(status)
    };
    assert_eq!(chat().await?, StatusCode::OK);
    // Rotated in the manager: the next refresh takes it, and the next check of the files puts it on the route.
    *value.lock().map_err(|e| e.to_string())? = "sk-second".into();
    let before = enterplace_core::secrets::generation();
    assert!(enterplace_core::secrets::refresh_from(vars()).is_empty());
    assert_eq!(enterplace_core::secrets::generation(), before + 1);
    gw.reloader.check(enterplace_server::Trigger::FileChange);
    assert_eq!(chat().await?, StatusCode::OK);
    // A manager that fails later keeps the key in hand.
    *value.lock().map_err(|e| e.to_string())? = String::new();
    let problems = enterplace_core::secrets::refresh_from(
        [("OPENAI_KEY".to_string(), "vault://gone#x".to_string())].into_iter(),
    );
    assert!(
        problems.iter().any(|p| p.contains("keeps the value")),
        "{problems:?}"
    );
    assert_eq!(
        enterplace_core::secrets::var("OPENAI_KEY").as_deref(),
        Some("sk-second")
    );
    let seen = seen.lock().map_err(|e| e.to_string())?.clone();
    assert_eq!(seen, ["Bearer sk-first", "Bearer sk-second"]);

    // The rotation and the failed refresh are both in the audit chain: which variable and reference, when, from
    // which manager, and never the value.
    let audit = dir.join("enterplace-audit.jsonl");
    let mut text = String::new();
    // Until the record reads whole: a read can land while the line is still being appended.
    for _ in 0..250 {
        text = std::fs::read_to_string(&audit).unwrap_or_default();
        if text.lines().any(|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .is_ok_and(|r| r["event"] == "secret_refresh_failed")
        }) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    }
    assert!(
        !text.contains("sk-first") && !text.contains("sk-second"),
        "{text}"
    );
    let records: Vec<serde_json::Value> = text
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let rotated = records
        .iter()
        .find(|r| r["event"] == "secret_rotated")
        .ok_or("no rotation record")?;
    assert_eq!(rotated["variable"], "OPENAI_KEY");
    assert_eq!(
        rotated["reference"],
        "vault://secret/data/enterplace#openai"
    );
    assert_eq!(rotated["source"], "vault");
    assert!(rotated["time"].as_str().is_some_and(|t| !t.is_empty()));
    let failed = records
        .iter()
        .find(|r| r["event"] == "secret_refresh_failed")
        .ok_or("no failure record")?;
    assert_eq!(failed["code"], "secret_refresh_failed");
    assert_eq!(failed["reference"], "vault://gone#x");
    assert!(
        failed["reason"]
            .as_str()
            .is_some_and(|r| r.contains("no such secret")),
        "{failed}"
    );
    assert!(enterplace_core::audit::verify(&audit).is_ok());

    // And counted for Prometheus, by manager.
    let response = gw
        .metrics
        .clone()
        .oneshot(Request::get("/metrics").body(Body::empty())?)
        .await?;
    let body = response.into_body().collect().await?.to_bytes();
    let metrics = String::from_utf8_lossy(&body);
    assert!(
        metrics.contains("enterplace_secret_rotations_total{source=\"vault\"} 1"),
        "{metrics}"
    );
    assert!(
        metrics.contains("enterplace_secret_refresh_failures_total{source=\"vault\"} 1"),
        "{metrics}"
    );
    Ok(())
}
