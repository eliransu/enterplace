//! Cursor's requests as its public docs describe them, through Enterplace: the key as an OpenAI API key (a bearer token),
//! the base URL with /v1, the model list it checks the key with, and streamed chat completions for an exact model
//! name. Not a run of Cursor itself: Cursor's servers send these requests, so a Enterplace they can reach is needed
//! (docs/src/content/docs/integrations/cursor.mdx).

use axum::{
    Router,
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
    routing::post,
};
use enterplace_core::id::sha256_hex;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const KEY: &str = "enterplace_cursor_0123456789abcdef0123456789";

#[tokio::test(flavor = "multi_thread")]
async fn cursors_documented_requests_pass_and_an_unlisted_model_is_refused() -> TestResult {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let app = Router::new().route(
        "/v1/chat/completions",
        post(|_: Bytes| async {
            let chunk = json!({"id": "c", "object": "chat.completion.chunk", "model": "gpt-4o-mini", "choices": [{"index": 0, "delta": {"content": "hi"}, "finish_reason": "stop"}]});
            (
                [(header::CONTENT_TYPE, "text/event-stream")],
                format!("data: {chunk}\n\ndata: [DONE]\n\n"),
            )
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let dir = std::env::temp_dir().join(format!("enterplace-cursor-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let policy = dir.join("enterplace.policy.yaml");
    std::fs::write(
        &policy,
        format!(
            "version: 1\nproviders:\n  - name: openai\n    kind: openai\n    url: http://127.0.0.1:{port}\n    allow_private: true\n    key_env: K\n    models: [gpt-4o-mini, gpt-4o]\nrules:\n  - name: devs\n    principals: {{ team: devs }}\n    models: [gpt-4o-mini]\n"
        ),
    )?;
    std::fs::write(
        dir.join("enterplace.keys.yaml"),
        format!(
            "keys:\n  - name: dana\n    team: devs\n    sha256: {}\n",
            sha256_hex(KEY.as_bytes())
        ),
    )?;
    let gw = enterplace_server::governed(&policy, None, &|_| Some("k".into()))?;
    let send = |method: &str, path: &str, body: Option<Value>| {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {KEY}"))
            .header(header::USER_AGENT, "Cursor/1.0")
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())));
        let router = gw.router.clone();
        async move {
            let response = router.oneshot(request?).await?;
            let status = response.status();
            let bytes = response.into_body().collect().await?.to_bytes();
            Ok::<_, Box<dyn std::error::Error>>((status, String::from_utf8(bytes.to_vec())?))
        }
    };
    // Cursor checks the key with the model list.
    let (status, models) = send("GET", "/v1/models", None).await?;
    assert_eq!(status, StatusCode::OK, "{models}");
    assert!(models.contains("gpt-4o-mini"), "{models}");
    // Chat and agent: streamed chat completions for the exact model name.
    let chat = |model: &str| json!({"model": model, "stream": true, "messages": [{"role": "system", "content": "You are a coding assistant."}, {"role": "user", "content": "hi"}]});
    let (status, streamed) =
        send("POST", "/v1/chat/completions", Some(chat("gpt-4o-mini"))).await?;
    assert_eq!(status, StatusCode::OK, "{streamed}");
    assert!(streamed.contains("\"hi\""), "{streamed}");
    // A model from Cursor's own list goes to Enterplace too, and the rule refuses it by name.
    let (status, refused) = send("POST", "/v1/chat/completions", Some(chat("gpt-4o"))).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
    assert!(refused.contains("model_not_allowed"), "{refused}");
    let audit = std::fs::read_to_string(dir.join("enterplace-audit.jsonl"))?;
    assert!(audit.contains("Cursor/1.0"), "the record names the tool");
    Ok(())
}
