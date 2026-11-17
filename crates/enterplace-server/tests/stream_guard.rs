//! Acceptance test for package 3.4: with `check_stream_every`, a blocking webhook stops a streamed answer partway.
//! The caller gets what was checked, then an error event, and never the text the webhook blocked.

use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    Router,
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
    response::IntoResponse,
    routing::post,
};
use enterplace_core::id::sha256_hex;
use http_body::Frame;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type Error = Box<dyn std::error::Error>;
const KEY: &str = "enterplace_stream_guard_key";

/// A response body fed piece by piece, as a model's tokens arrive.
struct Trickle(tokio::sync::mpsc::Receiver<Bytes>);

impl http_body::Body for Trickle {
    type Data = Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        self.0.poll_recv(cx).map(|b| b.map(|b| Ok(Frame::data(b))))
    }
}

/// The provider: twelve innocent pieces, the forbidden word, then more text, each piece 20 ms apart.
async fn provider() -> Result<u16, Error> {
    let app = Router::new().route(
        "/v1/chat/completions",
        post(|| async {
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                let chunk = |piece: &str| {
                    format!("data: {}\n\n", json!({"id": "c", "model": "model-a", "choices": [{"index": 0, "delta": {"content": piece}, "finish_reason": null}]}))
                };
                let mut pieces: Vec<String> = (0..12).map(|i| format!("Sentence {i} is fine. ")).collect();
                pieces.push("The code word is BANANA. ".into());
                pieces.extend((0..6).map(|i| format!("After {i}. ")));
                for piece in pieces {
                    if tx.send(Bytes::from(chunk(&piece))).await.is_err() {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                let _ = tx.send(Bytes::from("data: [DONE]\n\n")).await;
            });
            ([(header::CONTENT_TYPE, "text/event-stream")], Body::new(Trickle(rx))).into_response()
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

/// The webhook: blocks any text holding the code word, and keeps how many checks it was asked for.
async fn webhook() -> Result<(u16, Arc<Mutex<usize>>), Error> {
    let asked = Arc::new(Mutex::new(0usize));
    let count = asked.clone();
    let app = Router::new().route(
        "/check",
        post(move |body: Bytes| {
            if let Ok(mut n) = count.lock() {
                *n += 1;
            }
            let bad = String::from_utf8_lossy(&body).contains("BANANA");
            async move {
                if bad {
                    r#"{"action":"block","findings":[{"kind":"code_word"}]}"#
                } else {
                    r#"{"action":"allow"}"#
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((port, asked))
}

#[tokio::test]
async fn a_blocking_webhook_stops_a_stream_partway_and_the_blocked_text_never_leaves()
-> Result<(), Error> {
    let provider = provider().await?;
    let (hook, asked) = webhook().await?;
    let dir = std::env::temp_dir().join(format!("enterplace-stream-guard-{}", std::process::id()));
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
    url: http://127.0.0.1:{provider}
    allow_private: true
    key_env: MOCK_KEY
    models: [model-a]
guardrails:
  - name: vendor
    type: webhook
    url: http://127.0.0.1:{hook}/check
    on_failure: fail_closed
    on: [answer]
rules:
  - name: everyone
    principals: {{ any: true }}
    models: [model-a]
    guardrails: [vendor]
    check_stream_every: 60
"
        ),
    )?;
    std::fs::write(
        dir.join("enterplace.keys.yaml"),
        format!(
            "keys:\n  - name: maya\n    team: t\n    sha256: {}\n",
            sha256_hex(KEY.as_bytes())
        ),
    )?;
    let gw = enterplace_server::governed(&policy, None, &|_| Some("provider-secret".into()))?;
    let response = gw
        .router
        .clone()
        .oneshot(
            Request::post("/v1/chat/completions")
                .header(header::AUTHORIZATION, format!("Bearer {KEY}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"model":"model-a","stream":true,"messages":[{"role":"user","content":"hi"}]}"#))?,
        )
        .await?;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the stream starts before anything is blocked"
    );
    let body = String::from_utf8(response.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(
        body.contains("Sentence 0 is fine"),
        "checked text reached the caller: {body}"
    );
    assert!(
        !body.contains("BANANA"),
        "the blocked text never left: {body}"
    );
    assert!(
        !body.contains("After"),
        "nothing after the block left: {body}"
    );
    let last = body.trim_end().lines().last().unwrap_or_default();
    let error: Value = serde_json::from_str(last.strip_prefix("data: ").unwrap_or(last))?;
    assert_eq!(error["error"]["code"], "guardrail_blocked", "{body}");
    assert!(
        *asked.lock().map_err(|_| "poisoned")? >= 3,
        "the answer was checked as it came, not once"
    );

    let mut verdict = None;
    for _ in 0..50 {
        verdict = std::fs::read_to_string(dir.join("enterplace-audit.jsonl"))?
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .find(|r| r["event"] == "answer_guardrails");
        if verdict.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let verdict = verdict.ok_or("no answer_guardrails record")?;
    assert_eq!(verdict["verdict"], "block", "{verdict}");
    Ok(())
}
