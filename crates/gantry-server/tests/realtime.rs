//! Acceptance tests for realtime sessions (OpenAI Realtime and Gemini Live over WebSocket): identified and decided at
//! connect, events relayed both ways, each response metered from the provider's usage event, a kill switch or a spent
//! budget ends the session, and the session is recorded without its content.

use std::{path::PathBuf, time::Duration};

use axum::{
    Router,
    body::Body,
    extract::ws::{Message as ServerMessage, WebSocket, WebSocketUpgrade},
    http::{Request, StatusCode, header},
    response::Response,
    routing::get,
};
use futures_util::{SinkExt, StreamExt};
use gantry_core::id::sha256_hex;
use serde_json::Value;
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};
use tower::ServiceExt;

type Error = Box<dyn std::error::Error + Send + Sync>;

const DANA: &str = "gantry_realtime_dana_key_00000000";
const ADMIN: &str = "gantry_realtime_admin_key_0000000";

/// A provider that answers every client event with an audio delta and a response.done carrying usage.
async fn openai_session(mut socket: WebSocket) {
    while let Some(Ok(message)) = socket.next().await {
        let ServerMessage::Text(text) = message else {
            continue;
        };
        // A text item is answered with the transcript of saying it back, so a test controls what the model "said".
        if text.contains("conversation.item.create") {
            let said = serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|e| e["item"]["content"][0]["text"].as_str().map(String::from))
                .unwrap_or_default();
            let done = serde_json::json!({"type": "response.output_audio_transcript.done", "transcript": said});
            let _ = socket
                .send(ServerMessage::Text(done.to_string().into()))
                .await;
            continue;
        }
        if text.contains("setup") {
            let _ = socket
                .send(ServerMessage::Text(r#"{"setupComplete":{}}"#.into()))
                .await;
            let _ = socket
                .send(ServerMessage::Text(
                    r#"{"serverContent":{"turnComplete":true},"usageMetadata":{"promptTokenCount":100,"responseTokenCount":50,"totalTokenCount":150,"promptTokensDetails":[{"modality":"TEXT","tokenCount":60},{"modality":"AUDIO","tokenCount":40}],"responseTokensDetails":[{"modality":"AUDIO","tokenCount":30},{"modality":"TEXT","tokenCount":20}]}}"#.into(),
                ))
                .await;
            continue;
        }
        let _ = socket
            .send(ServerMessage::Text(
                r#"{"type":"response.output_audio.delta","delta":"AAAA"}"#.into(),
            ))
            .await;
        let done = if text.contains("audio") {
            r#"{"type":"response.done","response":{"id":"resp_2","usage":{"total_tokens":1500,"input_tokens":1000,"output_tokens":500,"input_token_details":{"text_tokens":400,"audio_tokens":600,"cached_tokens":300,"cached_tokens_details":{"text_tokens":100,"audio_tokens":200}},"output_token_details":{"text_tokens":100,"audio_tokens":400}}}}"#
        } else {
            r#"{"type":"response.done","response":{"id":"resp_1","usage":{"total_tokens":150,"input_tokens":100,"output_tokens":50,"input_token_details":{"cached_tokens":0}}}}"#
        };
        let _ = socket.send(ServerMessage::Text(done.into())).await;
    }
}

async fn provider() -> Result<u16, Error> {
    let upgrade = |ws: WebSocketUpgrade| async move { ws.on_upgrade(openai_session) };
    let app = Router::new().route("/v1/realtime", get(upgrade)).route(
        "/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent",
        get(upgrade),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

struct Gateway {
    port: u16,
    router: Router,
    audit: PathBuf,
}

async fn gateway(name: &str, budget: &str) -> Result<Gateway, Error> {
    gateway_with(name, "", budget).await
}

async fn gateway_with(name: &str, top: &str, budget: &str) -> Result<Gateway, Error> {
    let port = provider().await?;
    let dir = std::env::temp_dir().join(format!("gantry-realtime-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let policy = dir.join("gantry.policy.yaml");
    std::fs::write(
        &policy,
        format!(
            "version: 1
providers:
  - name: mock
    kind: openai
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: MOCK_KEY
    models: [rt-model]
  - name: gem
    kind: gemini
    url: http://127.0.0.1:{port}
    allow_private: true
    key_env: MOCK_KEY
    models: [live-model]
prices:
  rt-model: {{ input: 1000, output: 2000, cache_read: 100, input_audio: 10000, output_audio: 20000, cache_read_audio: 500 }}
  live-model: {{ input: 1000, output: 2000 }}
{top}rules:
  - name: data
    principals: {{ team: data }}
    models: [rt-model, live-model]
{budget}"
        ),
    )?;
    std::fs::write(
        dir.join("gantry.keys.yaml"),
        format!(
            "keys:\n  - name: dana\n    team: data\n    sha256: {}\n  - name: ops\n    team: ops\n    sha256: {}\n    admin: true\n",
            sha256_hex(DANA.as_bytes()),
            sha256_hex(ADMIN.as_bytes())
        ),
    )?;
    let gw = gantry_server::governed(&policy, None, &|_| Some("provider-secret".into()))
        .map_err(|e| -> Error { e.into() })?;
    let router = gw.router.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let gantry = listener.local_addr()?.port();
    let served = router.clone();
    tokio::spawn(async move {
        let _ = axum::serve(listener, served).await;
    });
    Ok(Gateway {
        port: gantry,
        router,
        audit: dir.join("gantry-audit.jsonl"),
    })
}

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect(
    port: u16,
    path: &str,
    key: &str,
) -> Result<Socket, tokio_tungstenite::tungstenite::Error> {
    let mut request = format!("ws://127.0.0.1:{port}{path}").into_client_request()?;
    if let Ok(value) = format!("Bearer {key}").parse() {
        request.headers_mut().insert(header::AUTHORIZATION, value);
    }
    request.headers_mut().insert(
        header::USER_AGENT,
        header::HeaderValue::from_static("live-client/1.0"),
    );
    tokio_tungstenite::connect_async(request)
        .await
        .map(|(socket, _)| socket)
}

fn refused_with(result: Result<Socket, tokio_tungstenite::tungstenite::Error>) -> Option<u16> {
    match result {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            Some(response.status().as_u16())
        }
        _ => None,
    }
}

async fn next_text(socket: &mut Socket) -> Result<Option<String>, Error> {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), socket.next()).await? {
            Some(Ok(Message::Text(text))) => return Ok(Some(text.to_string())),
            Some(Ok(Message::Close(_))) | None => return Ok(None),
            Some(Ok(_)) => continue,
            Some(Err(_)) => return Ok(None),
        }
    }
}

fn records(path: &PathBuf) -> Result<Vec<Value>, Error> {
    std::fs::read_to_string(path)?
        .lines()
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

async fn wait_for(path: &PathBuf, test: impl Fn(&Value) -> bool) -> Result<Value, Error> {
    for _ in 0..100 {
        if let Some(found) = records(path)?.into_iter().find(|r| test(r)) {
            return Ok(found);
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    Err("the record never came".into())
}

#[tokio::test]
async fn a_session_is_decided_at_connect() -> Result<(), Error> {
    let gw = gateway("decided", "").await?;
    assert_eq!(
        refused_with(connect(gw.port, "/v1/realtime?model=rt-model", "nobody").await),
        Some(401),
        "an unknown key never reaches the provider"
    );
    assert_eq!(
        refused_with(connect(gw.port, "/v1/realtime?model=gpt-9", DANA).await),
        Some(403),
        "a model the rule does not allow is refused at connect"
    );
    assert_eq!(
        refused_with(connect(gw.port, "/v1/realtime", DANA).await),
        Some(400),
        "the model is needed to decide"
    );
    let refused = records(&gw.audit)?
        .into_iter()
        .filter(|r| r["path"] == "/v1/realtime" && r["verdict"] == "refused")
        .count();
    assert_eq!(refused, 3, "each refusal is recorded");
    Ok(())
}

#[tokio::test]
async fn events_are_relayed_and_each_response_is_metered_and_the_session_recorded()
-> Result<(), Error> {
    let gw = gateway("relay", "").await?;
    let mut socket = connect(gw.port, "/v1/realtime?model=rt-model", DANA).await?;
    socket
        .send(Message::Text(r#"{"type":"response.create"}"#.into()))
        .await?;
    let delta = next_text(&mut socket).await?.ok_or("no delta")?;
    assert!(delta.contains("response.output_audio.delta"), "{delta}");
    let done = next_text(&mut socket).await?.ok_or("no done")?;
    assert!(done.contains("response.done"), "{done}");
    let usage = wait_for(&gw.audit, |r| {
        r["event"] == "usage" && r["session"].is_string()
    })
    .await?;
    assert_eq!(usage["input_tokens"], 100);
    assert_eq!(usage["output_tokens"], 50);
    let charged = usage["charged_usd"].as_f64().ok_or("no charge")?;
    assert!(
        (charged - (100.0 * 1000.0 + 50.0 * 2000.0) / 1e6).abs() < 1e-9,
        "{charged}"
    );
    socket.close(None).await?;
    let session = wait_for(&gw.audit, |r| r["event"] == "realtime_session").await?;
    assert_eq!(session["person"], "dana");
    assert_eq!(session["responses"], 1);
    assert_eq!(session["ended_by"], "client");
    let text = std::fs::read_to_string(&gw.audit)?;
    assert!(!text.contains("AAAA"), "no content is recorded");
    Ok(())
}

#[tokio::test]
async fn a_spent_budget_ends_the_session() -> Result<(), Error> {
    let gw = gateway("budget", "    budget: { usd: 0.1, per: month }\n").await?;
    let mut socket = connect(gw.port, "/v1/realtime?model=rt-model", DANA).await?;
    socket
        .send(Message::Text(r#"{"type":"response.create"}"#.into()))
        .await?;
    let mut ended = false;
    for _ in 0..5 {
        match next_text(&mut socket).await? {
            None => {
                ended = true;
                break;
            }
            Some(text) if text.contains("budget_exceeded") => {}
            Some(_) => {}
        }
    }
    assert!(ended, "the session ends once its response spent the budget");
    let session = wait_for(&gw.audit, |r| r["event"] == "realtime_session").await?;
    assert_eq!(session["ended_by"], "budget");
    // The budget is spent, so the next session is refused at connect.
    assert_eq!(
        refused_with(connect(gw.port, "/v1/realtime?model=rt-model", DANA).await),
        Some(429)
    );
    Ok(())
}

#[tokio::test]
async fn a_kill_switch_ends_a_session_in_flight() -> Result<(), Error> {
    let gw = gateway("kill", "").await?;
    let mut socket = connect(gw.port, "/v1/realtime?model=rt-model", DANA).await?;
    let response = gw
        .router
        .clone()
        .oneshot(
            Request::post("/admin/kills")
                .header(header::AUTHORIZATION, format!("Bearer {ADMIN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"scope":"person","value":"dana","reason":"incident"}"#,
                ))?,
        )
        .await?;
    let status: StatusCode = Response::status(&response);
    assert!(status.is_success(), "{status}");
    let mut ended = false;
    for _ in 0..5 {
        if next_text(&mut socket).await?.is_none() {
            ended = true;
            break;
        }
    }
    assert!(ended, "the kill switch closes the session");
    let session = wait_for(&gw.audit, |r| r["event"] == "realtime_session").await?;
    assert_eq!(session["ended_by"], "killed");
    Ok(())
}

#[tokio::test]
async fn a_gemini_live_session_is_decided_on_its_setup_and_metered() -> Result<(), Error> {
    let gw = gateway("gemini", "").await?;
    let path = "/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent";
    let mut socket = connect(gw.port, path, DANA).await?;
    socket
        .send(Message::Text(
            r#"{"setup":{"model":"models/gpt-9"}}"#.into(),
        ))
        .await?;
    assert!(
        next_text(&mut socket).await?.is_none(),
        "a model the rule does not allow closes it"
    );

    let mut socket = connect(gw.port, path, DANA).await?;
    socket
        .send(Message::Text(
            r#"{"setup":{"model":"models/live-model"}}"#.into(),
        ))
        .await?;
    let first = next_text(&mut socket).await?.ok_or("no setup answer")?;
    assert!(first.contains("setupComplete"), "{first}");
    // The decision is recorded once the setup names the model, with the tool it came from, as at connect.
    let decided = records(&gw.audit)?
        .into_iter()
        .filter(|r| r["path"] == path && r["event"] != "usage" && r["model"] == "live-model")
        .next_back()
        .ok_or("no decision record for the setup")?;
    assert_eq!(decided["user_agent"], "live-client/1.0", "{decided}");
    let usage = wait_for(&gw.audit, |r| {
        r["event"] == "usage" && r["model"] == "live-model"
    })
    .await?;
    // The details split prompt and answer by modality: audio is counted apart, at the model's audio price when set.
    assert_eq!(usage["input_tokens"], 60);
    assert_eq!(usage["input_audio_tokens"], 40);
    assert_eq!(usage["output_tokens"], 20);
    assert_eq!(usage["output_audio_tokens"], 30);
    Ok(())
}

#[tokio::test]
async fn realtime_audio_and_text_tokens_are_priced_apart_and_recorded_apart() -> Result<(), Error> {
    let gw = gateway("audio", "").await?;
    let mut socket = connect(gw.port, "/v1/realtime?model=rt-model", DANA).await?;
    socket
        .send(Message::Text(
            r#"{"type":"response.create","response":{"modalities":["audio"]}}"#.into(),
        ))
        .await?;
    next_text(&mut socket).await?.ok_or("no delta")?;
    next_text(&mut socket).await?.ok_or("no done")?;
    let usage = wait_for(&gw.audit, |r| {
        r["event"] == "usage" && r["response"] == "resp_2"
    })
    .await?;
    // 1000 prompt tokens: 300 cached (200 of them audio), 600 audio of which 400 not cached, 300 text not cached.
    assert_eq!(usage["input_tokens"], 300, "{usage}");
    assert_eq!(usage["cache_read_tokens"], 100);
    assert_eq!(usage["input_audio_tokens"], 400);
    assert_eq!(usage["cache_read_audio_tokens"], 200);
    assert_eq!(usage["output_tokens"], 100);
    assert_eq!(usage["output_audio_tokens"], 400);
    let want = (300.0 * 1000.0
        + 100.0 * 100.0
        + 400.0 * 10000.0
        + 200.0 * 500.0
        + 100.0 * 2000.0
        + 400.0 * 20000.0)
        / 1e6;
    let charged = usage["charged_usd"].as_f64().ok_or("no charge")?;
    assert!((charged - want).abs() < 1e-9, "{charged} != {want}");
    Ok(())
}

fn item(text: &str) -> Message {
    let event = serde_json::json!({"type": "conversation.item.create", "item": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": text}]}});
    Message::Text(event.to_string().into())
}

#[tokio::test]
async fn guardrails_drop_a_blocked_text_event_and_end_the_session_on_a_blocked_transcript()
-> Result<(), Error> {
    let top = "guardrails:\n  - name: no-secrets\n    type: secrets\n    action: block\n  - name: no-pii-said\n    type: pii\n    action: block\n    on: [answer]\n";
    let gw = gateway_with(
        "guarded",
        top,
        "    guardrails: [no-secrets, no-pii-said]\n",
    )
    .await?;
    let mut socket = connect(gw.port, "/v1/realtime?model=rt-model", DANA).await?;

    // A caller's text event with a secret is dropped: an error comes back and the session goes on.
    socket
        .send(item("deploy with AKIAIOSFODNN7EXAMPLE"))
        .await?;
    let error = next_text(&mut socket).await?.ok_or("no error event")?;
    assert!(
        error.contains("guardrail_blocked") && !error.contains("AKIA"),
        "{error}"
    );
    socket.send(item("hello")).await?;
    let said = next_text(&mut socket).await?.ok_or("no transcript")?;
    assert!(
        said.contains("output_audio_transcript.done") && said.contains("hello"),
        "{said}"
    );

    // The model saying an address (the transcript) ends the session.
    socket.send(item("mail maya@corp.example.com")).await?;
    let mut ended = false;
    while let Some(text) = next_text(&mut socket).await? {
        ended |= text.contains("guardrail_blocked");
    }
    assert!(ended, "the session was not ended by the guardrail");
    let session = wait_for(&gw.audit, |r| r["event"] == "realtime_session").await?;
    assert_eq!(session["ended_by"], "guardrail");
    let kinds: Vec<&str> = session["guardrails"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|e| e["kind"].as_str())
        .collect();
    assert_eq!(kinds, ["aws_access_key", "email_address"]);
    let text = std::fs::read_to_string(&gw.audit)?;
    assert!(
        !text.contains("maya@corp") && !text.contains("AKIA"),
        "no content is recorded"
    );
    Ok(())
}
