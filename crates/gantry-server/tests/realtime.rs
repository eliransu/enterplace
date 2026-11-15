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
    let app = Router::new()
        .route("/v1/realtime", get(upgrade))
        .route("/custom/live", get(upgrade))
        .route(
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
    gateway_own(name, top, budget, None).await
}

/// As [`gateway_with`], in a binary with an events plugin of its own.
async fn gateway_own(
    name: &str,
    top: &str,
    budget: &str,
    own: Option<std::sync::Arc<dyn gantry_server::EventsPlugin>>,
) -> Result<Gateway, Error> {
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
    let gw = gantry_server::governed_with(
        &policy,
        None,
        &|_| Some("provider-secret".into()),
        &move |_| {
            Ok(gantry_server::Extension {
                events: own.clone(),
                ..gantry_server::Extension::default()
            })
        },
    )
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

/// An events plugin (contract v2) gets each text of a realtime session as an event of one session, a turn per text
/// of the caller's, and a text it blocks is dropped like one a guardrail blocks.
#[tokio::test]
async fn an_events_plugin_sees_realtime_text_as_events_of_one_session() -> Result<(), Error> {
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
    let keep = seen.clone();
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let plugin = listener.local_addr()?.port();
    let app = Router::new().route(
        "/events",
        axum::routing::post(move |body: axum::body::Bytes| {
            let keep = keep.clone();
            async move {
                let sent: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                let block = sent["events"][0]["content"]
                    .as_str()
                    .is_some_and(|c| c.contains("forbidden"));
                if let Ok(mut all) = keep.lock() {
                    all.push(sent);
                }
                let verdict = if block {
                    r#"{"action":"block","findings":[{"kind":"off_purpose","event":0}]}"#
                } else {
                    r#"{"action":"allow"}"#
                };
                ([(header::CONTENT_TYPE, "application/json")], verdict)
            }
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let top = format!(
        "guardrails:\n  - name: watcher\n    type: events\n    url: http://127.0.0.1:{plugin}/events\n    on_failure: fail_closed\n"
    );
    let gw = gateway_with("events", &top, "    guardrails: [watcher]\n").await?;
    let mut socket = connect(gw.port, "/v1/realtime?model=rt-model", DANA).await?;
    socket.send(item("hello")).await?;
    let said = next_text(&mut socket).await?.ok_or("no transcript")?;
    assert!(said.contains("hello"), "{said}");
    socket.send(item("a forbidden thing")).await?;
    let error = next_text(&mut socket).await?.ok_or("no error event")?;
    assert!(
        error.contains("guardrail_blocked") && !error.contains("forbidden"),
        "{error}"
    );
    let seen = seen.lock().map(|s| s.clone()).unwrap_or_default();
    assert_eq!(seen.len(), 3, "{seen:?}");
    let kinds: Vec<&Value> = seen.iter().map(|e| &e["events"][0]["kind"]).collect();
    assert_eq!(
        kinds,
        [
            "realtime_user_message",
            "realtime_assistant_message",
            "realtime_user_message"
        ]
    );
    assert!(seen.iter().all(|e| e["phase"] == "realtime"));
    assert!(
        seen.iter()
            .all(|e| e["session_id"] == seen[0]["session_id"])
    );
    // The transcript is in the turn the caller's text opened; the caller's next text opens another.
    assert_eq!(seen[0]["turn_id"], seen[1]["turn_id"]);
    assert_eq!(seen[1]["events"][0]["event_index"], 1);
    assert_ne!(seen[2]["turn_id"], seen[0]["turn_id"]);
    assert_eq!(seen[2]["turn_index"], 2);
    Ok(())
}

/// A plugin built into the binary: it keeps what it is shown and blocks a text that says "forbidden".
struct Own(std::sync::Arc<std::sync::Mutex<Vec<gantry_core::events::Envelope>>>);

impl gantry_server::EventsPlugin for Own {
    fn judge(
        &self,
        envelope: gantry_core::events::Envelope,
    ) -> gantry_core::store::Pending<gantry_core::events::Verdict> {
        let block = envelope.events.iter().any(|e| {
            e.content
                .as_deref()
                .is_some_and(|c| c.contains("forbidden"))
        });
        if let Ok(mut seen) = self.0.lock() {
            seen.push(envelope);
        }
        Box::pin(async move {
            let mut verdict = gantry_core::events::Verdict::allow();
            if block {
                verdict.action = gantry_core::events::Action::Block;
            }
            Ok(verdict)
        })
    }
}

/// The binary's own plugin sees a realtime session's text on a rule with no guardrail at all, and what it blocks
/// is dropped.
#[tokio::test]
async fn a_binary_s_own_plugin_sees_realtime_text_on_a_rule_with_no_guardrail() -> Result<(), Error>
{
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let gw = gateway_own("own", "", "", Some(std::sync::Arc::new(Own(seen.clone())))).await?;
    let mut socket = connect(gw.port, "/v1/realtime?model=rt-model", DANA).await?;
    socket.send(item("hello")).await?;
    let said = next_text(&mut socket).await?.ok_or("no transcript")?;
    assert!(said.contains("hello"), "{said}");
    socket.send(item("a forbidden thing")).await?;
    let error = next_text(&mut socket).await?.ok_or("no error event")?;
    assert!(
        error.contains("guardrail_blocked") && !error.contains("forbidden"),
        "{error}"
    );
    let seen = seen.lock().map(|s| s.clone()).unwrap_or_default();
    let kinds: Vec<&str> = seen.iter().map(|e| e.events[0].kind.word()).collect();
    assert_eq!(
        kinds,
        [
            "realtime_user_message",
            "realtime_assistant_message",
            "realtime_user_message"
        ]
    );
    assert!(
        seen.iter()
            .all(|e| e.guardrail == "extension" && e.phase == "realtime")
    );
    assert_eq!(seen[0].context.session_id, seen[2].context.session_id);
    Ok(())
}

/// A forward proxy that takes HTTP CONNECT and records each request head, then joins the two ends.
async fn connect_proxy() -> Result<(u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>), Error> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let log = log.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if client.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    head.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&head).to_string();
                if let Ok(mut log) = log.lock() {
                    log.push(head.clone());
                }
                let Some(target) = head
                    .lines()
                    .next()
                    .and_then(|l| l.strip_prefix("CONNECT "))
                    .and_then(|l| l.split(' ').next())
                else {
                    return;
                };
                let Ok(mut upstream) = tokio::net::TcpStream::connect(target).await else {
                    return;
                };
                if client.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.is_ok() {
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                }
            });
        }
    });
    Ok((port, seen))
}

/// A realtime session to a provider with `proxy_env` is opened through that proxy, with its `headers_env`.
#[tokio::test]
async fn a_realtime_session_goes_through_the_provider_s_proxy() -> Result<(), Error> {
    let upstream = provider().await?;
    let (proxy, through) = connect_proxy().await?;
    let dir = std::env::temp_dir().join(format!("gantry-realtime-{}-proxy", std::process::id()));
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
    url: http://127.0.0.1:{upstream}
    allow_private: true
    key_env: MOCK_KEY
    proxy_env: EGRESS_PROXY
    headers_env: {{ x-team-id: TEAM_HEADER }}
    models: [rt-model]
rules:
  - name: data
    principals: {{ team: data }}
    models: [rt-model]
"
        ),
    )?;
    std::fs::write(
        dir.join("gantry.keys.yaml"),
        format!(
            "keys:\n  - name: dana\n    team: data\n    sha256: {}\n",
            sha256_hex(DANA.as_bytes())
        ),
    )?;
    let gw = gantry_server::governed(&policy, None, &|name| match name {
        "EGRESS_PROXY" => Some(format!("http://gw:s3cret@127.0.0.1:{proxy}")),
        "TEAM_HEADER" => Some("data-7".into()),
        _ => Some("provider-secret".into()),
    })
    .map_err(|e| -> Error { e.into() })?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let served = gw.router.clone();
    tokio::spawn(async move {
        let _ = axum::serve(listener, served).await;
    });
    let mut socket = connect(port, "/v1/realtime?model=rt-model", DANA).await?;
    socket
        .send(Message::Text(r#"{"type":"response.create"}"#.into()))
        .await?;
    let delta = next_text(&mut socket).await?.ok_or("no delta")?;
    assert!(delta.contains("response.output_audio.delta"), "{delta}");
    let heads = through.lock().map_err(|_| "poisoned")?.clone();
    let head = heads
        .first()
        .ok_or("the session did not go through the proxy")?;
    assert!(
        head.starts_with(&format!("CONNECT 127.0.0.1:{upstream} ")),
        "{head}"
    );
    assert!(head.contains("Basic Z3c6czNjcmV0"), "{head}");
    Ok(())
}

/// A provider's own WebSocket API, reached on `/passthrough/<provider>/<path>` on a path the rule lists: decided at
/// connect, relayed frame for frame with the provider's key, screened by the rule's guardrails, and recorded.
#[tokio::test]
async fn a_websocket_passthrough_is_relayed_on_listed_paths_only_and_recorded() -> Result<(), Error>
{
    let top = "guardrails:\n  - name: no-secrets\n    type: secrets\n    action: block\n";
    let gw = gateway_with(
        "ws-passthrough",
        top,
        "    guardrails: [no-secrets]\n    passthrough:\n      - { provider: mock, paths: [/custom/live] }\n",
    )
    .await?;
    let mut socket = connect(gw.port, "/passthrough/mock/custom/live?voice=alloy", DANA).await?;
    socket
        .send(Message::Text(r#"{"type":"anything","text":"hi"}"#.into()))
        .await?;
    let relayed = next_text(&mut socket).await?.ok_or("nothing relayed")?;
    assert!(relayed.contains("response.output_audio.delta"), "{relayed}");
    // A frame with a secret ends the session: an unknown protocol has no error event to answer with.
    socket
        .send(Message::Text(
            r#"{"type":"anything","text":"AKIAIOSFODNN7EXAMPLE"}"#.into(),
        ))
        .await?;
    while next_text(&mut socket).await?.is_some() {}
    let session = wait_for(&gw.audit, |r| r["event"] == "realtime_session").await?;
    assert_eq!(
        (
            session["api"].as_str(),
            session["path"].as_str(),
            session["person"].as_str(),
            session["ended_by"].as_str()
        ),
        (
            Some("websocket_passthrough"),
            Some("/custom/live"),
            Some("dana"),
            Some("guardrail")
        )
    );
    let decision = wait_for(&gw.audit, |r| {
        r["path"] == "/passthrough/mock/custom/live" && r["event"].is_null()
    })
    .await?;
    assert_eq!(decision["verdict"], "allow");
    let text = std::fs::read_to_string(&gw.audit)?;
    assert!(
        !text.contains("AKIA") && !text.contains("alloy"),
        "no content or query is recorded"
    );

    // A path the rule does not list, and an unknown key, are refused before the provider is dialled.
    assert_eq!(
        refused_with(connect(gw.port, "/passthrough/mock/other", DANA).await),
        Some(403)
    );
    assert_eq!(
        refused_with(connect(gw.port, "/passthrough/mock/custom/../live", DANA).await),
        Some(403)
    );
    assert_eq!(
        refused_with(
            connect(
                gw.port,
                "/passthrough/mock/custom/live",
                "gantry_nobody_000000000000"
            )
            .await
        ),
        Some(401)
    );
    Ok(())
}
