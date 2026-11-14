//! Acceptance tests for plugin events (contract v2, docs/governance/plugin-events): an outside service follows a
//! whole agent conversation as typed events with stable session and turn ids, on every API the gateway serves, and
//! its verdicts are obeyed: a tool call blocked in an answer, a tool result masked in the next request, a held
//! stream stopped partway, a session ended. An observing plugin never delays a request. The provider, the plugin and
//! the MCP server are mocks on this machine; one test runs the reference plugin in examples/plugins.

use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::{Body, Bytes},
    http::{HeaderMap, Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use gantry_core::{
    events::{Envelope, Verdict},
    id::sha256_hex,
};
use gantry_server::{EventsPlugin, Extension, Governed};
use http_body::Frame;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Error = Box<dyn std::error::Error>;

const MAYA: &str = "gantry_maya_0123456789abcdef0123456789";
/// The signing secret: the guardrails name CARGO_MANIFEST_DIR in `secret_env`, a variable cargo sets, because
/// setting one needs `unsafe`.
const SECRET: &str = env!("CARGO_MANIFEST_DIR");

async fn serve(app: Router) -> Result<u16, Error> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

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

fn json_answer(body: Value) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

/// Every request body the provider was sent, in order.
type Sent = Arc<Mutex<Vec<Value>>>;

const USAGE: &str = r#"{"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10}"#;

/// The provider, on all four APIs: asked about the weather it calls `get_weather`, given the tool's result it
/// answers in words, and anything else it answers "ok". A chat request with `stream` gets twelve innocent
/// sentences, the code word, then more, 10 ms apart.
async fn provider() -> Result<(u16, Sent), Error> {
    let sent = Sent::default();
    let keep = |sent: &Sent, body: &Bytes| {
        let value: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        if let Ok(mut all) = sent.lock() {
            all.push(value.clone());
        }
        value
    };
    let has = |body: &Value, needle: &str| body.to_string().contains(needle);
    let (a, b, c, d) = (sent.clone(), sent.clone(), sent.clone(), sent.clone());
    let app = Router::new()
        .route(
            "/v1/chat/completions",
            post(move |body: Bytes| {
                let sent = a.clone();
                async move {
                    let body = keep(&sent, &body);
                    if body["stream"] == true {
                        let (tx, rx) = tokio::sync::mpsc::channel(4);
                        tokio::spawn(async move {
                            let chunk = |piece: &str| {
                                format!("data: {}\n\n", json!({"id": "c", "model": "model-a", "choices": [{"index": 0, "delta": {"content": piece}, "finish_reason": null}]}))
                            };
                            let mut pieces: Vec<String> =
                                (0..12).map(|i| format!("Sentence {i} is fine. ")).collect();
                            pieces.push("The code word is BANANA. ".into());
                            pieces.extend((0..6).map(|i| format!("After {i}. ")));
                            for piece in pieces {
                                if tx.send(Bytes::from(chunk(&piece))).await.is_err() {
                                    return;
                                }
                                tokio::time::sleep(Duration::from_millis(10)).await;
                            }
                            let _ = tx.send(Bytes::from("data: [DONE]\n\n")).await;
                        });
                        return ([(header::CONTENT_TYPE, "text/event-stream")], Body::new(Trickle(rx)))
                            .into_response();
                    }
                    let message = if has(&body, "\"role\":\"tool\"") {
                        json!({"role": "assistant", "content": "It is 18C in Paris."})
                    } else if has(&body, "weather") {
                        json!({"role": "assistant", "content": null, "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "get_weather", "arguments": "{\"city\":\"Paris\"}"}}]})
                    } else {
                        json!({"role": "assistant", "content": "ok"})
                    };
                    let usage: Value = serde_json::from_str(USAGE).unwrap_or(Value::Null);
                    json_answer(json!({"id": "c", "object": "chat.completion", "model": "model-a", "choices": [{"index": 0, "finish_reason": "stop", "message": message}], "usage": usage}))
                }
            }),
        )
        .route(
            "/v1/messages",
            post(move |body: Bytes| {
                let sent = b.clone();
                async move {
                    let body = keep(&sent, &body);
                    let content = if has(&body, "tool_result") {
                        json!([{"type": "text", "text": "It is 18C in Paris."}])
                    } else {
                        json!([{"type": "tool_use", "id": "call_1", "name": "get_weather", "input": {"city": "Paris"}}])
                    };
                    json_answer(json!({"id": "m", "type": "message", "role": "assistant", "model": "claude-a", "content": content, "stop_reason": "end_turn", "usage": {"input_tokens": 5, "output_tokens": 5}}))
                }
            }),
        )
        .route(
            "/v1/responses",
            post(move |body: Bytes| {
                let sent = c.clone();
                async move {
                    let body = keep(&sent, &body);
                    let output = if has(&body, "function_call_output") {
                        json!([{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "It is 18C in Paris."}]}])
                    } else {
                        json!([{"type": "function_call", "call_id": "call_1", "name": "get_weather", "arguments": "{\"city\":\"Paris\"}"}])
                    };
                    json_answer(json!({"id": "r", "object": "response", "status": "completed", "model": "model-a", "output": output, "usage": {"input_tokens": 5, "output_tokens": 5, "total_tokens": 10}}))
                }
            }),
        )
        .route(
            "/v1beta/models/{call}",
            post(move |body: Bytes| {
                let sent = d.clone();
                async move {
                    let body = keep(&sent, &body);
                    let parts = if has(&body, "functionResponse") {
                        json!([{"text": "It is 18C in Paris."}])
                    } else {
                        json!([{"functionCall": {"id": "call_1", "name": "get_weather", "args": {"city": "Paris"}}}])
                    };
                    json_answer(json!({"candidates": [{"index": 0, "finishReason": "STOP", "content": {"role": "model", "parts": parts}}], "usageMetadata": {"promptTokenCount": 5, "candidatesTokenCount": 5, "totalTokenCount": 10}}))
                }
            }),
        );
    Ok((serve(app).await?, sent))
}

/// What the mock plugin does with what it is sent.
#[derive(Clone, Default)]
struct Behave {
    /// Blocks a tool call (the model's or an MCP one) of this tool.
    block_tool: Option<String>,
    /// Masks every tool result with "[masked]".
    mask_results: bool,
    /// Blocks an event whose text holds this.
    block_text: Option<String>,
    /// Blocks an event whose text holds this, and ends the session.
    end_on: Option<String>,
    /// Waits this long before answering.
    delay: Duration,
    /// Answers 500.
    broken: bool,
}

#[derive(Clone, Default)]
struct Plugin {
    behave: Arc<Mutex<Behave>>,
    /// Every envelope received, a batch's each on its own.
    envelopes: Arc<Mutex<Vec<Value>>>,
    /// Deliveries whose Standard Webhooks signature did not check out under `SECRET`.
    unsigned: Arc<Mutex<usize>>,
}

impl Plugin {
    fn set(&self, change: impl FnOnce(&mut Behave)) {
        if let Ok(mut behave) = self.behave.lock() {
            change(&mut behave);
        }
    }

    fn envelopes(&self) -> Vec<Value> {
        self.envelopes.lock().map(|e| e.clone()).unwrap_or_default()
    }

    /// Every event received, as (phase, index, kind, text, tool, call id, arguments, last in turn).
    fn events(&self) -> Vec<Value> {
        self.envelopes()
            .iter()
            .flat_map(|envelope| {
                let phase = envelope["phase"].clone();
                envelope["events"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(move |e| {
                        json!([
                            phase,
                            e["event_index"],
                            e["kind"],
                            e["content"],
                            e["name"],
                            e["call_id"],
                            e["arguments"],
                            e["last_in_turn"]
                        ])
                    })
            })
            .collect()
    }
}

async fn plugin() -> Result<(u16, Plugin), Error> {
    let plugin = Plugin::default();
    let state = plugin.clone();
    let app = Router::new().route(
        "/events",
        post(move |headers: HeaderMap, body: Bytes| {
            let state = state.clone();
            async move {
                let behave = state.behave.lock().map(|b| b.clone()).unwrap_or_default();
                let header = |name: &str| {
                    headers
                        .get(name)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_string()
                };
                let stamp = header("webhook-timestamp").parse::<u64>().unwrap_or(0);
                let want =
                    gantry_core::events::signature(SECRET, &header("webhook-id"), stamp, &body);
                if header("webhook-signature") != want
                    && let Ok(mut unsigned) = state.unsigned.lock()
                {
                    *unsigned += 1;
                }
                let sent: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                let batch = sent["batch"].as_array().cloned();
                if let Ok(mut all) = state.envelopes.lock() {
                    match &batch {
                        Some(batch) => all.extend(batch.iter().cloned()),
                        None => all.push(sent.clone()),
                    }
                }
                tokio::time::sleep(behave.delay).await;
                if behave.broken {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "down").into_response();
                }
                if batch.is_some() {
                    return json_answer(json!({}));
                }
                let events = sent["events"].as_array().cloned().unwrap_or_default();
                let holds = |event: &Value, needle: &Option<String>| {
                    needle.as_ref().is_some_and(|n| {
                        event["content"].as_str().is_some_and(|c| c.contains(n.as_str()))
                    })
                };
                for event in &events {
                    let index = event["event_index"].clone();
                    let call = matches!(event["kind"].as_str(), Some("tool_call" | "mcp_tool_call"));
                    if call && event["name"].as_str() == behave.block_tool.as_deref() {
                        return json_answer(json!({"action": "block", "reason": "that tool is not for this agent", "findings": [{"kind": "blocked_tool", "event": index, "severity": "high"}]}));
                    }
                    if holds(event, &behave.end_on) {
                        return json_answer(json!({"action": "block", "session_action": "end", "findings": [{"kind": "exfiltration_intent", "event": index, "severity": "critical"}]}));
                    }
                    if holds(event, &behave.block_text) {
                        return json_answer(json!({"action": "block", "findings": [{"kind": "code_word", "event": index}]}));
                    }
                }
                let masked: Vec<Value> = events
                    .iter()
                    .filter(|e| {
                        behave.mask_results
                            && matches!(e["kind"].as_str(), Some("tool_result" | "mcp_tool_result"))
                    })
                    .map(|e| json!({"event": e["event_index"], "content": "[masked]"}))
                    .collect();
                if masked.is_empty() {
                    json_answer(json!({"action": "allow"}))
                } else {
                    json_answer(json!({"action": "mask", "masked": masked, "findings": [{"kind": "pii", "severity": "medium"}]}))
                }
            }
        }),
    );
    Ok((serve(app).await?, plugin))
}

/// A policy with one events guardrail named `watcher` at `plugin`, with `settings` as its other lines, on the rule
/// of every caller. `more` is added at the top level (an `mcp:` section).
fn policy(provider: u16, plugin: u16, settings: &str, rule: &str, more: &str) -> String {
    format!(
        "version: 1
providers:
  - name: mock-openai
    kind: openai
    url: http://127.0.0.1:{provider}
    allow_private: true
    key_env: MOCK_KEY
    models: [model-a]
  - name: mock-anthropic
    kind: anthropic
    url: http://127.0.0.1:{provider}
    allow_private: true
    key_env: MOCK_KEY
    models: [claude-a]
  - name: mock-gemini
    kind: gemini
    url: http://127.0.0.1:{provider}
    allow_private: true
    key_env: MOCK_KEY
    models: [gemini-a]
applications:
  - name: support-bot
    intent: Answers questions about the weather.
guardrails:
  - name: watcher
    type: events
    url: http://127.0.0.1:{plugin}/events
    timeout_ms: 2000
{settings}{more}rules:
  - name: everyone
    principals: {{ any: true }}
    models: [\"*\"]
    guardrails: [watcher]
{rule}"
    )
}

const ENFORCE: &str = "    on_failure: fail_closed\n    secret_env: CARGO_MANIFEST_DIR\n";

struct Setup {
    audit: std::path::PathBuf,
    gw: Governed,
}

fn setup_with(
    name: &str,
    policy: &str,
    own: Option<Arc<dyn EventsPlugin>>,
) -> Result<Setup, Error> {
    let dir = std::env::temp_dir().join(format!("gantry-events-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("gantry.policy.yaml");
    std::fs::write(&path, policy)?;
    std::fs::write(
        dir.join("gantry.keys.yaml"),
        format!(
            "keys:\n  - name: maya.cohen\n    team: payments\n    sha256: {}\n",
            sha256_hex(MAYA.as_bytes())
        ),
    )?;
    let gw = gantry_server::governed_with(&path, None, &|_| Some("k".into()), &move |_| {
        Ok(Extension {
            events: own.clone(),
            ..Extension::default()
        })
    })?;
    Ok(Setup {
        audit: dir.join("gantry-audit.jsonl"),
        gw,
    })
}

fn setup(name: &str, policy: &str) -> Result<Setup, Error> {
    setup_with(name, policy, None)
}

async fn send_with(
    gw: &Governed,
    path: &str,
    headers: &[(&str, &str)],
    body: &Value,
) -> Result<(StatusCode, String), Error> {
    // Gemini's clients send the key in x-goog-api-key; a request carries one credential.
    let key = if path.starts_with("/v1beta/") {
        ("x-goog-api-key", MAYA.to_string())
    } else {
        ("authorization", format!("Bearer {MAYA}"))
    };
    let mut request = Request::post(path)
        .header(key.0, key.1)
        .header(header::USER_AGENT, "agent-under-test/1.0")
        .header(header::CONTENT_TYPE, "application/json");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = gw
        .router
        .clone()
        .oneshot(request.body(Body::from(body.to_string()))?)
        .await?;
    let status = response.status();
    let bytes = response.into_body().collect().await?.to_bytes();
    Ok((status, String::from_utf8_lossy(&bytes).to_string()))
}

async fn send(gw: &Governed, path: &str, body: &Value) -> Result<(StatusCode, Value), Error> {
    let (status, text) = send_with(gw, path, &[], body).await?;
    Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null)))
}

fn records(s: &Setup) -> Result<Vec<Value>, Error> {
    std::fs::read_to_string(&s.audit)?
        .lines()
        .map(|l| Ok(serde_json::from_str::<Value>(l)?))
        .collect()
}

/// The request decision records, in order.
fn decisions(s: &Setup) -> Result<Vec<Value>, Error> {
    Ok(records(s)?
        .into_iter()
        .filter(|r| r.get("method").is_some())
        .collect())
}

fn code(body: &Value) -> &str {
    body["error"]["code"].as_str().unwrap_or_default()
}

const GEMINI: &str = "/v1beta/models/gemini-a:generateContent";

/// The two calls of one tool-using turn, as each API's client sends them: the question with the system prompt and
/// the tool, then the same conversation with the model's tool call and the tool's result.
fn turn(api: &str) -> (&'static str, Value, Value) {
    let schema = json!({"type": "object", "properties": {"city": {"type": "string"}}});
    let result = "{\"temp\":\"18C\"}";
    match api {
        "chat" => {
            let tools = json!([{"type": "function", "function": {"name": "get_weather", "description": "The weather in a city", "parameters": schema}}]);
            let (system, user) = (
                json!({"role": "system", "content": "Be brief."}),
                json!({"role": "user", "content": "What is the weather in Paris?"}),
            );
            (
                "/v1/chat/completions",
                json!({"model": "model-a", "messages": [system, user], "tools": tools}),
                json!({"model": "model-a", "tools": tools, "messages": [system, user,
                    {"role": "assistant", "content": null, "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "get_weather", "arguments": "{\"city\":\"Paris\"}"}}]},
                    {"role": "tool", "tool_call_id": "call_1", "content": result}]}),
            )
        }
        "messages" => {
            let tools = json!([{"name": "get_weather", "description": "The weather in a city", "input_schema": schema}]);
            let user = json!({"role": "user", "content": "What is the weather in Paris?"});
            (
                "/v1/messages",
                json!({"model": "claude-a", "max_tokens": 100, "system": "Be brief.", "messages": [user], "tools": tools}),
                json!({"model": "claude-a", "max_tokens": 100, "system": "Be brief.", "tools": tools, "messages": [user,
                    {"role": "assistant", "content": [{"type": "tool_use", "id": "call_1", "name": "get_weather", "input": {"city": "Paris"}}]},
                    {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "call_1", "content": result}]}]}),
            )
        }
        "responses" => {
            let tools = json!([{"type": "function", "name": "get_weather", "description": "The weather in a city", "parameters": schema}]);
            let user = json!({"role": "user", "content": [{"type": "input_text", "text": "What is the weather in Paris?"}]});
            (
                "/v1/responses",
                json!({"model": "model-a", "instructions": "Be brief.", "input": [user], "tools": tools}),
                json!({"model": "model-a", "instructions": "Be brief.", "tools": tools, "input": [user,
                    {"type": "function_call", "call_id": "call_1", "name": "get_weather", "arguments": "{\"city\":\"Paris\"}"},
                    {"type": "function_call_output", "call_id": "call_1", "output": result}]}),
            )
        }
        _ => {
            let tools = json!([{"functionDeclarations": [{"name": "get_weather", "description": "The weather in a city", "parameters": schema}]}]);
            let system = json!({"parts": [{"text": "Be brief."}]});
            let user =
                json!({"role": "user", "parts": [{"text": "What is the weather in Paris?"}]});
            (
                GEMINI,
                json!({"systemInstruction": system, "contents": [user], "tools": tools}),
                json!({"systemInstruction": system, "tools": tools, "contents": [user,
                    {"role": "model", "parts": [{"functionCall": {"id": "call_1", "name": "get_weather", "args": {"city": "Paris"}}}]},
                    {"role": "user", "parts": [{"functionResponse": {"id": "call_1", "name": "get_weather", "response": {"temp": "18C"}}}]}]}),
            )
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tool_using_turn_is_the_same_events_on_four_apis() -> TestResult {
    let (provider, _) = provider().await?;
    let mut seen: Vec<(String, Vec<Value>, Vec<Value>)> = Vec::new();
    for api in ["chat", "messages", "responses", "gemini"] {
        let (port, plugin) = plugin().await?;
        let s = setup(
            &format!("four-{api}"),
            &policy(
                provider,
                port,
                ENFORCE,
                "    applications: [support-bot]\n",
                "",
            ),
        )?;
        let (path, first, second) = turn(api);
        for body in [&first, &second] {
            let (status, answer) = send(&s.gw, path, body).await?;
            assert_eq!(status, StatusCode::OK, "{api}: {answer}");
        }
        let envelopes = plugin.envelopes();
        assert_eq!(envelopes.len(), 4, "{api}: a request and an answer, twice");
        // One session and one turn for the whole exchange, and every delivery signed.
        let ids: Vec<(&Value, &Value)> = envelopes
            .iter()
            .map(|e| (&e["session_id"], &e["turn_id"]))
            .collect();
        assert!(ids.iter().all(|id| *id == ids[0]), "{api}: {ids:?}");
        assert!(ids[0].0.as_str().is_some_and(|s| s.starts_with("ses_")));
        assert_eq!(plugin.unsigned.lock().map(|n| *n).unwrap_or(1), 0, "{api}");
        let first = &envelopes[0];
        assert_eq!(first["contract"], 2);
        assert_eq!(first["mode"], "enforce");
        assert_eq!(first["person"], "maya.cohen");
        assert_eq!(first["team"], "payments");
        assert_eq!(first["route"], path);
        assert_eq!(first["user_agent"], "agent-under-test/1.0");
        assert_eq!(first["turn_index"], 1);
        assert_eq!(
            first["application"],
            json!({"name": "support-bot", "intent": "Answers questions about the weather."})
        );
        assert_eq!(
            first["events"][1]["tools"][0]["name"], "get_weather",
            "{api}: {first}"
        );
        let event_ids: Vec<Value> = envelopes
            .iter()
            .flat_map(|e| e["events"].as_array().cloned().unwrap_or_default())
            .map(|e| e["event_id"].clone())
            .collect();
        // The records carry the session and the turn, and never a word of the conversation.
        let log = std::fs::read_to_string(&s.audit)?;
        assert!(!log.contains("Paris") && !log.contains("18C"), "{log}");
        let all = records(&s)?;
        let decisions: Vec<&Value> = all.iter().filter(|r| r.get("method").is_some()).collect();
        let usage: Vec<&Value> = all.iter().filter(|r| r["event"] == "usage").collect();
        assert_eq!((decisions.len(), usage.len()), (2, 2), "{api}");
        for record in decisions.iter().chain(&usage) {
            assert_eq!(&record["session"], ids[0].0, "{api}: {record}");
            assert_eq!(&record["turn"], ids[0].1, "{api}: {record}");
        }
        assert_eq!(decisions[0]["events"][0]["guardrail"], "watcher");
        assert_eq!(decisions[0]["events"][0]["action"], "allow");
        assert_eq!(decisions[0]["events"][0]["events"], 3);
        // The request log finds the session's requests and lists its turns.
        let rows = gantry_core::insights::fold_chain(&s.audit)?;
        let session = ids[0].0.as_str().unwrap_or_default().to_string();
        let query = gantry_core::insights::Query {
            labels: vec![("session".into(), session)],
            limit: 50,
            ..Default::default()
        };
        let mine = query.select(&rows);
        assert_eq!(mine.len(), 2, "{api}");
        let turns = gantry_core::insights::ranking(&mine, "turn");
        assert_eq!(turns.len(), 1);
        assert_eq!(Some(turns[0].0.as_str()), ids[0].1.as_str());
        seen.push((api.to_string(), plugin.events(), event_ids));
    }
    let want = vec![
        json!([
            "request",
            0,
            "system_prompt",
            "Be brief.",
            null,
            null,
            null,
            false
        ]),
        json!([
            "request",
            1,
            "tool_definitions",
            null,
            null,
            null,
            tools,
            false
        ]),
        json!([
            "request",
            2,
            "user_message",
            "What is the weather in Paris?",
            null,
            null,
            null,
            false
        ]),
        json!(["answer", 3, "tool_call", null, "get_weather", "call_1", {"city": "Paris"}, false]),
        json!([
            "request",
            4,
            "tool_result",
            "{\"temp\":\"18C\"}",
            "get_weather",
            "call_1",
            null,
            false
        ]),
        json!([
            "answer",
            5,
            "assistant_message",
            "It is 18C in Paris.",
            null,
            null,
            null,
            true
        ]),
    ];
    for (api, events, _) in &seen {
        assert_eq!(events, &want, "{api}");
    }
    // The same conversation by the same key has the same event ids whichever API carried it.
    for (api, _, ids) in &seen[1..] {
        assert_eq!(ids, &seen[0].2, "{api}");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_user_message_is_a_second_turn_and_history_is_sent_when_asked() -> TestResult {
    let (provider, _) = provider().await?;
    let (port, plugin) = plugin().await?;
    let s = setup(
        "turns",
        &policy(
            provider,
            port,
            &format!("{ENFORCE}    history: true\n"),
            "",
            "",
        ),
    )?;
    let first = json!({"model": "model-a", "messages": [{"role": "user", "content": "hello"}]});
    let second = json!({"model": "model-a", "messages": [
        {"role": "user", "content": "hello"},
        {"role": "assistant", "content": "ok"},
        {"role": "user", "content": "and again"}]});
    let session = [("x-gantry-session", "conversation-7")];
    for body in [&first, &second] {
        let (status, text) = send_with(&s.gw, "/v1/chat/completions", &session, body).await?;
        assert_eq!(status, StatusCode::OK, "{text}");
    }
    let envelopes = plugin.envelopes();
    assert_eq!(envelopes.len(), 4);
    assert_eq!(envelopes[0]["session_id"], envelopes[2]["session_id"]);
    assert_ne!(envelopes[0]["turn_id"], envelopes[2]["turn_id"]);
    assert_eq!(
        (&envelopes[0]["turn_index"], &envelopes[2]["turn_index"]),
        (&json!(1), &json!(2))
    );
    // Only the new message is an event of the second call; the turn before it is its history, with the ids it had.
    assert_eq!(envelopes[2]["events"].as_array().map(Vec::len), Some(1));
    assert_eq!(envelopes[2]["events"][0]["content"], "and again");
    let history = envelopes[2]["history"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(history.len(), 2, "{history:?}");
    assert_eq!(
        history[0]["event_id"],
        envelopes[0]["events"][0]["event_id"]
    );
    assert_eq!(
        history[1]["event_id"],
        envelopes[1]["events"][0]["event_id"]
    );
    assert_eq!(history[1]["turn_id"], envelopes[0]["turn_id"]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tool_call_the_plugin_blocks_never_reaches_the_caller() -> TestResult {
    let (provider, _) = provider().await?;
    let (port, plugin) = plugin().await?;
    plugin.set(|b| b.block_tool = Some("get_weather".into()));
    let s = setup("block-call", &policy(provider, port, ENFORCE, "", ""))?;
    for api in ["chat", "messages", "responses", "gemini"] {
        let (path, first, _) = turn(api);
        let (status, answer) = send(&s.gw, path, &first).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{api}: {answer}");
        let text = answer.to_string();
        assert!(text.contains("guardrail_blocked"), "{api}: {text}");
        assert!(text.contains("blocked_tool (1)"), "{api}: {text}");
        // The plugin's reason may quote the conversation: it is neither shown nor recorded.
        assert!(
            !text.contains("not for this agent") && !text.contains("Paris"),
            "{text}"
        );
    }
    let log = std::fs::read_to_string(&s.audit)?;
    assert!(
        !log.contains("not for this agent") && !log.contains("Paris"),
        "{log}"
    );
    let all = records(&s)?;
    let answers: Vec<&Value> = all
        .iter()
        .filter(|r| r["event"] == "answer_guardrails")
        .collect();
    assert_eq!(answers.len(), 4);
    for record in answers {
        assert_eq!(record["verdict"], "block");
        assert_eq!(
            record["guardrails"],
            json!([{"guardrail": "watcher", "detector": "events", "kind": "blocked_tool", "action": "block", "count": 1}])
        );
        let finding = &record["events"][0]["findings"][0];
        assert_eq!(finding["kind"], "blocked_tool");
        assert_eq!(finding["event_kind"], "tool_call");
        assert_eq!(finding["event_index"], 3);
        assert_eq!(finding["severity"], "high");
        assert!(record["session"].is_string() && record["turn"].is_string());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tool_result_the_plugin_masks_is_sent_masked() -> TestResult {
    let (provider, sent) = provider().await?;
    let (port, plugin) = plugin().await?;
    plugin.set(|b| b.mask_results = true);
    let s = setup("mask-result", &policy(provider, port, ENFORCE, "", ""))?;
    for api in ["chat", "messages", "responses", "gemini"] {
        let (path, _, second) = turn(api);
        let (status, answer) = send(&s.gw, path, &second).await?;
        // Gemini holds a tool's result as a JSON object, and "[masked]" is not one: the request is refused, never
        // sent with the result as it was.
        if api == "gemini" {
            assert_eq!(status, StatusCode::BAD_GATEWAY, "{answer}");
            continue;
        }
        assert_eq!(status, StatusCode::OK, "{api}: {answer}");
        let got = sent
            .lock()
            .map(|all| all.last().cloned().unwrap_or_default())
            .unwrap_or_default()
            .to_string();
        assert!(
            got.contains("[masked]") && !got.contains("18C"),
            "{api}: {got}"
        );
    }
    let got = sent.lock().map(|all| all.len()).unwrap_or(0);
    assert_eq!(got, 3, "the Gemini request was not sent");
    let all = records(&s)?;
    let first = all
        .iter()
        .find(|r| r.get("method").is_some())
        .ok_or("no decision record")?;
    assert_eq!(first["events"][0]["action"], "mask");
    assert_eq!(first["guardrails"][0]["action"], "mask");
    assert_eq!(first["guardrails"][0]["kind"], "pii");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_held_stream_is_stopped_before_the_blocked_window_reaches_the_caller() -> TestResult {
    let (provider, _) = provider().await?;
    let (port, plugin) = plugin().await?;
    plugin.set(|b| b.block_text = Some("BANANA".into()));
    let s = setup(
        "stream-hold",
        &policy(
            provider,
            port,
            &format!("{ENFORCE}    stream: {{ chunk_chars: 60, hold: true }}\n"),
            "",
            "",
        ),
    )?;
    let body = json!({"model": "model-a", "stream": true, "messages": [{"role": "user", "content": "tell me"}]});
    let (status, text) = send_with(&s.gw, "/v1/chat/completions", &[], &body).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(text.contains("Sentence 0 is fine."), "{text}");
    assert!(
        !text.contains("BANANA") && !text.contains("After"),
        "{text}"
    );
    let last = text.trim_end().rsplit("\n\n").next().unwrap_or_default();
    assert!(
        last.contains("guardrail_blocked") && last.contains("stopped the model's answer partway"),
        "{last}"
    );
    // The windows were events of the answer, each the text since the one before.
    let windows: Vec<Value> = plugin
        .envelopes()
        .into_iter()
        .filter(|e| e["phase"] == "stream")
        .collect();
    assert!(windows.len() >= 2, "{windows:?}");
    assert_eq!(windows[0]["events"][0]["kind"], "assistant_message");
    assert_eq!(windows[0]["events"][0]["partial"], true);
    assert_eq!(windows[1]["events"][0]["window"], 1);
    assert!(
        windows[0]["events"][0]["content"]
            .as_str()
            .is_some_and(|c| c.starts_with("Sentence 0"))
    );
    assert!(
        windows[1]["events"][0]["content"]
            .as_str()
            .is_some_and(|c| !c.contains("Sentence 0"))
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    let all = records(&s)?;
    let stopped = all
        .iter()
        .find(|r| r["event"] == "answer_guardrails")
        .ok_or("no answer record")?;
    assert_eq!(stopped["verdict"], "block");
    assert_eq!(stopped["guardrails"][0]["kind"], "code_word");

    // Without the code word in the way, the whole stream arrives, and the answer ends the turn as one event.
    plugin.set(|b| b.block_text = None);
    let before = plugin.envelopes().len();
    let (_, text) = send_with(&s.gw, "/v1/chat/completions", &[], &body).await?;
    assert!(
        text.contains("BANANA") && text.contains("After 5.") && text.contains("[DONE]"),
        "{text}"
    );
    let after = plugin.envelopes();
    let last = after.last().ok_or("no envelope")?;
    assert!(after.len() > before);
    assert_eq!(last["phase"], "answer");
    assert_eq!(last["events"][0]["last_in_turn"], true);
    assert!(
        last["events"][0]["content"]
            .as_str()
            .is_some_and(|c| c.starts_with("Sentence 0") && c.ends_with("After 5. "))
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unheld_stream_goes_on_at_once_and_a_block_ends_it_where_it_lands() -> TestResult {
    let (provider, _) = provider().await?;
    let (port, plugin) = plugin().await?;
    plugin.set(|b| b.block_text = Some("BANANA".into()));
    let s = setup(
        "stream-free",
        &policy(
            provider,
            port,
            &format!("{ENFORCE}    stream: {{ chunk_chars: 60 }}\n"),
            "",
            "",
        ),
    )?;
    let body = json!({"model": "model-a", "stream": true, "messages": [{"role": "user", "content": "tell me"}]});
    let (status, text) = send_with(&s.gw, "/v1/chat/completions", &[], &body).await?;
    assert_eq!(status, StatusCode::OK);
    // The tokens were not held, so the code word may have been sent; the stream still ends with the refusal.
    assert!(text.contains("Sentence 0 is fine."), "{text}");
    assert!(!text.contains("[DONE]"), "{text}");
    let last = text.trim_end().rsplit("\n\n").next().unwrap_or_default();
    assert!(last.contains("guardrail_blocked"), "{last}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn an_observing_plugin_never_delays_a_request_and_drops_when_its_queue_is_full() -> TestResult
{
    let (provider, _) = provider().await?;
    let (port, plugin) = plugin().await?;
    // A plugin that takes 400 ms a delivery and would block everything, if it were asked.
    plugin.set(|b| {
        b.delay = Duration::from_millis(400);
        b.block_text = Some("hello".into());
    });
    let s = setup(
        "observe",
        &policy(
            provider,
            port,
            "    mode: observe\n    queue: 2\n    batch_size: 1\n    retries: 0\n    secret_env: CARGO_MANIFEST_DIR\n",
            "",
            "",
        ),
    )?;
    let body = json!({"model": "model-a", "messages": [{"role": "user", "content": "hello"}]});
    let started = Instant::now();
    for _ in 0..10 {
        let (status, answer) = send(&s.gw, "/v1/chat/completions", &body).await?;
        assert_eq!(status, StatusCode::OK, "{answer}");
    }
    // Ten requests, twenty envelopes, a plugin that would take eight seconds for them: none waited.
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "{:?}",
        started.elapsed()
    );
    let response =
        s.gw.metrics
            .clone()
            .oneshot(Request::get("/metrics").body(Body::empty())?)
            .await?;
    let metrics =
        String::from_utf8_lossy(&response.into_body().collect().await?.to_bytes()).to_string();
    let dropped: u64 = metrics
        .lines()
        .find_map(|l| l.strip_prefix("gantry_events_dropped_total{guardrail=\"watcher\"} "))
        .and_then(|n| n.trim().parse().ok())
        .ok_or_else(|| format!("no drop counter in:\n{metrics}"))?;
    assert!(dropped >= 10, "{dropped} of 20 envelopes dropped");
    // What was not dropped is delivered, signed, and says it is only told.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let envelopes = plugin.envelopes();
    assert!(!envelopes.is_empty());
    assert!(envelopes.iter().all(|e| e["mode"] == "observe"));
    assert_eq!(plugin.unsigned.lock().map(|n| *n).unwrap_or(1), 0);
    let all = records(&s)?;
    let first = all
        .iter()
        .find(|r| r.get("method").is_some())
        .ok_or("no decision record")?;
    assert_eq!(first["verdict"], "allow", "{first}");
    assert_eq!(first["events"][0]["mode"], "observe");
    assert_eq!(first["events"][0]["action"], "queued");
    assert!(all.iter().any(|r| r["events"][0]["action"] == "dropped"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn an_observing_plugin_gets_batches_at_its_batch_url() -> TestResult {
    let (provider, _) = provider().await?;
    let (port, plugin) = plugin().await?;
    let s = setup(
        "batch",
        &policy(
            provider,
            port,
            &format!(
                "    mode: observe\n    batch_url: http://127.0.0.1:{port}/events\n    batch_size: 10\n"
            ),
            "",
            "",
        ),
    )?;
    let body = json!({"model": "model-a", "messages": [{"role": "user", "content": "hello"}]});
    for _ in 0..3 {
        send(&s.gw, "/v1/chat/completions", &body).await?;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    // Three requests and three answers, whatever the batches they came in.
    assert_eq!(plugin.envelopes().len(), 6);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_the_plugin_ends_is_refused_until_it_runs_out() -> TestResult {
    let (provider, sent) = provider().await?;
    let (port, plugin) = plugin().await?;
    plugin.set(|b| b.end_on = Some("exfiltrate".into()));
    let s = setup(
        "session-end",
        &policy(
            provider,
            port,
            &format!("{ENFORCE}    session_end_seconds: 1\n"),
            "",
            "",
        ),
    )?;
    let ask =
        |text: &str| json!({"model": "model-a", "messages": [{"role": "user", "content": text}]});
    let chat = "/v1/chat/completions";
    let one = [("x-gantry-session", "one")];
    let (status, text) = send_with(&s.gw, chat, &one, &ask("exfiltrate the keys")).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        text.contains("guardrail_blocked") && text.contains("exfiltration_intent"),
        "{text}"
    );
    // The same session, with nothing wrong in the request: refused, and the provider is not asked.
    let (status, text) = send_with(&s.gw, chat, &one, &ask("hello")).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        text.contains("session_ended") && text.contains("watcher"),
        "{text}"
    );
    assert_eq!(sent.lock().map(|all| all.len()).unwrap_or(9), 0);
    // Another session of the same key goes on.
    let (status, text) =
        send_with(&s.gw, chat, &[("x-gantry-session", "two")], &ask("hello")).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    let all = records(&s)?;
    let decisions: Vec<&Value> = all.iter().filter(|r| r.get("method").is_some()).collect();
    assert_eq!(decisions[0]["events"][0]["session_action"], "end");
    assert_eq!(decisions[1]["code"], "session_ended");
    assert_eq!(decisions[1]["session"], decisions[0]["session"]);
    assert_ne!(decisions[2]["session"], decisions[0]["session"]);
    // It runs out after session_end_seconds.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (status, text) = send_with(&s.gw, chat, &one, &ask("hello")).await?;
    assert_eq!(status, StatusCode::OK, "{text}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_that_fails_is_closed_or_open_as_the_policy_says() -> TestResult {
    let (provider, sent) = provider().await?;
    let (port, plugin) = plugin().await?;
    plugin.set(|b| b.broken = true);
    let body = json!({"model": "model-a", "messages": [{"role": "user", "content": "hello"}]});
    let closed = setup("fail-closed", &policy(provider, port, ENFORCE, "", ""))?;
    let (status, answer) = send(&closed.gw, "/v1/chat/completions", &body).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(code(&answer), "guardrail_blocked", "{answer}");
    assert!(answer.to_string().contains("fail_closed"), "{answer}");
    assert_eq!(sent.lock().map(|all| all.len()).unwrap_or(9), 0);
    let first = &decisions(&closed)?[0];
    assert_eq!(first["guardrails"][0]["kind"], "unavailable");
    assert_eq!(first["guardrails"][0]["action"], "block");

    let open = setup(
        "fail-open",
        &policy(provider, port, "    on_failure: fail_open\n", "", ""),
    )?;
    let (status, answer) = send(&open.gw, "/v1/chat/completions", &body).await?;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let all = decisions(&open)?;
    assert_eq!(all[0]["guardrails"][0]["kind"], "unavailable");
    assert_eq!(all[0]["guardrails"][0]["action"], "skipped");
    assert_eq!(all[0]["events"][0]["unavailable"], true);

    // A plugin slower than timeout_ms has failed too.
    plugin.set(|b| {
        b.broken = false;
        b.delay = Duration::from_millis(600);
    });
    let slow = setup(
        "fail-slow",
        &policy(provider, port, ENFORCE, "", "").replace("timeout_ms: 2000", "timeout_ms: 100"),
    )?;
    let (status, answer) = send(&slow.gw, "/v1/chat/completions", &body).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn shadow_until_and_observe_mode_record_what_the_plugin_would_do() -> TestResult {
    let (provider, _) = provider().await?;
    let (port, plugin) = plugin().await?;
    plugin.set(|b| b.block_text = Some("hello".into()));
    let body = json!({"model": "model-a", "messages": [{"role": "user", "content": "hello"}]});
    let shadow = setup(
        "shadow",
        &policy(
            provider,
            port,
            &format!("{ENFORCE}    shadow_until: 2999-01-01\n"),
            "",
            "",
        ),
    )?;
    let (status, answer) = send(&shadow.gw, "/v1/chat/completions", &body).await?;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let first = &decisions(&shadow)?[0];
    assert_eq!(first["guardrails"][0]["action"], "shadow");
    assert_eq!(first["events"][0]["obeyed"], false);

    let observed = setup(
        "policy-observe",
        &policy(provider, port, ENFORCE, "", "").replace("version: 1", "version: 1\nmode: observe"),
    )?;
    let (status, answer) = send(&observed.gw, "/v1/chat/completions", &body).await?;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let first = &decisions(&observed)?[0];
    assert_eq!(first["outcome"], "would_refuse", "{first}");
    assert_eq!(first["would_refuse"][0]["guardrail"], "watcher");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn an_application_is_the_rules_or_the_callers_where_the_rule_lets_it() -> TestResult {
    let (provider, _) = provider().await?;
    let (port, plugin) = plugin().await?;
    let body = json!({"model": "model-a", "messages": [{"role": "user", "content": "hello"}]});
    let chat = "/v1/chat/completions";
    let listed = setup(
        "application",
        &policy(
            provider,
            port,
            ENFORCE,
            "    applications: [support-bot, \"*\"]\n",
            "",
        ),
    )?;
    // Several applications and no header: none is claimed.
    send_with(&listed.gw, chat, &[], &body).await?;
    // A listed one takes the policy's intent, whatever the caller states.
    let named = [
        ("x-gantry-application", "support-bot"),
        ("x-gantry-application-intent", "Moves money."),
    ];
    send_with(&listed.gw, chat, &named, &body).await?;
    // "*" takes any name, with the caller's own words.
    let other = [
        ("x-gantry-application", "night-batch"),
        ("x-gantry-application-intent", "Summarizes tickets."),
    ];
    send_with(&listed.gw, chat, &other, &body).await?;
    let envelopes = plugin.envelopes();
    assert!(
        envelopes[0].get("application").is_none(),
        "{}",
        envelopes[0]
    );
    assert_eq!(
        envelopes[2]["application"],
        json!({"name": "support-bot", "intent": "Answers questions about the weather."})
    );
    assert_eq!(
        envelopes[4]["application"],
        json!({"name": "night-batch", "intent": "Summarizes tickets."})
    );
    // A rule that lists none takes none from a caller.
    let none = setup("application-none", &policy(provider, port, ENFORCE, "", ""))?;
    let (status, text) = send_with(&none.gw, chat, &other, &body).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(text.contains("application_not_allowed"), "{text}");
    Ok(())
}

/// An MCP server with one tool, `echo`, whose result holds what it was called with.
async fn mcp_server() -> Result<(u16, Sent), Error> {
    let sent = Sent::default();
    let calls = sent.clone();
    let app = Router::new().route(
        "/mcp",
        post(move |body: Bytes| {
            let calls = calls.clone();
            async move {
                let message: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                let id = message["id"].clone();
                if id.is_null() {
                    return StatusCode::ACCEPTED.into_response();
                }
                let result = match message["method"].as_str().unwrap_or_default() {
                    "initialize" => json!({"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "tools", "version": "1"}}),
                    "tools/list" => json!({"tools": [
                        {"name": "echo", "description": "echo", "inputSchema": {"type": "object"}},
                        {"name": "delete_file", "description": "delete", "inputSchema": {"type": "object"}}]}),
                    _ => {
                        if let Ok(mut all) = calls.lock() {
                            all.push(message["params"].clone());
                        }
                        json!({"content": [{"type": "text", "text": format!("echo of {}", message["params"]["arguments"])}], "isError": false})
                    }
                };
                (
                    [
                        (header::CONTENT_TYPE, "application/json"),
                        (header::HeaderName::from_static("mcp-session-id"), "upstream-1"),
                    ],
                    json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string(),
                )
                    .into_response()
            }
        }),
    );
    Ok((serve(app).await?, sent))
}

async fn rpc(gw: &Governed, session: &str, tool: &str) -> Result<Value, Error> {
    let message = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": {"path": "notes.txt"}}});
    let request = Request::post("/mcp")
        .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("x-gantry-session", session)
        .body(Body::from(message.to_string()))?;
    let response = gw.router.clone().oneshot(request).await?;
    let body = response.into_body().collect().await?.to_bytes();
    if let Ok(value) = serde_json::from_slice::<Value>(&body) {
        return Ok(value);
    }
    Ok(String::from_utf8_lossy(&body)
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|data| serde_json::from_str::<Value>(data.trim()).ok())
        .next_back()
        .unwrap_or(Value::Null))
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_tool_calls_and_results_are_events_of_the_callers_session() -> TestResult {
    let (provider, _) = provider().await?;
    let (port, plugin) = plugin().await?;
    let (server, calls) = mcp_server().await?;
    plugin.set(|b| {
        b.block_tool = Some("delete_file".into());
        b.mask_results = true;
    });
    let s = setup(
        "mcp",
        &policy(
            provider,
            port,
            ENFORCE,
            "    tools: [tools.*]\n",
            &format!(
                "mcp:\n  - name: tools\n    url: http://127.0.0.1:{server}/mcp\n    allow_private: true\n"
            ),
        ),
    )?;
    let answer = rpc(&s.gw, "agent-run-1", "tools.echo").await?;
    // The result reached the caller as the plugin masked it.
    assert_eq!(
        answer["result"]["content"][0]["text"], "[masked]",
        "{answer}"
    );
    let envelopes = plugin.envelopes();
    assert_eq!(envelopes.len(), 2, "{envelopes:?}");
    assert_eq!(envelopes[0]["phase"], "mcp");
    assert_eq!(envelopes[0]["route"], "/mcp");
    assert_eq!(envelopes[0]["session_id"], envelopes[1]["session_id"]);
    assert_eq!(envelopes[0]["turn_id"], envelopes[1]["turn_id"]);
    let (call, result) = (&envelopes[0]["events"][0], &envelopes[1]["events"][0]);
    assert_eq!(call["kind"], "mcp_tool_call");
    assert_eq!(
        (&call["server"], &call["name"]),
        (&json!("tools"), &json!("echo"))
    );
    assert_eq!(call["arguments"], json!({"path": "notes.txt"}));
    assert_eq!(result["kind"], "mcp_tool_result");
    assert_eq!(result["event_index"], 1);
    assert!(
        result["content"]
            .as_str()
            .is_some_and(|c| c.contains("notes.txt"))
    );
    // A model request with the same session header is in the same session.
    let body = json!({"model": "model-a", "messages": [{"role": "user", "content": "hello"}]});
    send_with(
        &s.gw,
        "/v1/chat/completions",
        &[("x-gantry-session", "agent-run-1")],
        &body,
    )
    .await?;
    assert_eq!(
        plugin.envelopes()[2]["session_id"],
        envelopes[0]["session_id"]
    );
    // A call the plugin blocks is never made.
    let refused = rpc(&s.gw, "agent-run-1", "tools.delete_file").await?;
    assert!(
        refused.to_string().contains("guardrail_blocked")
            && refused.to_string().contains("blocked_tool"),
        "{refused}"
    );
    assert_eq!(calls.lock().map(|all| all.len()).unwrap_or(9), 1);
    let all = records(&s)?;
    let asked = all
        .iter()
        .find(|r| r["tool"] == "echo" && r.get("events").is_some() && r["event"] != "mcp_result")
        .ok_or("no record of the call")?;
    assert_eq!(asked["session"], envelopes[0]["session_id"]);
    assert_eq!(asked["events"][0]["action"], "allow");
    let outcome = all
        .iter()
        .find(|r| r["event"] == "mcp_result" && r.get("events").is_some())
        .ok_or("no record of the result")?;
    assert_eq!(outcome["events"][0]["action"], "mask");
    Ok(())
}

/// A plugin built into the binary: it blocks any request whose user says "forbidden", and counts what it saw.
struct Own(Arc<Mutex<Vec<Envelope>>>);

impl EventsPlugin for Own {
    fn judge(&self, envelope: Envelope) -> gantry_core::store::Pending<Verdict> {
        let block = envelope.events.iter().any(|e| {
            e.content
                .as_deref()
                .is_some_and(|c| c.contains("forbidden"))
        });
        if let Ok(mut seen) = self.0.lock() {
            seen.push(envelope);
        }
        Box::pin(async move {
            let mut verdict = Verdict::allow();
            if block {
                verdict.action = gantry_core::events::Action::Block;
            }
            Ok(verdict)
        })
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_binary_s_own_plugin_gets_the_same_events_with_no_guardrail_in_the_policy() -> TestResult
{
    let (provider, _) = provider().await?;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let own: Arc<dyn EventsPlugin> = Arc::new(Own(seen.clone()));
    let text = policy(provider, 9, ENFORCE, "", "").replace("    guardrails: [watcher]\n", "");
    let start = text.find("guardrails:").ok_or("no guardrails section")?;
    let end = text.find("rules:").ok_or("no rules section")?;
    let text = format!("{}{}", &text[..start], &text[end..]);
    let s = setup_with("own", &text, Some(own))?;
    let ask =
        |text: &str| json!({"model": "model-a", "messages": [{"role": "user", "content": text}]});
    let (status, answer) = send(&s.gw, "/v1/chat/completions", &ask("hello")).await?;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let (status, answer) = send(&s.gw, "/v1/chat/completions", &ask("a forbidden thing")).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(code(&answer), "guardrail_blocked", "{answer}");
    let seen = seen.lock().map(|s| s.clone()).unwrap_or_default();
    assert_eq!(
        seen.len(),
        3,
        "a request, its answer, and the refused request"
    );
    assert_eq!(seen[0].guardrail, "extension");
    assert_eq!(seen[1].phase, "answer");
    assert_eq!(seen[1].context.session_id, seen[0].context.session_id);
    let all = decisions(&s)?;
    assert_eq!(all[0]["events"][0]["guardrail"], "extension");
    Ok(())
}

/// The reference plugin in examples/plugins, as the docs' walkthrough runs it.
struct Reference(std::process::Child);

impl Drop for Reference {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_reference_plugin_prints_the_events_and_blocks_a_tool_by_name() -> TestResult {
    use std::io::{BufRead, BufReader};
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/plugins/event-printer/plugin.py");
    let port = std::net::TcpListener::bind(("127.0.0.1", 0))?
        .local_addr()?
        .port();
    let spawned = std::process::Command::new("python3")
        .arg("-u")
        .arg(&script)
        .args(["--port", &port.to_string(), "--block", "get_weather"])
        .env("PLUGIN_SECRET", SECRET)
        .stdout(std::process::Stdio::piped())
        .spawn();
    let Ok(child) = spawned else {
        eprintln!(
            "skipped: python3 is not on this machine, and the reference plugin is a Python script."
        );
        return Ok(());
    };
    let mut plugin = Reference(child);
    let mut lines = BufReader::new(plugin.0.stdout.take().ok_or("no stdout")?).lines();
    let first = lines.next().ok_or("the plugin printed nothing")??;
    assert!(first.contains("listening on"), "{first}");
    let (provider, _) = provider().await?;
    let s = setup("reference", &policy(provider, port, ENFORCE, "", ""))?;
    let (path, first, _) = turn("chat");
    let (status, answer) = send(&s.gw, path, &first).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer}");
    assert!(answer.to_string().contains("blocked_tool (1)"), "{answer}");
    let printed: Vec<String> = lines.by_ref().take(4).collect::<Result<_, _>>()?;
    assert!(
        printed[0].contains("system_prompt") && printed[0].contains("Be brief."),
        "{printed:?}"
    );
    assert!(printed[1].contains("tool_definitions") && printed[1].contains("get_weather"));
    assert!(printed[2].contains("user_message"));
    assert!(
        printed[3].contains("tool_call") && printed[3].contains("get_weather("),
        "{printed:?}"
    );
    Ok(())
}

#[test]
fn a_policy_with_a_wrong_events_guardrail_names_the_fix() {
    let check = |settings: &str| {
        let dir = std::env::temp_dir().join(format!(
            "gantry-events-{}-check-{}",
            std::process::id(),
            sha256_hex(settings.as_bytes())
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("gantry.policy.yaml");
        let _ = std::fs::write(&path, policy(1, 2, settings, "", ""));
        let _ = std::fs::write(dir.join("gantry.keys.yaml"), "keys: []\n");
        gantry_server::governed(&path, None, &|_| Some("k".into()))
            .err()
            .unwrap_or_default()
    };
    assert!(check("").contains("on_failure"), "{}", check(""));
    assert!(check("    mode: watch\n    on_failure: fail_open\n").contains("mode: enforce"));
    assert!(check("    on_failure: fail_open\n    action: block\n").contains("takes no action"));
    assert!(
        check("    on_failure: fail_open\n    queue: 5\n").contains("belongs to mode: observe")
    );
    assert!(
        check("    mode: observe\n    stream: { chunk_chars: 100, hold: true }\n")
            .contains("stream.hold")
    );
    assert!(
        check("    on_failure: fail_open\n    stream: { chunk_chars: 2 }\n")
            .contains("at least 20")
    );
    assert_eq!(check("    mode: observe\n"), "");
}
