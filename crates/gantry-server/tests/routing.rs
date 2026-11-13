//! Aliases with load balancing, cooldown and named fallbacks; tokens-per-minute limits and per-key model lists; and
//! the images, audio, moderations and rerank routes. Every provider here is a mock on 127.0.0.1.

use std::{
    collections::VecDeque,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    body::{Body, Bytes},
    http::{HeaderMap, Request, StatusCode, header},
    response::{IntoResponse, Response},
};
use gantry_core::{
    audit::AuditLog,
    config::{Alias, Balance, Deployment, Kind},
    guard::{Action, Check, Guardrail},
    id::sha256_hex,
    policy::{Budget, Limits, Models, Period, Policy, Who},
    usage::{Price, PriceOverrides},
};
use gantry_server::{Audit, Config, ProviderRoute, Secret};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const MAYA: &str = "gantry_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// What a mock provider was sent, and the answers it gives in turn (status, content type, body). The last repeats.
#[derive(Default)]
struct Mock {
    seen: Mutex<Vec<(String, HeaderMap, Bytes)>>,
    replies: Mutex<VecDeque<(u16, &'static str, Vec<u8>)>>,
}

impl Mock {
    fn seen(&self) -> Vec<(String, HeaderMap, Bytes)> {
        self.seen.lock().map(|s| s.clone()).unwrap_or_default()
    }
}

async fn mock(
    replies: Vec<(u16, &'static str, &str)>,
) -> Result<(SocketAddr, Arc<Mock>), Box<dyn std::error::Error>> {
    let state = Arc::new(Mock {
        replies: Mutex::new(
            replies
                .into_iter()
                .map(|(s, t, b)| (s, t, b.as_bytes().to_vec()))
                .collect(),
        ),
        ..Mock::default()
    });
    let mock = state.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = Router::new().fallback(move |request: Request<Body>| {
        let mock = mock.clone();
        async move {
            let target = request.uri().path().to_string();
            let headers = request.headers().clone();
            let body = request
                .into_body()
                .collect()
                .await
                .map(|b| b.to_bytes())
                .unwrap_or_default();
            if let Ok(mut seen) = mock.seen.lock() {
                seen.push((target, headers, body));
            }
            let reply = match mock.replies.lock() {
                Ok(mut replies) if replies.len() > 1 => replies.pop_front(),
                Ok(replies) => replies.front().cloned(),
                Err(_) => None,
            };
            let (status, content_type, body) =
                reply.unwrap_or((200, "application/json", b"{}".to_vec()));
            let response: Response = (
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                [(header::CONTENT_TYPE, content_type)],
                body,
            )
                .into_response();
            response
        }
    });
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((addr, state))
}

fn route(name: &str, kind: Kind, addr: SocketAddr, models: &[&str]) -> ProviderRoute {
    ProviderRoute {
        name: name.into(),
        kind,
        url: format!("http://{addr}"),
        key: Some(Secret::new(format!("{name}-provider-key"))),
        models: models.iter().map(|m| m.to_string()).collect(),
        ..ProviderRoute::default()
    }
}

fn smart(balance: Balance, deployments: &[(&str, &str, u32)]) -> Alias {
    Alias {
        name: "smart".into(),
        deployments: deployments
            .iter()
            .map(|(p, m, w)| Deployment {
                provider: p.to_string(),
                model: m.to_string(),
                weight: *w,
            })
            .collect(),
        balance,
        cooldown_seconds: 30,
        context_window_fallback: None,
        content_policy_fallback: None,
    }
}

struct Gateway {
    app: Router,
    log: PathBuf,
}

fn everyone() -> Policy {
    Policy::new()
        .with_key(MAYA, "maya.cohen", "payments")
        .with_rule("everyone", Who::Any, Models::Any)
}

fn gateway(
    name: &str,
    providers: Vec<ProviderRoute>,
    aliases: Vec<Alias>,
    policy: Policy,
) -> Result<Gateway, Box<dyn std::error::Error>> {
    let log = std::env::temp_dir().join(format!(
        "gantry-routing-{}-{name}.jsonl",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&log);
    let app = gantry_server::app(Config {
        providers,
        aliases,
        policy: Some(policy),
        audit: Some(Audit {
            log: Arc::new(AuditLog::open(&log)?),
            provider: String::new(),
            policy_sha256: sha256_hex(b"policy"),
            keys_sha256: sha256_hex(b"keys"),
        }),
        ..Config::default()
    })?;
    Ok(Gateway { app, log })
}

async fn send(
    gw: &Gateway,
    path: &str,
    content_type: &str,
    body: impl Into<Bytes>,
) -> Result<(StatusCode, HeaderMap, Bytes), Box<dyn std::error::Error>> {
    let request = Request::post(path)
        .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(body.into()))?;
    let response = gw.app.clone().oneshot(request).await?;
    let (status, headers) = (response.status(), response.headers().clone());
    Ok((
        status,
        headers,
        response.into_body().collect().await?.to_bytes(),
    ))
}

async fn post(
    gw: &Gateway,
    path: &str,
    body: &str,
) -> Result<(StatusCode, HeaderMap, String), Box<dyn std::error::Error>> {
    let (status, headers, bytes) = send(gw, path, "application/json", body.to_string()).await?;
    Ok((status, headers, String::from_utf8(bytes.to_vec())?))
}

/// Every record of the log, after waiting a little for one of `event`, which is written after the answer has left.
async fn records(gw: &Gateway, event: &str) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    for _ in 0..50 {
        let all: Vec<Value> = std::fs::read_to_string(&gw.log)?
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        if event.is_empty() || all.iter().any(|r| r["event"] == event) {
            return Ok(all);
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    Err(format!("no {event} record").into())
}

fn model_of(body: &Bytes) -> String {
    serde_json::from_slice::<Value>(body)
        .map(|v| v["model"].as_str().unwrap_or_default().to_string())
        .unwrap_or_default()
}

const CHAT_OK: &str = r#"{"id":"c","object":"chat.completion","choices":[],"usage":{"prompt_tokens":10,"completion_tokens":5}}"#;

#[tokio::test]
async fn an_alias_spreads_requests_by_weight_and_records_the_deployment() -> TestResult {
    let (a, east) = mock(vec![(200, "application/json", CHAT_OK)]).await?;
    let (b, west) = mock(vec![(200, "application/json", CHAT_OK)]).await?;
    let gw = gateway(
        "weights",
        vec![
            route("east", Kind::OpenAi, a, &["gpt-4o"]),
            route("west", Kind::OpenAi, b, &["gpt-4o-mini"]),
        ],
        vec![smart(
            Balance::RoundRobin,
            &[("east", "gpt-4o", 2), ("west", "gpt-4o-2024", 1)],
        )],
        everyone(),
    )?;
    let chat = r#"{"model":"smart","messages":[{"role":"user","content":"hi"}]}"#;
    for _ in 0..6 {
        let (status, _, body) = post(&gw, "/v1/chat/completions", chat).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    assert_eq!(east.seen().len(), 4);
    assert_eq!(west.seen().len(), 2);
    // Each deployment is sent its own model name; the caller's alias never reaches a provider.
    assert!(east.seen().iter().all(|(_, _, b)| model_of(b) == "gpt-4o"));
    assert!(
        west.seen()
            .iter()
            .all(|(_, _, b)| model_of(b) == "gpt-4o-2024")
    );
    let all = records(&gw, "usage").await?;
    let decisions: Vec<&Value> = all.iter().filter(|r| r["event"].is_null()).collect();
    assert_eq!(decisions[0]["model"], "smart");
    assert_eq!(decisions[0]["alias"], "smart");
    assert_eq!(decisions[0]["deployment"], "east/gpt-4o");
    assert_eq!(decisions[0]["provider"], "east");
    assert_eq!(decisions[2]["deployment"], "west/gpt-4o-2024");
    // The answer is charged as the model that served it.
    let usage = all.iter().find(|r| r["event"] == "usage").ok_or("usage")?;
    assert_eq!(usage["model"], "gpt-4o");
    Ok(())
}

#[tokio::test]
async fn a_failed_deployment_falls_through_and_cools_down() -> TestResult {
    let (a, east) = mock(vec![(500, "application/json", "{}")]).await?;
    let (b, west) = mock(vec![(200, "application/json", CHAT_OK)]).await?;
    let gw = gateway(
        "cooldown",
        vec![
            route("east", Kind::OpenAi, a, &["gpt-4o"]),
            route("west", Kind::OpenAi, b, &["gpt-4o-mini"]),
        ],
        vec![smart(
            Balance::RoundRobin,
            &[("east", "gpt-4o", 1), ("west", "gpt-4o-mini", 1)],
        )],
        everyone(),
    )?;
    let chat = r#"{"model":"smart","messages":[]}"#;
    let (status, _, body) = post(&gw, "/v1/chat/completions", chat).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!((east.seen().len(), west.seen().len()), (1, 1));
    // East failed, so for 30 seconds it is tried after west, whose turn it was not.
    for _ in 0..3 {
        post(&gw, "/v1/chat/completions", chat).await?;
    }
    assert_eq!((east.seen().len(), west.seen().len()), (1, 4));
    let all = records(&gw, "attempts").await?;
    let attempts = all
        .iter()
        .find(|r| r["event"] == "attempts")
        .ok_or("attempts")?;
    assert_eq!(attempts["attempts"][0]["provider"], "east/gpt-4o");
    assert_eq!(attempts["attempts"][1]["provider"], "west/gpt-4o-mini");
    // QA14-16 (AL2): charged at the price of the deployment that answered, gpt-4o-mini ($0.15 and $0.60 per
    // million), not at gpt-4o's, where the request was sent first.
    let mut usage = None;
    for _ in 0..50 {
        usage = records(&gw, "usage")
            .await?
            .into_iter()
            .find(|r| r["event"] == "usage" && r["id"] == attempts["id"]);
        if usage.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let usage = usage.ok_or("usage")?;
    assert_eq!(
        (&usage["model"], &usage["provider"]),
        (&json!("gpt-4o-mini"), &json!("west"))
    );
    let want = (10.0 * 0.15 + 5.0 * 0.60) / 1e6;
    assert!(
        (usage["cost_usd"].as_f64().unwrap_or_default() - want).abs() < 1e-12,
        "{usage}"
    );
    Ok(())
}

#[tokio::test]
async fn context_window_and_content_policy_errors_go_to_their_named_fallback() -> TestResult {
    let too_long = r#"{"error":{"code":"context_length_exceeded","message":"This model's maximum context length is 8192 tokens."}}"#;
    let filtered = r#"{"error":{"code":"content_filter","message":"filtered"}}"#;
    let (a, small) = mock(vec![
        (400, "application/json", too_long),
        (400, "application/json", filtered),
        (
            400,
            "application/json",
            r#"{"error":{"code":"invalid_value"}}"#,
        ),
    ])
    .await?;
    let (b, large) = mock(vec![(200, "application/json", CHAT_OK)]).await?;
    let mut alias = smart(Balance::RoundRobin, &[("small", "gpt-4o-mini", 1)]);
    alias.context_window_fallback = Some("gpt-4o-long".into());
    alias.content_policy_fallback = Some("gpt-4o-long".into());
    let gw = gateway(
        "named-fallback",
        vec![
            route("small", Kind::OpenAi, a, &["gpt-4o-mini"]),
            route("large", Kind::OpenAi, b, &["gpt-4o-long"]),
        ],
        vec![alias],
        everyone(),
    )?;
    let chat = r#"{"model":"smart","messages":[]}"#;
    for _ in 0..2 {
        let (status, _, body) = post(&gw, "/v1/chat/completions", chat).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    assert_eq!(large.seen().len(), 2);
    assert!(
        large
            .seen()
            .iter()
            .all(|(_, _, b)| model_of(b) == "gpt-4o-long")
    );
    // Any other 400 is the caller's to see, with the provider's own body.
    let (status, _, body) = post(&gw, "/v1/chat/completions", chat).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("invalid_value"), "{body}");
    assert_eq!((small.seen().len(), large.seen().len()), (3, 2));
    Ok(())
}

#[tokio::test]
async fn a_key_model_list_narrows_its_rule_and_its_model_list() -> TestResult {
    let (a, _) = mock(vec![(200, "application/json", CHAT_OK)]).await?;
    let text = format!(
        "keys:\n  - name: maya.cohen\n    team: payments\n    sha256: {}\n    models: [gpt-4o-mini]\n    tpm: 1000\n",
        sha256_hex(MAYA.as_bytes())
    );
    let entries = gantry_core::config::key_entries(std::path::Path::new("keys.yaml"), &text)
        .map_err(|e| e.join("\n"))?;
    assert_eq!(
        entries[0].models.as_deref(),
        Some(&["gpt-4o-mini".to_string()][..])
    );
    assert_eq!(entries[0].tpm, Some(1000));
    // The same key, built in code with the list the file gave it.
    let gw = gateway(
        "key-models",
        vec![route("openai", Kind::OpenAi, a, &["gpt-4o", "gpt-4o-mini"])],
        vec![],
        everyone().with_key_models(MAYA, &["gpt-4o-mini"]),
    )?;
    let (status, _, body) = post(
        &gw,
        "/v1/chat/completions",
        r#"{"model":"gpt-4o","messages":[]}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body.contains("model_not_allowed") && body.contains("gpt-4o-mini"),
        "{body}"
    );
    // UX12-2: the record says it was the key's own list, not the rule, that refused it.
    let refused = records(&gw, "")
        .await?
        .into_iter()
        .rfind(|r| r["code"] == "model_not_allowed")
        .ok_or("no record")?;
    assert_eq!(refused["key_models"], true);
    let request = Request::get("/v1/models")
        .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
        .body(Body::empty())?;
    let list = gw.app.clone().oneshot(request).await?;
    let list: Value = serde_json::from_slice(&list.into_body().collect().await?.to_bytes())?;
    let ids: Vec<&str> = list["data"]
        .as_array()
        .ok_or("data")?
        .iter()
        .filter_map(|m| m["id"].as_str())
        .collect();
    assert_eq!(ids, ["gpt-4o-mini"]);
    Ok(())
}

#[tokio::test]
async fn tokens_per_minute_are_reserved_then_counted_from_usage() -> TestResult {
    let used = r#"{"choices":[],"usage":{"prompt_tokens":100,"completion_tokens":600}}"#;
    let (a, openai) = mock(vec![(200, "application/json", used)]).await?;
    let policy = everyone().with_limits(Limits {
        tpm: Some(1000),
        ..Limits::default()
    });
    let gw = gateway(
        "tpm",
        vec![route("openai", Kind::OpenAi, a, &["gpt-4o"])],
        vec![],
        policy,
    )?;
    let chat = r#"{"model":"gpt-4o","messages":[],"max_tokens":200}"#;
    let (status, _, body) = post(&gw, "/v1/chat/completions", chat).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    records(&gw, "usage").await?;
    // 700 used, about 220 more asked for: fits. Then 1400 would not.
    let (status, _, _) = post(&gw, "/v1/chat/completions", chat).await?;
    assert_eq!(status, StatusCode::OK);
    for _ in 0..50 {
        if records(&gw, "usage")
            .await?
            .iter()
            .filter(|r| r["event"] == "usage")
            .count()
            == 2
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let (status, headers, body) = post(&gw, "/v1/chat/completions", chat).await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert!(
        body.contains("rate_limited") && body.contains("1000 per minute"),
        "{body}"
    );
    assert!(headers.contains_key(header::RETRY_AFTER));
    assert_eq!(openai.seen().len(), 2);
    let refused = records(&gw, "")
        .await?
        .into_iter()
        .rfind(|r| r["code"] == "rate_limited")
        .ok_or("no record")?;
    assert_eq!(
        (
            &refused["limit"]["kind"],
            &refused["limit"]["of"],
            &refused["limit"]["value"]
        ),
        (
            &Value::from("tpm"),
            &Value::from("rule"),
            &Value::from(1000)
        )
    );
    // Without max_tokens it reserves the model's whole output (16384 for gpt-4o), more than a minute allows: no
    // amount of waiting helps, so there is no Retry-After.
    let (status, headers, body) = post(
        &gw,
        "/v1/chat/completions",
        r#"{"model":"gpt-4o","messages":[]}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert!(body.contains("could use up to"), "{body}");
    assert!(!headers.contains_key(header::RETRY_AFTER));
    Ok(())
}

#[tokio::test]
async fn images_are_charged_by_the_image_and_their_prompt_is_guarded() -> TestResult {
    let two = r#"{"created":1,"data":[{"url":"https://img/1"},{"url":"https://img/2"}]}"#;
    let (a, openai) = mock(vec![(200, "application/json", two)]).await?;
    let mut prices = PriceOverrides::new();
    prices.insert(
        "dall-e-3".into(),
        Price {
            input: 0.0,
            output: 0.0,
            cache_read: None,
            cache_write: None,
            cache_write_1h: None,
            long_context: None,
            max_output: None,
            max_context: None,
            per_image: Some(0.04),
            source: Default::default(),
        },
    );
    let policy = everyone()
        .with_guardrails(&[Guardrail {
            name: "pii".into(),
            action: Action::Mask,
            check: Check::Pii,
            on: gantry_core::guard::On::REQUEST,
        }])
        .with_limits(Limits {
            budget: Some(Budget {
                usd: 10.0,
                per: Period::Day,
            }),
            ..Limits::default()
        })
        .with_prices(prices);
    let gw = gateway(
        "images",
        vec![route("openai", Kind::OpenAi, a, &["dall-e-3"])],
        vec![],
        policy,
    )?;
    let (status, _, body) = post(
        &gw,
        "/v1/images/generations",
        r#"{"model":"dall-e-3","prompt":"a cat that emails maya@example.com","n":2}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (path, _, sent) = openai.seen().first().cloned().ok_or("nothing sent")?;
    assert_eq!(path, "/v1/images/generations");
    let sent = String::from_utf8(sent.to_vec())?;
    assert!(
        !sent.contains("maya@example.com") && sent.contains("a cat"),
        "{sent}"
    );
    let all = records(&gw, "usage").await?;
    let usage = all.iter().find(|r| r["event"] == "usage").ok_or("usage")?;
    assert!(
        (usage["charged_usd"].as_f64().unwrap_or_default() - 0.08).abs() < 1e-9,
        "{usage}"
    );
    assert!(
        (usage["reserved_usd"].as_f64().unwrap_or_default() - 0.08).abs() < 1e-9,
        "{usage}"
    );
    Ok(())
}

#[tokio::test]
async fn a_transcription_form_is_decided_on_its_model_field_and_forwarded_as_sent() -> TestResult {
    let (a, openai) = mock(vec![(200, "application/json", r#"{"text":"hello"}"#)]).await?;
    let policy = Policy::new()
        .with_key(MAYA, "maya.cohen", "payments")
        .with_models("payments", ["whisper-1"])
        .with_guardrails(&[Guardrail {
            name: "secrets".into(),
            action: Action::Block,
            check: Check::Secrets,
            on: gantry_core::guard::On::REQUEST,
        }]);
    let gw = gateway(
        "audio",
        vec![route(
            "openai",
            Kind::OpenAi,
            a,
            &["whisper-1", "gpt-4o-transcribe"],
        )],
        vec![],
        policy,
    )?;
    let content_type = "multipart/form-data; boundary=gantry-test";
    let form = |model: &str| {
        let mut body = b"--gantry-test\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.wav\"\r\nContent-Type: audio/wav\r\n\r\nRIFF\x00\x01\x02\xffAKIAIOSFODNN7EXAMPLE\r\n--gantry-test\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n".to_vec();
        body.extend_from_slice(model.as_bytes());
        body.extend_from_slice(b"\r\n--gantry-test--\r\n");
        Bytes::from(body)
    };
    let (status, _, body) = send(&gw, TRANSCRIBE, content_type, form("whisper-1")).await?;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let (path, headers, sent) = openai.seen().first().cloned().ok_or("nothing sent")?;
    assert_eq!(path, TRANSCRIBE);
    assert_eq!(
        sent,
        form("whisper-1"),
        "the form is forwarded byte for byte"
    );
    assert_eq!(headers[header::CONTENT_TYPE], content_type);
    let (status, _, body) = send(&gw, TRANSCRIBE, content_type, form("gpt-4o-transcribe")).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body:?}");
    let (status, _, body) = send(
        &gw,
        TRANSCRIBE,
        "application/json",
        r#"{"model":"whisper-1"}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body:?}");
    assert_eq!(openai.seen().len(), 1);
    let all = records(&gw, "").await?;
    let first = all
        .iter()
        .find(|r| r["event"].is_null())
        .ok_or("no decision")?;
    assert_eq!(first["verdict"], "allow");
    assert_eq!(first["guardrails"], "not_run: the body is audio");
    Ok(())
}

const TRANSCRIBE: &str = "/v1/audio/transcriptions";

#[tokio::test]
async fn speech_moderations_and_rerank_are_governed_and_forwarded() -> TestResult {
    let (a, openai) = mock(vec![
        (200, "audio/mpeg", "ID3-binary-audio"),
        (200, "application/json", r#"{"results":[]}"#),
        (200, "application/json", r#"{"results":[]}"#),
    ])
    .await?;
    let (c, anthropic) = mock(vec![(200, "application/json", "{}")]).await?;
    let policy = everyone().with_guardrails(&[Guardrail {
        name: "pii".into(),
        action: Action::Mask,
        check: Check::Pii,
        on: gantry_core::guard::On::REQUEST,
    }]);
    let gw = gateway(
        "speech",
        vec![
            route(
                "openai",
                Kind::OpenAi,
                a,
                &["tts-1", "omni-moderation-latest", "rerank-v3.5"],
            ),
            route("anthropic", Kind::Anthropic, c, &["claude-sonnet-5-5"]),
        ],
        vec![],
        policy,
    )?;
    let (status, headers, audio) = send(
        &gw,
        "/v1/audio/speech",
        "application/json",
        r#"{"model":"tts-1","input":"call maya@example.com","voice":"alloy"}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "audio/mpeg");
    assert_eq!(&audio[..], b"ID3-binary-audio");
    let (status, _, body) = post(
        &gw,
        "/v1/moderations",
        r#"{"model":"omni-moderation-latest","input":"hello"}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _, body) = post(
        &gw,
        "/v1/rerank",
        r#"{"model":"rerank-v3.5","query":"who?","documents":["maya@example.com wrote",{"text":"plain"}]}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let seen = openai.seen();
    let paths: Vec<&str> = seen.iter().map(|(p, _, _)| p.as_str()).collect();
    assert_eq!(paths, ["/v1/audio/speech", "/v1/moderations", "/v1/rerank"]);
    for (_, _, body) in &seen {
        assert!(!String::from_utf8_lossy(body).contains("maya@example.com"));
    }
    let rerank: Value = serde_json::from_slice(&seen[2].2)?;
    assert_eq!(rerank["documents"][1], json!({"text": "plain"}));
    // These routes go to openai providers only.
    let (status, _, body) = post(
        &gw,
        "/v1/rerank",
        r#"{"model":"claude-sonnet-5-5","query":"q","documents":[]}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("wrong_route"), "{body}");
    assert!(anthropic.seen().is_empty());
    Ok(())
}

#[tokio::test]
async fn image_and_speech_requests_under_a_budget_need_a_price_that_bounds_them() -> TestResult {
    // QA14-3: a token-priced image or speech model is billed by its output tokens, which its body does not bound.
    let (a, _openai) = mock(vec![(
        200,
        "application/json",
        r#"{"data":[{"b64_json":"x"}],"usage":{"input_tokens":10,"output_tokens":4160}}"#,
    )])
    .await?;
    let price = |max_output: Option<u64>| Price {
        input: 5.0,
        output: 40.0,
        cache_read: None,
        cache_write: None,
        cache_write_1h: None,
        long_context: None,
        max_output,
        max_context: None,
        per_image: None,
        source: Default::default(),
    };
    let mut prices = PriceOverrides::new();
    prices.insert("img-tok".into(), price(None));
    prices.insert("tts-tok".into(), price(None));
    prices.insert("img-max".into(), price(Some(5000)));
    let policy = everyone()
        .with_limits(Limits {
            budget: Some(Budget {
                usd: 10.0,
                per: Period::Day,
            }),
            ..Limits::default()
        })
        .with_prices(prices);
    let gw = gateway(
        "image-budget",
        vec![route(
            "openai",
            Kind::OpenAi,
            a,
            &["img-tok", "tts-tok", "img-max"],
        )],
        vec![],
        policy,
    )?;
    for (path, body) in [
        (
            "/v1/images/generations",
            r#"{"model":"img-tok","prompt":"a cat"}"#,
        ),
        (
            "/v1/audio/speech",
            r#"{"model":"tts-tok","input":"hi","voice":"alloy"}"#,
        ),
    ] {
        let (status, _, answer) = post(&gw, path, body).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {answer}");
        assert!(answer.contains("max_tokens_needed"), "{path}: {answer}");
    }
    // With max_output the reservation holds n times it: 2 x 5000 output tokens at $40 per million.
    let (status, _, answer) = post(
        &gw,
        "/v1/images/generations",
        r#"{"model":"img-max","prompt":"a cat","n":2}"#,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let all = records(&gw, "usage").await?;
    let usage = all.iter().find(|r| r["event"] == "usage").ok_or("usage")?;
    let reserved = usage["reserved_usd"].as_f64().unwrap_or_default();
    assert!(reserved >= 10_000.0 * 40.0e-6, "{usage}");
    Ok(())
}

#[tokio::test]
async fn a_form_a_standard_parser_could_read_differently_is_refused() -> TestResult {
    // QA14-4: each body names whisper-1 where a loose reader looks and gpt-4o-transcribe where Python's email
    // parser (or Go's mime) looks. Gantry refuses them all rather than decide on one reading.
    let (a, openai) = mock(vec![(200, "application/json", r#"{"text":"hi"}"#)]).await?;
    let policy = Policy::new()
        .with_key(MAYA, "maya.cohen", "payments")
        .with_models("payments", ["whisper-1"]);
    let gw = gateway(
        "form-strict",
        vec![route(
            "openai",
            Kind::OpenAi,
            a,
            &["whisper-1", "gpt-4o-transcribe"],
        )],
        vec![],
        policy,
    )?;
    let form = |boundary: &str, parts: &[(&str, &str)]| {
        let mut body = String::new();
        for (disposition, value) in parts {
            body +=
                &format!("--{boundary}\r\nContent-Disposition: {disposition}\r\n\r\n{value}\r\n");
        }
        body + &format!("--{boundary}--\r\n")
    };
    let file = ("form-data; name=\"file\"; filename=\"a.wav\"", "RIFF");
    let decoy = (
        "form-data; name=\"x\"; filename=\"a;name=model;\"",
        "whisper-1",
    );
    let ct = "multipart/form-data; boundary=B";
    let mut bodies: Vec<(String, String)> = [
        "form-data; name*=UTF-8''model",
        "form-data; name = \"model\"",
        "form-data; name='model'",
        "form-data; name=\"mod\\el\"",
    ]
    .iter()
    .map(|real| {
        (
            ct.to_string(),
            form("B", &[file, (real, "gpt-4o-transcribe"), decoy]),
        )
    })
    .collect();
    // name*= beside a plain name: a parser that follows RFC 2231 takes name*= over name=.
    bodies.push((
        ct.into(),
        form(
            "B",
            &[
                file,
                ("form-data; name=\"x\"; name*=model", "gpt-4o-transcribe"),
                ("form-data; name=\"model\"", "whisper-1"),
            ],
        ),
    ));
    // A delimiter inside a value, not at a line start, and a second boundary parameter.
    bodies.push((
        ct.into(),
        form(
            "B",
            &[
                file,
                (
                    "form-data; name=\"x\"",
                    "a--B\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nwhisper-1",
                ),
            ],
        ),
    ));
    bodies.push((
        "multipart/form-data; boundary=A; boundary=B".into(),
        form(
            "B",
            &[file, ("form-data; name=\"model\"", "gpt-4o-transcribe")],
        ) + &form("A", &[("form-data; name=\"model\"", "whisper-1")]),
    ));
    for (content_type, body) in bodies {
        let (status, _, answer) = send(&gw, TRANSCRIBE, &content_type, body.clone()).await?;
        let answer = String::from_utf8_lossy(&answer).to_string();
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {answer}");
        assert!(answer.contains("unreadable_request"), "{body}: {answer}");
    }
    assert!(openai.seen().is_empty(), "nothing ambiguous was forwarded");
    let plain = form("B", &[file, ("form-data; name=\"model\"", "whisper-1")]);
    let (status, _, _) = send(&gw, TRANSCRIBE, ct, plain).await?;
    assert_eq!(status, StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn guardrails_read_every_documented_text_shape_of_the_newer_routes() -> TestResult {
    // QA14-5: the same AWS key a blocking secrets guardrail refuses in chat, in each documented shape of the
    // moderations, rerank and transcription routes, and in shapes the guardrails cannot read.
    let (a, openai) = mock(vec![(200, "application/json", r#"{"results":[]}"#)]).await?;
    let policy = everyone().with_guardrails(&[Guardrail {
        name: "secrets".into(),
        action: Action::Block,
        check: Check::Secrets,
        on: gantry_core::guard::On::REQUEST,
    }]);
    let gw = gateway(
        "text-shapes",
        vec![route(
            "openai",
            Kind::OpenAi,
            a,
            &[
                "omni-moderation-latest",
                "rerank-v3.5",
                "whisper-1",
                "tts-1",
                "dall-e-3",
            ],
        )],
        vec![],
        policy,
    )?;
    let secret = "key AKIAIOSFODNN7EXAMPLE";
    let blocked = [
        (
            "/v1/moderations",
            json!({"model": "omni-moderation-latest", "input": [{"type": "text", "text": secret}]}),
        ),
        (
            "/v1/rerank",
            json!({"model": "rerank-v3.5", "query": "q", "documents": [{"title": "t", "body": secret}], "rank_fields": ["body"]}),
        ),
        (
            "/v1/rerank",
            json!({"model": "rerank-v3.5", "query": [secret], "documents": ["d"]}),
        ),
    ];
    for (path, body) in blocked {
        let (status, _, answer) = post(&gw, path, &body.to_string()).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}: {answer}");
        assert!(answer.contains("guardrail_blocked"), "{body}: {answer}");
    }
    let unreadable = [
        (
            "/v1/moderations",
            json!({"model": "omni-moderation-latest", "input": [{"type": "texts", "content": secret}]}),
        ),
        (
            "/v1/images/generations",
            json!({"model": "dall-e-3", "prompt": [secret]}),
        ),
        (
            "/v1/audio/speech",
            json!({"model": "tts-1", "input": [secret], "voice": "alloy"}),
        ),
    ];
    for (path, body) in unreadable {
        let (status, _, answer) = post(&gw, path, &body.to_string()).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {answer}");
        assert!(answer.contains("unreadable_request"), "{body}: {answer}");
    }
    let form = |prompt: &str| {
        format!(
            "--B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.wav\"\r\n\r\nRIFF\r\n--B\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nwhisper-1\r\n--B\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\n{prompt}\r\n--B--\r\n"
        )
    };
    let ct = "multipart/form-data; boundary=B";
    let (status, _, answer) = send(&gw, TRANSCRIBE, ct, form(secret)).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{answer:?}");
    assert!(
        openai.seen().is_empty(),
        "nothing with the secret was forwarded"
    );
    // A clean prompt goes through, and its record shows the guardrails ran on it.
    let (status, _, _) = send(&gw, TRANSCRIBE, ct, form("names: Maya")).await?;
    assert_eq!(status, StatusCode::OK);
    let all = records(&gw, "").await?;
    let last = all
        .iter()
        .rev()
        .find(|r| r["event"].is_null())
        .ok_or("no decision")?;
    assert!(last["guardrails"].is_array(), "{last}");
    Ok(())
}

#[tokio::test]
async fn a_masking_guardrail_rewrites_a_transcription_prompt_in_place() -> TestResult {
    let (a, openai) = mock(vec![(200, "application/json", r#"{"text":"hi"}"#)]).await?;
    let policy = everyone().with_guardrails(&[Guardrail {
        name: "pii".into(),
        action: Action::Mask,
        check: Check::Pii,
        on: gantry_core::guard::On::REQUEST,
    }]);
    let gw = gateway(
        "form-mask",
        vec![route("openai", Kind::OpenAi, a, &["whisper-1"])],
        vec![],
        policy,
    )?;
    let body = "--B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.wav\"\r\n\r\nRIFF maya@example.com\r\n--B\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\nwrite to maya@example.com\r\n--B\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nwhisper-1\r\n--B--\r\n";
    let (status, _, _) = send(&gw, TRANSCRIBE, "multipart/form-data; boundary=B", body).await?;
    assert_eq!(status, StatusCode::OK);
    let (_, headers, sent) = openai.seen().first().cloned().ok_or("nothing sent")?;
    let sent = String::from_utf8(sent.to_vec())?;
    assert_eq!(
        sent.matches("maya@example.com").count(),
        1,
        "the prompt is masked, the audio is untouched: {sent}"
    );
    assert!(
        sent.contains("name=\"model\"\r\n\r\nwhisper-1\r\n--B--"),
        "{sent}"
    );
    assert!(
        headers
            .get(header::CONTENT_LENGTH)
            .is_none_or(|l| l.to_str().ok() == Some(&sent.len().to_string()))
    );
    Ok(())
}
