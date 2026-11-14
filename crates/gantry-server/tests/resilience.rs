//! Routing resilience: timeouts per provider, alias and deployment; health probes; key pools; multi-hop and
//! cross-API fallbacks; conditional routing; rate-limit-aware routing; wildcard models; the x-gantry-* answer
//! headers. Every provider here is a mock on 127.0.0.1 that can be told to stall, fail or refuse.

use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::{Body, Bytes},
    http::{HeaderMap, Request, StatusCode, header},
    response::Response,
};
use gantry_core::{
    audit::AuditLog,
    config::{Alias, Balance, Deployment, FallbackOn, Kind, Probe, Timeouts, When},
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

/// What a mock answers: a wait before its headers, its status and headers, and its body in pieces, each after a wait.
#[derive(Clone)]
struct Answer {
    wait_ms: u64,
    status: u16,
    headers: Vec<(&'static str, String)>,
    pieces: Vec<(u64, String)>,
}

fn answer(status: u16, body: &str) -> Answer {
    Answer {
        wait_ms: 0,
        status,
        headers: vec![("content-type", "application/json".into())],
        pieces: vec![(0, body.to_string())],
    }
}

type Reply = Arc<dyn Fn(&str, &HeaderMap, &Value) -> Answer + Send + Sync>;

/// What a mock was sent: path, headers and body.
#[derive(Default)]
struct Seen(Mutex<Vec<(String, HeaderMap, Value)>>);

impl Seen {
    fn all(&self) -> Vec<(String, HeaderMap, Value)> {
        self.0.lock().map(|s| s.clone()).unwrap_or_default()
    }
    fn count(&self, path: &str) -> usize {
        self.all().iter().filter(|(p, _, _)| p == path).count()
    }
}

async fn mock(reply: Reply) -> Result<(SocketAddr, Arc<Seen>), Box<dyn std::error::Error>> {
    let seen = Arc::new(Seen::default());
    let log = seen.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = Router::new().fallback(move |request: Request<Body>| {
        let (log, reply) = (log.clone(), reply.clone());
        async move {
            let path = request.uri().path().to_string();
            let headers = request.headers().clone();
            let bytes = request
                .into_body()
                .collect()
                .await
                .map(|b| b.to_bytes())
                .unwrap_or_default();
            let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            if let Ok(mut log) = log.0.lock() {
                log.push((path.clone(), headers.clone(), body.clone()));
            }
            let answer = reply(&path, &headers, &body);
            tokio::time::sleep(Duration::from_millis(answer.wait_ms)).await;
            // One piece with no wait is sent with its length, as providers send a whole answer.
            let mut response = match answer.pieces.as_slice() {
                [(0, text)] => Response::new(Body::from(text.clone())),
                _ => Response::new(Body::from_stream(futures_util::stream::unfold(
                    answer.pieces.clone().into_iter(),
                    |mut rest| async move {
                        let (wait, text) = rest.next()?;
                        tokio::time::sleep(Duration::from_millis(wait)).await;
                        Some((Ok::<Bytes, std::io::Error>(Bytes::from(text)), rest))
                    },
                ))),
            };
            *response.status_mut() =
                StatusCode::from_u16(answer.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            for (name, value) in answer.headers {
                if let Ok(value) = value.parse() {
                    response.headers_mut().insert(name, value);
                }
            }
            response
        }
    });
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((addr, seen))
}

/// A mock that answers every request the same way.
async fn same(a: Answer) -> Result<(SocketAddr, Arc<Seen>), Box<dyn std::error::Error>> {
    mock(Arc::new(move |_, _, _| a.clone())).await
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

fn deployment(provider: &str, model: &str) -> Deployment {
    Deployment {
        provider: provider.into(),
        model: model.into(),
        weight: 1,
        ..Deployment::default()
    }
}

fn alias(name: &str, balance: Balance, deployments: Vec<Deployment>) -> Alias {
    Alias {
        name: name.into(),
        deployments,
        balance,
        cooldown_seconds: 30,
        fallback_on: FallbackOn::DEFAULT.to_vec(),
        ..Alias::default()
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
        "gantry-resilience-{}-{name}.jsonl",
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

/// Sends a request and returns status, headers and the body, or the error the body broke off with.
async fn send(
    gw: &Gateway,
    path: &str,
    body: Value,
    headers: &[(&str, &str)],
) -> Result<(StatusCode, HeaderMap, Result<String, String>), Box<dyn std::error::Error>> {
    let mut request = Request::post(path)
        .header(header::AUTHORIZATION, format!("Bearer {MAYA}"))
        .header(header::CONTENT_TYPE, "application/json");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = gw
        .app
        .clone()
        .oneshot(request.body(Body::from(body.to_string()))?)
        .await?;
    let (status, headers) = (response.status(), response.headers().clone());
    let body = match response.into_body().collect().await {
        Ok(b) => Ok(String::from_utf8(b.to_bytes().to_vec())?),
        Err(err) => Err(err.to_string()),
    };
    Ok((status, headers, body))
}

async fn chat(
    gw: &Gateway,
    model: &str,
) -> Result<(StatusCode, HeaderMap, Result<String, String>), Box<dyn std::error::Error>> {
    send(
        gw,
        "/v1/chat/completions",
        json!({"model": model, "messages": [{"role": "user", "content": "hi"}]}),
        &[],
    )
    .await
}

/// Every record of the log, after waiting a little for one of `event`.
async fn records(gw: &Gateway, event: &str) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    for _ in 0..100 {
        let all: Vec<Value> = std::fs::read_to_string(&gw.log)?
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        if all.iter().any(|r| r["event"] == event) {
            return Ok(all);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Err(format!("no {event} record").into())
}

async fn attempts(gw: &Gateway) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    Ok(records(gw, "attempts")
        .await?
        .into_iter()
        .filter(|r| r["event"] == "attempts")
        .flat_map(|r| r["attempts"].as_array().cloned().unwrap_or_default())
        .collect())
}

const CHAT_OK: &str = r#"{"id":"c","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}"#;
const MESSAGES_OK: &str = r#"{"id":"msg_1","type":"message","role":"assistant","model":"claude-x","content":[{"type":"text","text":"from claude"}],"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":3}}"#;

#[tokio::test]
async fn a_deployment_that_does_not_answer_in_its_first_byte_time_is_passed_over_and_cools_down()
-> TestResult {
    let mut slow = answer(200, CHAT_OK);
    slow.wait_ms = 3000;
    let (a, slow_seen) = same(slow).await?;
    let (b, fast_seen) = same(answer(200, CHAT_OK)).await?;
    let mut first = deployment("slow", "m");
    first.weight = 1000;
    first.timeouts = Timeouts {
        first_byte_ms: Some(200),
        ..Timeouts::default()
    };
    let gw = gateway(
        "first-byte",
        vec![
            route("slow", Kind::OpenAi, a, &[]),
            route("fast", Kind::OpenAi, b, &[]),
        ],
        vec![alias(
            "smart",
            Balance::RoundRobin,
            vec![first, deployment("fast", "m")],
        )],
        everyone(),
    )?;
    let started = Instant::now();
    let (status, headers, _) = chat(&gw, "smart").await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(
        headers.get("x-gantry-provider").map(|v| v.as_bytes()),
        Some(&b"fast"[..])
    );
    let tried = attempts(&gw).await?;
    assert_eq!(tried[0]["outcome"], "upstream_timeout", "{tried:?}");
    // Cooling down: the next request does not wait on it again.
    let (status, _, _) = chat(&gw, "smart").await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(slow_seen.count("/v1/chat/completions"), 1);
    assert_eq!(fast_seen.count("/v1/chat/completions"), 2);
    Ok(())
}

#[tokio::test]
async fn a_stream_that_stalls_past_its_idle_limit_is_cut_off_and_its_deployment_cools_down()
-> TestResult {
    let mut stalls = answer(200, "");
    stalls.headers = vec![("content-type", "text/event-stream".into())];
    stalls.pieces = vec![
        (
            0,
            "data: {\"choices\":[{\"delta\":{\"content\":\"he\"}}]}\n\n".into(),
        ),
        (5000, "data: [DONE]\n\n".into()),
    ];
    let (a, stall_seen) = same(stalls).await?;
    let (b, _) = same(answer(200, CHAT_OK)).await?;
    let mut first = deployment("stalls", "m");
    first.weight = 1000;
    let mut smart = alias(
        "smart",
        Balance::RoundRobin,
        vec![first, deployment("fine", "m")],
    );
    smart.timeouts = Timeouts {
        idle_ms: Some(300),
        ..Timeouts::default()
    };
    let gw = gateway(
        "idle",
        vec![
            route("stalls", Kind::OpenAi, a, &[]),
            route("fine", Kind::OpenAi, b, &[]),
        ],
        vec![smart],
        everyone(),
    )?;
    let started = Instant::now();
    let (status, _, body) = chat(&gw, "smart").await?;
    assert_eq!(status, StatusCode::OK, "the stream had started");
    assert!(
        body.is_err(),
        "the stalled stream must break, not hang: {body:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    let (_, headers, _) = chat(&gw, "smart").await?;
    assert_eq!(
        headers.get("x-gantry-provider").map(|v| v.as_bytes()),
        Some(&b"fine"[..])
    );
    assert_eq!(stall_seen.count("/v1/chat/completions"), 1);
    Ok(())
}

#[tokio::test]
async fn a_provider_total_limit_cuts_an_answer_that_dribbles_forever() -> TestResult {
    let mut dribble = answer(200, "");
    dribble.headers = vec![("content-type", "text/event-stream".into())];
    dribble.pieces = (0..100)
        .map(|_| (100, ": keep-alive\n\n".to_string()))
        .collect();
    let (a, _) = same(dribble).await?;
    let mut provider = route("dribble", Kind::OpenAi, a, &["m"]);
    provider.timeouts = Timeouts {
        total_ms: Some(500),
        ..Timeouts::default()
    };
    let gw = gateway("total", vec![provider], vec![], everyone())?;
    let started = Instant::now();
    let (_, _, body) = chat(&gw, "m").await?;
    assert!(body.is_err(), "{body:?}");
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(400) && took < Duration::from_secs(2),
        "{took:?}"
    );
    Ok(())
}

#[tokio::test]
async fn a_health_probe_marks_a_deployment_down_before_a_caller_reaches_it() -> TestResult {
    let (a, down_seen) = mock(Arc::new(|path, _, _| {
        if path == "/v1/models" {
            answer(503, "{}")
        } else {
            answer(200, CHAT_OK)
        }
    }))
    .await?;
    let (b, _) = same(answer(200, CHAT_OK)).await?;
    let mut probed = deployment("down", "m");
    probed.weight = 1000;
    probed.probe = Some(Probe {
        every_seconds: 1,
        chat: false,
    });
    let gw = gateway(
        "probe",
        vec![
            route("down", Kind::OpenAi, a, &[]),
            route("up", Kind::OpenAi, b, &[]),
        ],
        vec![alias(
            "smart",
            Balance::RoundRobin,
            vec![probed, deployment("up", "m")],
        )],
        everyone(),
    )?;
    // The probe runs in the background, about once a second.
    let mut ready = Value::Null;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let response = gw
            .app
            .clone()
            .oneshot(Request::get("/readyz").body(Body::empty())?)
            .await?;
        ready = serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
        if ready["checks"]["deployments"]["probed"]["down/m"]["up"] == false {
            break;
        }
    }
    let probe = &ready["checks"]["deployments"]["probed"]["down/m"];
    assert_eq!(probe["up"], false, "{ready}");
    assert_eq!(probe["outcome"], "503", "{ready}");
    assert_eq!(
        ready["status"], "ready",
        "a down deployment is detail, not unreadiness"
    );
    let (_, headers, _) = chat(&gw, "smart").await?;
    assert_eq!(
        headers.get("x-gantry-provider").map(|v| v.as_bytes()),
        Some(&b"up"[..])
    );
    assert_eq!(
        down_seen.count("/v1/chat/completions"),
        0,
        "no caller was sent to it"
    );
    assert!(down_seen.count("/v1/models") >= 1);
    Ok(())
}

#[tokio::test]
async fn a_key_pool_sets_aside_a_refused_key_and_rests_a_rate_limited_one() -> TestResult {
    let (a, seen) = mock(Arc::new(|_, headers, _| {
        match headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
        {
            Some("Bearer key-revoked") => answer(401, r#"{"error":{"code":"invalid_api_key"}}"#),
            Some("Bearer key-quota") => {
                let mut a = answer(429, r#"{"error":{"code":"rate_limit_exceeded"}}"#);
                a.headers.push(("retry-after", "120".into()));
                a
            }
            _ => answer(200, CHAT_OK),
        }
    }))
    .await?;
    let mut provider = route("pooled", Kind::OpenAi, a, &["m"]);
    provider.keys = ["key-revoked", "key-quota", "key-good"]
        .iter()
        .map(|k| Secret::new(*k))
        .collect();
    let gw = gateway("keys", vec![provider], vec![], everyone())?;
    let (status, _, _) = chat(&gw, "m").await?;
    assert_eq!(status, StatusCode::OK);
    let tried = attempts(&gw).await?;
    let outcomes: Vec<&str> = tried.iter().filter_map(|a| a["outcome"].as_str()).collect();
    assert_eq!(outcomes, ["401", "429", "200"], "{tried:?}");
    // Each switch names the key by a hash prefix, never by the key.
    let good = &sha256_hex(b"key-good")[..8];
    assert_eq!(tried[2]["key"], good, "{tried:?}");
    let log = std::fs::read_to_string(&gw.log)?;
    assert!(
        !log.contains("key-revoked") && !log.contains("key-good"),
        "{log}"
    );
    // Both are set aside: the next requests go to the good key alone.
    for _ in 0..3 {
        assert_eq!(chat(&gw, "m").await?.0, StatusCode::OK);
    }
    assert_eq!(seen.all().len(), 6);
    Ok(())
}

#[tokio::test]
async fn provider_fallbacks_are_followed_hop_by_hop() -> TestResult {
    let (a, _) = same(answer(500, "{}")).await?;
    let (b, _) = same(answer(503, "{}")).await?;
    let (c, _) = same(answer(200, CHAT_OK)).await?;
    let mut first = route("a", Kind::OpenAi, a, &["m"]);
    first.fallback = Some("b".into());
    let mut second = route("b", Kind::OpenAi, b, &[]);
    second.fallback = Some("c".into());
    // c falls back to a: the loop is cut, each provider tried once.
    let mut third = route("c", Kind::OpenAi, c, &[]);
    third.fallback = Some("a".into());
    let gw = gateway("hops", vec![first, second, third], vec![], everyone())?;
    let (status, headers, _) = chat(&gw, "m").await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get("x-gantry-attempts").map(|v| v.as_bytes()),
        Some(&b"3"[..])
    );
    let tried: Vec<String> = attempts(&gw)
        .await?
        .iter()
        .map(|a| {
            format!(
                "{}:{}",
                a["provider"].as_str().unwrap_or(""),
                a["outcome"].as_str().unwrap_or("")
            )
        })
        .collect();
    assert_eq!(tried, ["a:500", "b:503", "c:200"]);
    Ok(())
}

#[tokio::test]
async fn an_alias_falls_back_across_apis_only_on_the_failures_it_names_and_only_to_allowed_models()
-> TestResult {
    let (a, _) = same(answer(429, r#"{"error":{"code":"rate_limit_exceeded"}}"#)).await?;
    let (b, claude_seen) = same(answer(200, MESSAGES_OK)).await?;
    let providers = || {
        vec![
            route("openai", Kind::OpenAi, a, &[]),
            route("claude", Kind::Anthropic, b, &["claude-x"]),
        ]
    };
    let mut smart = alias(
        "smart",
        Balance::RoundRobin,
        vec![deployment("openai", "gpt-x")],
    );
    smart.fallbacks = vec!["claude-x".into()];
    let gw = gateway("across", providers(), vec![smart.clone()], everyone())?;
    let (status, headers, body) = chat(&gw, "smart").await?;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let answer: Value = serde_json::from_str(&body?)?;
    assert_eq!(answer["object"], "chat.completion", "{answer}");
    assert_eq!(
        answer["choices"][0]["message"]["content"], "from claude",
        "{answer}"
    );
    assert_eq!(
        headers.get("x-gantry-provider").map(|v| v.as_bytes()),
        Some(&b"claude"[..])
    );
    let (path, sent_headers, sent) = claude_seen.all().first().cloned().ok_or("nothing sent")?;
    assert_eq!(path, "/v1/messages");
    assert_eq!(sent["model"], "claude-x");
    assert!(sent_headers.contains_key("anthropic-version"));

    // A 429 is not among the failures this alias falls back on: the caller gets it.
    smart.fallback_on = vec![FallbackOn::ServerError];
    let gw = gateway("across-not", providers(), vec![smart.clone()], everyone())?;
    assert_eq!(chat(&gw, "smart").await?.0, StatusCode::TOO_MANY_REQUESTS);

    // A rule that does not allow the fallback model never reaches it through the alias.
    smart.fallback_on = FallbackOn::DEFAULT.to_vec();
    let narrow = Policy::new()
        .with_key(MAYA, "maya.cohen", "payments")
        .with_rule("smart-only", Who::Any, Models::Only(vec!["smart".into()]));
    let gw = gateway("across-narrow", providers(), vec![smart], narrow)?;
    assert_eq!(chat(&gw, "smart").await?.0, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(claude_seen.count("/v1/messages"), 1);
    Ok(())
}

#[tokio::test]
async fn a_context_window_refusal_falls_back_when_fallback_on_names_it() -> TestResult {
    let (a, _) = same(answer(
        400,
        r#"{"error":{"code":"context_length_exceeded","message":"too long"}}"#,
    ))
    .await?;
    let (b, _) = same(answer(200, CHAT_OK)).await?;
    let mut smart = alias("smart", Balance::RoundRobin, vec![deployment("short", "m")]);
    smart.fallbacks = vec!["long-model".into()];
    smart.fallback_on = vec![FallbackOn::ContextWindow];
    let gw = gateway(
        "context",
        vec![
            route("short", Kind::OpenAi, a, &[]),
            route("long", Kind::OpenAi, b, &["long-model"]),
        ],
        vec![smart],
        everyone(),
    )?;
    let (status, headers, _) = chat(&gw, "smart").await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get("x-gantry-model").map(|v| v.as_bytes()),
        Some(&b"long-model"[..])
    );
    Ok(())
}

#[tokio::test]
async fn conditions_route_by_tools_prompt_size_header_and_customer() -> TestResult {
    let (a, _) = same(answer(200, CHAT_OK)).await?;
    let names = ["general", "tools", "long", "gold"];
    let providers: Vec<ProviderRoute> = names
        .iter()
        .map(|n| route(n, Kind::OpenAi, a, &[]))
        .collect();
    let when = |w: When| Some(w);
    let mut tools = deployment("tools", "m");
    tools.when = when(When {
        tools: Some(true),
        ..When::default()
    });
    let mut long = deployment("long", "m");
    long.when = when(When {
        min_prompt_tokens: Some(1000),
        ..When::default()
    });
    let mut gold = deployment("gold", "m");
    gold.when = when(When {
        header: Some(("x-tier".into(), "gold".into())),
        ..When::default()
    });
    let gw = gateway(
        "when",
        providers,
        vec![alias(
            "smart",
            Balance::RoundRobin,
            vec![deployment("general", "m"), tools, long, gold],
        )],
        everyone(),
    )?;
    let provider_of = |headers: &HeaderMap| {
        headers
            .get("x-gantry-provider")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    };
    let plain = json!({"model": "smart", "messages": [{"role": "user", "content": "hi"}]});
    let (_, headers, _) = send(&gw, "/v1/chat/completions", plain.clone(), &[]).await?;
    assert_eq!(provider_of(&headers), "general");
    let with_tools = json!({"model": "smart", "messages": [], "tools": [{"type": "function", "function": {"name": "f"}}]});
    let (_, headers, _) = send(&gw, "/v1/chat/completions", with_tools, &[]).await?;
    assert_eq!(provider_of(&headers), "tools");
    let long_prompt =
        json!({"model": "smart", "messages": [{"role": "user", "content": "x".repeat(8000)}]});
    let (_, headers, _) = send(&gw, "/v1/chat/completions", long_prompt, &[]).await?;
    assert_eq!(provider_of(&headers), "long");
    let (_, headers, _) = send(&gw, "/v1/chat/completions", plain, &[("x-tier", "gold")]).await?;
    assert_eq!(provider_of(&headers), "gold");
    let routing = records(&gw, "usage")
        .await?
        .into_iter()
        .filter_map(|r| r["routing"]["for"].as_str().map(str::to_string))
        .collect::<Vec<_>>();
    assert!(routing.contains(&"when".to_string()), "{routing:?}");
    Ok(())
}

#[tokio::test]
async fn a_deployment_nearly_out_of_its_rate_limit_is_steered_away_from() -> TestResult {
    let mut tight = answer(200, CHAT_OK);
    tight
        .headers
        .push(("x-ratelimit-remaining-requests", "1".into()));
    tight
        .headers
        .push(("x-ratelimit-limit-requests", "500".into()));
    let (a, tight_seen) = same(tight).await?;
    let mut roomy = answer(200, CHAT_OK);
    roomy
        .headers
        .push(("anthropic-ratelimit-requests-remaining", "400".into()));
    roomy
        .headers
        .push(("anthropic-ratelimit-requests-limit", "500".into()));
    let (b, roomy_seen) = same(roomy).await?;
    let mut first = deployment("tight", "m");
    first.weight = 1000;
    let gw = gateway(
        "headroom",
        vec![
            route("tight", Kind::OpenAi, a, &[]),
            route("roomy", Kind::OpenAi, b, &[]),
        ],
        vec![alias(
            "smart",
            Balance::RoundRobin,
            vec![first, deployment("roomy", "m")],
        )],
        everyone(),
    )?;
    for _ in 0..4 {
        assert_eq!(chat(&gw, "smart").await?.0, StatusCode::OK);
    }
    // Its weight would send it nearly everything; after its first answer said 1 of 500 left, it gets none.
    assert_eq!(tight_seen.count("/v1/chat/completions"), 1);
    assert_eq!(roomy_seen.count("/v1/chat/completions"), 3);
    Ok(())
}

#[tokio::test]
async fn adaptive_balance_scores_measured_latency() -> TestResult {
    let mut slow = answer(200, CHAT_OK);
    slow.wait_ms = 150;
    let (a, slow_seen) = same(slow).await?;
    let (b, _) = same(answer(200, CHAT_OK)).await?;
    let gw = gateway(
        "adaptive",
        vec![
            route("slow", Kind::OpenAi, a, &[]),
            route("fast", Kind::OpenAi, b, &[]),
        ],
        vec![alias(
            "smart",
            Balance::Adaptive,
            vec![deployment("slow", "m"), deployment("fast", "m")],
        )],
        everyone(),
    )?;
    for _ in 0..6 {
        assert_eq!(chat(&gw, "smart").await?.0, StatusCode::OK);
    }
    // Each is measured once; the slow one scores worse from then on.
    assert_eq!(slow_seen.count("/v1/chat/completions"), 1);
    let reasons: Vec<String> = records(&gw, "usage")
        .await?
        .iter()
        .filter_map(|r| r["routing"]["reason"].as_str().map(str::to_string))
        .collect();
    assert!(
        reasons.iter().any(|r| r.starts_with("adaptive: score")),
        "{reasons:?}"
    );
    Ok(())
}

fn price(input: f64, output: f64) -> Price {
    Price {
        input,
        output,
        cache_read: None,
        cache_write: None,
        cache_write_1h: None,
        long_context: None,
        max_output: None,
        max_context: None,
        per_image: None,
        source: Default::default(),
    }
}

#[tokio::test]
async fn wildcard_models_pass_new_names_through_and_a_budget_refuses_an_unpriced_one() -> TestResult
{
    let (a, seen) = same(answer(200, CHAT_OK)).await?;
    let providers = || vec![route("openai", Kind::OpenAi, a, &["gpt-*"])];
    let rule = || {
        Policy::new()
            .with_key(MAYA, "maya.cohen", "payments")
            .with_rule(
                "gpt",
                Who::Any,
                Models::Only(vec!["gpt-*".into(), "openai/*".into()]),
            )
    };
    let gw = gateway("wild", providers(), vec![], rule())?;
    let (status, headers, _) = chat(&gw, "gpt-9-preview").await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get("x-gantry-model").map(|v| v.as_bytes()),
        Some(&b"gpt-9-preview"[..])
    );
    // `<provider>/<model>` goes to that provider, named as it knows the model.
    let (status, _, _) = chat(&gw, "openai/gpt-10").await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        seen.all().last().map(|s| s.2["model"].clone()),
        Some(json!("gpt-10"))
    );
    // A model the rule's pattern does not match is refused.
    assert_eq!(chat(&gw, "o5").await?.0, StatusCode::FORBIDDEN);

    let mut prices = PriceOverrides::new();
    prices.insert("gpt-9-preview".into(), price(1.0, 2.0));
    let budgeted = rule()
        .with_limits(Limits {
            budgets: vec![gantry_core::policy::Cap {
                budget: Budget {
                    usd: 10.0,
                    per: Period::Day,
                },
                models: Vec::new(),
                from: None,
                shadow_until: None,
            }],
            ..Limits::default()
        })
        .with_prices(prices);
    let gw = gateway("wild-budget", providers(), vec![], budgeted)?;
    let ask = |model: &str| json!({"model": model, "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]});
    let (status, _, body) = send(&gw, "/v1/chat/completions", ask("gpt-9-preview"), &[]).await?;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let (status, _, body) =
        send(&gw, "/v1/chat/completions", ask("gpt-unpriced-model"), &[]).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.unwrap_or_default().contains("no_price"));
    Ok(())
}

#[tokio::test]
async fn every_answer_names_its_provider_deployment_model_cost_and_request() -> TestResult {
    let (a, _) = same(answer(200, CHAT_OK)).await?;
    let mut sse = answer(200, "");
    sse.headers = vec![("content-type", "text/event-stream".into())];
    sse.pieces = vec![(0, "data: {\"choices\":[]}\n\ndata: [DONE]\n\n".into())];
    let (b, _) = same(sse).await?;
    let mut prices = PriceOverrides::new();
    prices.insert("m1".into(), price(1.0, 2.0));
    prices.insert("m2".into(), price(1.0, 2.0));
    let gw = gateway(
        "headers",
        vec![
            route("east", Kind::OpenAi, a, &["m1"]),
            route("stream", Kind::OpenAi, b, &["m2"]),
        ],
        vec![alias(
            "smart",
            Balance::RoundRobin,
            vec![deployment("east", "m1")],
        )],
        everyone().with_prices(prices),
    )?;
    let (status, headers, _) = chat(&gw, "smart").await?;
    assert_eq!(status, StatusCode::OK);
    let get = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    };
    assert_eq!(get("x-gantry-provider"), "east");
    assert_eq!(get("x-gantry-deployment"), "east/m1");
    assert_eq!(get("x-gantry-model"), "m1");
    // 1000 tokens in at $1 per million and 500 out at $2 per million.
    assert_eq!(get("x-gantry-cost-usd"), "0.002");
    assert_eq!(get("x-gantry-request-id"), get("x-gantry-decision"));
    assert!(!get("x-gantry-request-id").is_empty());

    // A stream gets them on its first response, the cost as the prompt's estimate.
    let (status, headers, _) = send(
        &gw,
        "/v1/chat/completions",
        json!({"model": "m2", "stream": true, "messages": [{"role": "user", "content": "x".repeat(4000)}]}),
        &[],
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let cost: f64 = headers
        .get("x-gantry-cost-usd")
        .and_then(|v| v.to_str().ok())
        .ok_or("no cost header")?
        .parse()?;
    assert!(
        cost > 0.0009 && cost < 0.0012,
        "about 1000 tokens in at $1 per million: {cost}"
    );
    assert_eq!(
        headers.get("x-gantry-provider").map(|v| v.as_bytes()),
        Some(&b"stream"[..])
    );

    // A refusal carries the request ID too.
    let (status, headers, _) = chat(&gw, "nothing-serves-this").await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(headers.contains_key("x-gantry-request-id"));
    assert!(!headers.contains_key("x-gantry-provider"));
    Ok(())
}
