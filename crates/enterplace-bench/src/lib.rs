//! Measures what the gateway adds to a request: a mock upstream, an open-loop load generator,
//! and a report of latency percentiles.

use std::{
    collections::VecDeque,
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use enterplace_core::{
    guard::{Action, Check, Guardrail},
    policy::Policy,
};
use http_body::Frame;
use http_body_util::BodyExt;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

const CHAT_REQUEST: &str =
    r#"{"model":"mock-model","messages":[{"role":"user","content":"Say hello."}]}"#;
const CHAT_REQUEST_STREAM: &str =
    r#"{"model":"mock-model","stream":true,"messages":[{"role":"user","content":"Say hello."}]}"#;
const MESSAGE_REQUEST: &str = r#"{"model":"mock-claude","max_tokens":64,"messages":[{"role":"user","content":"Say hello."}]}"#;
const MESSAGE_REQUEST_STREAM: &str = r#"{"model":"mock-claude","max_tokens":64,"stream":true,"messages":[{"role":"user","content":"Say hello."}]}"#;
const CHAT_RESPONSE: &str = r#"{"id":"chatcmpl-mock","object":"chat.completion","created":0,"model":"mock-model","choices":[{"index":0,"message":{"role":"assistant","content":"Hello."},"finish_reason":"stop"}],"usage":{"prompt_tokens":9,"completion_tokens":2,"total_tokens":11}}"#;
const STREAM_WORDS: [&str; 8] = [
    "Hello",
    " there",
    ",",
    " this",
    " is",
    " a",
    " streamed",
    " answer.",
];

/// A body that hands out its chunks one at a time, so a stream really is several frames on the wire.
struct Chunks(VecDeque<Bytes>);

impl http_body::Body for Chunks {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        Poll::Ready(self.0.pop_front().map(|chunk| Ok(Frame::data(chunk))))
    }
}

/// Starts an upstream that answers every chat request at once with a fixed body,
/// or with a stream of chunks of different lengths when the request asks for one.
pub async fn spawn_mock_upstream(addr: SocketAddr) -> Result<SocketAddr, BoxError> {
    spawn_mock_upstream_with_latency(addr, Duration::ZERO).await
}

/// The same upstream, waiting `latency` before each answer, as a real provider does. Bifrost publishes its
/// overhead against a mock that takes about 1.5 s; this reproduces that setup.
pub async fn spawn_mock_upstream_with_latency(
    addr: SocketAddr,
    latency: Duration,
) -> Result<SocketAddr, BoxError> {
    async fn chat(latency: Duration, request: Request<Body>) -> Response {
        // The mock reads at most 1 MiB: enough to look for the stream flag, and a bound on what a test can send it.
        let Ok(body) = axum::body::to_bytes(request.into_body(), 1 << 20).await else {
            return StatusCode::PAYLOAD_TOO_LARGE.into_response();
        };
        if !latency.is_zero() {
            tokio::time::sleep(latency).await;
        }
        if body.windows(13).any(|w| w == b"\"stream\":true") {
            let mut chunks: VecDeque<Bytes> = STREAM_WORDS
                .iter()
                .map(|word| {
                    Bytes::from(format!(
                        "data: {{\"id\":\"chatcmpl-mock\",\"object\":\"chat.completion.chunk\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"{word}\"}}}}]}}\n\n"
                    ))
                })
                .collect();
            chunks.push_back(Bytes::from_static(b"data: [DONE]\n\n"));
            (
                [(header::CONTENT_TYPE, "text/event-stream")],
                Body::new(Chunks(chunks)),
            )
                .into_response()
        } else {
            ([(header::CONTENT_TYPE, "application/json")], CHAT_RESPONSE).into_response()
        }
    }
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    // The mock answers both routes the same way: the bench measures the gateway, not the provider.
    let app = Router::new()
        .route(
            "/v1/chat/completions",
            post(move |request| chat(latency, request)),
        )
        .route("/v1/messages", post(move |request| chat(latency, request)));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(bound)
}

/// The key the load generator sends. It is one of the keys in [`bench_policy`].
pub const BENCH_KEY: &str = "bench-key-0500";

/// A policy of realistic size: 1,000 keys in 50 teams, each team allowed three models, every rule checking
/// for secrets, so the gate measures the guardrail scan as well.
fn bench_policy(events: Option<SocketAddr>) -> Policy {
    let mut policy = Policy::new();
    for team in 0..50 {
        policy = policy.with_models(
            format!("team-{team}"),
            ["mock-model", "mock-claude", "other-model-a"],
        );
    }
    for key in 0..1000 {
        policy = policy.with_key(
            &format!("bench-key-{key:04}"),
            format!("person-{key}"),
            format!("team-{}", key % 50),
        );
    }
    let mut guards = vec![Guardrail {
        name: "no-secrets".into(),
        action: Action::Block,
        check: Check::Secrets,
        on: enterplace_core::guard::On::REQUEST,
        shadow_until: None,
    }];
    // An events guardrail in observe mode, with the defaults a policy file gives it: every request and every
    // answer becomes an envelope on its queue, sent in the background.
    if let Some(sink) = events {
        use enterplace_core::{events, guard};
        guards.push(Guardrail {
            name: "watcher".into(),
            action: events::guard_action(events::Mode::Observe),
            check: Check::Events(events::Events {
                hook: guard::Webhook {
                    url: format!("http://{sink}/events"),
                    timeout: Duration::from_secs(1),
                    on_failure: guard::OnFailure::FailOpen,
                    headers_env: Vec::new(),
                    vendor: guard::Vendor::Contract,
                    key_env: None,
                },
                mode: events::Mode::Observe,
                history: false,
                stream: None,
                session_end_seconds: 3600,
                secret_env: None,
                batch_url: Some(format!("http://{sink}/events")),
                queue: 1024,
                batch_size: 50,
                retries: 2,
            }),
            on: guard::On {
                request: false,
                answer: false,
            },
            shadow_until: None,
        });
    }
    policy.with_guardrails(&guards)
}

/// A plugin service for an events guardrail that takes every delivery and counts the envelopes in it.
pub async fn spawn_events_sink() -> Result<(SocketAddr, Arc<AtomicU64>), BoxError> {
    let received = Arc::new(AtomicU64::new(0));
    let count = received.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let bound = listener.local_addr()?;
    let app = Router::new().route(
        "/events",
        post(move |body: Bytes| {
            let count = count.clone();
            async move {
                // Every envelope names its phase once, alone or in a batch.
                let envelopes = body.windows(8).filter(|w| w == b"\"phase\":").count();
                count.fetch_add(envelopes as u64, Ordering::Relaxed);
                ([(header::CONTENT_TYPE, "application/json")], "{}")
            }
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((bound, received))
}

/// Starts the gateway in this process on the same accept loop the binary uses, forwarding to `upstream`,
/// with or without the policy check in the path.
/// Starts the gateway in front of `upstream`. With `check_policy`, every request is identified, decided and
/// written to an audit log, as in real serving. The log's path is returned so the caller can count its records.
pub async fn spawn_gateway(
    upstream: SocketAddr,
    check_policy: bool,
) -> Result<(SocketAddr, Option<PathBuf>), BoxError> {
    spawn_gateway_watched(upstream, check_policy, None).await
}

/// As [`spawn_gateway`]. With `events`, every rule of the policy also has an events guardrail in observe mode that
/// delivers to the plugin service at that address ([`spawn_events_sink`]).
pub async fn spawn_gateway_watched(
    upstream: SocketAddr,
    check_policy: bool,
    events: Option<SocketAddr>,
) -> Result<(SocketAddr, Option<PathBuf>), BoxError> {
    static RUN: AtomicU64 = AtomicU64::new(0);
    let audit_path = check_policy.then(|| {
        std::env::temp_dir().join(format!(
            "enterplace-bench-{}-{}.jsonl",
            std::process::id(),
            RUN.fetch_add(1, Ordering::Relaxed)
        ))
    });
    let audit = match &audit_path {
        Some(path) => {
            let _ = std::fs::remove_file(path);
            Some(enterplace_server::Audit {
                log: Arc::new(enterplace_core::audit::AuditLog::open(path)?),
                provider: "mock".into(),
                policy_sha256: String::new(),
                keys_sha256: String::new(),
            })
        }
        None => None,
    };
    let config = enterplace_server::Config {
        // The messages route goes to a provider of the anthropic kind, as Claude Code's requests do.
        providers: vec![enterplace_server::ProviderRoute {
            name: "mock-anthropic".into(),
            kind: enterplace_core::config::Kind::Anthropic,
            url: format!("http://{upstream}"),
            key: Some(enterplace_server::Secret::new("mock-provider-key")),
            models: vec!["mock-claude".into()],
            ..enterplace_server::ProviderRoute::default()
        }],
        upstream: Some(format!("http://{upstream}")),
        policy: check_policy.then(|| bench_policy(events)),
        audit,
        ..enterplace_server::Config::default()
    };
    let timeouts = config.timeouts.clone();
    let app = enterplace_server::app(config)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let bound = listener.local_addr()?;
    tokio::spawn(enterplace_server::serve_on(
        listener,
        app,
        timeouts,
        std::future::pending(),
    ));
    Ok((bound, audit_path))
}

#[derive(Clone, Copy, Debug)]
pub struct Load {
    pub rps: u32,
    pub duration: Duration,
    pub stream: bool,
    /// Claude Code's route, `/v1/messages`, with the key in x-api-key, in place of the chat route.
    pub messages: bool,
}

/// Percentiles of one measured quantity.
#[derive(Clone, Copy, Debug, Default)]
pub struct Spread {
    pub p50: Duration,
    pub p99: Duration,
    pub max: Duration,
}

#[derive(Clone, Debug)]
pub struct Report {
    pub sent: usize,
    pub ok: usize,
    /// From the moment the request was handed to the HTTP client until its last byte arrived.
    pub latency: Spread,
    /// How late each request was sent compared with its schedule. This is the load generator's own
    /// timer error. It is reported apart so it is not mistaken for the server's latency.
    pub lag: Spread,
    /// Time the gateway says it spent on the request itself, from its `Server-Timing` header.
    /// `None` when the target does not send one, as the upstream alone does not.
    pub own: Option<Spread>,
}

struct Sample {
    latency: Duration,
    lag: Duration,
    own: Option<Duration>,
}

/// The `dur` value, in milliseconds, of a `Server-Timing: enterplace;dur=0.123` header.
fn own_time(response: &Response<hyper::body::Incoming>) -> Option<Duration> {
    let value = response.headers().get("server-timing")?.to_str().ok()?;
    let millis: f64 = value
        .split("dur=")
        .nth(1)?
        .split([',', ';'])
        .next()?
        .trim()
        .parse()
        .ok()?;
    Some(Duration::from_secs_f64(millis / 1000.0))
}

/// Sends requests at a fixed rate.
///
/// Open loop on purpose: a slow answer does not delay the next request. A closed loop would hide
/// exactly the stalls this is here to find.
pub async fn run_load(target: SocketAddr, load: Load) -> Result<Report, BoxError> {
    run_load_on(&load_client(), target, load).await
}

/// The load generator's HTTP client. Its pool keeps connections open between runs that share it.
pub type LoadClient = Client<hyper_util::client::legacy::connect::HttpConnector, Body>;

pub fn load_client() -> LoadClient {
    Client::builder(TokioExecutor::new()).build_http()
}

/// Raises the rate to `load.rps` in five one-second steps, on `client`, so the connections a slow upstream
/// needs (rate times latency, 7,500 at 5,000 a second and 1.5 s) are opened gradually and kept in its pool.
/// Opened all at once, they overflow the listen queue and the run measures connection retries.
/// Returns how many requests it sent.
pub async fn ramp(client: &LoadClient, target: SocketAddr, load: Load) -> Result<usize, BoxError> {
    let mut sent = 0;
    for percent in [10, 25, 50, 75, 100] {
        let step = Load {
            rps: (load.rps * percent / 100).max(1),
            duration: Duration::from_secs(1),
            ..load
        };
        sent += run_load_on(client, target, step).await?.sent;
    }
    Ok(sent)
}

/// [`run_load`] on a client the caller keeps, so its warm connections are reused.
pub async fn run_load_on(
    client: &LoadClient,
    target: SocketAddr,
    load: Load,
) -> Result<Report, BoxError> {
    let (path, body) = match (load.messages, load.stream) {
        (false, false) => ("/v1/chat/completions", CHAT_REQUEST),
        (false, true) => ("/v1/chat/completions", CHAT_REQUEST_STREAM),
        (true, false) => ("/v1/messages", MESSAGE_REQUEST),
        (true, true) => ("/v1/messages", MESSAGE_REQUEST_STREAM),
    };
    let uri = format!("http://{target}{path}");
    let body = Bytes::from_static(body.as_bytes());
    let messages = load.messages;
    let total = (u64::from(load.rps) * load.duration.as_millis() as u64 / 1000) as usize;
    let gap = Duration::from_secs(1) / load.rps.max(1);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Option<Sample>>();

    let start = Instant::now();
    for i in 0..total {
        let due = start + gap * i as u32;
        tokio::time::sleep_until(due.into()).await;
        let (client, uri, body, tx) = (client.clone(), uri.clone(), body.clone(), tx.clone());
        tokio::spawn(async move {
            let request = Request::post(uri).header(header::CONTENT_TYPE, "application/json");
            let request = if messages {
                request.header("x-api-key", BENCH_KEY)
            } else {
                request.header(header::AUTHORIZATION, format!("Bearer {BENCH_KEY}"))
            };
            let request = request.body(Body::from(body));
            let sent = Instant::now();
            let outcome = match request {
                Ok(request) => match client.request(request).await {
                    Ok(response) if response.status().is_success() => {
                        let own = own_time(&response);
                        // The clock stops when the whole body has arrived, so a stream is timed to its last chunk.
                        response.into_body().collect().await.ok().map(|_| Sample {
                            latency: sent.elapsed(),
                            lag: sent - due,
                            own,
                        })
                    }
                    _ => None,
                },
                Err(_) => None,
            };
            let _ = tx.send(outcome);
        });
    }
    drop(tx);

    let (mut latency, mut lag, mut own) = (
        Vec::with_capacity(total),
        Vec::with_capacity(total),
        Vec::new(),
    );
    let mut sent = 0;
    while let Some(outcome) = rx.recv().await {
        sent += 1;
        if let Some(sample) = outcome {
            latency.push(sample.latency);
            lag.push(sample.lag);
            own.extend(sample.own);
        }
    }
    let ok = latency.len();
    Ok(Report {
        sent,
        ok,
        latency: spread(latency),
        lag: spread(lag),
        own: (!own.is_empty()).then(|| spread(own)),
    })
}

fn spread(mut samples: Vec<Duration>) -> Spread {
    samples.sort_unstable();
    Spread {
        p50: percentile(&samples, 50),
        p99: percentile(&samples, 99),
        max: samples.last().copied().unwrap_or_default(),
    }
}

/// Nearest-rank percentile of sorted samples. Zero when there are none.
fn percentile(sorted: &[Duration], pct: usize) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let rank = (sorted.len() * pct).div_ceil(100).clamp(1, sorted.len());
    sorted[rank - 1]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn percentile_uses_nearest_rank() {
        let samples: Vec<Duration> = (1..=100).map(ms).collect();
        assert_eq!(percentile(&samples, 50), ms(50));
        assert_eq!(percentile(&samples, 99), ms(99));
        assert_eq!(percentile(&[ms(7)], 99), ms(7));
        assert_eq!(percentile(&[], 99), Duration::ZERO);
    }
}
