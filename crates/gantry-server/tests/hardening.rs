//! Tests for what a proxy must never do: leak a credential, forward a header that belongs to one connection,
//! wait forever, or say something about its insides to a caller. Each one fails if the behavior is removed.

use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::{Body, Bytes},
    http::{HeaderMap, Request, StatusCode, header},
    routing::post,
};
use gantry_core::policy::Policy;
use gantry_server::{Config, Timeouts};
use http_body_util::BodyExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Seen = Arc<Mutex<Option<(HeaderMap, Bytes)>>>;

/// An upstream that records the headers and body of the last request it received.
async fn recording_upstream() -> Result<(SocketAddr, Seen), Box<dyn std::error::Error>> {
    let seen: Seen = Arc::default();
    let record = seen.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move |request: Request<Body>| {
            let record = record.clone();
            async move {
                let (parts, body) = request.into_parts();
                let bytes = body
                    .collect()
                    .await
                    .map(|b| b.to_bytes())
                    .unwrap_or_default();
                if let Ok(mut slot) = record.lock() {
                    *slot = Some((parts.headers, bytes));
                }
                "{}"
            }
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((addr, seen))
}

fn policy() -> Policy {
    Policy::new()
        .with_key("key-maya", "maya.cohen", "payments")
        .with_models("payments", ["claude-haiku-5-5", "claude-sonnet-5-5"])
}

fn config(upstream: SocketAddr, checked: bool) -> Config {
    Config {
        upstream: Some(format!("http://{upstream}")),
        policy: checked.then(policy),
        ..Config::default()
    }
}

const BODY: &str =
    r#"{"model":"claude-haiku-5-5","user":"u-17","metadata":{"trace":"t-9"},"messages":[]}"#;

fn chat() -> axum::http::request::Builder {
    Request::post("/v1/chat/completions").header(header::CONTENT_TYPE, "application/json")
}

fn seen_request(seen: &Seen) -> Result<(HeaderMap, Bytes), Box<dyn std::error::Error>> {
    seen.lock()
        .map_err(|_| "lock poisoned")?
        .clone()
        .ok_or_else(|| "the upstream received nothing".into())
}

async fn error_code(
    response: axum::response::Response,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let bytes = response.into_body().collect().await?.to_bytes();
    let text = String::from_utf8(bytes.to_vec())?;
    let json: serde_json::Value =
        serde_json::from_str(&text).map_err(|_| format!("the error body is not JSON: {text}"))?;
    let code = json["error"]["code"]
        .as_str()
        .ok_or("the error has no code")?
        .to_string();
    Ok((code, text))
}

#[tokio::test]
async fn the_callers_credentials_never_reach_the_upstream() -> TestResult {
    let (upstream, seen) = recording_upstream().await?;
    let request = chat()
        .header(header::AUTHORIZATION, "Bearer key-maya")
        .header(header::COOKIE, "session=abc")
        .header(header::PROXY_AUTHORIZATION, "Basic Zm9vOmJhcg==")
        .body(Body::from(BODY))?;
    let response = gantry_server::app(config(upstream, true))?
        .oneshot(request)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let (headers, _) = seen_request(&seen)?;
    for name in [
        header::AUTHORIZATION,
        header::COOKIE,
        header::PROXY_AUTHORIZATION,
    ] {
        assert!(!headers.contains_key(&name), "{name} reached the upstream");
    }
    Ok(())
}

#[tokio::test]
async fn caller_aws_headers_never_reach_the_upstream() -> TestResult {
    // QA10-9: an x-amz header beside Gantry's own signature would let a caller choose how Bedrock reads it.
    let (upstream, seen) = recording_upstream().await?;
    let request = chat()
        .header(header::AUTHORIZATION, "Bearer key-maya")
        .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
        .header("x-amzn-bedrock-trace", "ENABLED")
        .body(Body::from(BODY))?;
    let response = gantry_server::app(config(upstream, true))?
        .oneshot(request)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let (headers, _) = seen_request(&seen)?;
    assert!(
        !headers
            .keys()
            .any(|name| name.as_str().starts_with("x-amz")),
        "{headers:?}"
    );
    Ok(())
}

#[tokio::test]
async fn an_encoded_body_is_refused_and_never_forwarded() -> TestResult {
    // QA10-14: Gantry reads the body as plain JSON, so a Content-Encoding header would no longer describe it.
    let (upstream, seen) = recording_upstream().await?;
    let request = chat()
        .header(header::AUTHORIZATION, "Bearer key-maya")
        .header(header::CONTENT_ENCODING, "gzip")
        .body(Body::from(BODY))?;
    let response = gantry_server::app(config(upstream, true))?
        .oneshot(request)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let (code, text) = error_code(response).await?;
    assert_eq!(code, "unreadable_request");
    assert!(text.contains("Content-Encoding"), "{text}");
    assert!(
        seen_request(&seen).is_err(),
        "the request reached the upstream"
    );
    // identity is no encoding at all.
    let request = chat()
        .header(header::AUTHORIZATION, "Bearer key-maya")
        .header(header::CONTENT_ENCODING, "identity")
        .body(Body::from(BODY))?;
    let response = gantry_server::app(config(upstream, true))?
        .oneshot(request)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn user_and_metadata_reach_the_upstream_unchanged_checked_and_unchecked() -> TestResult {
    for checked in [true, false] {
        let (upstream, seen) = recording_upstream().await?;
        let request = chat()
            .header(header::AUTHORIZATION, "Bearer key-maya")
            .body(Body::from(BODY))?;
        gantry_server::app(config(upstream, checked))?
            .oneshot(request)
            .await?;
        let (_, body) = seen_request(&seen)?;
        assert_eq!(body, BODY.as_bytes(), "checked={checked}");
    }
    Ok(())
}

#[tokio::test]
async fn hop_by_hop_request_headers_stop_at_the_gateway() -> TestResult {
    let (upstream, seen) = recording_upstream().await?;
    let request = chat()
        .header(header::CONNECTION, "x-only-this-hop, keep-alive")
        .header("x-only-this-hop", "1")
        .header("keep-alive", "timeout=5")
        .header(header::TE, "trailers")
        .header(header::UPGRADE, "websocket")
        .header("x-end-to-end", "kept")
        .body(Body::from(BODY))?;
    gantry_server::app(config(upstream, false))?
        .oneshot(request)
        .await?;

    let (headers, _) = seen_request(&seen)?;
    for name in ["x-only-this-hop", "keep-alive", "te", "upgrade"] {
        assert!(!headers.contains_key(name), "{name} reached the upstream");
    }
    assert_eq!(
        headers.get("x-end-to-end").and_then(|v| v.to_str().ok()),
        Some("kept")
    );
    Ok(())
}

/// An upstream on a raw socket, so the test controls every byte and every pause of the answer.
async fn raw_upstream(
    parts: Vec<(Duration, &'static str)>,
) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        let mut buffer = [0u8; 4096];
        let _ = socket.read(&mut buffer).await;
        for (pause, bytes) in parts {
            tokio::time::sleep(pause).await;
            if socket.write_all(bytes.as_bytes()).await.is_err() {
                return;
            }
        }
        // Hold the connection so the test, not a close, decides when the answer ends.
        tokio::time::sleep(Duration::from_secs(5)).await;
    });
    Ok(addr)
}

#[tokio::test]
async fn hop_by_hop_response_headers_stop_at_the_gateway() -> TestResult {
    let upstream = raw_upstream(vec![(
        Duration::ZERO,
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: x-upstream-hop\r\nx-upstream-hop: 1\r\nKeep-Alive: timeout=9\r\nx-end-to-end: kept\r\n\r\n{}",
    )])
    .await?;
    let response = gantry_server::app(config(upstream, false))?
        .oneshot(chat().body(Body::from(BODY))?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    for name in ["x-upstream-hop", "keep-alive", "connection"] {
        assert!(
            !response.headers().contains_key(name),
            "{name} reached the caller"
        );
    }
    assert_eq!(
        response
            .headers()
            .get("x-end-to-end")
            .and_then(|v| v.to_str().ok()),
        Some("kept")
    );
    assert!(
        response.headers().contains_key("server-timing"),
        "the gateway must report its own time"
    );
    Ok(())
}

#[tokio::test]
async fn an_upstream_that_never_answers_is_given_up_on() -> TestResult {
    let upstream = raw_upstream(vec![(
        Duration::from_secs(4),
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
    )])
    .await?;
    let mut config = config(upstream, false);
    config.timeouts = Timeouts {
        first_byte: Duration::from_millis(200),
        ..Timeouts::default()
    };
    let started = Instant::now();
    let response = gantry_server::app(config)?
        .oneshot(chat().body(Body::from(BODY))?)
        .await?;

    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the gateway waited {:?}",
        started.elapsed()
    );
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    let (code, text) = error_code(response).await?;
    assert_eq!(code, "upstream_timeout");
    assert!(
        !text.contains("127.0.0.1"),
        "the error names the upstream: {text}"
    );
    Ok(())
}

#[tokio::test]
async fn an_unreachable_upstream_is_reported_without_its_address() -> TestResult {
    // Port 1 on loopback refuses connections.
    let config = Config {
        upstream: Some("http://127.0.0.1:1".into()),
        ..Config::default()
    };
    let response = gantry_server::app(config)?
        .oneshot(chat().body(Body::from(BODY))?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let (code, text) = error_code(response).await?;
    assert_eq!(code, "upstream_unreachable");
    assert!(
        !text.contains("127.0.0.1") && !text.contains("GANTRY_UPSTREAM"),
        "the error tells the caller about the operator's setup: {text}"
    );
    Ok(())
}

/// A body that notes whether anyone tried to read it.
struct Watched(Arc<AtomicBool>);

impl http_body::Body for Watched {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        self.0.store(true, Ordering::SeqCst);
        Poll::Ready(None)
    }
}

#[tokio::test]
async fn a_stranger_is_refused_before_their_body_is_read() -> TestResult {
    let (upstream, _) = recording_upstream().await?;
    for (auth, expected) in [
        (None, "no_key"),
        (Some("Bearer key-nobody"), "unknown_key"),
        (Some("Basic abc"), "no_key"),
    ] {
        let read = Arc::new(AtomicBool::new(false));
        let mut request = chat();
        if let Some(auth) = auth {
            request = request.header(header::AUTHORIZATION, auth);
        }
        let response = gantry_server::app(config(upstream, true))?
            .oneshot(request.body(Body::new(Watched(read.clone())))?)
            .await?;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{auth:?}");
        assert_eq!(error_code(response).await?.0, expected, "{auth:?}");
        assert!(
            !read.load(Ordering::SeqCst),
            "the body of an unidentified caller was read ({auth:?})"
        );
    }
    Ok(())
}

#[tokio::test]
async fn two_authorization_headers_are_refused_and_a_lowercase_scheme_is_accepted() -> TestResult {
    let (upstream, _) = recording_upstream().await?;
    let app = gantry_server::app(config(upstream, true))?;

    let twice = chat()
        .header(header::AUTHORIZATION, "Bearer key-maya")
        .header(header::AUTHORIZATION, "Bearer other")
        .body(Body::from(BODY))?;
    let response = app.clone().oneshot(twice).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(error_code(response).await?.0, "ambiguous_key");

    let lower = chat()
        .header(header::AUTHORIZATION, "bearer  key-maya ")
        .body(Body::from(BODY))?;
    assert_eq!(app.oneshot(lower).await?.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn a_refused_model_names_what_the_team_may_use() -> TestResult {
    let (upstream, seen) = recording_upstream().await?;
    let request = chat()
        .header(header::AUTHORIZATION, "Bearer key-maya")
        .body(Body::from(r#"{"model":"claude-opus-5-5","messages":[]}"#))?;
    let response = gantry_server::app(config(upstream, true))?
        .oneshot(request)
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let (code, text) = error_code(response).await?;
    assert_eq!(code, "model_not_allowed");
    assert!(
        text.contains("claude-haiku-5-5, claude-sonnet-5-5"),
        "the refusal does not list the allowed models: {text}"
    );
    assert!(
        seen_request(&seen).is_err(),
        "a refused request reached the upstream"
    );
    Ok(())
}

#[tokio::test]
async fn a_duplicated_model_field_cannot_slip_past_the_policy() -> TestResult {
    // One parser may read the first "model" and another the last. The gateway must not guess.
    let (upstream, seen) = recording_upstream().await?;
    let body = r#"{"model":"claude-haiku-5-5","model":"claude-opus-5-5","messages":[]}"#;
    let request = chat()
        .header(header::AUTHORIZATION, "Bearer key-maya")
        .body(Body::from(body))?;
    let response = gantry_server::app(config(upstream, true))?
        .oneshot(request)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        seen_request(&seen).is_err(),
        "the request reached the upstream"
    );
    Ok(())
}

#[tokio::test]
async fn an_upstream_setting_that_would_misroute_or_leak_is_refused_at_startup() {
    for bad in [
        "http://svc:S3cret@127.0.0.1:9000",
        "http://127.0.0.1:9000?x=1",
        "http://127.0.0.1:9000#frag",
        "http://127.0.0.1:0",
        "http://:9000",
        "http://127.0.0.1:65536",
        "http://127.0.0.1:9000;x",
        "ftp://127.0.0.1:9000",
        "http://127.0.0.1:9000 ",
        "127.0.0.1:9000",
        "",
    ] {
        let result = gantry_server::app(Config {
            upstream: Some(bad.into()),
            ..Config::default()
        });
        match result {
            Ok(_) => panic!("accepted {bad:?}"),
            // The refusal must not repeat a password back into a log.
            Err(err) => assert!(
                !err.to_string().contains("S3cret"),
                "the error repeats the login: {err}"
            ),
        }
    }
    for good in [
        "http://127.0.0.1:9000",
        "http://127.0.0.1:9000/",
        "HTTP://localhost:9000",
        "http://[::1]:9000",
        // A path is the vendor's prefix, such as Groq's /openai/v1: the route after /v1 is added to it.
        "http://127.0.0.1:9000/v1",
    ] {
        assert!(
            gantry_server::app(Config {
                upstream: Some(good.into()),
                ..Config::default()
            })
            .is_ok(),
            "refused {good:?}"
        );
    }
}

/// Starts the gateway on a real socket with the accept loop the binary uses.
async fn live_gateway(
    config: Config,
    stop: impl Future<Output = ()> + Send + 'static,
) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let timeouts = config.timeouts.clone();
    let app = gantry_server::app(config)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(gantry_server::serve_on(listener, app, timeouts, stop));
    Ok(addr)
}

async fn read_some(socket: &mut TcpStream, within: Duration) -> Option<String> {
    let mut buffer = vec![0u8; 8192];
    match tokio::time::timeout(within, socket.read(&mut buffer)).await {
        Ok(Ok(n)) => Some(String::from_utf8_lossy(&buffer[..n]).into_owned()),
        _ => None,
    }
}

const RAW_REQUEST: &str = "POST /v1/chat/completions HTTP/1.1\r\nHost: gantry\r\nContent-Type: application/json\r\nContent-Length: 39\r\n\r\n{\"model\":\"claude-haiku-5-5\",\"stream\":1}";

#[tokio::test]
async fn a_stream_reaches_the_caller_chunk_by_chunk() -> TestResult {
    // The upstream sends the first chunk at once and the second after a long pause.
    // A gateway that buffers the answer cannot deliver the first chunk before the pause is over.
    let upstream = raw_upstream(vec![
        (Duration::ZERO, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n10\r\ndata: first one\n\r\n"),
        (Duration::from_secs(3), "10\r\ndata: second 1\n\n\r\n0\r\n\r\n"),
    ])
    .await?;
    let gateway = live_gateway(config(upstream, false), std::future::pending()).await?;
    let mut socket = TcpStream::connect(gateway).await?;
    socket.write_all(RAW_REQUEST.as_bytes()).await?;

    let started = Instant::now();
    let mut received = String::new();
    while !received.contains("data: first one") {
        let more = read_some(&mut socket, Duration::from_secs(2))
            .await
            .ok_or("the first chunk did not arrive while the upstream was still sending")?;
        received.push_str(&more);
    }
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(
        !received.contains("second"),
        "the second chunk cannot have arrived yet"
    );
    Ok(())
}

#[tokio::test]
async fn a_client_that_never_finishes_its_headers_is_dropped() -> TestResult {
    let (upstream, _) = recording_upstream().await?;
    let mut config = config(upstream, true);
    config.timeouts = Timeouts {
        read_headers: Duration::from_millis(300),
        ..Timeouts::default()
    };
    let gateway = live_gateway(config, std::future::pending()).await?;

    let mut socket = TcpStream::connect(gateway).await?;
    socket
        .write_all(b"POST /v1/chat/completions HTTP/1.1\r\nHost: gantry\r\nX-Slow: ")
        .await?;
    let mut buffer = [0u8; 1024];
    // Reading returns 0 bytes, or an error, once the gateway has closed the connection. A response with a status also counts as let go.
    let closed = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match socket.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await;
    assert!(
        closed.is_ok(),
        "the connection was still open 3 seconds after a 300 ms header deadline"
    );
    Ok(())
}

#[tokio::test]
async fn a_connection_that_says_nothing_is_dropped() -> TestResult {
    let (upstream, _) = recording_upstream().await?;
    let mut config = config(upstream, false);
    config.timeouts = Timeouts {
        read_headers: Duration::from_millis(300),
        ..Timeouts::default()
    };
    let gateway = live_gateway(config, std::future::pending()).await?;

    // Not one byte is sent. Before protocol detection was turned off, this connection stayed open forever.
    let mut socket = TcpStream::connect(gateway).await?;
    let mut buffer = [0u8; 64];
    let closed = tokio::time::timeout(Duration::from_secs(3), socket.read(&mut buffer)).await;
    assert!(
        matches!(closed, Ok(Ok(0) | Err(_))),
        "a silent connection was still open 3 seconds after a 300 ms header deadline"
    );
    Ok(())
}

#[tokio::test]
async fn a_connection_that_never_gets_to_a_request_is_dropped() -> TestResult {
    let (upstream, _) = recording_upstream().await?;
    // One byte of a request line, and the HTTP/2 preface: both used to hold a connection open forever.
    for opening in [&b"P"[..], &b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"[..]] {
        let mut config = config(upstream, false);
        config.timeouts = Timeouts {
            read_headers: Duration::from_millis(300),
            ..Timeouts::default()
        };
        let gateway = live_gateway(config, std::future::pending()).await?;
        let mut socket = TcpStream::connect(gateway).await?;
        socket.write_all(opening).await?;
        let mut received = Vec::new();
        let mut buffer = [0u8; 1024];
        let closed = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                match socket.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => received.extend_from_slice(&buffer[..n]),
                }
            }
        })
        .await;
        assert!(
            closed.is_ok(),
            "still open 3 seconds after a 300 ms deadline: {opening:?}"
        );
        // An HTTP/2 server answers the preface with a SETTINGS frame, which starts with three length bytes and a 4.
        assert!(
            received.is_empty() || received.starts_with(b"HTTP/1.1 "),
            "the gateway answered in HTTP/2: {received:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_slow_body_is_blamed_on_the_client_when_unchecked_too() -> TestResult {
    let (upstream, seen) = recording_upstream().await?;
    let mut config = config(upstream, false);
    config.timeouts = Timeouts {
        read_body: Duration::from_millis(300),
        ..Timeouts::default()
    };
    let gateway = live_gateway(config, std::future::pending()).await?;

    let mut socket = TcpStream::connect(gateway).await?;
    socket
        .write_all(b"POST /v1/chat/completions HTTP/1.1\r\nHost: gantry\r\nContent-Length: 500\r\n\r\n{\"model\":")
        .await?;
    let answer = read_some(&mut socket, Duration::from_secs(3))
        .await
        .ok_or("no answer within 3 seconds of a 300 ms body deadline")?;
    assert!(
        answer.starts_with("HTTP/1.1 408") && answer.contains("body_timeout"),
        "{answer}"
    );
    assert!(
        seen.lock().map_err(|_| "lock")?.is_none(),
        "the provider was held open by a slow client"
    );
    Ok(())
}

#[tokio::test]
async fn the_providers_own_timing_header_is_kept() -> TestResult {
    let upstream = raw_upstream(vec![(
        Duration::ZERO,
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nServer-Timing: db;dur=53\r\n\r\n{}",
    )])
    .await?;
    let response = gantry_server::app(config(upstream, false))?
        .oneshot(chat().body(Body::from(BODY))?)
        .await?;
    let timings: Vec<&str> = response
        .headers()
        .get_all("server-timing")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    assert_eq!(timings.len(), 2, "{timings:?}");
    assert_eq!(timings[0], "db;dur=53");
    assert!(timings[1].starts_with("gantry;dur="));
    Ok(())
}

#[tokio::test]
async fn every_refusal_is_json_with_a_code_whatever_the_route() -> TestResult {
    let (upstream, _) = recording_upstream().await?;
    for check in [false, true] {
        let app = gantry_server::app(config(upstream, check))?;
        for request in [
            Request::get("/v1/chat/completions"),
            Request::post("/nope"),
            Request::delete("/"),
        ] {
            let response = app.clone().oneshot(request.body(Body::empty())?).await?;
            assert!(response.status().is_client_error());
            assert_eq!(
                response
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok()),
                Some("application/json")
            );
            assert!(response.headers().contains_key("x-gantry-decision"));
            let body = response.into_body().collect().await?.to_bytes();
            let json: serde_json::Value = serde_json::from_slice(&body)?;
            assert!(json["error"]["code"].is_string(), "{json}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn a_body_that_stalls_is_given_up_on() -> TestResult {
    let (upstream, _) = recording_upstream().await?;
    let mut config = config(upstream, true);
    config.timeouts = Timeouts {
        read_body: Duration::from_millis(300),
        ..Timeouts::default()
    };
    let gateway = live_gateway(config, std::future::pending()).await?;

    let mut socket = TcpStream::connect(gateway).await?;
    // The headers promise 500 bytes. Only a few arrive.
    socket
        .write_all(b"POST /v1/chat/completions HTTP/1.1\r\nHost: gantry\r\nAuthorization: Bearer key-maya\r\nContent-Length: 500\r\n\r\n{\"model\":")
        .await?;
    let answer = read_some(&mut socket, Duration::from_secs(3))
        .await
        .ok_or("no answer within 3 seconds of a 300 ms body deadline")?;
    assert!(answer.starts_with("HTTP/1.1 408"), "{answer}");
    assert!(answer.contains("body_timeout"), "{answer}");
    Ok(())
}

#[tokio::test]
async fn a_request_in_flight_finishes_after_the_stop_signal() -> TestResult {
    let upstream = raw_upstream(vec![(
        Duration::from_millis(600),
        "HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\n{\"late\":true}",
    )])
    .await?;
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let gateway = live_gateway(config(upstream, false), async {
        let _ = stopped.await;
    })
    .await?;

    let mut socket = TcpStream::connect(gateway).await?;
    socket.write_all(RAW_REQUEST.as_bytes()).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Stop while the upstream is still thinking.
    let _ = stop.send(());

    let mut received = String::new();
    while !received.contains("{\"late\":true}") {
        let more = read_some(&mut socket, Duration::from_secs(3))
            .await
            .ok_or("the request in flight was dropped at the stop signal")?;
        if more.is_empty() {
            return Err(format!(
                "the connection closed before the answer arrived, after: {received}"
            )
            .into());
        }
        received.push_str(&more);
    }
    // And nothing new is accepted.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        TcpStream::connect(gateway).await.is_err(),
        "the gateway still accepts connections after stopping"
    );
    Ok(())
}
