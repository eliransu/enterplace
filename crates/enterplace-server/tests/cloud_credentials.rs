//! Cloud credentials for Bedrock and Vertex AI from the platform Enterplace runs on: the AWS chain (environment keys,
//! web identity at STS, the container credentials endpoint, IMDSv2, an assumed role) and Google's (a service account
//! key signed into a token, the metadata server), each renewed before it expires. Every endpoint is a mock on
//! 127.0.0.1, reached through the override variables the AWS and Google documentation name, and each mock checks the
//! documented request shape.
//!
//! The key pair in tests/cloud is a throwaway made for these tests with
//! `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048`; its public half is the PKCS #1 DER in hex.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use enterplace_core::audit::AuditLog;
use enterplace_core::config::Kind;
use enterplace_core::id::sha256_hex;
use enterplace_core::policy::{Models, Policy, Who};
use enterplace_core::sigv4;
use enterplace_server::{Audit, Config, ProviderRoute, cloud};
use http_body_util::BodyExt;
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Debug)]
struct Seen {
    method: Method,
    path: String,
    headers: HeaderMap,
    body: String,
}

type Reply = Box<dyn Fn(&Seen, usize) -> (StatusCode, String) + Send + Sync>;

struct Mock {
    seen: Mutex<Vec<Seen>>,
    reply: Reply,
}

async fn handle(State(mock): State<Arc<Mock>>, request: axum::http::Request<Body>) -> Response {
    let (parts, body) = request.into_parts();
    let body = match body.collect().await {
        Ok(collected) => String::from_utf8_lossy(&collected.to_bytes()).into_owned(),
        Err(_) => String::new(),
    };
    let seen = Seen {
        method: parts.method,
        path: parts
            .uri
            .path_and_query()
            .map_or(String::new(), |pq| pq.as_str().to_string()),
        headers: parts.headers,
        body,
    };
    let (status, text) = {
        let mut all = match mock.seen.lock() {
            Ok(all) => all,
            Err(poisoned) => poisoned.into_inner(),
        };
        all.push(seen.clone());
        (mock.reply)(&seen, all.len() - 1)
    };
    (status, text).into_response()
}

async fn mock(reply: Reply) -> Result<(SocketAddr, Arc<Mock>), std::io::Error> {
    let mock = Arc::new(Mock {
        seen: Mutex::new(Vec::new()),
        reply,
    });
    let router = axum::Router::new()
        .fallback(handle)
        .with_state(mock.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Ok((addr, mock))
}

fn seen(mock: &Mock) -> Vec<Seen> {
    match mock.seen.lock() {
        Ok(all) => all.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

fn env(pairs: &[(&str, String)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

/// Every lookup goes to the map, never to the real environment, so a CI runner's own cloud never answers.
async fn aws(
    vars: HashMap<String, String>,
    role: Option<&str>,
) -> Result<cloud::Live<sigv4::Credentials>, Box<dyn std::error::Error + Send + Sync>> {
    let role = role.map(String::from);
    // The first fetch blocks its caller, as it does at start, so it runs off the runtime that serves the mocks.
    let live = tokio::task::spawn_blocking(move || {
        cloud::aws("bedrock", "us-east-1", role.as_deref(), &|name| {
            vars.get(name).cloned()
        })
    })
    .await??;
    Ok(live)
}

async fn google(
    vars: HashMap<String, String>,
) -> Result<cloud::Live<axum::http::HeaderValue>, Box<dyn std::error::Error + Send + Sync>> {
    let live = tokio::task::spawn_blocking(move || {
        cloud::google("vertex", &|name| vars.get(name).cloned())
    })
    .await??;
    Ok(live)
}

fn form(body: &str) -> HashMap<String, String> {
    body.split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (k.to_string(), decode(v)))
        .collect()
}

fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let escaped = bytes
            .get(i + 1..i + 3)
            .and_then(|hex| std::str::from_utf8(hex).ok())
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match (bytes[i], escaped) {
            (b'%', Some(byte)) => {
                out.push(byte);
                i += 3;
            }
            (b'+', _) => {
                out.push(b' ');
                i += 1;
            }
            (byte, _) => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn later(seconds: u64) -> String {
    enterplace_core::audit::rfc3339(SystemTime::now() + Duration::from_secs(seconds))
}

fn sts_answer(action: &str, key: &str, expires: &str) -> String {
    format!(
        "<{action}Response xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><{action}Result><Credentials>\
         <SessionToken>{key}-session</SessionToken><SecretAccessKey>{key}-secret</SecretAccessKey>\
         <Expiration>{expires}</Expiration><AccessKeyId>{key}</AccessKeyId></Credentials></{action}Result></{action}Response>"
    )
}

fn json_answer(key: &str, expires: &str) -> String {
    serde_json::json!({
        "Code": "Success",
        "Type": "AWS-HMAC",
        "AccessKeyId": key,
        "SecretAccessKey": format!("{key}-secret"),
        "Token": format!("{key}-session"),
        "Expiration": expires,
    })
    .to_string()
}

fn temp_dir(name: &str) -> Result<std::path::PathBuf, std::io::Error> {
    let dir = std::env::temp_dir().join(format!(
        "enterplace-cloud-{name}-{}",
        enterplace_core::id::random_hex(6)
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

const KEY: &str = "enterplace_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// A governed gateway in front of one provider, as `enterplace serve` builds it.
fn gateway(
    provider: ProviderRoute,
) -> Result<axum::Router, Box<dyn std::error::Error + Send + Sync>> {
    let log = temp_dir("audit")?.join("audit.jsonl");
    Ok(enterplace_server::app(Config {
        providers: vec![provider],
        policy: Some(
            Policy::new()
                .with_key(KEY, "maya.cohen", "payments")
                .with_rule("everyone", Who::Any, Models::Any),
        ),
        audit: Some(Audit {
            log: Arc::new(AuditLog::open(&log)?),
            provider: String::new(),
            policy_sha256: sha256_hex(b"policy"),
            keys_sha256: sha256_hex(b"keys"),
        }),
        ..Config::default()
    })?)
}

// 1. AWS.

#[tokio::test(flavor = "multi_thread")]
async fn environment_keys_come_first_and_call_nothing() -> TestResult {
    let (addr, sts) = mock(Box::new(|_, _| {
        (StatusCode::INTERNAL_SERVER_ERROR, String::new())
    }))
    .await?;
    let live = aws(
        env(&[
            ("AWS_ACCESS_KEY_ID", "AKIDENV".into()),
            ("AWS_SECRET_ACCESS_KEY", "env-secret".into()),
            ("AWS_SESSION_TOKEN", "env-session".into()),
            ("AWS_WEB_IDENTITY_TOKEN_FILE", "/nonexistent".into()),
            (
                "AWS_ROLE_ARN",
                "arn:aws:iam::123456789012:role/enterplace".into(),
            ),
            ("AWS_ENDPOINT_URL_STS", format!("http://{addr}")),
        ]),
        None,
    )
    .await?;
    let now = live.get();
    assert_eq!(now.access_key_id, "AKIDENV");
    assert_eq!(now.session_token.as_deref(), Some("env-session"));
    assert!(
        live.source().contains("AWS_ACCESS_KEY_ID"),
        "{}",
        live.source()
    );
    assert!(seen(&sts).is_empty());
    // Neither the source nor the debug form shows a secret.
    assert!(!format!("{live:?} {}", live.source()).contains("env-secret"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_web_identity_token_is_exchanged_at_sts() -> TestResult {
    let expires = later(3600);
    let answer = sts_answer("AssumeRoleWithWebIdentity", "ASIAWEB", &expires);
    let (addr, sts) = mock(Box::new(move |_, _| (StatusCode::OK, answer.clone()))).await?;
    let dir = temp_dir("irsa")?;
    let token_file = dir.join("token");
    std::fs::write(&token_file, "eyJ.projected.token\n")?;
    let live = aws(
        env(&[
            (
                "AWS_WEB_IDENTITY_TOKEN_FILE",
                token_file.display().to_string(),
            ),
            (
                "AWS_ROLE_ARN",
                "arn:aws:iam::123456789012:role/enterplace".into(),
            ),
            ("AWS_ENDPOINT_URL_STS", format!("http://{addr}")),
            ("AWS_EC2_METADATA_DISABLED", "true".into()),
        ]),
        None,
    )
    .await?;
    let calls = seen(&sts);
    assert_eq!(calls.len(), 1);
    let call = &calls[0];
    assert_eq!(call.method, Method::POST);
    assert_eq!(call.path, "/");
    assert_eq!(
        call.headers[header::CONTENT_TYPE],
        "application/x-www-form-urlencoded"
    );
    // AssumeRoleWithWebIdentity is not signed: the token is the proof.
    assert!(call.headers.get(header::AUTHORIZATION).is_none());
    let fields = form(&call.body);
    assert_eq!(fields["Action"], "AssumeRoleWithWebIdentity");
    assert_eq!(fields["Version"], "2011-06-15");
    assert_eq!(
        fields["RoleArn"],
        "arn:aws:iam::123456789012:role/enterplace"
    );
    assert_eq!(fields["WebIdentityToken"], "eyJ.projected.token");
    assert!(!fields["RoleSessionName"].is_empty());
    let now = live.get();
    assert_eq!(now.access_key_id, "ASIAWEB");
    assert_eq!(now.secret_access_key, "ASIAWEB-secret");
    assert_eq!(now.session_token.as_deref(), Some("ASIAWEB-session"));
    assert!(live.source().contains("web identity"), "{}", live.source());
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn the_container_endpoint_is_asked_with_its_authorization_token() -> TestResult {
    let expires = later(3600);
    let answer = json_answer("ASIAECS", &expires);
    let (addr, ecs) = mock(Box::new(move |_, _| (StatusCode::OK, answer.clone()))).await?;
    let dir = temp_dir("ecs")?;
    let token_file = dir.join("eks-pod-identity-token");
    std::fs::write(&token_file, "pod-identity-token\n")?;
    let live = aws(
        env(&[
            (
                "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                format!("http://{addr}/v1/credentials"),
            ),
            (
                "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
                token_file.display().to_string(),
            ),
            ("AWS_EC2_METADATA_DISABLED", "true".into()),
        ]),
        None,
    )
    .await?;
    let calls = seen(&ecs);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].method, Method::GET);
    assert_eq!(calls[0].path, "/v1/credentials");
    assert_eq!(
        calls[0].headers[header::AUTHORIZATION],
        "pod-identity-token"
    );
    let now = live.get();
    assert_eq!(now.access_key_id, "ASIAECS");
    assert_eq!(now.session_token.as_deref(), Some("ASIAECS-session"));
    assert!(live.source().contains("container"), "{}", live.source());
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_container_endpoint_over_plain_http_must_be_local() -> TestResult {
    let result = aws(
        env(&[
            (
                "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                "http://credentials.example.com/v1".into(),
            ),
            ("AWS_EC2_METADATA_DISABLED", "true".into()),
        ]),
        None,
    )
    .await;
    let Err(err) = result else {
        return Err("a remote plain HTTP credentials endpoint was used".into());
    };
    let text = err.to_string();
    assert!(
        text.contains("AWS_CONTAINER_CREDENTIALS_FULL_URI"),
        "{text}"
    );
    assert!(text.contains("loopback"), "{text}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn imdsv2_takes_a_session_token_then_the_role_credentials() -> TestResult {
    let expires = later(3600);
    let (addr, imds) = mock(Box::new(move |call, _| {
        let token_ok = call
            .headers
            .get("x-aws-ec2-metadata-token")
            .is_some_and(|v| v == "imds-session");
        match (call.method.as_str(), call.path.as_str()) {
            ("PUT", "/latest/api/token")
                if call
                    .headers
                    .get("x-aws-ec2-metadata-token-ttl-seconds")
                    .is_some() =>
            {
                (StatusCode::OK, "imds-session".into())
            }
            ("GET", "/latest/meta-data/iam/security-credentials/") if token_ok => {
                (StatusCode::OK, "enterplace-instance-role\n".into())
            }
            ("GET", "/latest/meta-data/iam/security-credentials/enterplace-instance-role")
                if token_ok =>
            {
                (StatusCode::OK, json_answer("ASIAEC2", &expires))
            }
            _ => (StatusCode::UNAUTHORIZED, String::new()),
        }
    }))
    .await?;
    let live = aws(
        env(&[(
            "AWS_EC2_METADATA_SERVICE_ENDPOINT",
            format!("http://{addr}/"),
        )]),
        None,
    )
    .await?;
    let calls = seen(&imds);
    let order: Vec<(&str, &str)> = calls
        .iter()
        .map(|c| (c.method.as_str(), c.path.as_str()))
        .collect();
    assert_eq!(
        order,
        [
            ("PUT", "/latest/api/token"),
            ("GET", "/latest/meta-data/iam/security-credentials/"),
            (
                "GET",
                "/latest/meta-data/iam/security-credentials/enterplace-instance-role"
            ),
        ]
    );
    let ttl: u32 = calls[0].headers["x-aws-ec2-metadata-token-ttl-seconds"]
        .to_str()?
        .parse()?;
    assert!((1..=21600).contains(&ttl));
    assert_eq!(live.get().access_key_id, "ASIAEC2");
    assert!(live.source().contains("instance"), "{}", live.source());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn the_first_source_that_works_wins_and_failures_are_named() -> TestResult {
    let expires = later(3600);
    let (sts_addr, _) = mock(Box::new(|_, _| {
        (
            StatusCode::FORBIDDEN,
            "<Error><Code>AccessDenied</Code></Error>".into(),
        )
    }))
    .await?;
    let answer = json_answer("ASIAECS", &expires);
    let (ecs_addr, _) = mock(Box::new(move |_, _| (StatusCode::OK, answer.clone()))).await?;
    let dir = temp_dir("order")?;
    let token_file = dir.join("token");
    std::fs::write(&token_file, "t")?;
    let web = [
        (
            "AWS_WEB_IDENTITY_TOKEN_FILE",
            token_file.display().to_string(),
        ),
        (
            "AWS_ROLE_ARN",
            "arn:aws:iam::123456789012:role/enterplace".into(),
        ),
        ("AWS_ENDPOINT_URL_STS", format!("http://{sts_addr}")),
        ("AWS_EC2_METADATA_DISABLED", "true".into()),
    ];
    let mut both = web.to_vec();
    both.push((
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        format!("http://{ecs_addr}/creds"),
    ));
    let live = aws(env(&both), None).await?;
    assert_eq!(live.get().access_key_id, "ASIAECS");
    // With nothing else to try, the refusal names the source, what STS said, and how to fix it.
    let Err(err) = aws(env(&web), None).await else {
        return Err("credentials were found where STS refused".into());
    };
    let text = err.to_string();
    assert!(text.contains("web identity"), "{text}");
    assert!(text.contains("403"), "{text}");
    assert!(text.contains("AccessDenied"), "{text}");
    assert!(text.contains("AWS_ACCESS_KEY_ID"), "{text}");
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_named_role_is_assumed_with_a_signed_request() -> TestResult {
    let expires = later(3600);
    let answer = sts_answer("AssumeRole", "ASIAROLE", &expires);
    let (addr, sts) = mock(Box::new(move |_, _| (StatusCode::OK, answer.clone()))).await?;
    let live = aws(
        env(&[
            ("AWS_ACCESS_KEY_ID", "AKIDBASE".into()),
            ("AWS_SECRET_ACCESS_KEY", "base-secret".into()),
            ("AWS_ENDPOINT_URL_STS", format!("http://{addr}")),
        ]),
        Some("arn:aws:iam::210987654321:role/bedrock-invoker"),
    )
    .await?;
    let calls = seen(&sts);
    assert_eq!(calls.len(), 1);
    let call = &calls[0];
    let fields = form(&call.body);
    assert_eq!(fields["Action"], "AssumeRole");
    assert_eq!(fields["Version"], "2011-06-15");
    assert_eq!(
        fields["RoleArn"],
        "arn:aws:iam::210987654321:role/bedrock-invoker"
    );
    // Signed with the base credentials, for the sts service, over the body as sent.
    let date = call.headers["x-amz-date"].to_str()?.to_string();
    let host = addr.to_string();
    let expected = sigv4::sign(
        &sigv4::Credentials {
            access_key_id: "AKIDBASE".into(),
            secret_access_key: "base-secret".into(),
            session_token: None,
        },
        "us-east-1",
        "sts",
        &sigv4::Request {
            method: "POST",
            path: "/",
            query: "",
            headers: &[
                ("host", &host),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            payload: call.body.as_bytes(),
        },
        &date,
    );
    assert_eq!(call.headers[header::AUTHORIZATION], expected[0].1.as_str());
    assert!(expected[0].1.contains("/us-east-1/sts/aws4_request"));
    assert_eq!(live.get().access_key_id, "ASIAROLE");
    assert!(
        live.source().contains("bedrock-invoker"),
        "{}",
        live.source()
    );
    Ok(())
}

/// Credentials that expire in a few seconds are renewed halfway through, in the background: a reader never waits,
/// and a Bedrock request signed after the renewal carries the new key and its session token. Nothing restarts.
#[tokio::test(flavor = "multi_thread")]
async fn aws_credentials_are_renewed_before_they_expire() -> TestResult {
    let (addr, ecs) = mock(Box::new(|_, n| {
        let key = if n == 0 { "ASIAFIRST" } else { "ASIASECOND" };
        (
            StatusCode::OK,
            json_answer(key, &later(if n == 0 { 4 } else { 3600 })),
        )
    }))
    .await?;
    let live = aws(
        env(&[
            (
                "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                format!("http://{addr}/creds"),
            ),
            ("AWS_EC2_METADATA_DISABLED", "true".into()),
        ]),
        None,
    )
    .await?;
    let (bedrock_addr, bedrock) = mock(Box::new(|_, _| {
        (
            StatusCode::OK,
            serde_json::json!({"id": "msg_1", "type": "message", "role": "assistant", "model": "m",
                "content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn", "stop_sequence": null,
                "usage": {"input_tokens": 1, "output_tokens": 1}})
            .to_string(),
        )
    }))
    .await?;
    let app = gateway(ProviderRoute {
        name: "bedrock".into(),
        kind: Kind::Bedrock,
        url: format!("http://{bedrock_addr}"),
        models: vec!["claude-sonnet-5-5".into()],
        upstream_models: [(
            "claude-sonnet-5-5".to_string(),
            "anthropic.claude-x".to_string(),
        )]
        .into_iter()
        .collect(),
        region: Some("us-east-1".into()),
        aws: Some(live.clone()),
        ..ProviderRoute::default()
    })?;
    let send = || {
        axum::http::Request::post("/v1/messages")
            .header(header::AUTHORIZATION, format!("Bearer {KEY}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"model":"claude-sonnet-5-5","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}"#,
            ))
    };
    let answer = app.clone().oneshot(send()?).await?;
    assert_eq!(answer.status(), StatusCode::OK);
    let started = Instant::now();
    while live.get().access_key_id == "ASIAFIRST" {
        let read = Instant::now();
        let _ = live.get();
        assert!(read.elapsed() < Duration::from_millis(50), "a read waited");
        if started.elapsed() > Duration::from_secs(10) {
            return Err("the credentials were not renewed".into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // Renewed before the first set expired (4 seconds), not after.
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(seen(&ecs).len(), 2);
    let answer = app.oneshot(send()?).await?;
    assert_eq!(answer.status(), StatusCode::OK);
    let calls = seen(&bedrock);
    assert_eq!(calls.len(), 2);
    let credential = |call: &Seen| {
        call.headers[header::AUTHORIZATION]
            .to_str()
            .unwrap_or_default()
            .to_string()
    };
    assert!(credential(&calls[0]).contains("Credential=ASIAFIRST/"));
    assert_eq!(
        calls[0].headers["x-amz-security-token"],
        "ASIAFIRST-session"
    );
    assert!(credential(&calls[1]).contains("Credential=ASIASECOND/"));
    assert_eq!(
        calls[1].headers["x-amz-security-token"],
        "ASIASECOND-session"
    );
    Ok(())
}

// 2. Google.

fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for byte in text.bytes() {
        let value = URL_SAFE.iter().position(|c| *c == byte)? as u32;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

fn public_key() -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let hex = include_str!("cloud/service-account-public.hex").trim();
    (0..hex.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&hex[i..i + 2], 16)?))
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_service_account_key_signs_a_jwt_for_a_token() -> TestResult {
    let (addr, oauth) = mock(Box::new(|_, _| {
        (
            StatusCode::OK,
            r#"{"access_token":"ya29.service-account","expires_in":3599,"token_type":"Bearer"}"#
                .into(),
        )
    }))
    .await?;
    let dir = temp_dir("sa")?;
    let key_file = dir.join("key.json");
    let token_uri = format!("http://{addr}/token");
    std::fs::write(
        &key_file,
        serde_json::json!({
            "type": "service_account",
            "project_id": "enterplace-test",
            "private_key_id": "test-key-id",
            "private_key": include_str!("cloud/service-account-key.pem"),
            "client_email": "enterplace@enterplace-test.iam.gserviceaccount.example",
            "token_uri": token_uri,
        })
        .to_string(),
    )?;
    let live = google(env(&[
        (
            "GOOGLE_APPLICATION_CREDENTIALS",
            key_file.display().to_string(),
        ),
        ("GCE_METADATA_HOST", "127.0.0.1:9".into()),
    ]))
    .await?;
    assert_eq!(live.get(), "Bearer ya29.service-account");
    assert!(live.get().is_sensitive());
    assert!(
        live.source().contains("GOOGLE_APPLICATION_CREDENTIALS"),
        "{}",
        live.source()
    );
    let calls = seen(&oauth);
    assert_eq!(calls.len(), 1);
    let call = &calls[0];
    assert_eq!(call.method, Method::POST);
    assert_eq!(call.path, "/token");
    assert_eq!(
        call.headers[header::CONTENT_TYPE],
        "application/x-www-form-urlencoded"
    );
    let fields = form(&call.body);
    assert_eq!(
        fields["grant_type"],
        "urn:ietf:params:oauth:grant-type:jwt-bearer"
    );
    let parts: Vec<&str> = fields["assertion"].split('.').collect();
    assert_eq!(parts.len(), 3);
    let head: serde_json::Value =
        serde_json::from_slice(&b64url_decode(parts[0]).ok_or("header is not base64url")?)?;
    assert_eq!(head["alg"], "RS256");
    assert_eq!(head["typ"], "JWT");
    assert_eq!(head["kid"], "test-key-id");
    let claims: serde_json::Value =
        serde_json::from_slice(&b64url_decode(parts[1]).ok_or("claims are not base64url")?)?;
    assert_eq!(
        claims["iss"],
        "enterplace@enterplace-test.iam.gserviceaccount.example"
    );
    assert_eq!(claims["aud"], token_uri.as_str());
    assert_eq!(
        claims["scope"],
        "https://www.googleapis.com/auth/cloud-platform"
    );
    let (iat, exp) = (
        claims["iat"].as_u64().ok_or("no iat")?,
        claims["exp"].as_u64().ok_or("no exp")?,
    );
    assert_eq!(exp - iat, 3600);
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();
    assert!(iat.abs_diff(now) < 60);
    // The signature checks out with the public half of the key pair, made apart from Enterplace by openssl.
    let signature = b64url_decode(parts[2]).ok_or("signature is not base64url")?;
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::RSA_PKCS1_2048_8192_SHA256,
        public_key()?,
    )
    .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
    .map_err(|_| "the JWT signature does not verify")?;
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn the_metadata_server_is_asked_with_its_flavor_header() -> TestResult {
    let (addr, metadata) = mock(Box::new(|call, _| {
        let flavored = call
            .headers
            .get("metadata-flavor")
            .is_some_and(|v| v == "Google");
        if flavored && call.path == "/computeMetadata/v1/instance/service-accounts/default/token" {
            (
                StatusCode::OK,
                r#"{"access_token":"ya29.metadata","expires_in":3599,"token_type":"Bearer"}"#
                    .into(),
            )
        } else {
            (StatusCode::FORBIDDEN, String::new())
        }
    }))
    .await?;
    let live = google(env(&[("GCE_METADATA_HOST", addr.to_string())])).await?;
    assert_eq!(live.get(), "Bearer ya29.metadata");
    assert!(
        live.source().contains("metadata server"),
        "{}",
        live.source()
    );
    let calls = seen(&metadata);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].method, Method::GET);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_credentials_file_is_refused_by_name() -> TestResult {
    let dir = temp_dir("external")?;
    let file = dir.join("wif.json");
    std::fs::write(&file, r#"{"type":"something_else"}"#)?;
    let Err(err) = google(env(&[
        ("GOOGLE_APPLICATION_CREDENTIALS", file.display().to_string()),
        ("GCE_METADATA_HOST", "127.0.0.1:9".into()),
    ]))
    .await
    else {
        return Err("an unknown credentials type was used".into());
    };
    let text = err.to_string();
    assert!(text.contains("something_else"), "{text}");
    assert!(text.contains("service_account"), "{text}");
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

/// A token that lasts a few seconds is renewed halfway through, and the next Vertex request carries the new one.
#[tokio::test(flavor = "multi_thread")]
async fn google_tokens_are_renewed_before_they_expire() -> TestResult {
    let (addr, metadata) = mock(Box::new(|_, n| {
        let (token, ttl) = if n == 0 {
            ("first", 4)
        } else {
            ("second", 3599)
        };
        (
            StatusCode::OK,
            format!(
                r#"{{"access_token":"ya29.{token}","expires_in":{ttl},"token_type":"Bearer"}}"#
            ),
        )
    }))
    .await?;
    let live = google(env(&[("GCE_METADATA_HOST", addr.to_string())])).await?;
    let (vertex_addr, vertex) = mock(Box::new(|_, _| {
        (
            StatusCode::OK,
            serde_json::json!({"id": "msg_1", "type": "message", "role": "assistant", "model": "m",
                "content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn", "stop_sequence": null,
                "usage": {"input_tokens": 1, "output_tokens": 1}})
            .to_string(),
        )
    }))
    .await?;
    let app = gateway(ProviderRoute {
        name: "claude-vertex".into(),
        kind: Kind::VertexAnthropic,
        url: format!("http://{vertex_addr}/v1/projects/p/locations/us-east5/publishers/anthropic"),
        models: vec!["claude-sonnet-4-6".into()],
        google: Some(live.clone()),
        ..ProviderRoute::default()
    })?;
    let send = || {
        axum::http::Request::post("/v1/messages")
            .header(header::AUTHORIZATION, format!("Bearer {KEY}"))
            .header(header::CONTENT_TYPE, "application/json")
            .header("anthropic-version", "2023-06-01")
            .body(Body::from(
                r#"{"model":"claude-sonnet-4-6","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}"#,
            ))
    };
    assert_eq!(app.clone().oneshot(send()?).await?.status(), StatusCode::OK);
    let started = Instant::now();
    while live.get() == "Bearer ya29.first" {
        if started.elapsed() > Duration::from_secs(10) {
            return Err("the token was not renewed".into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(seen(&metadata).len(), 2);
    assert_eq!(app.oneshot(send()?).await?.status(), StatusCode::OK);
    let calls = seen(&vertex);
    assert_eq!(calls[0].headers[header::AUTHORIZATION], "Bearer ya29.first");
    assert_eq!(
        calls[1].headers[header::AUTHORIZATION],
        "Bearer ya29.second"
    );
    Ok(())
}

/// A forward proxy that takes HTTP CONNECT, as a corporate egress proxy does. It records each request head, and
/// sends a host under `.test` (a name only it knows) to 127.0.0.1, so a call that reaches the mock went through it.
async fn connect_proxy() -> Result<(SocketAddr, Arc<Mutex<Vec<String>>>), std::io::Error> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let seen = Arc::new(Mutex::new(Vec::new()));
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
                let Some((host, port)) = head
                    .lines()
                    .next()
                    .and_then(|l| l.strip_prefix("CONNECT "))
                    .and_then(|l| l.split(' ').next())
                    .and_then(|t| t.rsplit_once(':'))
                else {
                    return;
                };
                let host = if host.ends_with(".test") {
                    "127.0.0.1"
                } else {
                    host
                };
                let Ok(mut upstream) =
                    tokio::net::TcpStream::connect((host, port.parse().unwrap_or(0))).await
                else {
                    return;
                };
                if client.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.is_ok() {
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                }
            });
        }
    });
    Ok((addr, seen))
}

#[tokio::test(flavor = "multi_thread")]
async fn sts_is_reached_through_the_provider_s_proxy() -> TestResult {
    let expires = later(3600);
    let answer = sts_answer("AssumeRoleWithWebIdentity", "ASIAPROXY", &expires);
    let (addr, sts) = mock(Box::new(move |_, _| (StatusCode::OK, answer.clone()))).await?;
    let (proxy, through) = connect_proxy().await?;
    let dir = temp_dir("proxied")?;
    let token_file = dir.join("token");
    std::fs::write(&token_file, "eyJ.projected.token\n")?;
    let vars = env(&[
        (
            "AWS_WEB_IDENTITY_TOKEN_FILE",
            token_file.display().to_string(),
        ),
        (
            "AWS_ROLE_ARN",
            "arn:aws:iam::123456789012:role/enterplace".into(),
        ),
        // A name only the proxy resolves: STS answers only through it.
        (
            "AWS_ENDPOINT_URL_STS",
            format!("http://sts.test:{}", addr.port()),
        ),
        ("AWS_EC2_METADATA_DISABLED", "true".into()),
    ]);
    let url = format!("http://gw:s3cret@{proxy}");
    let live = tokio::task::spawn_blocking(move || {
        cloud::aws_via(
            "bedrock",
            "us-east-1",
            None,
            &|name| vars.get(name).cloned(),
            Some(&url),
        )
    })
    .await??;
    assert_eq!(live.get().access_key_id, "ASIAPROXY");
    assert_eq!(seen(&sts).len(), 1);
    let heads = through.lock().map_err(|_| "poisoned")?.clone();
    let head = heads.first().ok_or("nothing went through the proxy")?;
    assert!(
        head.starts_with(&format!("CONNECT sts.test:{} ", addr.port())),
        "{head}"
    );
    // gw:s3cret, as Basic credentials.
    assert!(head.contains("Basic Z3c6czNjcmV0"), "{head}");
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}
