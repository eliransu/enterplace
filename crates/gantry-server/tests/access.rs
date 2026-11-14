//! Key management and access: a key's fields changed through the admin API and recorded with what they were and
//! became, a key's settings with its spend, rotation with a grace window in which every use of the old key is
//! recorded, per-key rpm, parallel and route limits, source address ranges per key and per rule (with
//! X-Forwarded-For read only from trusted proxies), and JWTs from a trusted identity provider in place of a key.
//! Every provider here is a mock on 127.0.0.1.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::atomic::AtomicUsize,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use gantry_core::id::sha256_hex;
use gantry_server::Governed;
use http_body_util::BodyExt;
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

type Error = Box<dyn std::error::Error>;
type TestResult = Result<(), Error>;

const ADMIN: &str = "gantry_admin_0123456789abcdef0123456789abcdef";
const MAYA: &str = "gantry_maya_0123456789abcdef0123456789abcdef0";
const CHAT_OK: &str = r#"{"id":"c","object":"chat.completion","choices":[],"usage":{"prompt_tokens":10,"completion_tokens":5}}"#;

/// A provider that answers every chat request; model `slow` answers after 400 ms.
async fn provider() -> Result<SocketAddr, Error> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = Router::new().fallback(|request: Request<Body>| async move {
        let body = request
            .into_body()
            .collect()
            .await
            .map(|b| b.to_bytes())
            .unwrap_or_default();
        if body.windows(6).any(|w| w == b"\"slow\"") {
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
        ([(header::CONTENT_TYPE, "application/json")], CHAT_OK).into_response()
    });
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(addr)
}

fn dir(name: &str) -> Result<PathBuf, Error> {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "gantry-access-{}-{}-{name}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// A governed gateway with an admin and maya, and `extra` added to the policy (top-level keys and rule fields).
fn gateway(name: &str, port: u16, top: &str, rule: &str) -> Result<(Governed, PathBuf), Error> {
    let dir = dir(name)?;
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
    models: [m, slow]
{top}rules:
  - name: everyone
    principals: {{ any: true }}
    models: [\"*\"]
{rule}"
        ),
    )?;
    let entry = |name: &str, key: &str, admin: bool| {
        format!(
            "  - name: {name}\n    team: ops\n    sha256: {}\n{}",
            sha256_hex(key.as_bytes()),
            if admin { "    admin: true\n" } else { "" }
        )
    };
    std::fs::write(
        dir.join("gantry.keys.yaml"),
        format!(
            "keys:\n{}{}",
            entry("ops", ADMIN, true),
            entry("maya", MAYA, false)
        ),
    )?;
    let gw = gantry_server::governed(&policy, None, &|_| Some("provider-key".into()))?;
    Ok((gw, dir))
}

fn request(method: &str, path: &str, key: &str, body: &str) -> Result<Request<Body>, Error> {
    Ok(Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {key}"))
        .body(Body::from(body.to_string()))?)
}

async fn answer(app: &Router, request: Request<Body>) -> Result<(StatusCode, Value), Error> {
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, serde_json::from_slice(&body).unwrap_or(Value::Null)))
}

async fn chat(app: &Router, key: &str, model: &str) -> Result<(StatusCode, Value), Error> {
    answer(
        app,
        request(
            "POST",
            "/v1/chat/completions",
            key,
            &format!(r#"{{"model":"{model}","messages":[]}}"#),
        )?,
    )
    .await
}

fn code(body: &Value) -> &str {
    body["error"]["code"].as_str().unwrap_or_default()
}

fn records(dir: &Path) -> Result<Vec<Value>, Error> {
    std::fs::read_to_string(dir.join("gantry-audit.jsonl"))?
        .lines()
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn maya_prefix() -> String {
    sha256_hex(MAYA.as_bytes())[..8].to_string()
}

#[tokio::test]
async fn an_admin_changes_a_key_and_the_record_says_what_each_field_was_and_became() -> TestResult {
    let port = provider().await?.port();
    let (gw, dir) = gateway("update", port, "", "")?;
    let path = format!("/admin/keys/{}", maya_prefix());
    let (status, body) = answer(
        &gw.router,
        request(
            "PATCH",
            &path,
            ADMIN,
            r#"{"rpm": 1, "tags": ["eval"], "metadata": {"owner": "maya", "ticket": "OPS-1"}}"#,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["key"]["rpm"], 1);
    assert_eq!(body["status"]["in_effect"], true);
    let changed = records(&dir)?
        .into_iter()
        .find(|r| r["action"] == "update_key")
        .ok_or("the change was not recorded")?;
    assert_eq!(
        changed["target"]["changes"]["rpm"],
        json!({ "from": null, "to": 1 })
    );
    assert_eq!(changed["target"]["changes"]["tags"]["to"], json!(["eval"]));
    assert_eq!(changed["person"], "ops");
    // The key's own rpm holds at once.
    assert_eq!(chat(&gw.router, MAYA, "m").await?.0, StatusCode::OK);
    let (status, body) = chat(&gw.router, MAYA, "m").await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(code(&body), "rate_limited");
    let limited = records(&dir)?
        .into_iter()
        .rev()
        .find(|r| r["code"] == "rate_limited")
        .ok_or("no record")?;
    assert_eq!(limited["limit"]["of"], "key");
    // null removes a field.
    let (status, body) = answer(
        &gw.router,
        request("PATCH", &path, ADMIN, r#"{"rpm": null}"#)?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(chat(&gw.router, MAYA, "m").await?.0, StatusCode::OK);
    let (status, body) = answer(
        &gw.router,
        request(
            "PATCH",
            &path,
            ADMIN,
            r#"{"budget": {"usd": 5, "per": "day"}}"#,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Key info: settings and spend, never the key.
    let (status, info) = answer(&gw.router, request("GET", &path, ADMIN, "")?).await?;
    assert_eq!(status, StatusCode::OK, "{info}");
    assert_eq!(info["key"]["metadata"]["ticket"], "OPS-1");
    assert_eq!(info["key"]["budget"], json!({ "usd": 5.0, "per": "day" }));
    assert_eq!(info["spend"].as_array().map(Vec::len), Some(2), "{info}");
    assert_eq!(info["spend_counted_by"], "this gateway");
    assert!(!info.to_string().contains(MAYA));
    // Wrong changes are refused whole, and change nothing.
    let keys_before = std::fs::read_to_string(dir.join("gantry.keys.yaml"))?;
    for (bad, said) in [
        (r#"{"rpm": 0}"#, "rpm is a whole number"),
        (r#"{"name": "dana"}"#, "is not a key field"),
        (r#"{"admin": true}"#, "is not a key field"),
        (
            r#"{"tags": ["ok"], "from": ["nope"]}"#,
            "is not an address range",
        ),
        (r#"{"models": ["not-served"]}"#, "is not served here"),
        (r#"{}"#, "send the fields to change"),
    ] {
        let (status, body) = answer(&gw.router, request("PATCH", &path, ADMIN, bad)?).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {body}");
        assert!(body.to_string().contains(said), "{bad}: {body}");
    }
    assert_eq!(
        std::fs::read_to_string(dir.join("gantry.keys.yaml"))?,
        keys_before
    );
    // Only an admin may change a key.
    let (status, body) =
        answer(&gw.router, request("PATCH", &path, MAYA, r#"{"rpm": 5}"#)?).await?;
    assert_eq!((status, code(&body)), (StatusCode::FORBIDDEN, "not_admin"));
    Ok(())
}

#[tokio::test]
async fn a_rotated_key_works_through_its_grace_with_every_use_recorded_then_stops() -> TestResult {
    let port = provider().await?.port();
    let (gw, dir) = gateway("rotate", port, "", "")?;
    let old = maya_prefix();
    let (status, rotated) = answer(
        &gw.router,
        request(
            "POST",
            &format!("/admin/keys/{old}/rotate"),
            ADMIN,
            r#"{"grace": "1h"}"#,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED, "{rotated}");
    let new_key = rotated["key"].as_str().ok_or("no key")?.to_string();
    let new_prefix = rotated["sha256_prefix"]
        .as_str()
        .ok_or("no prefix")?
        .to_string();
    assert_eq!(rotated["replaces"], old.as_str());
    // Both keys work during the grace, as the same person.
    assert_eq!(chat(&gw.router, &new_key, "m").await?.0, StatusCode::OK);
    assert_eq!(chat(&gw.router, MAYA, "m").await?.0, StatusCode::OK);
    let all = records(&dir)?;
    let used_old = all
        .iter()
        .filter(|r| r["key"] == old.as_str() && r["path"] == "/v1/chat/completions")
        .collect::<Vec<_>>();
    assert_eq!(used_old.len(), 1);
    assert_eq!(used_old[0]["person"], "maya");
    assert_eq!(
        used_old[0]["key_rotated"]["replaced_by"],
        new_prefix.as_str()
    );
    assert!(
        all.iter()
            .any(|r| r["action"] == "rotate_key"
                && r["target"]["replaced_by"] == new_prefix.as_str())
    );
    let used_new = all
        .iter()
        .find(|r| r["key"] == new_prefix.as_str())
        .ok_or("no record of the new key")?;
    assert!(used_new.get("key_rotated").is_none());
    // A key already rotated is not rotated again.
    let (status, body) = answer(
        &gw.router,
        request("POST", &format!("/admin/keys/{old}/rotate"), ADMIN, "")?,
    )
    .await?;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::CONFLICT, "already_rotated")
    );
    // A rotation with no grace ends the old key now.
    let (status, again) = answer(
        &gw.router,
        request(
            "POST",
            &format!("/admin/keys/{new_prefix}/rotate"),
            ADMIN,
            r#"{"grace": "0"}"#,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED, "{again}");
    let (status, body) = chat(&gw.router, &new_key, "m").await?;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::UNAUTHORIZED, "key_expired"),
        "{body}"
    );
    let newest = again["key"].as_str().ok_or("no key")?;
    assert_eq!(chat(&gw.router, newest, "m").await?.0, StatusCode::OK);
    for bad in [
        r#"{"grace": "forever"}"#,
        r#"{"grace": "91d"}"#,
        r#"{"wait": "1h"}"#,
    ] {
        let prefix = &again["sha256_prefix"].as_str().ok_or("no prefix")?;
        let (status, _) = answer(
            &gw.router,
            request("POST", &format!("/admin/keys/{prefix}/rotate"), ADMIN, bad)?,
        )
        .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
    Ok(())
}

#[tokio::test]
async fn a_key_limited_to_routes_or_to_parallel_requests_is_refused_past_them() -> TestResult {
    let port = provider().await?.port();
    let (gw, _dir) = gateway("routes", port, "", "")?;
    let path = format!("/admin/keys/{}", maya_prefix());
    let (status, _) = answer(
        &gw.router,
        request("PATCH", &path, ADMIN, r#"{"routes": ["/v1/embeddings"]}"#)?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = chat(&gw.router, MAYA, "m").await?;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::FORBIDDEN, "route_not_allowed"),
        "{body}"
    );
    let (status, _) = answer(
        &gw.router,
        request("PATCH", &path, ADMIN, r#"{"routes": null, "parallel": 1}"#)?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let (first, second) = tokio::join!(chat(&gw.router, MAYA, "slow"), async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        chat(&gw.router, MAYA, "slow").await
    });
    let (first, second) = (first?, second?);
    assert_eq!(first.0, StatusCode::OK, "{}", first.1);
    assert_eq!(
        (second.0, code(&second.1)),
        (StatusCode::TOO_MANY_REQUESTS, "parallel_limited"),
        "{}",
        second.1
    );
    // The place comes back with the answer.
    assert_eq!(chat(&gw.router, MAYA, "slow").await?.0, StatusCode::OK);
    Ok(())
}

/// Serves `router` on a real socket, so requests carry the connection's address.
async fn live(router: Router) -> Result<SocketAddr, Error> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(gantry_server::serve_on(
        listener,
        router,
        gantry_server::Timeouts::default(),
        std::future::pending(),
    ));
    Ok(addr)
}

/// One chat request over a fresh connection, with extra header lines. Returns the status and the body.
async fn raw_chat(addr: SocketAddr, key: &str, extra: &str) -> Result<(u16, String), Error> {
    let body = r#"{"model":"m","messages":[]}"#;
    let mut socket = tokio::net::TcpStream::connect(addr).await?;
    socket
        .write_all(
            format!(
                "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {key}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await?;
    let mut text = String::new();
    socket.read_to_string(&mut text).await?;
    let status = text.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    Ok((status, body))
}

#[tokio::test]
async fn source_ranges_hold_per_key_and_per_rule_and_forwarded_for_counts_only_from_a_trusted_proxy()
-> TestResult {
    let port = provider().await?.port();
    let (gw, dir) = gateway("from", port, "", "")?;
    let (status, _) = answer(
        &gw.router,
        request(
            "PATCH",
            &format!("/admin/keys/{}", maya_prefix()),
            ADMIN,
            r#"{"from": ["10.0.0.0/8"]}"#,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let addr = live(gw.router.clone()).await?;
    let (status, body) = raw_chat(addr, MAYA, "").await?;
    assert_eq!(status, 403, "{body}");
    assert!(
        body.contains("ip_not_allowed") && body.contains("127.0.0.1"),
        "{body}"
    );
    // A client cannot claim another address: no proxy is trusted here.
    let (status, _) = raw_chat(addr, MAYA, "X-Forwarded-For: 10.1.2.3\r\n").await?;
    assert_eq!(status, 403);
    let refused = records(&dir)?
        .into_iter()
        .rev()
        .find(|r| r["code"] == "ip_not_allowed")
        .ok_or("no record")?;
    assert_eq!(refused["client"], "127.0.0.1");
    assert_eq!(refused["ip_not_allowed"], "key");

    // Behind a trusted load balancer the address it names is the client's, and a rule's range holds too.
    let (gw, dir) = gateway(
        "from-proxy",
        port,
        "trusted_proxies: [127.0.0.1]\n",
        "    from: [10.0.0.0/8, 192.0.2.0/24]\n",
    )?;
    let addr = live(gw.router.clone()).await?;
    let (status, body) = raw_chat(addr, MAYA, "X-Forwarded-For: 10.1.2.3\r\n").await?;
    assert_eq!(status, 200, "{body}");
    let allowed = records(&dir)?
        .into_iter()
        .rev()
        .find(|r| r["path"] == "/v1/chat/completions")
        .ok_or("no record")?;
    assert_eq!(allowed["client"], "10.1.2.3");
    let (status, body) = raw_chat(addr, MAYA, "X-Forwarded-For: 198.51.100.7\r\n").await?;
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("rule \\\"everyone\\\""), "{body}");
    // The admin, with no range of its own, is held by the rule as well.
    let (status, _) = raw_chat(addr, ADMIN, "").await?;
    assert_eq!(status, 403);
    Ok(())
}

fn b64url(bytes: &[u8]) -> String {
    const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(char::from(URL_SAFE[(n >> (18 - 6 * i) & 63) as usize]));
        }
    }
    out
}

/// An identity provider: a P-256 signing key and its key set served at /jwks.
struct Idp {
    key: EcdsaKeyPair,
    rng: SystemRandom,
    url: String,
}

impl Idp {
    async fn start() -> Result<Idp, Error> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| "no key")?;
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .map_err(|_| "bad key")?;
        let point = key.public_key().as_ref().to_vec();
        let jwks = json!({ "keys": [{
            "kty": "EC", "crv": "P-256", "kid": "k1", "use": "sig",
            "x": b64url(&point[1..33]), "y": b64url(&point[33..65]),
        }] })
        .to_string();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let app = Router::new().route(
            "/jwks",
            get(move || {
                let jwks = jwks.clone();
                async move { ([(header::CONTENT_TYPE, "application/json")], jwks) }
            }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Idp { key, rng, url })
    }

    fn token(&self, claims: &Value) -> Result<String, Error> {
        let head = b64url(
            json!({ "alg": "ES256", "kid": "k1", "typ": "JWT" })
                .to_string()
                .as_bytes(),
        );
        let body = b64url(claims.to_string().as_bytes());
        let signed = format!("{head}.{body}");
        let sig = self
            .key
            .sign(&self.rng, signed.as_bytes())
            .map_err(|_| "no signature")?;
        Ok(format!("{signed}.{}", b64url(sig.as_ref())))
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[tokio::test]
async fn a_jwt_from_a_trusted_issuer_is_decided_and_recorded_as_its_person_and_anything_else_is_refused()
-> TestResult {
    let port = provider().await?.port();
    let idp = Idp::start().await?;
    let issuer = idp.url.clone();
    let top = format!(
        "jwt:\n  - issuer: {issuer}\n    audience: gantry\n    jwks_url: {issuer}/jwks\n    person_claim: email\n    team_claim: groups\n"
    );
    let (gw, dir) = gateway("jwt", port, &top, "")?;
    let claims = |over: Value| {
        let mut base = json!({
            "iss": issuer, "aud": ["gantry", "other"], "sub": "u-123", "email": "dana@example.com",
            "groups": ["research"], "exp": now() + 300,
        });
        if let (Some(base), Value::Object(over)) = (base.as_object_mut(), over) {
            base.extend(over);
        }
        base
    };
    let token = idp.token(&claims(json!({})))?;
    let (status, body) = chat(&gw.router, &token, "m").await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let record = records(&dir)?
        .into_iter()
        .rev()
        .find(|r| r["path"] == "/v1/chat/completions")
        .ok_or("no record")?;
    assert_eq!(record["person"], "dana@example.com");
    assert_eq!(record["team"], "research");
    assert_eq!(record["auth"], "jwt");
    assert_eq!(record["jwt_issuer"], issuer.as_str());
    assert_eq!(record["jwt_subject"], "u-123");
    assert!(
        !record.to_string().contains(&token),
        "the token is never recorded"
    );

    let mut tampered = idp.token(&claims(json!({})))?;
    tampered.replace_range(tampered.len() - 4.., "AAAA");
    for (token, wanted) in [
        (
            idp.token(&claims(json!({ "aud": "someone-else" })))?,
            "jwt_invalid",
        ),
        (
            idp.token(&claims(json!({ "exp": now() - 3600 })))?,
            "jwt_expired",
        ),
        (
            idp.token(&claims(json!({ "iss": "https://evil.example.com" })))?,
            "jwt_untrusted",
        ),
        (
            idp.token(&claims(json!({ "groups": ["a", "b"] })))?,
            "jwt_claims",
        ),
        (idp.token(&claims(json!({ "email": null })))?, "jwt_claims"),
        (tampered, "jwt_invalid"),
    ] {
        let (status, body) = chat(&gw.router, &token, "m").await?;
        assert_eq!(code(&body), wanted, "{body}");
        assert!(status == StatusCode::UNAUTHORIZED, "{status} {body}");
    }
    // A key still works beside the issuer.
    assert_eq!(chat(&gw.router, MAYA, "m").await?.0, StatusCode::OK);
    Ok(())
}
